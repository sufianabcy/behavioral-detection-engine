r"""Read Windows event logs: binary .evtx files and XML exports.

Both end up as Windows Event XML. One event looks like this (trimmed):

    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Sysmon" />
        <EventID>1</EventID>
        <TimeCreated SystemTime="2026-11-03T09:14:05.0934170Z" />
        <EventRecordID>48211</EventRecordID>
        <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
        <Computer>WKSTN-07.corp.example</Computer>
      </System>
      <EventData>
        <Data Name="UtcTime">2026-11-03 09:14:05.093</Data>
        <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
        <Data Name="CommandLine">powershell.exe -nop -w hidden -enc ...</Data>
        ...
      </EventData>
    </Event>

`event_from_element()` turns one of those into an `Event`; the two `read_*`
functions find the events in a file.

Phase 7 lesson: different tools write the same typed value differently. A
GUID can arrive as {365abb72-...} or 365ABB72-..., a hex number as 0x3e4 or
0x00000000000003e4, a boolean as true or True. `canonical_value()` writes each
one way, so an event looks the same whichever tool read it.
"""

from __future__ import annotations

import codecs
import logging
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..event import Event, parse_time

log = logging.getLogger(__name__)

_XML_DECLARATION = re.compile(r"^\s*<\?xml[^>]*\?>")
# Characters XML 1.0 forbids. A few real logs contain them (raw bytes in a
# privilege list, for example), and one would make the whole event unreadable.
_XML_INVALID = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")
_GUID = re.compile(r"^\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?$")
_HEX = re.compile(r"^0[xX][0-9a-fA-F]+$")
_EVTX_MAGIC = b"ElfFile\x00"  # the first 8 bytes of every .evtx file


def canonical_value(value: str) -> str:
    """Write typed values one way, whichever tool rendered them.

    GUIDs become {lowercase}, as Sysmon writes them; hex numbers lose their
    leading zeros (0x00000000000003e7 -> 0x3e7), as Windows shows them;
    True/False become true/false. Everything else is left exactly as it is.
    """
    guid = _GUID.match(value)
    if guid:
        return "{" + guid.group(1).lower() + "}"
    if _HEX.match(value):
        return hex(int(value, 16))
    if value in ("True", "False"):
        return value.lower()
    return value


def _local(tag: str) -> str:
    """'{http://schemas...}EventID' -> 'EventID' (drop the XML namespace)."""
    return tag.rsplit("}", 1)[-1]


def _child(element: ET.Element, name: str) -> ET.Element | None:
    for child in element:
        if _local(child.tag) == name:
            return child
    return None


def _text(element: ET.Element | None) -> str:
    return (element.text or "").strip() if element is not None else ""


def event_from_element(root: ET.Element, meta: dict[str, Any] | None = None) -> Event | None:
    """Convert one <Event> XML element to an Event. Returns None if unusable."""
    system = _child(root, "System")
    if system is None:
        return None
    try:
        event_id = int(_text(_child(system, "EventID")))
    except ValueError:
        return None

    data: dict[str, str] = {}
    event_data = _child(root, "EventData")
    if event_data is not None:
        for position, item in enumerate(event_data):
            if _local(item.tag) == "Data":
                data[item.get("Name") or f"Data{position}"] = canonical_value(item.text or "")
    user_data = _child(root, "UserData")  # some events use this instead of EventData
    if user_data is not None:
        for item in user_data.iter():
            if item is not user_data and len(item) == 0:
                data.setdefault(_local(item.tag), canonical_value((item.text or "").strip()))

    # Sysmon's UtcTime says when the action happened; TimeCreated says when it
    # was written to the log. Prefer the first, fall back to the second.
    time_created = _child(system, "TimeCreated")
    candidates = [data.get("UtcTime"), time_created.get("SystemTime") if time_created is not None else None]
    timestamp = None
    for candidate in candidates:
        if candidate:
            try:
                timestamp = parse_time(candidate)
                break
            except ValueError:
                continue
    if timestamp is None:
        return None

    info: dict[str, Any] = dict(meta or {})
    record_id = _text(_child(system, "EventRecordID"))
    if record_id.isdigit():
        info["record_id"] = int(record_id)
    provider = _child(system, "Provider")
    if provider is not None and provider.get("Name"):
        info["provider"] = provider.get("Name")

    return Event(
        event_id=event_id,
        timestamp=timestamp,
        host=_text(_child(system, "Computer")),
        channel=_text(_child(system, "Channel")),
        data=data,
        meta=info,
    )


def parse_event_xml(xml_text: str, meta: dict[str, Any] | None = None) -> Event | None:
    """Parse the XML of a single event."""
    return event_from_element(ET.fromstring(_XML_INVALID.sub("�", xml_text)), meta)


def _decode(raw: bytes) -> str:
    """Decode an XML export whatever tool wrote it.

    On Windows, `wevtutil qe ... /f:xml > out.xml` in PowerShell 5 writes
    UTF-16 with a byte-order mark; Event Viewer and most other tools write
    UTF-8, sometimes with a byte-order mark too.
    """
    if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return raw.decode("utf-16")
    return raw.decode("utf-8-sig")


def _find_events(element: ET.Element) -> Iterator[ET.Element]:
    for child in element:
        if _local(child.tag) == "Event":
            yield child  # don't look inside an event for more events
        else:
            yield from _find_events(child)


def read_xml_file(path: Path) -> Iterator[Event]:
    """Read an XML export: Event Viewer's 'Save as XML' (<Events><Event>...)
    or wevtutil output (bare <Event> elements one after another)."""
    text = _XML_INVALID.sub("�", _XML_DECLARATION.sub("", _decode(path.read_bytes())))
    wrapper = ET.fromstring(f"<wrapper>{text}</wrapper>")
    for element in _find_events(wrapper):
        event = event_from_element(element, {"source_file": path.name})
        if event is not None:
            yield event


def evtx_backend() -> str:
    """Which .evtx parser is installed: "evtx" or "python-evtx".

    `evtx` is written in Rust: about 40 times faster, and in phase 7 it read
    every record of 571 public recordings, where python-evtx (pure Python)
    could not decode any record in 15 of them (1,681 records). requirements.txt
    installs `evtx` everywhere it has a ready-made build, and python-evtx only
    on Windows on ARM, where it doesn't. Never install both in one environment
    on a Mac or on Windows: their import names, `evtx` and `Evtx`, differ only
    in case, and those file systems treat them as the same folder.
    """
    try:
        import evtx  # noqa: F401
        return "evtx"
    except ImportError:
        pass
    try:
        import Evtx.Evtx  # noqa: F401
        return "python-evtx"
    except ImportError:
        raise RuntimeError(
            "Reading .evtx files needs the evtx package. Run: python -m pip install -r requirements.txt\n"
            "If it is installed and this still fails, evtx and python-evtx may have overwritten each other "
            "(this happens on macOS and Windows): recreate the environment with "
            "python -m venv --clear .venv, then install requirements.txt again."
        ) from None


def _records_rust(path: Path) -> Iterator[str | None]:
    """XML of each record, read with the `evtx` package (None for a damaged record)."""
    from evtx import PyEvtxParser

    records = iter(PyEvtxParser(str(path), number_of_threads=1).records())  # one thread: same order every run
    failures_in_a_row = 0
    while failures_in_a_row < 100:  # a file this damaged has nothing more to give
        try:
            record = next(records)
        except StopIteration:
            return
        except RuntimeError:
            failures_in_a_row += 1
            yield None
            continue
        failures_in_a_row = 0
        yield None if isinstance(record, Exception) else record["data"]


def _records_python(path: Path) -> Iterator[str | None]:
    """XML of each record, read with python-evtx (None for a damaged record)."""
    from Evtx.Evtx import Evtx

    with Evtx(str(path)) as evtx_file:
        for record in evtx_file.records():
            try:
                yield record.xml()
            except Exception:  # python-evtx raises many kinds of errors on records it can't decode
                yield None


def read_evtx(path: Path, stats: dict[str, int] | None = None) -> Iterator[Event]:
    """Read a binary .evtx file, with whichever parser `evtx_backend()` finds.

    Damaged records are skipped with a warning; `stats["unreadable"]` counts them.
    """
    backend = evtx_backend()
    if path.stat().st_size == 0:
        return
    # Both parsers happily open any file and find no records in it, so check
    # the "ElfFile" signature at the start ourselves.
    with path.open("rb") as handle:
        if handle.read(len(_EVTX_MAGIC)) != _EVTX_MAGIC:
            raise ValueError(f"{path.name} is not a valid .evtx file (its header is wrong)")
    records = _records_rust(path) if backend == "evtx" else _records_python(path)
    skipped = 0
    for xml_text in records:
        # A damaged record should not stop the rest of the file, so an error
        # here only skips that one record.
        if xml_text is None:
            skipped += 1
            continue
        try:
            event = parse_event_xml(xml_text, {"source_file": path.name})
        except (ET.ParseError, ValueError):
            skipped += 1
            continue
        if event is not None:
            yield event
    if skipped:
        log.warning("skipped %d unreadable records in %s (read with %s)", skipped, path.name, backend)
        if stats is not None:
            stats["unreadable"] = stats.get("unreadable", 0) + skipped
