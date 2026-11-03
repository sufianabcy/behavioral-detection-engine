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
                data[item.get("Name") or f"Data{position}"] = item.text or ""
    user_data = _child(root, "UserData")  # some events use this instead of EventData
    if user_data is not None:
        for item in user_data.iter():
            if item is not user_data and len(item) == 0:
                data.setdefault(_local(item.tag), (item.text or "").strip())

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
    return event_from_element(ET.fromstring(xml_text), meta)


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
    text = _XML_DECLARATION.sub("", _decode(path.read_bytes()))
    wrapper = ET.fromstring(f"<wrapper>{text}</wrapper>")
    for element in _find_events(wrapper):
        event = event_from_element(element, {"source_file": path.name})
        if event is not None:
            yield event


def read_evtx(path: Path) -> Iterator[Event]:
    """Read a binary .evtx file (needs the python-evtx package)."""
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        raise RuntimeError(
            "Reading .evtx files needs the python-evtx package. "
            "Run: python -m pip install -r requirements.txt"
        ) from None

    if path.stat().st_size == 0:
        return
    skipped = 0
    with Evtx(str(path)) as evtx_file:
        # python-evtx happily opens any file and finds no records in it, so
        # check the "ElfFile" signature at the start ourselves.
        try:
            is_evtx = evtx_file.get_file_header().check_magic()
        except Exception:
            is_evtx = False
        if not is_evtx:
            raise ValueError(f"{path.name} is not a valid .evtx file (its header is wrong)")
        for record in evtx_file.records():
            # A damaged record should not stop the rest of the file, so any
            # error here only skips that one record.
            try:
                event = parse_event_xml(record.xml(), {"source_file": path.name})
            except Exception:
                skipped += 1
                continue
            if event is not None:
                yield event
    if skipped:
        log.warning("skipped %d unreadable records in %s", skipped, path.name)
