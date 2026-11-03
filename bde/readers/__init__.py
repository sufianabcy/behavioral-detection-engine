"""Readers: turn any supported log file into a stream of `Event` objects.

This is the normalizer from the plan. Supported inputs:

  .evtx   binary Windows event log (needs python-evtx)
  .xml    XML export from Event Viewer or wevtutil
  .jsonl  our own format (from the generator or from `bde convert`)

A folder is read file by file, in name order.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from ..event import Event
from .jsonl import read_jsonl, write_jsonl
from .windows import parse_event_xml, read_evtx, read_xml_file

SUPPORTED_SUFFIXES = (".evtx", ".xml", ".jsonl")

__all__ = [
    "SUPPORTED_SUFFIXES",
    "parse_event_xml",
    "read_events",
    "read_evtx",
    "read_jsonl",
    "read_xml_file",
    "write_jsonl",
]


def read_events(path: str | Path) -> Iterator[Event]:
    """Yield every event in a file, or in every supported file in a folder."""
    path = Path(path)
    if path.is_dir():
        for child in sorted(path.iterdir()):
            if child.is_file() and child.suffix.lower() in SUPPORTED_SUFFIXES:
                yield from read_events(child)
        return
    if not path.exists():
        raise FileNotFoundError(f"no such file or folder: {path}")
    suffix = path.suffix.lower()
    if suffix == ".evtx":
        yield from read_evtx(path)
    elif suffix == ".xml":
        yield from read_xml_file(path)
    elif suffix == ".jsonl":
        yield from read_jsonl(path)
    else:
        supported = ", ".join(SUPPORTED_SUFFIXES)
        raise ValueError(f"don't know how to read {path.name}: expected one of {supported}")
