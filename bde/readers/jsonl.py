"""Our own event format: JSON Lines (.jsonl), one event per line.

Example line (wrapped here for reading):

    {"EventID": 1, "Time": "2026-11-03T09:14:05.093Z",
     "Computer": "WKSTN-07.corp.example",
     "Channel": "Microsoft-Windows-Sysmon/Operational",
     "EventData": {"Image": "C:\\\\Windows\\\\...\\\\powershell.exe", ...},
     "meta": {"label": "malicious", "chain": "chain-1"}}

The scenario generator (phase 2) writes this format, and `bde convert`
turns .evtx and XML files into it, because JSON is much faster to read again
than parsing .evtx.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from pathlib import Path

from ..event import Event


def read_jsonl(path: Path) -> Iterator[Event]:
    # Always say utf-8: Windows would otherwise pick a legacy code page.
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path.name} line {line_number}: not valid JSON ({exc.msg})") from None
            try:
                yield Event.from_dict(record)
            except ValueError as exc:
                raise ValueError(f"{path.name} line {line_number}: {exc}") from None


def write_jsonl(events: Iterable[Event], path: Path) -> int:
    """Write events as JSONL. Returns how many were written."""
    count = 0
    # newline="\n" keeps Unix line endings on Windows too, so the file is
    # byte-for-byte the same whichever computer wrote it.
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            handle.write(event.to_json() + "\n")
            count += 1
    return count
