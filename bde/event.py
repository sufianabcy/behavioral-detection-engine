"""The normalized event: one shape for every log source.

Every Windows event has two parts:

* a **System** part that all events share: event ID, time, computer, channel;
* an **EventData** part of name/value pairs that depends on the event type.
  For a Sysmon process-create event these are Image, CommandLine,
  ProcessGuid, ParentImage and so on.

`Event` keeps exactly that split. EventData keeps Sysmon's own field names,
because Sigma rules (phase 3) are written against those names. Whatever the
source (an .evtx file, an XML export, or our own generator), the readers in
`bde.readers` turn it into this one shape, so the rest of the engine never
needs to know where an event came from.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import PureWindowsPath
from typing import Any

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# Sysmon's event IDs. They only mean this when the event came from the Sysmon
# channel: other logs reuse the same small numbers for unrelated things.
SYSMON_EVENT_NAMES: dict[int, str] = {
    1: "Process create",
    2: "File creation time changed",
    3: "Network connection",
    4: "Sysmon service state changed",
    5: "Process terminated",
    6: "Driver loaded",
    7: "Image loaded",
    8: "CreateRemoteThread",
    9: "RawAccessRead",
    10: "Process access",
    11: "File create",
    12: "Registry key create/delete",
    13: "Registry value set",
    14: "Registry key/value rename",
    15: "File stream created",
    16: "Sysmon config change",
    17: "Pipe created",
    18: "Pipe connected",
    19: "WMI event filter",
    20: "WMI event consumer",
    21: "WMI consumer-to-filter binding",
    22: "DNS query",
    23: "File delete (archived)",
    24: "Clipboard change",
    25: "Process tampering",
    26: "File delete logged",
    27: "File block executable",
    28: "File block shredding",
    29: "File executable detected",
    255: "Sysmon error",
}

# A few non-Sysmon events we will meet later (chain 3 uses the logon event).
OTHER_EVENT_NAMES: dict[tuple[str, int], str] = {
    ("Security", 4624): "Logon",
    ("Security", 4625): "Failed logon",
    ("Security", 4688): "Process create (Security log)",
    ("Microsoft-Windows-PowerShell/Operational", 4104): "PowerShell script block",
}

# Sysmon writes this when it doesn't know a process (e.g. the parent of System).
NULL_GUID = "{00000000-0000-0000-0000-000000000000}"

_TIME_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$",
    re.IGNORECASE,
)


@dataclass(slots=True)
class Event:
    """One log event, from any source, in the shape the engine works with."""

    event_id: int  # System/EventID: 1 = process create, 3 = network, ...
    timestamp: datetime  # always timezone-aware UTC
    host: str  # System/Computer: the machine that logged it
    channel: str  # System/Channel: which log it came from
    data: dict[str, str] = field(default_factory=dict)  # EventData, Sysmon names
    meta: dict[str, Any] = field(default_factory=dict)  # ours, not Windows': source file, labels

    def get(self, name: str, default: str = "") -> str:
        """Value of an EventData field, or `default` when it is missing."""
        value = self.data.get(name)
        return default if value is None else value

    @property
    def is_sysmon(self) -> bool:
        return self.channel == SYSMON_CHANNEL

    @property
    def name(self) -> str:
        """Human-readable event type, e.g. 'Process create'."""
        if self.is_sysmon:
            return SYSMON_EVENT_NAMES.get(self.event_id, f"Sysmon event {self.event_id}")
        return OTHER_EVENT_NAMES.get(
            (self.channel, self.event_id), f"{self.channel or 'unknown log'} event {self.event_id}"
        )

    @property
    def process_guid(self) -> str | None:
        """The ProcessGuid of the process that caused this event, if any."""
        return clean_guid(self.data.get("ProcessGuid"))

    @property
    def parent_guid(self) -> str | None:
        """For process-create events: the ProcessGuid of the parent."""
        return clean_guid(self.data.get("ParentProcessGuid"))

    # --- our JSONL format -------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "EventID": self.event_id,
            "Time": format_time(self.timestamp),
            "Computer": self.host,
            "Channel": self.channel,
            "EventData": dict(self.data),
        }
        if self.meta:
            record["meta"] = dict(self.meta)
        return record

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, record: dict[str, Any]) -> Event:
        try:
            return cls(
                event_id=int(record["EventID"]),
                timestamp=parse_time(str(record["Time"])),
                host=str(record["Computer"]),
                channel=str(record["Channel"]),
                data={
                    str(key): "" if value is None else str(value)
                    for key, value in (record.get("EventData") or {}).items()
                },
                meta=dict(record.get("meta") or {}),
            )
        except KeyError as exc:
            raise ValueError(f"event is missing the {exc} key") from None


def windows_basename(path: str) -> str:
    r"""'C:\Windows\System32\cmd.exe' -> 'cmd.exe', on any operating system.

    pathlib.Path follows the rules of the computer the code runs on, so on a
    Mac it would not split on backslashes. Paths inside Windows logs are
    Windows paths wherever we read them, so we use PureWindowsPath for them.
    """
    if not path:
        return ""
    return PureWindowsPath(path).name or path


def host_matches(host: str, wanted: str) -> bool:
    """True if `wanted` names `host`, either fully or by its short name.

    'WKSTN-07' and 'wkstn-07.corp.example' both match 'WKSTN-07.corp.example'.
    """
    host, wanted = host.lower(), wanted.lower()
    return host == wanted or host.split(".", 1)[0] == wanted


def clean_guid(value: str | None) -> str | None:
    """Normalize a Sysmon GUID to '{lowercase}'. Empty or all-zero -> None."""
    if not value or not value.strip():
        return None
    guid = value.strip().lower()
    if not guid.startswith("{"):
        guid = "{" + guid + "}"
    return None if guid == NULL_GUID else guid


def parse_time(text: str) -> datetime:
    """Parse the timestamp styles found in Windows logs into UTC datetimes.

    Accepts, for example:
      2026-11-03 09:14:05.093        Sysmon UtcTime (space, no zone: UTC)
      2026-11-03T09:14:05.0934170Z   System/TimeCreated (7 decimal places)
      2026-11-03T09:14:05.093Z       our JSONL
      2026-11-03T10:14:05+01:00      any explicit offset
    """
    match = _TIME_RE.match(text.strip())
    if not match:
        raise ValueError(f"unrecognised timestamp {text!r}")
    day, clock, fraction, zone = match.groups()
    stamp = datetime.strptime(f"{day} {clock}", "%Y-%m-%d %H:%M:%S")
    if fraction:  # Python keeps at most 6 decimal places (microseconds)
        stamp = stamp.replace(microsecond=int(fraction[:6].ljust(6, "0")))
    if zone and zone.upper() != "Z":
        sign = 1 if zone[0] == "+" else -1
        hours, minutes = int(zone[1:3]), int(zone[-2:])
        offset = timezone(sign * timedelta(hours=hours, minutes=minutes))
        return stamp.replace(tzinfo=offset).astimezone(timezone.utc)
    return stamp.replace(tzinfo=timezone.utc)


def format_time(stamp: datetime) -> str:
    """UTC ISO-8601 with milliseconds and a Z, e.g. 2026-11-03T09:14:05.093Z."""
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
