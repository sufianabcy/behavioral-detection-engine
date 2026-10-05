"""
simulator/base.py
─────────────────────────────────────────────────────────────────────────────
Base class for all event generators.

Every event emitted by a simulator conforms to this schema:

    {
        "timestamp"      : "<ISO-8601 UTC>",
        "host"           : "<hostname>",
        "user"           : "<username>",
        "process"        : "<process name>",
        "parent_process" : "<parent process name>",
        "command"        : "<full command line>",
        "source"         : "<simulator identifier>",

        # optional enrichment fields (may be absent)
        "pid"            : <int>,
        "ppid"           : <int>,
        "severity"       : "info|low|medium|high|critical",
        "tags"           : ["<tag>", ...],
        "extra"          : {<arbitrary key-value pairs>}
    }
"""

from __future__ import annotations

import json
import os
import random
import sys
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, IO


# ── Schema constants ──────────────────────────────────────────────────────────

SEVERITY_LEVELS = ("info", "low", "medium", "high", "critical")

REQUIRED_FIELDS = (
    "timestamp",
    "host",
    "user",
    "process",
    "parent_process",
    "command",
    "source",
)

# ── Shared host/user pools (subclasses can override) ─────────────────────────

DEFAULT_HOSTS = [
    "WKSTN-ALPHA",
    "WKSTN-BRAVO",
    "WKSTN-CHARLIE",
    "SRV-DC01",
    "SRV-FILE01",
    "LAPTOP-HR-01",
    "LAPTOP-DEV-07",
]

DEFAULT_USERS = [
    "jsmith",
    "adavis",
    "mwilson",
    "lchen",
    "bthomas",
    "sysadmin",
    "serviceacct",
    "SYSTEM",
]


# ─────────────────────────────────────────────────────────────────────────────
# EventGenerator — abstract base class
# ─────────────────────────────────────────────────────────────────────────────

class EventGenerator(ABC):
    """Abstract base for all behavioural event simulators.

    Subclasses must implement :meth:`generate_event`, which returns a single
    event dict.  Use :meth:`emit` / :meth:`emit_batch` to serialise and route
    events to the configured output sink (stdout by default, or a file).

    Parameters
    ----------
    source:
        A short identifier for the simulator (e.g. ``"powershell_macro"``).
        Stored in every event's ``source`` field.
    hosts:
        Pool of hostnames to draw from randomly.  Falls back to
        :data:`DEFAULT_HOSTS` when *None*.
    users:
        Pool of usernames to draw from randomly.  Falls back to
        :data:`DEFAULT_USERS` when *None*.
    output_file:
        Optional path to a ``.jsonl`` file.  When supplied, events are
        *appended* to the file instead of being printed to stdout.
    pretty:
        If *True*, JSON is pretty-printed (2-space indent).  Only applies to
        stdout output; file output is always compact JSONL.
    seed:
        Optional RNG seed for reproducible simulations.
    """

    def __init__(
        self,
        source: str,
        hosts: list[str] | None = None,
        users: list[str] | None = None,
        output_file: str | Path | None = None,
        pretty: bool = False,
        seed: int | None = None,
    ) -> None:
        self.source = source
        self.hosts: list[str] = hosts or DEFAULT_HOSTS[:]
        self.users: list[str] = users or DEFAULT_USERS[:]
        self.output_file: Path | None = Path(output_file) if output_file else None
        self.pretty = pretty
        self._rng = random.Random(seed)
        self._event_count = 0

    # ── Abstract interface ────────────────────────────────────────────────────

    @abstractmethod
    def generate_event(self) -> dict[str, Any]:
        """Return a single fully-populated event dictionary.

        Implementations must call :meth:`_base_event` to obtain the skeleton
        (which guarantees all required fields are present) and then add
        simulator-specific fields before returning.
        """

    # ── Core helpers ──────────────────────────────────────────────────────────

    def _base_event(
        self,
        process: str,
        parent_process: str,
        command: str,
        *,
        host: str | None = None,
        user: str | None = None,
        severity: str = "info",
        tags: list[str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build the required-field skeleton for an event.

        Parameters
        ----------
        process:
            The name of the process generating the event.
        parent_process:
            The name of the process that spawned *process*.
        command:
            The full command-line string of *process*.
        host:
            Hostname override; random pick from the pool when *None*.
        user:
            Username override; random pick from the pool when *None*.
        severity:
            One of :data:`SEVERITY_LEVELS`.
        tags:
            Optional list of categorical tags for downstream enrichment.
        extra:
            Optional free-form metadata dict included verbatim in the event.

        Returns
        -------
        dict
            A fully-populated event skeleton ready to be extended.
        """
        if severity not in SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid severity '{severity}'. Choose from {SEVERITY_LEVELS}."
            )

        event: dict[str, Any] = {
            # ── Required fields (schema contract) ───────────────────────────
            "timestamp"     : _utcnow_iso(),
            "host"          : host or self._rng.choice(self.hosts),
            "user"          : user or self._rng.choice(self.users),
            "process"       : process,
            "parent_process": parent_process,
            "command"       : command,
            "source"        : self.source,
            # ── Standard enrichment ─────────────────────────────────────────
            "event_id"      : str(uuid.uuid4()),
            "pid"           : self._rng.randint(1000, 65535),
            "ppid"          : self._rng.randint(1000, 65535),
            "severity"      : severity,
            "tags"          : tags or [],
        }
        if extra:
            event["extra"] = extra
        return event

    def validate_event(self, event: dict[str, Any]) -> bool:
        """Return *True* if *event* contains all required fields."""
        missing = [f for f in REQUIRED_FIELDS if f not in event]
        if missing:
            raise ValueError(f"Event is missing required fields: {missing}")
        return True

    # ── Emission helpers ──────────────────────────────────────────────────────

    def emit(self, event: dict[str, Any] | None = None) -> dict[str, Any]:
        """Generate (if not supplied) and emit one event.

        Parameters
        ----------
        event:
            Pre-built event dict.  When *None*, :meth:`generate_event` is
            called to produce one.

        Returns
        -------
        dict
            The event that was emitted.
        """
        if event is None:
            event = self.generate_event()
        self.validate_event(event)
        self._write(event)
        self._event_count += 1
        return event

    def emit_batch(self, count: int = 10) -> list[dict[str, Any]]:
        """Emit *count* events and return them as a list."""
        return [self.emit() for _ in range(count)]

    # ── Private helpers ───────────────────────────────────────────────────────

    def _write(self, event: dict[str, Any]) -> None:
        """Serialise *event* to the configured output sink."""
        if self.output_file:
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            with self.output_file.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False) + "\n")
        else:
            if self.pretty:
                print(json.dumps(event, indent=2, ensure_ascii=False))
            else:
                print(json.dumps(event, ensure_ascii=False))

    # ── RNG convenience wrappers ──────────────────────────────────────────────

    def _choice(self, seq: list) -> Any:
        return self._rng.choice(seq)

    def _randint(self, a: int, b: int) -> int:
        return self._rng.randint(a, b)

    def _randhex(self, length: int = 16) -> str:
        """Return a random hex string of *length* characters."""
        return "".join(self._rng.choices("0123456789abcdef", k=length))

    # ── Dunder helpers ────────────────────────────────────────────────────────

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"{self.__class__.__name__}("
            f"source={self.source!r}, emitted={self._event_count})"
        )


# ── Module-level utilities ────────────────────────────────────────────────────

def _utcnow_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with 'Z' suffix."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def load_events_from_file(path: str | Path) -> list[dict[str, Any]]:
    """Parse a ``.jsonl`` log file and return a list of event dicts."""
    events: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON on line {lineno}: {exc}") from exc
    return events


def summarise_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Return a simple statistical summary of a list of events."""
    sources: dict[str, int] = {}
    severities: dict[str, int] = {}
    hosts: set[str] = set()
    users: set[str] = set()

    for ev in events:
        sources[ev.get("source", "unknown")] = (
            sources.get(ev.get("source", "unknown"), 0) + 1
        )
        severities[ev.get("severity", "unknown")] = (
            severities.get(ev.get("severity", "unknown"), 0) + 1
        )
        if "host" in ev:
            hosts.add(ev["host"])
        if "user" in ev:
            users.add(ev["user"])

    return {
        "total_events": len(events),
        "by_source"   : sources,
        "by_severity" : severities,
        "unique_hosts": sorted(hosts),
        "unique_users": sorted(users),
    }

