"""Phase 3: run the Sigma rules over events and collect **signals**.

A signal is one rule matching one event: "certutil downloaded a file, on
WKSTN-15 at 08:36:02". Signals are cheap and noisy on purpose. Phase 4 decides
which of them, together, tell the story of an attack.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from .event import Event
from .sigma import LEVELS, SigmaRule


@dataclass(eq=False)
class Signal:
    rule: SigmaRule
    event: Event

    @property
    def time(self) -> datetime:
        return self.event.timestamp

    @property
    def host(self) -> str:
        return self.event.host

    @property
    def level(self) -> str:
        return self.rule.level

    @property
    def severity(self) -> int:
        """0 (informational) to 4 (critical), for sorting."""
        return LEVELS.index(self.rule.level)

    @property
    def process_guid(self) -> str | None:
        return self.event.process_guid


def find_signals(events: Iterable[Event], rules: list[SigmaRule]) -> list[Signal]:
    """Test every event against the rules that apply to it; oldest signal first."""
    by_source: dict[tuple[str, int], list[SigmaRule]] = defaultdict(list)
    for rule in rules:  # index rules by the (channel, event ID) they read, so each event meets few rules
        for source in rule.sources:
            by_source[source].append(rule)
    signals = []
    for event in events:
        candidates = by_source.get((event.channel, event.event_id), []) + by_source.get((event.channel, 0), [])
        for rule in candidates:
            if rule.matches(event):
                signals.append(Signal(rule, event))
    signals.sort(key=lambda s: s.time)
    return signals
