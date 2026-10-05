"""
detection/engine.py
─────────────────────────────────────────────────────────────────────────────
Behavioural Detection Engine — Scorer + Correlator + Alert pipeline.

Architecture
────────────
                       ┌──────────────┐
  JSON event ──────────► RulesLoader  │  loads & compiles rules.json
                       └──────┬───────┘
                              │ list[Rule]
                       ┌──────▼───────┐
  JSON event ──────────►   Scorer     │  matches every rule → RuleMatch list
                       └──────┬───────┘
                              │ list[RuleMatch]
                       ┌──────▼───────┐
  host context ─────────► Correlator  │  rolling time-window per host
                       └──────┬───────┘
                              │ Alert | None
                       ┌──────▼───────┐
                       │   consumer   │  downstream SIEM / logger / webhook
                       └──────────────┘

Public API
──────────
    from detection.engine import DetectionEngine

    engine = DetectionEngine()                       # auto-loads rules.json
    alert  = engine.process(event_dict)              # returns Alert or None
    alerts = engine.process_batch(list_of_events)    # list[Alert]

    # Lower-level access
    scorer     = engine.scorer
    correlator = engine.correlator

Classes
───────
    Rule          — parsed, compiled representation of one rules.json entry
    RuleMatch     — a Rule that matched a specific event, with context
    Alert         — raised when a host's cumulative score exceeds threshold
    Scorer        — stateless per-event rule matcher
    Correlator    — stateful per-host rolling window + threshold trigger
    RulesLoader   — loads / validates / compiles rules.json
    DetectionEngine — top-level facade wiring everything together

Usage (CLI)
───────────
    # Pretty-print alerts from a simulator log
    python engine.py --input ../logs/mixed_sim.jsonl --pretty

    # Read from stdin (pipe from simulator)
    python ../simulator/run_all.py --no-file | python engine.py --stdin
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Iterator

# ── Default paths ──────────────────────────────────────────────────────────────

_HERE       = Path(__file__).parent
_RULES_FILE = _HERE / "rules.json"


# =============================================================================
# Data-transfer objects
# =============================================================================

@dataclass(frozen=True)
class Rule:
    """Compiled, immutable representation of a single detection rule.

    All ``conditions`` regex strings are pre-compiled to
    :class:`re.Pattern` objects at load time so matching is fast.
    """

    id:          str
    name:        str
    family:      str
    description: str
    conditions:  dict[str, re.Pattern]   # field → compiled regex
    score:       int
    severity:    str
    mitre:       list[str]
    tags:        list[str]

    def matches(self, event: dict[str, Any]) -> bool:
        """Return *True* iff every condition in this rule matches the event.

        A rule fires only when **all** of its field patterns match
        (logical AND). Missing event fields are treated as empty strings
        so patterns can still be evaluated.
        """
        for field_name, pattern in self.conditions.items():
            value = str(event.get(field_name, ""))
            if not pattern.search(value):
                return False
        return True


@dataclass
class RuleMatch:
    """Records a single rule that fired against a specific event."""

    rule:       Rule
    event_id:   str
    host:       str
    user:       str
    timestamp:  datetime
    # The specific field values that satisfied the rule conditions
    matched_fields: dict[str, str]

    @property
    def score(self) -> int:
        return self.rule.score

    @property
    def mitre(self) -> list[str]:
        return self.rule.mitre

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id"       : self.rule.id,
            "rule_name"     : self.rule.name,
            "family"        : self.rule.family,
            "score"         : self.rule.score,
            "severity"      : self.rule.severity,
            "mitre"         : self.rule.mitre,
            "tags"          : self.rule.tags,
            "event_id"      : self.event_id,
            "host"          : self.host,
            "user"          : self.user,
            "timestamp"     : self.timestamp.isoformat(),
            "matched_fields": self.matched_fields,
        }


@dataclass
class Alert:
    """Generated when a host's rolling-window score exceeds the threshold.

    Attributes
    ----------
    host:
        The host that triggered the alert.
    cumulative_score:
        Total risk score accumulated within the correlation window.
    threshold:
        The score threshold that was breached.
    window_seconds:
        Length of the rolling window (seconds).
    window_start / window_end:
        Earliest and latest event timestamps contributing to this alert.
    matches:
        All :class:`RuleMatch` objects that contributed to the score.
    mitre_techniques:
        De-duplicated, sorted list of all MITRE ATT&CK technique IDs.
    reason:
        Human-readable explanation of why the alert was raised.
    triggered_at:
        UTC timestamp when the alert was generated.
    families:
        Set of rule families involved (powershell / wmi / certutil / generic).
    """

    host:              str
    cumulative_score:  int
    threshold:         int
    window_seconds:    int
    window_start:      datetime
    window_end:        datetime
    matches:           list[RuleMatch]
    mitre_techniques:  list[str]
    reason:            str
    triggered_at:      datetime = field(
                           default_factory=lambda: datetime.now(tz=timezone.utc)
                       )
    families:          set[str] = field(default_factory=set)

    # ── Formatting helpers ──────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of the alert."""
        return {
            "alert_type"      : "HOST_THRESHOLD_BREACH",
            "triggered_at"    : self.triggered_at.isoformat(),
            "host"            : self.host,
            "cumulative_score": self.cumulative_score,
            "threshold"       : self.threshold,
            "window_seconds"  : self.window_seconds,
            "window_start"    : self.window_start.isoformat(),
            "window_end"      : self.window_end.isoformat(),
            "mitre_techniques": self.mitre_techniques,
            "families"        : sorted(self.families),
            "reason"          : self.reason,
            "contributing_rules": [
                {
                    "rule_id"  : m.rule.id,
                    "rule_name": m.rule.name,
                    "score"    : m.rule.score,
                    "event_id" : m.event_id,
                    "timestamp": m.timestamp.isoformat(),
                }
                for m in self.matches
            ],
        }

    def __str__(self) -> str:
        bar = "─" * 60
        lines = [
            f"\n{'═'*60}",
            f"  🚨  ALERT — {self.host}",
            f"{'═'*60}",
            f"  Score       : {self.cumulative_score}/{self.threshold} (threshold breached)",
            f"  Window      : {self.window_seconds}s  [{self.window_start.strftime('%H:%M:%S')} → {self.window_end.strftime('%H:%M:%S')}]",
            f"  MITRE       : {', '.join(self.mitre_techniques) or 'N/A'}",
            f"  Families    : {', '.join(sorted(self.families))}",
            f"  Reason      : {self.reason}",
            bar,
            "  Contributing rules:",
        ]
        for m in self.matches:
            lines.append(
                f"    [{m.rule.id:10s}] +{m.rule.score:>3}pt  {m.rule.name}"
            )
        lines.append(f"{'═'*60}\n")
        return "\n".join(lines)


# =============================================================================
# RulesLoader
# =============================================================================

class RulesLoader:
    """Loads, validates, and compiles detection rules from a JSON file.

    Parameters
    ----------
    path:
        Path to the ``rules.json`` file.  Defaults to the ``rules.json``
        file in the same directory as this module.

    Raises
    ------
    FileNotFoundError
        When the rules file does not exist.
    ValueError
        When a rule is missing required fields or has an invalid regex.
    """

    REQUIRED_RULE_FIELDS = {"id", "name", "family", "description",
                            "conditions", "score", "severity", "mitre"}

    def __init__(self, path: str | Path = _RULES_FILE) -> None:
        self.path = Path(path)
        self._rules: list[Rule] = []
        self._meta:  dict[str, Any] = {}

    # ── Public ────────────────────────────────────────────────────────────────

    def load(self) -> list[Rule]:
        """Parse and compile all rules.  Returns a list of :class:`Rule`."""
        if not self.path.exists():
            raise FileNotFoundError(
                f"Rules file not found: {self.path}\n"
                "Make sure 'rules.json' exists in the detection/ directory."
            )
        with self.path.open(encoding="utf-8") as fh:
            raw = json.load(fh)

        self._meta  = raw.get("_meta", {})
        raw_rules   = raw.get("rules", [])
        self._rules = [self._compile_rule(r, idx) for idx, r in enumerate(raw_rules)]
        return self._rules

    @property
    def meta(self) -> dict[str, Any]:
        return self._meta

    @property
    def rules(self) -> list[Rule]:
        if not self._rules:
            self.load()
        return self._rules

    # ── Private ───────────────────────────────────────────────────────────────

    def _compile_rule(self, raw: dict[str, Any], idx: int) -> Rule:
        """Validate and compile one raw rule dict into a :class:`Rule`."""
        missing = self.REQUIRED_RULE_FIELDS - set(raw.keys())
        if missing:
            raise ValueError(
                f"Rule at index {idx} is missing required fields: {missing}\n"
                f"Rule data: {raw}"
            )

        compiled_conditions: dict[str, re.Pattern] = {}
        for field_name, pattern_str in raw["conditions"].items():
            try:
                compiled_conditions[field_name] = re.compile(pattern_str)
            except re.error as exc:
                raise ValueError(
                    f"Rule '{raw['id']}': invalid regex in condition "
                    f"'{field_name}': {pattern_str!r} — {exc}"
                ) from exc

        return Rule(
            id          = raw["id"],
            name        = raw["name"],
            family      = raw["family"],
            description = raw["description"],
            conditions  = compiled_conditions,
            score       = int(raw["score"]),
            severity    = raw["severity"],
            mitre       = list(raw.get("mitre", [])),
            tags        = list(raw.get("tags", [])),
        )


# =============================================================================
# Scorer
# =============================================================================

class Scorer:
    """Stateless per-event rule matcher.

    Given an event dict, ``score_event`` tests every loaded rule and returns
    a list of :class:`RuleMatch` objects for rules that fired.

    Parameters
    ----------
    rules:
        List of compiled :class:`Rule` objects.  Typically supplied by
        :class:`RulesLoader`.
    """

    def __init__(self, rules: list[Rule]) -> None:
        self._rules = rules

    # ── Public API ────────────────────────────────────────────────────────────

    def score_event(self, event: dict[str, Any]) -> list[RuleMatch]:
        """Evaluate all rules against *event*.

        Returns
        -------
        list[RuleMatch]
            One entry per rule that matched.  Empty list for clean events.
        """
        matches: list[RuleMatch] = []
        ts = _parse_timestamp(event.get("timestamp", ""))

        for rule in self._rules:
            if rule.matches(event):
                matched_fields = {
                    f: str(event.get(f, ""))
                    for f in rule.conditions
                }
                matches.append(
                    RuleMatch(
                        rule           = rule,
                        event_id       = event.get("event_id", ""),
                        host           = event.get("host", "UNKNOWN"),
                        user           = event.get("user", "UNKNOWN"),
                        timestamp      = ts,
                        matched_fields = matched_fields,
                    )
                )
        return matches

    def total_score(self, matches: list[RuleMatch]) -> int:
        """Return the sum of scores for a list of :class:`RuleMatch` objects."""
        return sum(m.score for m in matches)

    @property
    def rule_count(self) -> int:
        return len(self._rules)


# =============================================================================
# Correlator
# =============================================================================

@dataclass
class _HostState:
    """Internal mutable state for a single host inside the Correlator."""
    # Deque of (arrival_time, RuleMatch) tuples within the active window
    window: deque[tuple[datetime, RuleMatch]] = field(
        default_factory=deque
    )
    # Total raw score in the current window (maintained incrementally)
    running_score: int = 0
    # Has an alert already been raised for the *current* breach?
    # Resets when the score drops back below threshold.
    alert_raised: bool = False


class Correlator:
    """Maintains a rolling time-window of rule matches per host and raises
    :class:`Alert` objects when cumulative host scores breach the threshold.

    Design
    ──────
    * Each host gets its own sliding window of :class:`RuleMatch` entries.
    * On every call to :meth:`ingest`, expired entries (older than
      ``window_seconds``) are evicted from the front of the deque.
    * An :class:`Alert` is emitted exactly **once** per breach — the
      ``alert_raised`` flag prevents duplicate alerts for the same event
      cluster.  The flag resets when the score falls below threshold again.

    Parameters
    ----------
    threshold:
        Cumulative risk score that triggers an alert (default 60).
    window_seconds:
        Length of the rolling window in seconds (default 300 = 5 min).
    """

    def __init__(
        self,
        threshold:      int = 60,
        window_seconds: int = 300,
    ) -> None:
        self.threshold      = threshold
        self.window_seconds = window_seconds
        self._states: dict[str, _HostState] = defaultdict(_HostState)

    # ── Public API ────────────────────────────────────────────────────────────

    def ingest(self, matches: list[RuleMatch]) -> Alert | None:
        """Feed a batch of :class:`RuleMatch` objects (from one event) into
        the correlator.

        Returns
        -------
        Alert | None
            An :class:`Alert` if the host's cumulative score just crossed the
            threshold, otherwise *None*.
        """
        if not matches:
            return None

        # All matches from the same event share the same host & timestamp
        host = matches[0].host
        now  = matches[0].timestamp
        state = self._states[host]

        # 1. Evict expired entries
        self._evict(state, now)

        # 2. Append new matches
        for m in matches:
            state.window.append((now, m))
            state.running_score += m.score

        # 3. Check threshold
        if state.running_score >= self.threshold and not state.alert_raised:
            state.alert_raised = True
            return self._build_alert(host, state, now)

        # 4. Reset the breach flag if score recovered below threshold
        if state.running_score < self.threshold:
            state.alert_raised = False

        return None

    def current_score(self, host: str) -> int:
        """Return the current rolling score for *host* (evicts stale entries)."""
        state = self._states.get(host)
        if state is None:
            return 0
        self._evict(state, datetime.now(tz=timezone.utc))
        return state.running_score

    def active_hosts(self) -> dict[str, int]:
        """Return a mapping of host → current score for all tracked hosts."""
        now = datetime.now(tz=timezone.utc)
        result: dict[str, int] = {}
        for host, state in self._states.items():
            self._evict(state, now)
            if state.running_score > 0:
                result[host] = state.running_score
        return result

    def reset_host(self, host: str) -> None:
        """Clear all state for *host* (useful in tests or after triage)."""
        if host in self._states:
            del self._states[host]

    def reset_all(self) -> None:
        """Clear all per-host state."""
        self._states.clear()

    # ── Private ───────────────────────────────────────────────────────────────

    def _evict(self, state: _HostState, now: datetime) -> None:
        """Remove entries older than ``window_seconds`` from the front of the deque."""
        cutoff = now - timedelta(seconds=self.window_seconds)
        while state.window and state.window[0][0] < cutoff:
            _, expired_match = state.window.popleft()
            state.running_score -= expired_match.score
            # Guard against floating-point drift going negative
            if state.running_score < 0:
                state.running_score = 0

    def _build_alert(
        self, host: str, state: _HostState, now: datetime
    ) -> Alert:
        """Construct an :class:`Alert` from the current host window."""
        active_matches = [m for _, m in state.window]

        # Collect de-duplicated MITRE techniques and rule families
        mitre_set:  set[str] = set()
        family_set: set[str] = set()
        rule_names: list[str] = []
        for m in active_matches:
            mitre_set.update(m.rule.mitre)
            family_set.add(m.rule.family)
            rule_names.append(m.rule.name)

        # Build a concise human-readable reason string
        reason = _build_reason(active_matches, state.running_score, self.threshold)

        # Window boundaries
        timestamps = [ts for ts, _ in state.window]
        window_start = min(timestamps) if timestamps else now
        window_end   = max(timestamps) if timestamps else now

        return Alert(
            host             = host,
            cumulative_score = state.running_score,
            threshold        = self.threshold,
            window_seconds   = self.window_seconds,
            window_start     = window_start,
            window_end       = window_end,
            matches          = active_matches,
            mitre_techniques = sorted(mitre_set),
            reason           = reason,
            triggered_at     = now,
            families         = family_set,
        )


# =============================================================================
# DetectionEngine  (top-level façade)
# =============================================================================

class DetectionEngine:
    """Top-level façade wiring :class:`RulesLoader`, :class:`Scorer`, and
    :class:`Correlator` together.

    Parameters
    ----------
    rules_path:
        Path to ``rules.json``.  Defaults to the file next to this module.
    threshold:
        Cumulative score that triggers an :class:`Alert`.
    window_seconds:
        Rolling correlation window length in seconds.

    Examples
    --------
    >>> engine = DetectionEngine()
    >>> alert  = engine.process(event)      # returns Alert or None
    >>> alerts = engine.process_batch(events)
    """

    def __init__(
        self,
        rules_path:     str | Path = _RULES_FILE,
        threshold:      int = 60,
        window_seconds: int = 300,
    ) -> None:
        loader         = RulesLoader(rules_path)
        rules          = loader.load()
        self._meta     = loader.meta

        # Override threshold/window from rules.json _meta if not explicitly set
        _th  = self._meta.get("score_threshold", threshold)
        _win = self._meta.get("window_seconds",  window_seconds)

        self.scorer     = Scorer(rules)
        self.correlator = Correlator(threshold=_th, window_seconds=_win)

        self._processed   = 0
        self._alert_count = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def process(self, event: dict[str, Any]) -> Alert | None:
        """Score one event and feed matches into the correlator.

        Parameters
        ----------
        event:
            A single event dict conforming to the simulator schema.

        Returns
        -------
        Alert | None
            An :class:`Alert` if the host's threshold was just breached,
            otherwise *None*.
        """
        self._processed += 1
        matches = self.scorer.score_event(event)
        alert   = self.correlator.ingest(matches)
        if alert:
            self._alert_count += 1
        return alert

    def process_batch(
        self,
        events: list[dict[str, Any]],
    ) -> list[Alert]:
        """Process a list of events and return all alerts raised.

        Events are processed in list order, preserving temporal sequence.
        """
        alerts: list[Alert] = []
        for ev in events:
            alert = self.process(ev)
            if alert:
                alerts.append(alert)
        return alerts

    def process_jsonl(
        self,
        path: str | Path,
    ) -> Iterator[Alert]:
        """Stream events from a ``.jsonl`` file, yielding alerts as they fire.

        Parameters
        ----------
        path:
            Path to a JSONL log file (e.g. ``logs/mixed_sim.jsonl``).

        Yields
        ------
        Alert
            Each alert raised in the order events were processed.
        """
        path = Path(path)
        with path.open(encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    _warn(f"Skipping malformed JSON on line {lineno}: {exc}")
                    continue
                alert = self.process(event)
                if alert:
                    yield alert

    # ── Stats ─────────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict[str, Any]:
        """Return a summary of engine activity since initialisation."""
        return {
            "rules_loaded"   : self.scorer.rule_count,
            "events_processed": self._processed,
            "alerts_raised"  : self._alert_count,
            "active_hosts"   : self.correlator.active_hosts(),
            "threshold"      : self.correlator.threshold,
            "window_seconds" : self.correlator.window_seconds,
        }

    def __repr__(self) -> str:
        return (
            f"DetectionEngine(rules={self.scorer.rule_count}, "
            f"processed={self._processed}, alerts={self._alert_count})"
        )


# =============================================================================
# Helpers
# =============================================================================

def _parse_timestamp(ts_str: str) -> datetime:
    """Parse an ISO-8601 UTC timestamp string into a timezone-aware datetime.

    Falls back to ``datetime.now(UTC)`` for missing or malformed values.
    """
    if not ts_str:
        return datetime.now(tz=timezone.utc)
    # Handle the trailing 'Z' that Python < 3.11 doesn't natively support
    ts_str = ts_str.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        return datetime.now(tz=timezone.utc)


def _build_reason(
    matches: list[RuleMatch],
    score:   int,
    threshold: int,
) -> str:
    """Build a concise, human-readable explanation for an alert."""
    # Count by family
    family_counts: dict[str, int] = defaultdict(int)
    for m in matches:
        family_counts[m.rule.family] += 1

    # Highest-scoring match
    top = max(matches, key=lambda m: m.rule.score)

    family_summary = ", ".join(
        f"{count} {fam} rule{'s' if count > 1 else ''}"
        for fam, count in sorted(family_counts.items())
    )

    return (
        f"Host accumulated {score} risk points (threshold: {threshold}) "
        f"across {len(matches)} rule match{'es' if len(matches) != 1 else ''} "
        f"({family_summary}). "
        f"Highest-scoring rule: [{top.rule.id}] '{top.rule.name}' "
        f"(+{top.rule.score}pt, severity={top.rule.severity}). "
        f"MITRE coverage: {', '.join(sorted({t for m in matches for t in m.rule.mitre}))}."
    )


def _warn(msg: str) -> None:
    print(f"\033[33m[WARN]\033[0m  {msg}", file=sys.stderr)


def _info(msg: str) -> None:
    print(f"\033[36m[INFO]\033[0m  {msg}", file=sys.stderr)


# =============================================================================
# CLI entry point
# =============================================================================

def _parse_args():
    import argparse
    p = argparse.ArgumentParser(
        description="Run the detection engine against a JSONL event log.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--input", "-i", type=str,
        help="Path to a .jsonl event log file.",
    )
    src.add_argument(
        "--stdin", action="store_true",
        help="Read newline-delimited JSON events from stdin.",
    )
    p.add_argument(
        "--rules", type=str, default=str(_RULES_FILE),
        help="Path to the rules.json file.",
    )
    p.add_argument(
        "--threshold", "-t", type=int, default=None,
        help="Override the score threshold from rules.json.",
    )
    p.add_argument(
        "--window", "-w", type=int, default=None,
        help="Override the correlation window (seconds) from rules.json.",
    )
    p.add_argument(
        "--pretty", action="store_true",
        help="Pretty-print alerts to stdout.",
    )
    p.add_argument(
        "--json-alerts", action="store_true",
        help="Emit each alert as a JSON line to stdout (machine-readable).",
    )
    p.add_argument(
        "--stats", action="store_true",
        help="Print engine statistics after processing.",
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    kwargs: dict[str, Any] = {"rules_path": args.rules}
    if args.threshold is not None:
        kwargs["threshold"] = args.threshold
    if args.window is not None:
        kwargs["window_seconds"] = args.window

    engine = DetectionEngine(**kwargs)
    _info(
        f"Engine ready — {engine.scorer.rule_count} rules loaded, "
        f"threshold={engine.correlator.threshold}pt, "
        f"window={engine.correlator.window_seconds}s"
    )

    def _handle_alert(alert: Alert) -> None:
        if args.pretty:
            print(str(alert))
        if args.json_alerts:
            print(json.dumps(alert.to_dict(), ensure_ascii=False))
        if not args.pretty and not args.json_alerts:
            # Minimal default output
            techniques = ", ".join(alert.mitre_techniques) or "N/A"
            print(
                f"[ALERT] host={alert.host!r}  "
                f"score={alert.cumulative_score}/{alert.threshold}  "
                f"MITRE={techniques}"
            )

    if args.stdin:
        _info("Reading events from stdin …")
        for lineno, line in enumerate(sys.stdin, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                _warn(f"Bad JSON on stdin line {lineno}: {exc}")
                continue
            alert = engine.process(event)
            if alert:
                _handle_alert(alert)
    else:
        _info(f"Processing {args.input} …")
        for alert in engine.process_jsonl(args.input):
            _handle_alert(alert)

    if args.stats:
        s = engine.stats
        _info(
            f"\nStats — events={s['events_processed']}, "
            f"alerts={s['alerts_raised']}, "
            f"active_hosts={len(s['active_hosts'])}"
        )
        if s["active_hosts"]:
            _info("Active host scores:")
            for h, sc in sorted(s["active_hosts"].items(), key=lambda x: -x[1]):
                _info(f"  {h:<25} {sc:>4} pt")


if __name__ == "__main__":
    main()

