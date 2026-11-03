"""Phase 4: turn signals into incidents.

Signals answer "did something suspicious happen?". Incidents answer "is this
an attack, and what is its story?". Three techniques, each explained in
docs/phase-4-correlation.md:

1. **Chain rules** (rules/chains/*.yml): an anchor signal, then further steps
   that must happen in the anchor's own branch of the process tree, within a
   time window, usually in order.
2. **Risk scoring** (rules/risk.yml): every signal adds fading points to its
   host; a host that piles up enough, across several ATT&CK tactics, becomes
   an incident even when no chain rule describes what happened.
3. **Cross-host linking**: when an incident's processes run as an account
   that logged on over the network just before, find the computer that
   logon came from, and the process there that connected.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from .attack import sort_tactics, sort_techniques, tactics_from_tags, techniques_from_tags
from .event import Event, windows_basename
from .signals import Signal
from .sigma import LEVELS
from .tree import ProcessNode, ProcessTree, ancestry, has_ancestor, is_same_or_descendant, lineage

_DURATION = re.compile(r"^\s*(\d+)\s*([smhd])\s*$")


def parse_duration(text: str) -> timedelta:
    """'15m' -> 15 minutes. Units: s, m, h, d (as in Sigma's timespan)."""
    match = _DURATION.match(str(text))
    if not match:
        raise ValueError(f"bad duration {text!r}: use a number and s, m, h or d, like 15m")
    number, unit = int(match.group(1)), match.group(2)
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]: number})


def short_host(host: str) -> str:
    return host.split(".", 1)[0]


def account_name(user: str) -> str:
    """'CORP\\adm-rpatel' -> 'adm-rpatel' (lowercase)."""
    return user.rsplit("\\", 1)[-1].lower()


# --- chain rules --------------------------------------------------------------


@dataclass
class ChainStep:
    name: str
    signals: tuple[str, ...]
    description: str = ""
    ancestor: tuple[str, ...] = ()  # only for the first step: required ancestor programs
    min_distinct: int = 1  # how many *different* signal rules this step needs


@dataclass
class ChainRule:
    name: str
    title: str
    id: str
    level: str
    timespan: timedelta
    steps: list[ChainStep]
    min_steps: int
    ordered: bool = True
    crosshost: bool = False
    description: str = ""
    tags: list[str] = field(default_factory=list)
    path: Path | None = None

    @property
    def techniques(self) -> list[str]:
        return techniques_from_tags(self.tags)

    @classmethod
    def from_dict(cls, data: dict[str, Any], known_signals: set[str], path: Path | None = None) -> ChainRule:
        where = path.name if path else "chain rule"
        for key in ("name", "title", "id", "level", "timespan", "steps", "min_steps"):
            if key not in data:
                raise ValueError(f"{where}: missing required field '{key}'")
        if data["level"] not in LEVELS:
            raise ValueError(f"{where}: level must be one of {', '.join(LEVELS)}")
        steps = []
        for raw in data["steps"]:
            step = ChainStep(
                name=str(raw["name"]),
                signals=tuple(str(s) for s in raw["signals"]),
                description=str(raw.get("description", "")),
                ancestor=tuple(str(a) for a in raw.get("ancestor", [])),
                min_distinct=int(raw.get("min_distinct", 1)),
            )
            unknown = [s for s in step.signals if s not in known_signals]
            if unknown:
                raise ValueError(f"{where}: step {step.name!r} uses unknown signal rule {unknown[0]!r}")
            if step.min_distinct > len(step.signals):
                raise ValueError(f"{where}: step {step.name!r} needs more distinct rules than it lists")
            steps.append(step)
        if len(steps) < 2:
            raise ValueError(f"{where}: a chain needs at least two steps")
        if any(s.ancestor for s in steps[1:]):
            raise ValueError(f"{where}: only the first step may set 'ancestor'")
        min_steps = int(data["min_steps"])
        if not 1 <= min_steps <= len(steps):
            raise ValueError(f"{where}: min_steps must be between 1 and the number of steps")
        return cls(
            name=str(data["name"]),
            title=str(data["title"]),
            id=str(data["id"]),
            level=str(data["level"]),
            timespan=parse_duration(data["timespan"]),
            steps=steps,
            min_steps=min_steps,
            ordered=bool(data.get("ordered", True)),
            crosshost=bool(data.get("crosshost", False)),
            description=" ".join(str(data.get("description", "")).split()),
            tags=[str(t) for t in data.get("tags", [])],
            path=path,
        )


def load_chain_rules(folder: Path, known_signals: set[str]) -> list[ChainRule]:
    rules = []
    for path in sorted(folder.glob("*.yml")):
        with open(path, encoding="utf-8") as handle:
            rules.append(ChainRule.from_dict(yaml.safe_load(handle), known_signals, path))
    return rules


@dataclass
class RiskConfig:
    points: dict[str, float]
    half_life: timedelta
    window: timedelta
    tactic_bonus: float
    threshold: float

    @classmethod
    def load(cls, path: Path) -> RiskConfig:
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        points = {level: float(data["points"].get(level, 0)) for level in LEVELS}
        return cls(points, parse_duration(data["half_life"]), parse_duration(data["window"]),
                   float(data["tactic_bonus"]), float(data["threshold"]))


# --- incidents ---------------------------------------------------------------


@dataclass(eq=False)
class StepMatch:
    step: ChainStep
    signals: list[Signal]
    satisfied_at: datetime | None = None  # when this step had all it needed

    @property
    def matched(self) -> bool:
        return self.satisfied_at is not None


@dataclass(eq=False)
class Origin:
    """Where the attacker came from, for an incident that began with a network logon."""

    host: str | None  # the source computer, if we know its address
    source_ip: str
    account: str
    logon: Event
    process: ProcessNode | None = None  # the process on `host` that connected
    connection: Event | None = None


@dataclass(eq=False)
class Incident:
    kind: str  # "chain" or "risk"
    rule_name: str
    title: str
    level: str
    host: str
    signals: list[Signal]
    detected_at: datetime
    steps: list[StepMatch] = field(default_factory=list)
    root: ProcessNode | None = None
    score: float | None = None
    tags: list[str] = field(default_factory=list)
    origin: Origin | None = None
    related: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    id: str = ""

    @property
    def first_seen(self) -> datetime:
        return min(s.time for s in self.signals)

    @property
    def last_seen(self) -> datetime:
        return max(s.time for s in self.signals)

    @property
    def hosts(self) -> list[str]:
        hosts = [self.host]
        if self.origin and self.origin.host and self.origin.host not in hosts:
            hosts.insert(0, self.origin.host)
        return hosts

    @property
    def techniques(self) -> list[str]:
        found = techniques_from_tags(self.tags)
        for signal in self.signals:
            found += signal.rule.techniques
        return sort_techniques(found)

    @property
    def tactics(self) -> list[str]:
        found = tactics_from_tags(self.tags)
        for signal in self.signals:
            found += signal.rule.tactics
        return sort_tactics(found)

    @property
    def matched_steps(self) -> int:
        return sum(1 for m in self.steps if m.matched)

    def processes(self, tree: ProcessTree) -> list[ProcessNode]:
        nodes: list[ProcessNode] = [self.root] if self.root else []
        for signal in self.signals:
            node = tree.node_for(signal.event)
            if node is not None and node not in nodes:
                nodes.append(node)
        return nodes

    def evidence_events(self, tree: ProcessTree) -> list[Event]:
        """Every event this incident points at: its signals, the process starts
        above them (up to the grandparent), and the cross-host origin."""
        events: list[Event] = [s.event for s in self.signals]
        for node in self.processes(tree):
            for member in lineage(node)[-3:]:
                if member.creation is not None:
                    events.append(member.creation)
        if self.origin:
            events.append(self.origin.logon)
            if self.origin.connection is not None:
                events.append(self.origin.connection)
            if self.origin.process is not None:
                events += [n.creation for n in lineage(self.origin.process)[-2:] if n.creation is not None]
        unique: dict[int, Event] = {}
        for event in events:
            unique.setdefault(id(event), event)
        return sorted(unique.values(), key=lambda e: e.timestamp)


# --- 1. chain rules ------------------------------------------------------------


def match_chain(rule: ChainRule, signals: list[Signal], tree: ProcessTree) -> list[Incident]:
    by_rule: dict[str, list[Signal]] = defaultdict(list)
    for signal in signals:
        by_rule[signal.rule.name].append(signal)

    first = rule.steps[0]
    anchors: list[tuple[Signal, ProcessNode]] = []
    for name in first.signals:
        for signal in by_rule[name]:
            node = tree.node_for(signal.event)
            if node is None:  # chain rules need the process tree, so Sysmon events
                continue
            if first.ancestor and not has_ancestor(node, first.ancestor):
                continue
            anchors.append((signal, node))
    anchors.sort(key=lambda pair: pair[0].time)

    # Several anchor signals in one branch, close in time, are one attack:
    # Word -> cmd -> powershell can match the first step three times. Group
    # them under the top-most process of the branch.
    anchors.sort(key=lambda pair: (pair[0].time, len(ancestry(pair[1]))))
    groups: list[tuple[list[ProcessNode], datetime, list[Signal]]] = []  # ([top], start, signals)
    for signal, node in anchors:
        for group in groups:
            top_holder, group_start, group_signals = group
            top = top_holder[0]
            if signal.time > group_start + rule.timespan:
                continue
            if is_same_or_descendant(node, top) or is_same_or_descendant(top, node):
                if node is not top and is_same_or_descendant(top, node):
                    top_holder[0] = node  # the new anchor sits higher in the same branch
                group_signals.append(signal)
                break
        else:
            groups.append(([node], signal.time, [signal]))

    incidents = []
    for top_holder, start, anchor_signals in groups:
        top = top_holder[0]
        end = start + rule.timespan
        matches = [StepMatch(first, anchor_signals, start)]
        last = start
        for step in rule.steps[1:]:
            candidates = []
            for name in step.signals:
                for signal in by_rule[name]:
                    if signal.host != top.host or not start <= signal.time <= end:
                        continue
                    if rule.ordered and signal.time < last:
                        continue
                    node = tree.node_for(signal.event)
                    if node is not None and is_same_or_descendant(node, top):
                        candidates.append(signal)
            candidates.sort(key=lambda s: s.time)
            satisfied = _satisfied_at(candidates, step.min_distinct)
            matches.append(StepMatch(step, candidates if satisfied else [], satisfied))
            if satisfied and rule.ordered:
                last = satisfied
        done = sorted(m.satisfied_at for m in matches if m.satisfied_at is not None)
        if len(done) < rule.min_steps:
            continue
        evidence = _unique([s for m in matches for s in m.signals] + _context(signals, tree, top, start, end))
        incidents.append(Incident(
            kind="chain", rule_name=rule.name, title=rule.title, level=rule.level, host=top.host,
            signals=evidence, detected_at=done[rule.min_steps - 1], steps=matches, root=top, tags=list(rule.tags),
        ))
    return incidents


def _satisfied_at(candidates: list[Signal], min_distinct: int) -> datetime | None:
    """When the candidates first covered `min_distinct` different rules."""
    seen: list[str] = []
    for signal in candidates:
        if signal.rule.name not in seen:
            seen.append(signal.rule.name)
            if len(seen) >= min_distinct:
                return signal.time
    return None


def _context(signals: list[Signal], tree: ProcessTree, top: ProcessNode, start: datetime, end: datetime) -> list[Signal]:
    """Other signals in the same branch and time window: not steps, but part of the story."""
    found = []
    for signal in signals:
        if signal.host == top.host and start <= signal.time <= end:
            node = tree.node_for(signal.event)
            if node is not None and is_same_or_descendant(node, top):
                found.append(signal)
    return found


def _unique(signals: Iterable[Signal]) -> list[Signal]:
    unique: dict[int, Signal] = {}
    for signal in signals:
        unique.setdefault(id(signal), signal)
    return sorted(unique.values(), key=lambda s: s.time)


# --- 2. risk scoring -----------------------------------------------------------


def risk_score(contributions: list[Signal], now: datetime, config: RiskConfig) -> float:
    """Points that have faded with age, plus a bonus per extra ATT&CK tactic."""
    active = [s for s in contributions if timedelta(0) <= now - s.time <= config.window and config.points[s.level] > 0]
    faded = sum(config.points[s.level] * 0.5 ** ((now - s.time) / config.half_life) for s in active)
    tactics = {t for s in active for t in s.rule.tactics}
    return faded + config.tactic_bonus * max(0, len(tactics) - 1)


def signal_account(signal: Signal) -> str:
    """The account behind a signal's event ('' if the event doesn't say)."""
    event = signal.event
    user = event.get("User") or event.get("SubjectUserName")
    return account_name(user) if user else ""


def score_risk(signals: list[Signal], config: RiskConfig) -> list[Incident]:
    by_host: dict[str, list[Signal]] = defaultdict(list)
    for signal in signals:
        by_host[signal.host].append(signal)
    incidents = []
    for host in sorted(by_host, key=str.lower):
        contributions: list[Signal] = []
        counted: dict[tuple[str, str], datetime] = {}
        current: Incident | None = None
        for signal in by_host[host]:
            if current is not None and risk_score(contributions, signal.time, config) < config.threshold / 2:
                current = None  # the score has faded to half the threshold: this episode is over
            key = (signal.rule.name, signal.process_guid or f"event-{id(signal.event)}")
            repeat = key in counted and signal.time - counted[key] <= config.window
            if not repeat:
                counted[key] = signal.time
                contributions.append(signal)
            score = risk_score(contributions, signal.time, config)
            if current is not None:
                current.signals.append(signal)
                current.score = max(current.score or 0, score)
            elif not repeat and score >= config.threshold:
                # Evidence: recent signals (younger than one half-life) and older
                # ones by the same account. Everything in the window counts toward
                # the score, but an admin's gpupdate 40 minutes earlier shouldn't be
                # listed as part of an attacker's session.
                account = signal_account(signal)
                active = [s for s in contributions
                          if signal.time - s.time <= config.window and config.points[s.level] > 0
                          and (signal.time - s.time <= config.half_life or signal_account(s) == account)]
                current = Incident(
                    kind="risk", rule_name="risk", title="", level="high", host=host, signals=list(active),
                    detected_at=signal.time, score=score,
                )
                incidents.append(current)
        for incident in incidents:
            if incident.host == host:
                tactics = incident.tactics
                behaviours = len({(s.rule.name, s.process_guid) for s in incident.signals})
                incident.title = (f"Risky activity on {short_host(host)}: {behaviours} suspicious behaviours "
                                  f"across {len(tactics)} ATT&CK tactics")
                if (incident.score or 0) >= 2 * config.threshold:
                    incident.level = "critical"
    return incidents


# --- 3. cross-host linking --------------------------------------------------------


def address_book(events: Iterable[Event]) -> dict[str, str]:
    """IP address -> host, learned from the logs themselves.

    A Sysmon network event with Initiated=true was logged by the computer that
    opened the connection, so its SourceIp is that computer's own address.
    """
    votes: dict[str, Counter[str]] = defaultdict(Counter)
    for event in events:
        if event.is_sysmon and event.event_id == 3 and event.get("Initiated").lower() == "true":
            ip = event.get("SourceIp")
            if ip and not ip.startswith("127.") and ip != "::1":
                votes[ip][event.host] += 1
    return {ip: counter.most_common(1)[0][0] for ip, counter in sorted(votes.items())}


def find_origin(incident: Incident, tree: ProcessTree, logons: list[Event], network: list[Event],
                book: dict[str, str]) -> Origin | None:
    # Which account did this activity? Count each signal's process user; the
    # most common one is the account whose logon we look for.
    votes: Counter[str] = Counter()
    for signal in incident.signals:
        node = tree.node_for(signal.event)
        user = node.user if node is not None else signal.event.get("SubjectUserName")
        if user and not user.upper().startswith("NT AUTHORITY"):
            votes[account_name(user)] += 1
    if not votes:
        return None
    account = votes.most_common(1)[0][0]
    accounts = {account}
    own_signals = [s for s in incident.signals
                   if (n := tree.node_for(s.event)) is not None and account_name(n.user) == account]
    first_seen = min((s.time for s in own_signals), default=incident.first_seen)
    own_ips = {ip for ip, host in book.items() if host == incident.host}
    earliest = first_seen - timedelta(minutes=10)
    candidates = [
        e for e in logons
        if e.host == incident.host and earliest <= e.timestamp <= first_seen
        and e.get("LogonType") in ("3", "10") and e.get("TargetUserName").lower() in accounts
        and e.get("IpAddress") not in ("", "-", "127.0.0.1", "::1") and e.get("IpAddress") not in own_ips
    ]
    if not candidates:
        return None
    logon = max(candidates, key=lambda e: e.timestamp)  # the last logon before the activity
    source_ip = logon.get("IpAddress")
    source = book.get(source_ip)
    origin = Origin(host=source, source_ip=source_ip, account=logon.get("TargetUserName"), logon=logon)
    if source is None:
        return origin
    connections = [
        e for e in network
        if e.host == source and e.get("Initiated").lower() == "true" and e.get("DestinationIp") in own_ips
        and logon.timestamp - timedelta(minutes=2) <= e.timestamp <= logon.timestamp + timedelta(seconds=5)
    ]
    if connections:
        connection = max(connections, key=lambda e: e.timestamp)
        origin.connection = connection
        origin.process = tree.node_for(connection)
    return origin


# --- all together ------------------------------------------------------------------


def correlate(events: list[Event], signals: list[Signal], tree: ProcessTree, chain_rules: list[ChainRule],
              risk: RiskConfig) -> list[Incident]:
    chain_incidents = [i for rule in chain_rules for i in match_chain(rule, signals, tree)]
    incidents = list(chain_incidents)

    for risky in score_risk(signals, risk):
        shared = [c for c in chain_incidents if c.host == risky.host
                  and any(any(r is c_signal for c_signal in c.signals) for r in risky.signals)]
        if not shared:
            incidents.append(risky)
            continue
        # The risk score rose because of the same activity a chain rule already
        # explains: one incident, not two. Keep the earlier detection time.
        chain = min(shared, key=lambda c: c.detected_at)
        chain.score = max(chain.score or 0, risky.score or 0)
        if risky.detected_at < chain.detected_at:
            chain.notes.append(f"Risk scoring raised this first, at {risky.detected_at:%H:%M:%S}, when the host's "
                               f"score reached {risk.threshold:.0f}; the chain rule completed at "
                               f"{chain.detected_at:%H:%M:%S}.")
            chain.detected_at = risky.detected_at
        else:
            chain.notes.append(f"The host's risk score also passed {risk.threshold:.0f} "
                               f"(peak {risky.score:.0f}).")
        unused = [s for s in risky.signals if not any(s is c for c in chain.signals)]
        in_branch = sorted({s.rule.name for s in unused if chain.root is not None
                            and (n := tree.node_for(s.event)) is not None and is_same_or_descendant(n, chain.root)})
        elsewhere = sorted({s.rule.name for s in unused} - set(in_branch))
        if in_branch:
            chain.notes.append("Later in the same risk episode, this process branch also triggered: "
                               + ", ".join(in_branch) + ".")
        if elsewhere:
            chain.notes.append("Other processes on this host triggered, in the same risk episode: "
                               + ", ".join(elsewhere) + ".")

    logons = [e for e in events if e.channel == "Security" and e.event_id == 4624]
    network = [e for e in events if e.is_sysmon and e.event_id == 3]
    book = address_book(network)
    for incident in incidents:
        incident.origin = find_origin(incident, tree, logons, network, book)

    incidents.sort(key=lambda i: (i.detected_at, i.host))
    for number, incident in enumerate(incidents, start=1):
        incident.id = f"INC-{number:03d}"
    _link(incidents, tree)
    return incidents


def _link(incidents: list[Incident], tree: ProcessTree) -> None:
    """Connect incidents that are parts of one intrusion."""
    for incident in incidents:
        origin = incident.origin
        if origin is None or origin.process is None:
            continue
        for other in incidents:
            if other is incident or other.host != origin.process.host:
                continue
            if any(is_same_or_descendant(origin.process, node) for node in other.processes(tree)):
                if other.id not in incident.related:
                    incident.related.append(other.id)
                if incident.id not in other.related:
                    other.related.append(incident.id)


def describe_process(node: ProcessNode) -> str:
    return f"{node.name} (pid {node.pid})" if node.pid is not None else node.name


def process_label(event: Event) -> str:
    return windows_basename(event.get("Image")) or event.name
