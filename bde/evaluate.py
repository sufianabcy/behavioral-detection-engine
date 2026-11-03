"""Phase 5: measure the engine against ground truth.

The generator labels every event (meta["label"], meta["instance"]), and the
rules never read those labels. So we can run the engine on generated data and
score it honestly:

* **Recall** per chain: of the attack instances that happened, how many did
  at least one incident flag? An instance counts as detected when one of its
  events is a *signal* inside an incident (the engine pointed at it directly).
* **Precision** for incidents: of the incidents raised, how many contain at
  least one malicious signal? The others are false alarms.
* **Signal precision**: the same question for single signals, to show how
  much noise the correlation layer removes.
* **Time to detect**: from the attack's first process start to the moment
  the incident could have been raised.
* **Soak test**: hours of purely normal activity; every incident is a false
  alarm. Reported per 1,000 events and per host per day.

Unseen variants are scored separately: they test whether the rules
generalise, rather than just recognise the generator they were written with.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from statistics import median

from .engine import Detection, RuleSet, detect
from .generator import CHAIN_TITLES, SEEN_CHAINS, UNSEEN_CHAINS, Scenario, ScenarioConfig, generate


@dataclass
class InstanceResult:
    id: str
    chain: str
    variant: str
    detected_by: list[str]  # incident IDs
    time_to_detect: timedelta | None

    @property
    def detected(self) -> bool:
        return bool(self.detected_by)


@dataclass
class RunScore:
    seed: int
    events: int
    signals: int
    malicious_signals: int
    incidents: int
    true_incidents: int
    instances: list[InstanceResult]
    false_incidents: list[str]  # short descriptions
    false_signal_rules: Counter[str] = field(default_factory=Counter)
    false_signal_twins: Counter[str] = field(default_factory=Counter)


def _cause(meta: dict) -> str:
    """Which normal activity produced an event: 'admin-certutil-download (twin of chain-2)'."""
    activity = meta.get("activity", "unlabelled")
    return f"{activity} (twin of {meta['twin']})" if meta.get("twin") else activity


def score_run(scenario: Scenario, result: Detection) -> RunScore:
    first_run: dict[str, object] = {}
    for event in scenario.events:  # first process start of each instance
        instance = event.meta.get("instance")
        if instance and event.is_sysmon and event.event_id == 1 and instance not in first_run:
            first_run[instance] = event.timestamp

    detected: dict[str, list[tuple[str, object]]] = defaultdict(list)
    true_incidents, false_incidents = 0, []
    for incident in result.incidents:
        instances = {s.event.meta.get("instance") for s in incident.signals} - {None}
        for instance in instances:
            detected[instance].append((incident.id, incident.detected_at))
        if instances:
            true_incidents += 1
        else:
            causes = sorted({_cause(s.event.meta) for s in incident.signals})
            false_incidents.append(f"{incident.title}  <- {', '.join(causes)}")

    results = []
    for instance in scenario.instances:
        hits = sorted(detected.get(instance.id, []), key=lambda pair: pair[1])
        start = first_run.get(instance.id, instance.start)
        ttd = hits[0][1] - start if hits else None  # type: ignore[operator]
        results.append(InstanceResult(instance.id, instance.chain, instance.variant, [h[0] for h in hits], ttd))

    false_rules: Counter[str] = Counter()
    false_twins: Counter[str] = Counter()
    malicious = 0
    for signal in result.signals:
        if signal.event.meta.get("label") == "malicious":
            malicious += 1
        else:
            false_rules[signal.rule.name] += 1
            false_twins[_cause(signal.event.meta)] += 1
    return RunScore(
        seed=scenario.config.seed, events=len(result.events), signals=len(result.signals),
        malicious_signals=malicious, incidents=len(result.incidents), true_incidents=true_incidents,
        instances=results, false_incidents=false_incidents, false_signal_rules=false_rules,
        false_signal_twins=false_twins,
    )


@dataclass
class SoakScore:
    hours: float
    hosts: int
    events: int
    signals: int
    incidents: list[str]

    @property
    def per_thousand_events(self) -> float:
        return 1000 * len(self.incidents) / max(self.events, 1)

    @property
    def per_host_day(self) -> float:
        return len(self.incidents) / max(self.hosts * self.hours / 24, 1e-9)


def run_evaluation(seeds: list[int], hours: float = 3.0, workstations: int = 5, unseen: bool = True,
                   rules: RuleSet | None = None) -> list[RunScore]:
    rules = rules or RuleSet.load()
    chains = SEEN_CHAINS + (UNSEEN_CHAINS if unseen else ())
    scores = []
    for seed in seeds:
        scenario = generate(ScenarioConfig(seed=seed, hours=hours, workstations=workstations, chains=chains))
        scores.append(score_run(scenario, detect(scenario.events, rules)))
    return scores


def run_soak(seed: int = 1000, hours: float = 24.0, workstations: int = 8, rules: RuleSet | None = None) -> SoakScore:
    """Only normal work, twins included: everything the engine raises is a false alarm."""
    rules = rules or RuleSet.load()
    scenario = generate(ScenarioConfig(seed=seed, hours=hours, workstations=workstations, chains=()))
    result = detect(scenario.events, rules)
    return SoakScore(
        hours=hours, hosts=len(scenario.hosts), events=len(result.events), signals=len(result.signals),
        incidents=[f"{i.title}  <- {', '.join(sorted({_cause(s.event.meta) for s in i.signals}))}"
                   for i in result.incidents],
    )


def _pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f}%" if whole else "n/a"


def _seconds(delta: timedelta) -> str:
    seconds = delta.total_seconds()
    return f"{seconds:.1f} s" if seconds < 120 else f"{seconds / 60:.1f} min"


def format_report(scores: list[RunScore], soak: SoakScore | None = None) -> list[str]:
    lines = []
    seeds = [s.seed for s in scores]
    lines.append(f"Evaluation over {len(scores)} generated scenarios (seeds {seeds[0]} to {seeds[-1]}), "
                 f"{sum(s.events for s in scores):,} events in total.")
    lines.append("")
    lines.append(f"{'Chain':<10} {'Variant':<8} {'Instances':>9} {'Detected':>9} {'Recall':>8} {'Median TTD':>11} "
                 f"{'Worst TTD':>10}")
    by_chain: dict[str, list[InstanceResult]] = defaultdict(list)
    for score in scores:
        for instance in score.instances:
            by_chain[instance.chain].append(instance)
    for chain in [c for c in CHAIN_TITLES if c in by_chain]:
        found = by_chain[chain]
        hits = [i for i in found if i.detected_by]
        ttds = [i.time_to_detect for i in hits if i.time_to_detect is not None]
        med = _seconds(timedelta(seconds=median(t.total_seconds() for t in ttds))) if ttds else "-"
        worst = _seconds(max(ttds)) if ttds else "-"
        lines.append(f"{chain:<10} {found[0].variant:<8} {len(found):>9} {len(hits):>9} "
                     f"{_pct(len(hits), len(found)):>8} {med:>11} {worst:>10}")
    for variant in ("seen", "unseen"):
        group = [i for chain in by_chain.values() for i in chain if i.variant == variant]
        if group:
            hit = sum(1 for i in group if i.detected_by)
            lines.append(f"  {variant} chains overall: {hit} of {len(group)} detected ({_pct(hit, len(group))})")
    lines.append("")
    incidents = sum(s.incidents for s in scores)
    true = sum(s.true_incidents for s in scores)
    lines.append(f"Incidents: {incidents} raised, {true} true, {incidents - true} false alarms "
                 f"-> precision {_pct(true, incidents)}")
    signals = sum(s.signals for s in scores)
    bad = sum(s.malicious_signals for s in scores)
    lines.append(f"Signals:   {signals} raised, {bad} on malicious events, {signals - bad} on normal ones "
                 f"-> signal precision {_pct(bad, signals)}")
    rules: Counter[str] = Counter()
    twins: Counter[str] = Counter()
    for score in scores:
        rules.update(score.false_signal_rules)
        twins.update(score.false_signal_twins)
    if rules:
        lines.append("  Signals on normal activity, by rule:")
        for name, count in rules.most_common():
            lines.append(f"    {count:5}  {name}")
        lines.append("  ...and by the normal activity that caused them:")
        for name, count in twins.most_common():
            lines.append(f"    {count:5}  {name}")
    false = Counter(f for s in scores for f in s.false_incidents)
    if false:
        lines.append("  False alarm incidents, by kind:")
        for item, count in false.most_common():
            lines.append(f"    {count:5}  {item}")
    if soak is not None:
        lines.append("")
        lines.append(f"Soak test: {soak.hours:g} hours of normal work on {soak.hosts} hosts, {soak.events:,} events, "
                     f"{soak.signals} signals.")
        lines.append(f"  {len(soak.incidents)} incidents -> {soak.per_thousand_events:.2f} per 1,000 events, "
                     f"{soak.per_host_day:.2f} per host per day")
        for item, count in Counter(soak.incidents).most_common():
            lines.append(f"    {count:5}  {item}")
    return lines
