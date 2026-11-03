"""The whole pipeline in one call: events in, incidents out.

    events  ->  process tree (phase 1)
            ->  signals: Sigma rules on single events (phase 3)
            ->  incidents: chains, risk, cross-host links (phase 4)
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .correlation import ChainRule, Incident, RiskConfig, correlate, load_chain_rules
from .event import Event
from .paths import RULES
from .sigma import SigmaRule, load_rules
from .signals import Signal, find_signals
from .tree import ProcessTree


@dataclass
class RuleSet:
    sigma: list[SigmaRule]
    chains: list[ChainRule]
    risk: RiskConfig

    @classmethod
    def load(cls, folder: Path = RULES) -> RuleSet:
        sigma = load_rules(folder / "sigma")
        chains = load_chain_rules(folder / "chains", {rule.name for rule in sigma})
        return cls(sigma, chains, RiskConfig.load(folder / "risk.yml"))


@dataclass
class Detection:
    events: list[Event]
    tree: ProcessTree
    signals: list[Signal]
    incidents: list[Incident]
    rules: RuleSet


def detect(events: Iterable[Event], rules: RuleSet | None = None) -> Detection:
    rules = rules or RuleSet.load()
    ordered = sorted(events, key=lambda e: e.timestamp)
    tree = ProcessTree.from_events(ordered)
    signals = find_signals(ordered, rules.sigma)
    incidents = correlate(ordered, signals, tree, rules.chains, rules.risk)
    return Detection(ordered, tree, signals, incidents, rules)
