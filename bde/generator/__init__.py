"""Phase 2: the scenario generator.

Builds labelled, Sysmon-shaped events for a small simulated company: normal
work, benign look-alikes ("twins"), and the attack chains. See
docs/phase-2-scenarios.md.
"""

from .scenario import (
    CHAIN_TITLES,
    SEEN_CHAINS,
    UNSEEN_CHAINS,
    Instance,
    Scenario,
    ScenarioConfig,
    generate,
)

__all__ = ["CHAIN_TITLES", "SEEN_CHAINS", "UNSEEN_CHAINS", "Instance", "Scenario", "ScenarioConfig", "generate"]
