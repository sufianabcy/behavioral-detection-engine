"""
detection/__init__.py
─────────────────────────────────────────────────────────────────────────────
Public API for the detection package.

    from detection.engine import DetectionEngine, Alert, Scorer, Correlator
    from detection.engine import Rule, RuleMatch, RulesLoader
"""

from detection.engine import (
    DetectionEngine,
    Alert,
    Scorer,
    Correlator,
    Rule,
    RuleMatch,
    RulesLoader,
)

__all__ = [
    "DetectionEngine",
    "Alert",
    "Scorer",
    "Correlator",
    "Rule",
    "RuleMatch",
    "RulesLoader",
]

