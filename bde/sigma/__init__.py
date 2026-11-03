"""Phase 3: a small Sigma rule engine. See docs/phase-3-signals.md."""

from .rule import LEVELS, SigmaRule, field_value, load_rule, load_rules

__all__ = ["LEVELS", "SigmaRule", "field_value", "load_rule", "load_rules"]
