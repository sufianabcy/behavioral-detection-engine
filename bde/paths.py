"""Where the project's own files live, wherever you run it from."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
SIGMA_RULES = RULES / "sigma"
CHAIN_RULES = RULES / "chains"
RISK_CONFIG = RULES / "risk.yml"
