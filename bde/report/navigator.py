"""ATT&CK Navigator layers: colour the ATT&CK matrix by what we detect.

Open https://mitre-attack.github.io/attack-navigator/, choose "Open Existing
Layer" > "Upload from local", and pick the .json file. If the Navigator warns
that the layer's ATT&CK version differs from its own, the layer still loads.
"""

from __future__ import annotations

import json
from collections import defaultdict

from ..attack import ATTACK_VERSION
from ..correlation import Incident

LAYER_FORMAT = "4.5"
NAVIGATOR_VERSION = "5.1.0"

COVERAGE_COLORS = {
    "tested": "#4caf50",  # a rule fires on it in the simulated chains
    "rule-only": "#ffc107",  # a rule exists, checked only by unit tests
    "gap": "#ef5350",  # it happens in a simulated chain, and nothing detects it
}
COVERAGE_LABELS = {
    "tested": "Detected in the simulated chains",
    "rule-only": "Rule exists, unit-tested only",
    "gap": "Happens in a simulated chain, not detected",
}


def _layer(name: str, description: str, techniques: list[dict], legend: list[dict]) -> dict:
    return {
        "name": name,
        "versions": {"attack": ATTACK_VERSION, "navigator": NAVIGATOR_VERSION, "layer": LAYER_FORMAT},
        "domain": "enterprise-attack",
        "description": description,
        "filters": {"platforms": ["Windows"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True,
                   "showAggregateScores": False, "countUnscored": False, "expandedSubtechniques": "annotated"},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#66b1ff"], "minValue": 0, "maxValue": 1},
        "legendItems": legend,
        "metadata": [],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }


def coverage_layer(coverage: dict[str, dict]) -> dict:
    """`coverage` comes from report.mapping.build_coverage()."""
    techniques = []
    for technique, info in sorted(coverage.items()):
        rules = info["rules"] + info["chains"]
        comment = (f"{COVERAGE_LABELS[info['status']]}. " +
                   (f"Detected by: {', '.join(rules)}." if rules else "No rule."))
        techniques.append({
            "techniqueID": technique,
            "score": 1 if info["status"] != "gap" else 0,
            "color": COVERAGE_COLORS[info["status"]],
            "comment": comment,
            "enabled": True,
            "metadata": [{"name": "rule", "value": r} for r in rules],
            "links": [],
            "showSubtechniques": True,
        })
    legend = [{"label": COVERAGE_LABELS[k], "color": v} for k, v in COVERAGE_COLORS.items()]
    return _layer("bde detection coverage", "Which ATT&CK techniques the bde rules detect, and how well tested.",
                  techniques, legend)


def incidents_layer(incidents: list[Incident], name: str = "bde incidents") -> dict:
    """Techniques seen in one run's incidents; the comment lists which incidents."""
    found: dict[str, list[str]] = defaultdict(list)
    for incident in incidents:
        for technique in incident.techniques:
            found[technique].append(incident.id)
    techniques = [{
        "techniqueID": technique, "score": len(ids), "color": "", "comment": "Seen in " + ", ".join(ids),
        "enabled": True, "metadata": [], "links": [], "showSubtechniques": True,
    } for technique, ids in sorted(found.items())]
    layer = _layer(name, "ATT&CK techniques in the incidents of one bde run (score = number of incidents).",
                   techniques, [])
    layer["gradient"] = {"colors": ["#ffe0b2", "#e65100"], "minValue": 0,
                         "maxValue": max((len(v) for v in found.values()), default=1)}
    return layer


def dumps(layer: dict) -> str:
    return json.dumps(layer, indent=2, ensure_ascii=False) + "\n"
