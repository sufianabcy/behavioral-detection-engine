"""Generate the ATT&CK mapping document from the rules themselves.

The mapping is a course deliverable, and hand-written mappings drift: someone
edits a rule and forgets the document. Here the document is *computed* from
three sources, so it can't disagree with the code:

1. the ATT&CK tags in the Sigma rules and chain rules (what we claim to detect);
2. the generator's ground truth (which techniques the simulated chains use);
3. a run of the engine on the demo data (what it actually detected).

A test regenerates it and fails if docs/attack-mapping.md is out of date.
"""

from __future__ import annotations

from ..attack import ATTACK_VERSION, sort_techniques, tactic_name, technique_name, technique_tactics, technique_url
from ..engine import Detection, RuleSet, detect
from ..generator import SEEN_CHAINS, UNSEEN_CHAINS, Scenario, ScenarioConfig, generate
from .describe import describe_event

DATA_SOURCES = {
    "process_creation": "Sysmon 1 (process create), or Security 4688",
    "network_connection": "Sysmon 3 (network connection)",
    "file_event": "Sysmon 11 (file create)",
    "registry_set": "Sysmon 13 (registry value set)",
    "dns_query": "Sysmon 22 (DNS query)",
    "security": "Security log",
}
STATUS_TEXT = {
    "tested": "Detected in the simulated chains",
    "rule-only": "Rule exists, tested by unit tests only",
    "gap": "Not detected (gap)",
}
MAPPING_SEED = 7


def mapping_run(rules: RuleSet | None = None) -> tuple[Scenario, Detection]:
    """The run the mapping is computed from: seed 7, every chain including unseen variants."""
    rules = rules or RuleSet.load()
    scenario = generate(ScenarioConfig(seed=MAPPING_SEED, chains=SEEN_CHAINS + UNSEEN_CHAINS))
    return scenario, detect(scenario.events, rules)


def _data_needed(logsource: dict[str, str]) -> str:
    return DATA_SOURCES.get(logsource.get("category") or logsource.get("service", ""), str(logsource))


def build_coverage(rules: RuleSet, scenario: Scenario, result: Detection) -> dict[str, dict]:
    coverage: dict[str, dict] = {}

    def entry(technique: str) -> dict:
        return coverage.setdefault(technique, {
            "rules": [], "chains": [], "data": [], "simulated": [], "example": "", "falsepositives": [],
            "levels": {}, "status": "gap",
        })

    for rule in rules.sigma:
        for technique in rule.techniques:
            item = entry(technique)
            item["rules"].append(rule.name)
            item["levels"][rule.name] = rule.level
            data = _data_needed(rule.logsource)
            if data not in item["data"]:
                item["data"].append(data)
            for fp in rule.falsepositives:
                if fp not in item["falsepositives"]:
                    item["falsepositives"].append(fp)
    for chain in rules.chains:
        for technique in chain.techniques:
            item = entry(technique)
            item["chains"].append(chain.name)
            if "Sysmon 1 (process tree), plus the step rules' data" not in item["data"]:
                item["data"].append("Sysmon 1 (process tree), plus the step rules' data")
            if chain.crosshost and "Security 4624 (logons) and Sysmon 3, for the cross-host link" not in item["data"]:
                item["data"].append("Security 4624 (logons) and Sysmon 3, for the cross-host link")

    for event in scenario.events:  # ground truth: techniques the simulated attacks use
        if event.meta.get("label") != "malicious":
            continue
        for technique in event.meta.get("techniques", []):
            item = entry(technique)
            chain = event.meta["chain"]
            if chain not in item["simulated"]:
                item["simulated"].append(chain)
            if not item["example"]:
                item["example"] = describe_event(event)

    simulated = {t for t, item in coverage.items() if item["simulated"]}

    def is_simulated(technique: str) -> bool:  # a parent counts if one of its sub-techniques was simulated
        return technique in simulated or any(t.startswith(technique + ".") for t in simulated)

    for incident in result.incidents:  # what the engine actually detected
        if not any(s.event.meta.get("label") == "malicious" for s in incident.signals):
            continue
        for technique in incident.techniques:
            item = coverage.get(technique)
            if item and (item["rules"] or item["chains"]) and is_simulated(technique):
                coverage[technique]["status"] = "tested"
                if not coverage[technique]["example"]:
                    hit = next((s for s in incident.signals if technique in s.rule.techniques), None)
                    if hit:
                        coverage[technique]["example"] = describe_event(hit.event)
    for item in coverage.values():
        if item["status"] != "tested" and (item["rules"] or item["chains"]):
            item["status"] = "rule-only"
        item["simulated"].sort()
    return coverage


def _cut(text: str, width: int = 160) -> str:
    text = " ".join(text.split()).replace("|", "\\|")
    return text if len(text) <= width else text[: width - 3] + "..."


def render_mapping(rules: RuleSet | None = None) -> str:
    rules = rules or RuleSet.load()
    scenario, result = mapping_run(rules)
    coverage = build_coverage(rules, scenario, result)
    ordered = sort_techniques(coverage)
    counts = {status: sum(1 for t in ordered if coverage[t]["status"] == status) for status in STATUS_TEXT}

    out = [
        "# ATT&CK technique mapping",
        "",
        "<!-- Generated by `python -m bde mapping`. Do not edit by hand: change a rule, then regenerate. -->",
        "",
        f"This document is generated from the rules in `rules/` and a run of the engine on the demo data "
        f"(seed {MAPPING_SEED}, all seven simulated chains, including the three unseen variants). "
        f"A test fails when it is out of date, so it always matches the code.",
        "",
        f"ATT&CK version: Enterprise v{ATTACK_VERSION}. In this version the old *Defense Evasion* tactic is split "
        "into **Stealth** (TA0005) and **Defense Impairment** (TA0112); Disable or Modify Tools moved from "
        "T1562.001 to **T1685** and Clear Windows Event Logs from T1070.001 to **T1685.005**.",
        "",
        f"**Coverage:** {counts['tested']} techniques detected in the simulated chains, {counts['rule-only']} with a "
        f"rule that only unit tests exercise, and {counts['gap']} that the simulated attacks use but nothing "
        "detects (listed under Gaps, on purpose: they show the engine's limits).",
        "",
        "## Summary",
        "",
        "| Tactic | Technique | Detected by | Coverage |",
        "| --- | --- | --- | --- |",
    ]
    for technique in ordered:
        item = coverage[technique]
        tactics = ", ".join(tactic_name(t) for t in technique_tactics(technique)) or "?"
        detectors = ", ".join(f"`{r}`" for r in item["rules"] + item["chains"]) or "nothing"
        out.append(f"| {tactics} | [{technique}]({technique_url(technique)}) {technique_name(technique)} | "
                   f"{detectors} | {STATUS_TEXT[item['status']]} |")

    out += ["", "## Techniques in detail", ""]
    for technique in ordered:
        item = coverage[technique]
        if item["status"] == "gap":
            continue
        out.append(f"### {technique} {technique_name(technique)}")
        out.append("")
        out.append(f"- **Tactics:** {', '.join(tactic_name(t) for t in technique_tactics(technique))}")
        if item["rules"]:
            out.append("- **Detected by:** " + ", ".join(f"`{r}` ({item['levels'][r]})" for r in item["rules"]))
        if item["chains"]:
            out.append("- **Chain rules:** " + ", ".join(f"`{c}`" for c in item["chains"])
                       + " (visible only from the whole chain, not from one event)")
        out.append(f"- **Data needed:** {'; '.join(item['data'])}")
        out.append(f"- **Simulated chains:** {', '.join(item['simulated']) or 'none (unit tests only)'}")
        if item["example"]:
            out.append(f"- **Example evidence:** `{_cut(item['example'])}`")
        if item["falsepositives"]:
            out.append(f"- **Known false positives:** {'; '.join(item['falsepositives'])}")
        out.append(f"- **Coverage:** {STATUS_TEXT[item['status']]}")
        out.append("")

    out += ["## Gaps", "",
            "Techniques the simulated attacks use that no rule detects. Each is a possible next rule.", "",
            "| Technique | Used in | Example from the simulated data |", "| --- | --- | --- |"]
    for technique in ordered:
        item = coverage[technique]
        if item["status"] == "gap":
            out.append(f"| [{technique}]({technique_url(technique)}) {technique_name(technique)} | "
                       f"{', '.join(item['simulated'])} | `{_cut(item['example'], 110)}` |")

    out += ["", "## All rules", "", "| Rule | Level | What it detects | Techniques |", "| --- | --- | --- | --- |"]
    for rule in sorted(rules.sigma, key=lambda r: r.name):
        out.append(f"| `{rule.name}` | {rule.level} | {rule.title} | {', '.join(rule.techniques)} |")
    for chain in rules.chains:
        steps = " -> ".join(step.name for step in chain.steps)
        out.append(f"| `{chain.name}` (chain) | {chain.level} | {chain.title}. Steps: {steps}; needs "
                   f"{chain.min_steps} | {', '.join(chain.techniques) or '(from its steps)'} |")
    out.append("")
    return "\n".join(out)
