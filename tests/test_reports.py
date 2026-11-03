"""Phases 5 and 6: scoring, reports and the generated ATT&CK documents."""

import json
import re

import pytest

from bde.attack import ATTACK_VERSION, TECHNIQUES
from bde.engine import RuleSet, detect
from bde.evaluate import format_report, run_evaluation, run_soak, score_run
from bde.generator import generate
from bde.paths import ROOT
from bde.report.html import render_html
from bde.report.jsonout import incidents_json
from bde.report.mapping import build_coverage, mapping_run, render_mapping
from bde.report.navigator import coverage_layer, incidents_layer
from bde.report.text import render_incidents


@pytest.fixture(scope="module")
def rules():
    return RuleSet.load()


@pytest.fixture(scope="module")
def demo(rules):
    scenario = generate()
    return scenario, detect(scenario.events, rules)


# --- phase 5: evaluation -------------------------------------------------------------


def test_score_run_counts_true_and_false_incidents(demo):
    scenario, result = demo
    score = score_run(scenario, result)
    assert score.incidents == score.true_incidents == len(result.incidents)
    assert score.malicious_signals <= score.signals
    for instance in score.instances:
        assert instance.time_to_detect is not None and instance.time_to_detect.total_seconds() >= 0


def test_evaluation_over_a_few_seeds(rules):
    scores = run_evaluation([1, 2], hours=3, workstations=5, unseen=True, rules=rules)
    assert [s.seed for s in scores] == [1, 2]
    lines = "\n".join(format_report(scores))
    assert "seen chains overall" in lines and "unseen chains overall" in lines
    assert "Incidents:" in lines and "precision" in lines


def test_soak_test_has_no_attacks(rules):
    soak = run_soak(seed=1000, hours=3, workstations=5, rules=rules)
    assert soak.events > 0
    assert soak.per_thousand_events >= 0 and soak.per_host_day >= 0


# --- phase 6: reports ----------------------------------------------------------------------


def test_html_report_is_self_contained_and_complete(demo):
    _, result = demo
    page = render_html(result, title="test report", source="seed 7")
    assert page.startswith("<!doctype html>")
    for incident in result.incidents:
        assert f'id="{incident.id}"' in page
    assert "<script src" not in page and "<link rel=\"stylesheet\"" not in page  # works offline
    assert "prefers-color-scheme: dark" in page


def test_html_report_escapes_log_text(rules):
    """Command lines come from logs, which an attacker controls: never inject them as HTML."""
    scenario = generate()
    for event in scenario.events:
        if event.meta.get("instance") == "chain-1#1" and event.event_id == 1 and "powershell" in event.get("Image"):
            event.data["CommandLine"] += " <script>alert(1)</script>"
    page = render_html(detect(scenario.events, rules))
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_text_report_lists_every_incident(demo):
    _, result = demo
    text = "\n".join(render_incidents(result, width=100))
    for incident in result.incidents:
        assert incident.id in text


def test_incidents_json_is_valid(demo):
    _, result = demo
    data = json.loads(incidents_json(result))
    assert [i["id"] for i in data["incidents"]] == [i.id for i in result.incidents]
    first = data["incidents"][0]
    assert {"hosts", "techniques", "signals", "origin", "steps"} <= set(first)


def test_navigator_layers_use_known_techniques(demo, rules):
    _, result = demo
    scenario, run = mapping_run(rules)
    for layer in (incidents_layer(result.incidents), coverage_layer(build_coverage(rules, scenario, run))):
        assert layer["versions"]["attack"] == ATTACK_VERSION
        assert layer["domain"] == "enterprise-attack"
        assert layer["techniques"]
        for entry in layer["techniques"]:
            assert entry["techniqueID"] in TECHNIQUES
        json.dumps(layer)  # serializable


def test_coverage_marks_gaps_honestly(rules):
    scenario, run = mapping_run(rules)
    coverage = build_coverage(rules, scenario, run)
    statuses = {technique: info["status"] for technique, info in coverage.items()}
    assert statuses["T1059.001"] == "tested"
    assert statuses["T1218.005"] == "rule-only"  # mshta: a rule, but no simulated chain uses it
    assert statuses["T1053.005"] == "gap"  # the unseen remote scheduled task


def test_mapping_document_is_up_to_date(rules):
    """docs/attack-mapping.md is generated. If this fails, run: python -m bde mapping"""
    written = (ROOT / "docs" / "attack-mapping.md").read_text(encoding="utf-8")
    assert written == render_mapping(rules)


def test_mapping_document_links_every_technique(rules):
    text = render_mapping(rules)
    for technique in re.findall(r"^### (T\d{4}(?:\.\d{3})?)", text, flags=re.MULTILINE):
        assert technique in TECHNIQUES
