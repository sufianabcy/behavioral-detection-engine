"""Phase 7: scanning folders of public recordings, and scoring them by the
ATT&CK technique named in their folders."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from bde.engine import RuleSet
from bde.event import SYSMON_CHANNEL, Event
from bde.external import (
    claimed_techniques,
    format_report,
    in_scope,
    scan_folder,
    technique_label,
    technique_matches,
)
from bde.readers import write_jsonl

T0 = datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
STAGE2 = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFMASQBNAFUATABBAFQARQBEAC0AUwBUAEEARwBFAC0AMgAnAA=="


@pytest.mark.parametrize("relative, label", [
    ("TA0002-Execution/T1059.001-PowerShell/ID4104-x.evtx", "T1059.001"),
    ("TA0003-Persistence/T1098.xxx-Account manipulation/ID4738-y.evtx", "T1098"),
    ("Credential Access/4794_DSRM_password_change_t1098.evtx", "T1098"),
    ("Defense Evasion/Win_4985_T1186_Process_Doppelganging.evtx", "T1186"),
    ("Execution/ID4688-new process.evtx", None),  # "ID4688" is an event ID, not a technique
    ("Lateral Movement/LM_wmi_4624.evtx", None),
])
def test_technique_label_comes_from_the_nearest_folder_or_the_file_name(relative, label):
    root = Path("/data")
    assert technique_label(root / relative, root) == label


def test_technique_matching_follows_sub_techniques():
    assert technique_matches("T1218.011", "T1218.011")
    assert technique_matches("T1218.011", "T1218")  # a rule for the parent covers the sub-technique
    assert technique_matches("T1547", "T1547.001")  # a parent-level recording, a sub-technique rule
    assert not technique_matches("T1218.011", "T1218.005")
    assert not technique_matches("T1059", "T1059X")


def test_scope_comes_from_the_rules_tags():
    rules = RuleSet.load()
    claimed = claimed_techniques(rules)
    assert "T1059.001" in claimed and "T1047" in claimed
    assert in_scope("T1059.001", claimed)
    assert not in_scope("T1053.005", claimed)  # scheduled tasks: the documented gap


def _write(path: Path, events: list[Event]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(events, path)


@pytest.fixture()
def dataset(tmp_path):
    root = tmp_path / "recordings"
    encoded = Event(1, T0, "PC01", SYSMON_CHANNEL, {
        "Image": PS, "CommandLine": f"powershell.exe -nop -enc {STAGE2}", "ParentImage": "C:\\Windows\\explorer.exe",
        "ProcessGuid": "{11111111-0000-0000-0000-000000000001}"})
    plain = Event(1, T0, "PC01", SYSMON_CHANNEL, {
        "Image": "C:\\Windows\\System32\\notepad.exe", "CommandLine": "notepad.exe",
        "ParentImage": "C:\\Windows\\explorer.exe", "ProcessGuid": "{11111111-0000-0000-0000-000000000002}"})
    _write(root / "TA0002-Execution" / "T1059.001-PowerShell" / "encoded.jsonl", [encoded])
    _write(root / "TA0002-Execution" / "T1059.001-PowerShell" / "quiet.jsonl", [plain])
    _write(root / "TA0002-Execution" / "T1053.005-Scheduled Task" / "task.jsonl", [plain])
    _write(root / "Other" / "unlabelled.jsonl", [plain])
    (root / "Other" / "broken.evtx").write_bytes(b"not an event log at all")
    return root


def test_scan_scores_each_file_by_its_technique(dataset):
    results = {r.path.name: r for r in scan_folder(dataset)}
    assert set(results) == {"encoded.jsonl", "quiet.jsonl", "task.jsonl", "unlabelled.jsonl", "broken.evtx"}
    assert results["encoded.jsonl"].detected()
    assert results["encoded.jsonl"].signals["proc_powershell_encoded_command"] == 1
    assert not results["quiet.jsonl"].detected()
    assert results["unlabelled.jsonl"].label is None
    assert "not a valid .evtx file" in results["broken.evtx"].error


def test_report_counts_scope_and_detections(dataset):
    rules = RuleSet.load()
    text = "\n".join(format_report(scan_folder(dataset, rules), rules, dataset))
    assert "5 files, 4 events; 0 unreadable records; 1 files could not be read." in text
    assert "In scope, a rule claims the technique: 2 files, 1 detected by a rule for that technique (50.0%)" in text
    assert "T1059.001    2 files   1 detected" in text
    assert "Out of scope: 1 files; 0 raised signals anyway." in text
    assert "1 files have no technique in their folder or file name." in text
    assert "Other/broken.evtx: could not read" in text
