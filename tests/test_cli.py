import pytest

from bde.__main__ import main
from bde.readers import read_jsonl
from helpers import SAMPLE, XML_EXPORT


def run(capsys, *argv):
    code = main([str(a) for a in argv])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_stats(capsys):
    code, out, _ = run(capsys, "stats", SAMPLE)
    assert code == 0
    assert "Events: 12   Hosts: 2" in out
    assert "Process create" in out


def test_tree_in_ascii(capsys):
    code, out, _ = run(capsys, "tree", SAMPLE, "--ascii")
    assert code == 0
    assert "`-- powershell.exe" in out
    assert "11 Sysmon events used, 1 other event skipped." in out


def test_convert_xml_export_to_jsonl(tmp_path, capsys):
    target = tmp_path / "converted.jsonl"
    code, out, _ = run(capsys, "convert", XML_EXPORT, "-o", target)
    assert code == 0 and "Wrote 3 events" in out
    assert len(list(read_jsonl(target))) == 3


def test_missing_input_is_a_clean_error(tmp_path, capsys):
    code, _, err = run(capsys, "stats", tmp_path / "nope.jsonl")
    assert code == 2
    assert "no such file" in err


def test_tree_explains_when_there_is_nothing_to_draw(tmp_path, capsys):
    only_logons = tmp_path / "logons.jsonl"
    only_logons.write_text(
        '{"EventID": 4624, "Time": "2026-11-03T09:04:58Z", "Computer": "H", "Channel": "Security", "EventData": {}}\n',
        encoding="utf-8",
    )
    code, out, _ = run(capsys, "tree", only_logons)
    assert code == 0
    assert "No Sysmon events with a ProcessGuid" in out


# --- phases 2 to 6 ---------------------------------------------------------------------


def test_generate_prints_the_fingerprint(tmp_path, capsys):
    from test_generator import SEED_7_SHA256

    target = tmp_path / "scenario.jsonl"
    code, out, _ = run(capsys, "generate", "-o", target)
    assert code == 0
    assert f"SHA-256 {SEED_7_SHA256}" in out
    assert "chain-4#1" in out


def test_generate_rejects_an_unknown_chain(tmp_path, capsys):
    with pytest.raises(SystemExit):
        run(capsys, "generate", "--chains", "1,9", "-o", tmp_path / "x.jsonl")
    assert "unknown chain" in capsys.readouterr().err


def test_detect_on_generated_logs_writes_reports(tmp_path, capsys):
    events = tmp_path / "s.jsonl"
    run(capsys, "generate", "--chains", "2", "--seed", "3", "-o", events)
    code, out, _ = run(capsys, "detect", events, "--out", tmp_path / "report", "--ascii")
    assert code == 0
    assert "INC-001" in out
    for name in ("report.html", "incidents.json", "incidents-layer.json"):
        assert (tmp_path / "report" / name).is_file()


def test_detect_on_the_hand_made_sample(capsys):
    code, out, _ = run(capsys, "detect", SAMPLE, "--ascii")
    assert code == 0
    assert "chain_office_document_to_powershell" in out


def test_rules_lists_and_validates(capsys):
    code, out, _ = run(capsys, "rules")
    assert code == 0
    assert "Sigma rules (rules/sigma), all valid" in out
    assert "chain_wmi_remote_shell_discovery" in out


def test_evaluate_small(capsys):
    code, out, _ = run(capsys, "evaluate", "--seeds", "1-2", "--soak-hours", "2")
    assert code == 0
    assert "Evaluation over 2 generated scenarios" in out
    assert "Soak test" in out


def test_mapping_check(capsys):
    code, out, _ = run(capsys, "mapping", "--check")
    assert code == 0, out


def test_mapping_check_spots_a_stale_file(tmp_path, capsys):
    stale = tmp_path / "mapping.md"
    stale.write_text("old\n", encoding="utf-8")
    code, out, _ = run(capsys, "mapping", "--check", "-o", stale)
    assert code == 1 and "out of date" in out


def test_navigator_layer_file(tmp_path, capsys):
    import json

    target = tmp_path / "layer.json"
    code, _, _ = run(capsys, "navigator", "-o", target)
    assert code == 0
    assert json.loads(target.read_text(encoding="utf-8"))["domain"] == "enterprise-attack"


def test_demo_end_to_end(tmp_path, capsys):
    code, out, _ = run(capsys, "demo", "--out", tmp_path, "--ascii")
    assert code == 0
    assert "4 of 4 attack chains detected; 0 false alarms." in out
    assert (tmp_path / "report.html").is_file() and (tmp_path / "coverage-layer.json").is_file()
