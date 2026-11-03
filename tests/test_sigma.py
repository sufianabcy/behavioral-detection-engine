"""Phase 3: our small Sigma evaluator.

These tests pin down Sigma's matching rules (case, wildcards, modifiers) and
check that a broken rule is refused with a clear message, never half-loaded.
"""

from datetime import datetime, timezone

import pytest
import yaml

from bde.event import SYSMON_CHANNEL, Event
from bde.sigma import SigmaRule, load_rules
from bde.sigma.condition import parse_condition
from bde.sigma.values import compile_test, windash_variants

T0 = datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)


def check_of(modifiers, values, field="CommandLine"):
    """compile_test with a short spelling: check_of(['contains'], ['x'])('...')."""
    return compile_test(field, modifiers, values)


# --- values and modifiers ----------------------------------------------------------


def test_plain_value_is_a_whole_match_ignoring_case():
    check = check_of([], ["powershell.exe"])
    assert check("PowerShell.EXE")
    assert not check("powershell.exe -nop")  # no modifier = the whole value


def test_contains_startswith_endswith():
    assert check_of(["contains"], ["-urlcache"])("certutil -urlcache -f http://x")
    assert check_of(["startswith"], ["C:\\Users\\"])("c:\\users\\kchen\\a.js")
    assert not check_of(["startswith"], ["C:\\Users\\"])("D:\\C:\\Users\\")
    assert check_of(["endswith"], ["\\rundll32.exe"])("C:\\Windows\\System32\\RUNDLL32.EXE")


def test_wildcards_and_escaped_wildcards():
    # In Sigma, a backslash before * or ? escapes it; write \\* for "a backslash, then anything"
    assert check_of([], ["*\\Temp\\\\*.ps1"])("C:\\Windows\\Temp\\upd.ps1")
    assert check_of([], ["file?.txt"])("file1.txt") and not check_of([], ["file?.txt"])("file12.txt")
    literal = check_of(["contains"], ["\\*"])
    assert literal("a*b") and not literal("ab")


def test_regex_characters_in_plain_values_are_literal():
    check = check_of(["contains"], ["a.b(c)"])
    assert check("xa.b(c)y") and not check("xaxb(c)y")


def test_a_list_means_any_and_all_means_every():
    assert check_of(["contains"], ["-enc", "-e "])("powershell -e AAAA")
    both = check_of(["contains", "all"], ["-nop", "hidden"])
    assert both("powershell -nop -w hidden") and not both("powershell -nop")


def test_cased_respects_case():
    check = check_of(["contains", "cased"], ["Invoke-"])
    assert check("Invoke-CimMethod") and not check("invoke-cimmethod")


def test_windash_accepts_every_dash_style():
    check = check_of(["windash", "contains"], [" -urlcache "])
    for spelling in ("certutil -urlcache -f", "certutil /urlcache /f", "certutil \u2013urlcache x"):
        assert check(spelling), spelling
    assert len(windash_variants("-a -b")) == 25


def test_regex_with_flags():
    assert check_of(["re"], [r"-e(nc)?\s"])("x -enc y")
    assert not check_of(["re"], [r"-ENC\s"])("x -enc y")
    assert check_of(["re", "i"], [r"-ENC\s"])("x -enc y")


def test_null_matches_missing_or_empty():
    check = check_of([], [None])
    assert check(None) and check("") and not check("x")


def test_exists():
    assert check_of(["exists"], [True])("x") and not check_of(["exists"], [True])(None)
    assert check_of(["exists"], [False])(None)
    with pytest.raises(ValueError, match="exists"):
        check_of(["exists"], ["yes"])


def test_cidr():
    private = check_of(["cidr"], ["10.0.0.0/8", "192.168.0.0/16"], field="DestinationIp")
    assert private("10.20.1.37") and private("192.168.1.1")
    assert not private("203.0.113.10")
    assert not private("not an ip") and not private(None)
    assert check_of(["cidr"], ["fe80::/10"])("fe80::1")


def test_numbers():
    assert check_of(["gte"], [4])("4") and not check_of(["gt"], [4])("4")
    assert check_of(["lt"], [10])("9.5") and not check_of(["lt"], [10])("abc")


def test_unknown_modifier_is_refused():
    with pytest.raises(ValueError, match="unsupported modifier 'base64offset'"):
        check_of(["base64offset", "contains"], ["x"])


def test_yaml_numbers_and_booleans_compare_as_text():
    assert check_of([], [4624], field="EventID")("4624")
    assert check_of([], [True], field="Initiated")("true")


# --- conditions ----------------------------------------------------------------------


def evaluate(condition, true_names, names=("selection", "filter", "sel_a", "sel_b", "_helper")):
    node = parse_condition(condition, list(names))
    return node(lambda name: name in true_names)


def test_and_or_not_with_sigma_precedence():
    # not > and > or, like the Sigma specification
    assert evaluate("selection and not filter", {"selection"})
    assert not evaluate("selection and not filter", {"selection", "filter"})
    assert evaluate("sel_a or sel_b and filter", {"sel_a"})  # = sel_a or (sel_b and filter)
    assert not evaluate("(sel_a or sel_b) and filter", {"sel_a"})


def test_one_of_and_all_of_patterns():
    assert evaluate("1 of sel_*", {"sel_b"})
    assert not evaluate("all of sel_*", {"sel_b"})
    assert evaluate("all of sel_*", {"sel_a", "sel_b"})
    # "them" leaves out names starting with "_"
    assert evaluate("all of them", {"selection", "filter", "sel_a", "sel_b"})


def test_keywords_are_case_insensitive():
    assert evaluate("Selection AND NOT Filter".replace("Selection", "selection").replace("Filter", "filter"),
                    {"selection"})


@pytest.mark.parametrize("condition, message", [
    ("selection and", "ends too early"),
    ("(selection", "ends too early"),
    ("(selection or", "ends too early"),
    ("selection )", "unexpected"),
    ("unknown", "doesn't define"),
    ("1 of nothing_*", "matches no search identifier"),
    ("selection | count() > 5", "aggregations"),
    ("selection filter", "unexpected"),
])
def test_bad_conditions_are_refused(condition, message):
    with pytest.raises(ValueError, match=message):
        parse_condition(condition, ["selection", "filter"])


# --- whole rules ---------------------------------------------------------------------

BASE = {
    "title": "Test rule",
    "id": "0d4e0cd6-6b3c-4d5c-9b4e-3a5f0c1e2d7b",
    "name": "test_rule",
    "level": "medium",
    "logsource": {"product": "windows", "category": "process_creation"},
    "tags": ["attack.execution", "attack.t1059.001"],
    "detection": {
        "selection": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "-nop"},
        "filter": {"ParentImage|endswith": "\\svchost.exe"},
        "condition": "selection and not filter",
    },
}


def rule(**changes) -> SigmaRule:
    data = yaml.safe_load(yaml.safe_dump(BASE))  # a deep copy
    for key, value in changes.items():
        if value is None:
            data.pop(key)
        else:
            data[key] = value
    return SigmaRule.from_dict(data)


def process(image, command, parent="C:\\Windows\\explorer.exe", channel=SYSMON_CHANNEL, event_id=1, **extra):
    return Event(event_id, T0, "WKSTN-07.corp.example", channel,
                 {"Image": image, "CommandLine": command, "ParentImage": parent, **extra})


PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"


def test_selection_and_filter():
    r = rule()
    assert r.matches(process(PS, "powershell -nop -c x"))
    assert not r.matches(process(PS, "powershell -c x"))
    assert not r.matches(process(PS, "powershell -nop", parent="C:\\Windows\\System32\\svchost.exe"))


def test_rule_only_reads_its_own_logsource():
    r = rule()
    network = process(PS, "powershell -nop", event_id=3)
    assert not r.applies_to(network) and not r.matches(network)


def test_process_creation_rules_also_read_security_4688():
    r = rule()
    event = Event(4688, T0, "WKSTN-07", "Security",
                  {"NewProcessName": PS, "CommandLine": "powershell -nop", "ParentProcessName": "C:\\x\\cmd.exe"})
    assert r.matches(event)


def test_service_rules_cover_every_event_id_of_their_log():
    r = rule(logsource={"product": "windows", "service": "security"},
             detection={"selection": {"EventID": 1102}, "condition": "selection"})
    assert r.matches(Event(1102, T0, "SRV", "Security", {}))
    assert not r.matches(Event(1102, T0, "SRV", "System", {}))


def test_list_of_maps_means_any_map():
    r = rule(detection={"selection": [{"Image|endswith": "\\cmd.exe"}, {"Image|endswith": "\\powershell.exe"}],
                        "condition": "selection"})
    assert r.matches(process(PS, "x")) and r.matches(process("C:\\Windows\\System32\\cmd.exe", "x"))
    assert not r.matches(process("C:\\Windows\\notepad.exe", "x"))


def test_keyword_lists_search_every_field():
    r = rule(detection={"keywords": ["SIMULATED-STAGE"], "condition": "keywords"})
    assert r.matches(process(PS, "Write-Output 'simulated-stage-2'"))


def test_several_conditions_mean_any_of_them():
    r = rule(detection={"a": {"CommandLine|contains": "aaa"}, "b": {"CommandLine|contains": "bbb"},
                        "condition": ["a", "b"]})
    assert r.matches(process(PS, "x bbb")) and not r.matches(process(PS, "x ccc"))


def test_techniques_and_tactics_come_from_tags():
    r = rule()
    assert r.techniques == ["T1059.001"]
    assert r.tactics == ["execution"]


@pytest.mark.parametrize("changes, message", [
    ({"id": None}, "missing required field 'id'"),
    ({"id": "not-a-uuid"}, "lowercase UUID"),
    ({"name": "Has Spaces"}, "name must use only"),
    ({"level": "severe"}, "level must be one of"),
    ({"tags": ["attack.T1059"]}, "tags must be lowercase"),
    ({"logsource": {"product": "linux", "category": "process_creation"}}, "only product 'windows'"),
    ({"logsource": {"product": "windows", "category": "kernel_stuff"}}, "unsupported logsource category"),
    ({"logsource": {"product": "windows"}}, "needs a category or a service"),
    ({"detection": {"selection": {"Image": "x"}}}, "no condition"),
    ({"detection": {"selection": {}, "condition": "selection"}}, "is empty"),
    ({"detection": {"selection": {"Image": "x"}, "timeframe": "5m", "condition": "selection"}}, "timeframe"),
    ({"detection": {"selection": {"Image|base64": "x"}, "condition": "selection"}}, "unsupported modifier"),
])
def test_broken_rules_are_refused(changes, message):
    with pytest.raises(ValueError, match=message):
        rule(**changes)


def test_duplicate_names_are_refused(tmp_path):
    for number in (1, 2):
        data = dict(BASE, id=f"0d4e0cd6-6b3c-4d5c-9b4e-3a5f0c1e2d7{number}")
        (tmp_path / f"r{number}.yml").write_text(yaml.safe_dump(data), encoding="utf-8")
    with pytest.raises(ValueError, match="share the name 'test_rule'"):
        load_rules(tmp_path)


def test_one_rule_per_file(tmp_path):
    (tmp_path / "two.yml").write_text(yaml.safe_dump(BASE) + "---\n" + yaml.safe_dump(BASE), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly one rule"):
        load_rules(tmp_path)
