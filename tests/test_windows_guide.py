"""The Windows testing guide promises what Part C's commands will trigger.

These events are shaped like the ones Sysmon writes for those commands, so
if a rule change breaks a promise in docs/windows-testing-guide.md, this test
says so before a tester finds out the hard way.
"""

from datetime import datetime, timedelta, timezone

import pytest

from bde.engine import RuleSet, detect
from bde.event import SYSMON_CHANNEL, Event

T0 = datetime(2026, 11, 3, 14, 0, tzinfo=timezone.utc)
HOST = "DESKTOP-TEST"
SYS32 = "C:\\Windows\\System32\\"
PS = SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe"
USER_PS = "{11111111-0000-0000-0000-000000000001}"  # the tester's own PowerShell window
ENC = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFMASQBNAFUATABBAFQARQBEAC0AUwBUAEEARwBFAC0AMgAnAA=="


def start(minute, number, image, command, parent=USER_PS, parent_image=PS):
    return Event(1, T0 + timedelta(minutes=minute), HOST, SYSMON_CHANNEL, {
        "ProcessGuid": f"{{11111111-0000-0000-0000-{number:012d}}}", "ProcessId": str(5000 + number),
        "Image": image, "CommandLine": command, "User": "DESKTOP-TEST\\tester",
        "ParentProcessGuid": parent, "ParentImage": parent_image, "ParentProcessId": "4000",
    })


STEPS = {
    "C1": [start(0, 2, PS, f'"{PS}" -nop -w hidden -enc {ENC}')],
    "C2": [
        start(2, 3, SYS32 + "whoami.exe", '"C:\\Windows\\system32\\whoami.exe" /all'),
        start(2.5, 4, SYS32 + "nltest.exe", '"C:\\Windows\\system32\\nltest.exe" /dclist:'),
        start(3, 5, SYS32 + "net.exe", '"C:\\Windows\\system32\\net.exe" group "Domain Admins" /domain'),
        start(3, 6, SYS32 + "net1.exe", 'C:\\Windows\\system32\\net1 group "Domain Admins" /domain',
              parent="{11111111-0000-0000-0000-000000000005}", parent_image=SYS32 + "net.exe"),
    ],
    "C3": [start(5, 7, SYS32 + "certutil.exe",
                 '"C:\\Windows\\system32\\certutil.exe" -decode C:\\Users\\Public\\bde-test.txt '
                 "C:\\Users\\Public\\bde-test.out")],
    "C4": [Event(13, T0 + timedelta(minutes=8), HOST, SYSMON_CHANNEL, {
        "ProcessGuid": USER_PS, "Image": PS, "EventType": "SetValue",
        "TargetObject": "HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\BDE-Test",
        "Details": "powershell.exe -w hidden -c Write-Output BDE-TEST",
    })],
    "C5": [
        start(9, 8, SYS32 + "certutil.exe",
              '"C:\\Windows\\system32\\certutil.exe" -hashfile C:\\Windows\\System32\\notepad.exe SHA256'),
        start(9.5, 9, SYS32 + "whoami.exe", '"C:\\Windows\\system32\\whoami.exe"'),
    ],
}

EXPECTED = {
    "C1": {"proc_powershell_encoded_command", "proc_powershell_hidden_window"},
    "C2": {"proc_whoami_privileges", "proc_nltest_domain_discovery", "proc_domain_group_discovery"},
    "C3": {"proc_certutil_decode"},
    "C4": {"reg_run_key_script_engine", "reg_run_key_modified"},
    "C5": set(),
}


@pytest.fixture(scope="module")
def result():
    # The tester's PowerShell window started before Sysmon logged anything,
    # exactly like explorer.exe in the phase 1 sample: it becomes a placeholder.
    events = [e for step in STEPS.values() for e in step]
    return detect(events, RuleSet.load())


@pytest.mark.parametrize("step", sorted(EXPECTED))
def test_each_step_fires_what_the_guide_says(result, step):
    step_events = {id(e) for e in STEPS[step]}
    fired = {s.rule.name for s in result.signals if id(s.event) in step_events}
    assert fired == EXPECTED[step]


def test_part_c_raises_one_risk_incident_and_no_chain(result):
    assert [i.kind for i in result.incidents] == ["risk"]
    assert result.incidents[0].title.startswith(f"Risky activity on {HOST}")
