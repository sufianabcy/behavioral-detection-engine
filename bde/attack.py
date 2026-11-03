"""MITRE ATT&CK reference data for the techniques this project touches.

Checked against ATT&CK v20 (October 2026). Two things changed recently that
older tutorials won't show:

* The **Defense Evasion** tactic no longer exists. ATT&CK split it into
  **Stealth** (TA0005: hiding and blending in) and **Defense Impairment**
  (TA0112: breaking security tools and logs).
* Some techniques moved to new IDs with that split. "Disable or Modify Tools"
  was T1562.001 and is now **T1685**; "Clear Windows Event Logs" was
  T1070.001 and is now **T1685.005**. The old ATT&CK pages redirect.

Sigma rules tag techniques as `attack.t1059.001` and tactics as
`attack.execution`; the helpers below read those tags.
"""

from __future__ import annotations

from collections.abc import Iterable

ATTACK_VERSION = "20"
ATTACK_URL = "https://attack.mitre.org"

# Tactic short name -> (ID, display name), in the matrix's left-to-right order.
TACTICS: dict[str, tuple[str, str]] = {
    "reconnaissance": ("TA0043", "Reconnaissance"),
    "resource-development": ("TA0042", "Resource Development"),
    "initial-access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege-escalation": ("TA0004", "Privilege Escalation"),
    "stealth": ("TA0005", "Stealth"),
    "defense-impairment": ("TA0112", "Defense Impairment"),
    "credential-access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "lateral-movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"),
    "command-and-control": ("TA0011", "Command and Control"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "impact": ("TA0040", "Impact"),
}

# Technique ID -> (name, tactics). Names are "Parent: Sub-technique" for sub-techniques.
TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1566.001": ("Phishing: Spearphishing Attachment", ("initial-access",)),
    "T1566.002": ("Phishing: Spearphishing Link", ("initial-access",)),
    "T1078.002": ("Valid Accounts: Domain Accounts", ("initial-access", "persistence", "privilege-escalation", "stealth")),
    "T1204.002": ("User Execution: Malicious File", ("execution",)),
    "T1059": ("Command and Scripting Interpreter", ("execution",)),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", ("execution",)),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", ("execution",)),
    "T1059.007": ("Command and Scripting Interpreter: JavaScript", ("execution",)),
    "T1047": ("Windows Management Instrumentation", ("execution",)),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", ("execution", "persistence", "privilege-escalation")),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                  ("persistence", "privilege-escalation")),
    "T1027.010": ("Obfuscated Files or Information: Command Obfuscation", ("stealth",)),
    "T1564.003": ("Hide Artifacts: Hidden Window", ("stealth",)),
    "T1140": ("Deobfuscate/Decode Files or Information", ("stealth",)),
    "T1197": ("BITS Jobs", ("execution", "persistence", "stealth")),
    "T1218": ("System Binary Proxy Execution", ("stealth",)),
    "T1218.005": ("System Binary Proxy Execution: Mshta", ("stealth",)),
    "T1218.010": ("System Binary Proxy Execution: Regsvr32", ("stealth",)),
    "T1218.011": ("System Binary Proxy Execution: Rundll32", ("stealth",)),
    "T1685": ("Disable or Modify Tools", ("defense-impairment",)),
    "T1685.005": ("Disable or Modify Tools: Clear Windows Event Logs", ("defense-impairment",)),
    "T1033": ("System Owner/User Discovery", ("discovery",)),
    "T1018": ("Remote System Discovery", ("discovery",)),
    "T1069.002": ("Permission Groups Discovery: Domain Groups", ("discovery",)),
    "T1482": ("Domain Trust Discovery", ("discovery",)),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", ("lateral-movement",)),
    "T1071.001": ("Application Layer Protocol: Web Protocols", ("command-and-control",)),
    "T1105": ("Ingress Tool Transfer", ("command-and-control",)),
    "T1490": ("Inhibit System Recovery", ("impact",)),
}


def technique_name(technique: str) -> str:
    return TECHNIQUES.get(technique, (technique, ()))[0]


def technique_tactics(technique: str) -> tuple[str, ...]:
    return TECHNIQUES.get(technique, ("", ()))[1]


def technique_url(technique: str) -> str:
    """T1059.001 -> https://attack.mitre.org/techniques/T1059/001/"""
    return f"{ATTACK_URL}/techniques/{technique.replace('.', '/')}/"


def tactic_name(tactic: str) -> str:
    return TACTICS.get(tactic, ("", tactic))[1]


def techniques_from_tags(tags: Iterable[str]) -> list[str]:
    """['attack.execution', 'attack.t1059.001'] -> ['T1059.001']"""
    found = []
    for tag in tags:
        tag = tag.lower()
        if tag.startswith("attack.t") and tag[8:9].isdigit():
            technique = tag[7:].upper()
            if technique not in found:
                found.append(technique)
    return found


def tactics_from_tags(tags: Iterable[str]) -> list[str]:
    """['attack.execution', 'attack.t1059.001'] -> ['execution']"""
    found = []
    for tag in tags:
        tag = tag.lower()
        if tag.startswith("attack.") and tag[7:] in TACTICS and tag[7:] not in found:
            found.append(tag[7:])
    return found


def tactic_order(tactic: str) -> int:
    return list(TACTICS).index(tactic) if tactic in TACTICS else len(TACTICS)


def sort_techniques(techniques: Iterable[str]) -> list[str]:
    """Order by the first tactic in the matrix (left to right), then by ID."""

    def key(technique: str) -> tuple[int, str]:
        tactics = technique_tactics(technique)
        return (min((tactic_order(t) for t in tactics), default=len(TACTICS)), technique)

    return sorted(set(techniques), key=key)


def sort_tactics(tactics: Iterable[str]) -> list[str]:
    return sorted(set(tactics), key=tactic_order)
