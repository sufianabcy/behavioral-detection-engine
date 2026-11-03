"""Everything the generator names: programs, users, network addresses, payloads.

Safety rules, enforced by tests/test_generator.py:

* Every encoded PowerShell command decodes to a harmless string: the attack
  stage-2 is literally `Write-Output 'SIMULATED-STAGE-2'`.
* "Internet" addresses come only from the three ranges RFC 5737 reserves for
  documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which are
  never routed on the real internet. Domains end in .example (RFC 2606).
* Internal addresses are private 10.x addresses.
"""

from __future__ import annotations

import base64
import hashlib

DOMAIN = "corp.example"
NETBIOS = "CORP"
DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"

SYSTEM_USER = "NT AUTHORITY\\SYSTEM"
NETWORK_SERVICE = "NT AUTHORITY\\NETWORK SERVICE"
LOCAL_SERVICE = "NT AUTHORITY\\LOCAL SERVICE"

# --- inert payloads --------------------------------------------------------


def encode_powershell(script: str) -> str:
    """What `powershell -EncodedCommand` expects: Base64 of UTF-16LE text."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def decode_powershell(blob: str) -> str:
    return base64.b64decode(blob).decode("utf-16-le")


STAGE2_SCRIPT = "Write-Output 'SIMULATED-STAGE-2'"
STAGE2_B64 = encode_powershell(STAGE2_SCRIPT)

# A real remote-management agent would send something like this, encoded.
RMM_SCRIPT = "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version"
RMM_B64 = encode_powershell(RMM_SCRIPT)

SAFE_DECODED_SCRIPTS = (STAGE2_SCRIPT, RMM_SCRIPT)

# --- network ----------------------------------------------------------------

DC_IP = "10.20.0.10"
MAIL_HOST, MAIL_IP = "mail.corp.example", "10.20.0.30"
INTRANET_HOST, INTRANET_IP = "intranet.corp.example", "10.20.0.40"

# Benign "internet" sites: all in 192.0.2.0/24.
BENIGN_SITES = [
    ("www.news.example", "192.0.2.15"),
    ("docs.vendor.example", "192.0.2.21"),
    ("search.example", "192.0.2.33"),
    ("video.stream.example", "192.0.2.47"),
    ("shop.example", "192.0.2.58"),
]
TEAMS_SITE = ("teams.collab.example", "192.0.2.70")
UPDATE_SITE = ("update.os-vendor.example", "192.0.2.80")
CRL_SITE = ("crl.pki-vendor.example", "192.0.2.90")
RMM_SITE = ("agent.rmm-vendor.example", "192.0.2.100")

# Attacker infrastructure: 203.0.113.0/24 and 198.51.100.0/24 only.
C2_DOMAINS = ["cdn.update-check.example", "static.files-cdn.example", "telemetry.app-metrics.example"]
C2_NETWORK_A = "203.0.113."  # chain 1 and 3 (HTTPS C2)
C2_NETWORK_B = "198.51.100."  # chain 2 (payload host)

DOCUMENTATION_NETWORKS = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")

# --- programs ---------------------------------------------------------------
# name -> (full path, OriginalFileName, Description)

_SYS32 = "C:\\Windows\\System32\\"
_OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16\\"

BINARIES: dict[str, tuple[str, str, str]] = {
    "System": ("System", "", ""),
    "smss.exe": (_SYS32 + "smss.exe", "smss.exe", "Windows Session Manager"),
    "services.exe": (_SYS32 + "services.exe", "services.exe", "Services and Controller app"),
    "winlogon.exe": (_SYS32 + "winlogon.exe", "WINLOGON.EXE", "Windows Logon Application"),
    "userinit.exe": (_SYS32 + "userinit.exe", "USERINIT.EXE", "Userinit Logon Application"),
    "svchost.exe": (_SYS32 + "svchost.exe", "svchost.exe", "Host Process for Windows Services"),
    "explorer.exe": ("C:\\Windows\\explorer.exe", "EXPLORER.EXE", "Windows Explorer"),
    "WmiPrvSE.exe": (_SYS32 + "wbem\\WmiPrvSE.exe", "Wmiprvse.exe", "WMI Provider Host"),
    "powershell.exe": (
        _SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
        "PowerShell.EXE",
        "Windows PowerShell",
    ),
    "cmd.exe": (_SYS32 + "cmd.exe", "Cmd.Exe", "Windows Command Processor"),
    "wscript.exe": (_SYS32 + "wscript.exe", "wscript.exe", "Microsoft \u00ae Windows Based Script Host"),
    "certutil.exe": (_SYS32 + "certutil.exe", "CertUtil.exe", "CertUtil.exe"),
    "rundll32.exe": (_SYS32 + "rundll32.exe", "RUNDLL32.EXE", "Windows host process (Rundll32)"),
    "regsvr32.exe": (_SYS32 + "regsvr32.exe", "REGSVR32.EXE", "Microsoft(C) Register Server"),
    "bitsadmin.exe": (_SYS32 + "bitsadmin.exe", "bitsadmin.exe", "BITS administration utility"),
    "schtasks.exe": (_SYS32 + "schtasks.exe", "schtasks.exe", "Task Scheduler Configuration Tool"),
    "whoami.exe": (_SYS32 + "whoami.exe", "whoami.exe", "whoami - displays logged on user information"),
    "net.exe": (_SYS32 + "net.exe", "net.exe", "Net Command"),
    "net1.exe": (_SYS32 + "net1.exe", "net1.exe", "Net Command"),
    "nltest.exe": (_SYS32 + "nltest.exe", "nltestrk.exe", "Microsoft\u00ae Logon Server Test Utility"),
    "ipconfig.exe": (_SYS32 + "ipconfig.exe", "ipconfig.exe", "IP Configuration Utility"),
    "gpupdate.exe": (_SYS32 + "gpupdate.exe", "GPUpdate.exe", "Microsoft\u00ae Windows\u00ae Group Policy Update Utility"),
    "vssadmin.exe": (_SYS32 + "vssadmin.exe", "VSSADMIN.EXE", "Command Line Interface for Microsoft\u00ae Volume Shadow Copy Service"),
    "wbadmin.exe": (_SYS32 + "wbadmin.exe", "WBADMIN.EXE", "Command Line Interface for Microsoft\u00ae BLB Backup"),
    "bcdedit.exe": (_SYS32 + "bcdedit.exe", "bcdedit.exe", "Boot Configuration Data Editor"),
    "wevtutil.exe": (_SYS32 + "wevtutil.exe", "wevtutil.exe", "Eventing Command Line Utility"),
    "robocopy.exe": (_SYS32 + "Robocopy.exe", "robocopy.exe", "Microsoft Robocopy"),
    "notepad.exe": (_SYS32 + "notepad.exe", "NOTEPAD.EXE", "Notepad"),
    "mstsc.exe": (_SYS32 + "mstsc.exe", "mstsc.exe", "Remote Desktop Connection"),
    "mmc.exe": (_SYS32 + "mmc.exe", "MMC.EXE", "Microsoft Management Console"),
    "taskhostw.exe": (_SYS32 + "taskhostw.exe", "taskhostw.exe", "Host Process for Windows Tasks"),
    "splwow64.exe": ("C:\\Windows\\splwow64.exe", "splwow64.exe", "Print driver host for applications"),
    "WINWORD.EXE": (_OFFICE + "WINWORD.EXE", "WinWord.exe", "Microsoft Word"),
    "EXCEL.EXE": (_OFFICE + "EXCEL.EXE", "Excel.exe", "Microsoft Excel"),
    "OUTLOOK.EXE": (_OFFICE + "OUTLOOK.EXE", "Outlook.exe", "Microsoft Outlook"),
    "msedge.exe": (
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "msedge.exe",
        "Microsoft Edge",
    ),
    "ms-teams.exe": (
        "C:\\Program Files\\WindowsApps\\MSTeams_8wekyb3d8bbwe\\ms-teams.exe",
        "ms-teams.exe",
        "Microsoft Teams",
    ),
    "OneDrive.exe": (
        "C:\\Users\\Public\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",  # real path is per user
        "OneDrive.exe",
        "Microsoft OneDrive",
    ),
    "rmm-agent.exe": (
        "C:\\Program Files\\ExampleRMM\\rmm-agent.exe",
        "rmm-agent.exe",
        "ExampleRMM remote management agent",
    ),
}


def binary(name: str) -> tuple[str, str, str]:
    return BINARIES[name]


def fake_hash(image: str) -> str:
    """A stand-in for Sysmon's Hashes field. Not the hash of any real file."""
    return "SHA256=" + hashlib.sha256(f"bde-simulated:{image.lower()}".encode("utf-8")).hexdigest().upper()


# --- people -----------------------------------------------------------------
# sAMAccountName -> relative ID in the domain SID

USER_RIDS: dict[str, int] = {
    "jsmith": 1104,
    "adavis": 1105,
    "mlopez": 1106,
    "kchen": 1107,
    "rpatel": 1108,
    "tnguyen": 1109,
    "bokafor": 1110,
    "lsilva": 1111,
    "adm-adavis": 1201,
    "adm-rpatel": 1202,
    "svc_backup": 1301,
}


def user_sid(sam: str) -> str:
    return f"{DOMAIN_SID}-{USER_RIDS.get(sam, 1500)}"


def qualified(sam: str) -> str:
    """'jsmith' -> 'CORP\\jsmith' (how Sysmon writes the User field)."""
    return sam if "\\" in sam else f"{NETBIOS}\\{sam}"
