"""
simulator/normal.py
─────────────────────────────────────────────────────────────────────────────
Generates realistic benign baseline traffic for false-positive testing.

Purpose
───────
A detection engine that only sees malicious events during development will
inevitably be over-tuned — every unusual-looking command will trigger an
alert.  This module provides a rich pool of day-to-day Windows activity so
that rules can be validated against a realistic mix of signal and noise.

Categories of benign activity simulated
────────────────────────────────────────
  • Software updates  (Windows Update, browser updates, package managers)
  • IT administration (Group Policy refresh, disk checks, antivirus scans)
  • Developer tools   (git, npm, pip, docker, VS Code helpers)
  • Office activity   (Word, Excel, Outlook opening documents)
  • Scheduled tasks   (backup agents, log rotators, health checks)
  • Network tools     (ping, tracert, nslookup, curl, wget — legitimate uses)
  • Certutil benign   (legitimate certificate operations — NOT downloading)
  • PowerShell benign (short, readable, non-encoded admin one-liners)

Usage
─────
    python normal.py --count 50 --pretty
    python normal.py --count 200 --output logs/baseline.jsonl
    python normal.py --count 20 --category it_admin --pretty
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).parent))
from base import EventGenerator


# ═════════════════════════════════════════════════════════════════════════════
# Benign event pools
# ═════════════════════════════════════════════════════════════════════════════

# ── Software / system updates ─────────────────────────────────────────────────
_UPDATE_EVENTS: list[dict] = [
    {
        "process": "wuauclt.exe",
        "parent" : "services.exe",
        "cmd"    : "wuauclt.exe /updatenow",
    },
    {
        "process": "MsMpEng.exe",
        "parent" : "services.exe",
        "cmd"    : "\"C:\\Program Files\\Windows Defender\\MsMpEng.exe\"",
    },
    {
        "process": "chrome.exe",
        "parent" : "GoogleUpdate.exe",
        "cmd"    : (
            "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" "
            "--update-if-newer"
        ),
    },
    {
        "process": "msiexec.exe",
        "parent" : "services.exe",
        "cmd"    : "msiexec.exe /i C:\\windows\\installer\\{patch}.msi /quiet /norestart",
    },
    {
        "process": "TrustedInstaller.exe",
        "parent" : "services.exe",
        "cmd"    : "C:\\windows\\servicing\\TrustedInstaller.exe",
    },
    {
        "process": "WaaSMedicAgent.exe",
        "parent" : "svchost.exe",
        "cmd"    : "WaaSMedicAgent.exe",
    },
]

# ── IT / sysadmin tasks ───────────────────────────────────────────────────────
_IT_ADMIN_EVENTS: list[dict] = [
    {
        "process": "gpupdate.exe",
        "parent" : "cmd.exe",
        "cmd"    : "gpupdate /force",
    },
    {
        "process": "chkdsk.exe",
        "parent" : "cmd.exe",
        "cmd"    : "chkdsk C: /f /r /x",
    },
    {
        "process": "sfc.exe",
        "parent" : "cmd.exe",
        "cmd"    : "sfc /scannow",
    },
    {
        "process": "dism.exe",
        "parent" : "cmd.exe",
        "cmd"    : "dism /Online /Cleanup-Image /RestoreHealth",
    },
    {
        "process": "net.exe",
        "parent" : "cmd.exe",
        "cmd"    : "net use \\\\fileserver\\share /persistent:yes",
    },
    {
        "process": "net.exe",
        "parent" : "cmd.exe",
        "cmd"    : "net localgroup administrators",
    },
    {
        "process": "eventvwr.exe",
        "parent" : "explorer.exe",
        "cmd"    : "eventvwr.exe",
    },
    {
        "process": "resmon.exe",
        "parent" : "taskmgr.exe",
        "cmd"    : "resmon.exe",
    },
    {
        "process": "powershell.exe",
        "parent" : "cmd.exe",
        "cmd"    : "powershell.exe Get-EventLog -LogName System -Newest 50",
    },
    {
        "process": "powershell.exe",
        "parent" : "explorer.exe",
        "cmd"    : "powershell.exe -Command \"Get-Service | Where-Object {$_.Status -eq 'Running'}\"",
    },
    {
        "process": "powershell.exe",
        "parent" : "cmd.exe",
        "cmd"    : "powershell.exe -Command \"Test-NetConnection -ComputerName dc01 -Port 445\"",
    },
    {
        "process": "wevtutil.exe",
        "parent" : "cmd.exe",
        "cmd"    : "wevtutil qe System /c:10 /f:text",
    },
]

# ── Developer workflow ────────────────────────────────────────────────────────
_DEV_EVENTS: list[dict] = [
    {
        "process": "git.exe",
        "parent" : "cmd.exe",
        "cmd"    : "git pull origin main",
    },
    {
        "process": "git.exe",
        "parent" : "cmd.exe",
        "cmd"    : "git commit -m \"fix: resolve merge conflict in auth module\"",
    },
    {
        "process": "node.exe",
        "parent" : "cmd.exe",
        "cmd"    : "node C:\\Users\\dev\\project\\server.js",
    },
    {
        "process": "npm.cmd",
        "parent" : "cmd.exe",
        "cmd"    : "npm install --save-dev eslint",
    },
    {
        "process": "python.exe",
        "parent" : "cmd.exe",
        "cmd"    : "python.exe -m pytest tests/ -v",
    },
    {
        "process": "pip.exe",
        "parent" : "cmd.exe",
        "cmd"    : "pip install requests --upgrade",
    },
    {
        "process": "docker.exe",
        "parent" : "cmd.exe",
        "cmd"    : "docker build -t my-app:latest .",
    },
    {
        "process": "Code.exe",
        "parent" : "explorer.exe",
        "cmd"    : "\"C:\\Program Files\\Microsoft VS Code\\Code.exe\" --new-window",
    },
    {
        "process": "java.exe",
        "parent" : "cmd.exe",
        "cmd"    : "java -jar C:\\tools\\jenkins\\jenkins.war --httpPort=8080",
    },
]

# ── Office / productivity ─────────────────────────────────────────────────────
_OFFICE_EVENTS: list[dict] = [
    {
        "process": "WINWORD.EXE",
        "parent" : "explorer.exe",
        "cmd"    : "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n",
    },
    {
        "process": "EXCEL.EXE",
        "parent" : "explorer.exe",
        "cmd"    : (
            "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE\" "
            "C:\\Users\\{user}\\Documents\\Q3_Report.xlsx"
        ),
    },
    {
        "process": "OUTLOOK.EXE",
        "parent" : "explorer.exe",
        "cmd"    : "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\"",
    },
    {
        "process": "Teams.exe",
        "parent" : "explorer.exe",
        "cmd"    : "\"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe\"",
    },
    {
        "process": "OneDrive.exe",
        "parent" : "explorer.exe",
        "cmd"    : "\"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background",
    },
    {
        "process": "acrobat.exe",
        "parent" : "explorer.exe",
        "cmd"    : (
            "\"C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe\" "
            "C:\\Users\\{user}\\Downloads\\invoice.pdf"
        ),
    },
]

# ── Scheduled tasks / background agents ──────────────────────────────────────
_SCHEDULED_EVENTS: list[dict] = [
    {
        "process": "schtasks.exe",
        "parent" : "taskeng.exe",
        "cmd"    : "schtasks /run /tn \"\\Microsoft\\Windows\\Defrag\\ScheduledDefrag\"",
    },
    {
        "process": "vssadmin.exe",
        "parent" : "taskeng.exe",
        "cmd"    : "vssadmin list shadows",
    },
    {
        "process": "robocopy.exe",
        "parent" : "taskeng.exe",
        "cmd"    : (
            "robocopy C:\\Users\\{user}\\Documents \\\\nas\\backup\\{user} "
            "/MIR /R:1 /W:1 /LOG:C:\\logs\\robocopy.log"
        ),
    },
    {
        "process": "defrag.exe",
        "parent" : "svchost.exe",
        "cmd"    : "defrag C: /U /V",
    },
    {
        "process": "cleanmgr.exe",
        "parent" : "taskeng.exe",
        "cmd"    : "cleanmgr /sagerun:1",
    },
]

# ── Network tools (legitimate) ────────────────────────────────────────────────
_NETWORK_EVENTS: list[dict] = [
    {
        "process": "ping.exe",
        "parent" : "cmd.exe",
        "cmd"    : "ping -n 4 8.8.8.8",
    },
    {
        "process": "nslookup.exe",
        "parent" : "cmd.exe",
        "cmd"    : "nslookup corp.internal",
    },
    {
        "process": "tracert.exe",
        "parent" : "cmd.exe",
        "cmd"    : "tracert -d 10.0.0.1",
    },
    {
        "process": "netstat.exe",
        "parent" : "cmd.exe",
        "cmd"    : "netstat -ano",
    },
    {
        "process": "curl.exe",
        "parent" : "cmd.exe",
        "cmd"    : "curl -s https://api.github.com/repos/owner/repo/releases/latest",
    },
    {
        "process": "ssh.exe",
        "parent" : "cmd.exe",
        "cmd"    : "ssh -i C:\\Users\\{user}\\.ssh\\id_rsa user@internal-server.corp",
    },
]

# ── Certutil — legitimate certificate operations ──────────────────────────────
_CERTUTIL_BENIGN_EVENTS: list[dict] = [
    {
        "process": "certutil.exe",
        "parent" : "cmd.exe",
        "cmd"    : "certutil -store My",
    },
    {
        "process": "certutil.exe",
        "parent" : "cmd.exe",
        "cmd"    : "certutil -dump C:\\Users\\{user}\\Desktop\\cert.cer",
    },
    {
        "process": "certutil.exe",
        "parent" : "cmd.exe",
        "cmd"    : "certutil -verify -urlfetch C:\\Users\\{user}\\Documents\\server.crt",
    },
    {
        "process": "certutil.exe",
        "parent" : "mmc.exe",
        "cmd"    : "certutil -setreg chain\\ChainCacheResyncFiletime @now",
    },
    {
        "process": "certutil.exe",
        "parent" : "cmd.exe",
        "cmd"    : "certutil -addstore Root C:\\cacerts\\internal-ca.crt",
    },
]


# ── Category registry ─────────────────────────────────────────────────────────
_CATEGORY_MAP: dict[str, list[dict]] = {
    "software_update": _UPDATE_EVENTS,
    "it_admin"       : _IT_ADMIN_EVENTS,
    "developer"      : _DEV_EVENTS,
    "office"         : _OFFICE_EVENTS,
    "scheduled_task" : _SCHEDULED_EVENTS,
    "network"        : _NETWORK_EVENTS,
    "certutil_benign": _CERTUTIL_BENIGN_EVENTS,
}

_ALL_EVENTS: list[dict] = [ev for pool in _CATEGORY_MAP.values() for ev in pool]


# ─────────────────────────────────────────────────────────────────────────────
# NormalTrafficSimulator
# ─────────────────────────────────────────────────────────────────────────────

class NormalTrafficSimulator(EventGenerator):
    """Generates realistic benign Windows process events for baseline testing.

    Parameters
    ----------
    category:
        Restrict output to a specific activity category, or ``"all"`` (default)
        to draw from the full pool.  Valid values:
        ``software_update``, ``it_admin``, ``developer``, ``office``,
        ``scheduled_task``, ``network``, ``certutil_benign``.
    weight_malicious_lookalikes:
        When *True* (default), events that share binaries with attack
        simulations (``certutil.exe``, ``powershell.exe``) are slightly
        over-represented, making the baseline harder to separate from noise.
    **kwargs:
        Forwarded to :class:`~base.EventGenerator`.
    """

    SOURCE = "normal_traffic"

    def __init__(
        self,
        category: str = "all",
        weight_malicious_lookalikes: bool = True,
        **kwargs: Any,
    ) -> None:
        kwargs.setdefault("source", self.SOURCE)
        super().__init__(**kwargs)

        if category != "all" and category not in _CATEGORY_MAP:
            raise ValueError(
                f"Invalid category '{category}'. "
                f"Valid options: all, {', '.join(_CATEGORY_MAP)}"
            )
        self._category = category
        self._weight_lookalikes = weight_malicious_lookalikes
        self._pool = self._build_pool()

    # ── Pool construction ─────────────────────────────────────────────────────

    def _build_pool(self) -> list[dict]:
        if self._category != "all":
            pool = _CATEGORY_MAP[self._category][:]
        else:
            pool = _ALL_EVENTS[:]

        if self._weight_lookalikes and self._category == "all":
            # Double the weight of certutil benign + powershell admin events
            # so the engine must learn to discriminate, not just block the binary.
            lookalikes = [
                ev for ev in pool
                if ev["process"] in ("certutil.exe", "powershell.exe")
            ]
            pool.extend(lookalikes)  # duplicate for higher sampling probability
        return pool

    # ── Core generator ────────────────────────────────────────────────────────

    def generate_event(self) -> dict[str, Any]:
        template = self._choice(self._pool)
        user     = self._choice(self.users)

        # Interpolate {user} placeholder if present
        cmd = template["cmd"].replace("{user}", user).replace(
            "{patch}", self._randhex(8).upper()
        )

        return self._base_event(
            process        = template["process"],
            parent_process = template["parent"],
            command        = cmd,
            user           = user,
            severity       = "info",
            tags           = ["baseline", "benign", self._category if self._category != "all" else "mixed"],
            extra          = {
                "activity_category": self._resolve_category(template),
                "is_baseline"      : True,
                "detection_note"   : (
                    "This event is intentionally benign. A well-tuned detection "
                    "rule should NOT fire on this event."
                ),
            },
        )

    def _resolve_category(self, template: dict) -> str:
        """Look up which category pool a template belongs to."""
        for cat, pool in _CATEGORY_MAP.items():
            if template in pool:
                return cat
        return "unknown"

    # ── Convenience: mixed scenario ───────────────────────────────────────────

    def generate_mixed_batch(
        self,
        count: int = 50,
        malicious_ratio: float = 0.15,
        malicious_generators: list[EventGenerator] | None = None,
    ) -> list[dict[str, Any]]:
        """Return a realistic mixed batch of benign and malicious events.

        Parameters
        ----------
        count:
            Total number of events.
        malicious_ratio:
            Fraction of events that should be malicious (0.0 – 1.0).
        malicious_generators:
            List of malicious :class:`~base.EventGenerator` instances to
            sample from.  Falls back to benign-only when *None*.

        Returns
        -------
        list[dict]
            Shuffled list of mixed events.
        """
        n_bad  = int(count * malicious_ratio)
        n_good = count - n_bad

        events: list[dict[str, Any]] = [self.generate_event() for _ in range(n_good)]

        if malicious_generators and n_bad:
            for i in range(n_bad):
                gen = self._choice(malicious_generators)
                events.append(gen.generate_event())

        self._rng.shuffle(events)
        return events


# ── CLI entry point ───────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate benign baseline traffic for false-positive testing.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--count", "-n", type=int, default=20)
    parser.add_argument(
        "--category",
        choices=["all"] + list(_CATEGORY_MAP.keys()),
        default="all",
        help="Restrict events to a specific activity category.",
    )
    parser.add_argument("--output", "-o", type=str, default=None)
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--seed", type=int, default=None)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    sim = NormalTrafficSimulator(
        category    = args.category,
        output_file = args.output,
        pretty      = args.pretty,
        seed        = args.seed,
    )
    sim.emit_batch(args.count)


if __name__ == "__main__":
    main()

