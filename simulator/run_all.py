"""
simulator/run_all.py
─────────────────────────────────────────────────────────────────────────────
Orchestrator — runs all simulators together and writes a combined JSONL log.

Useful for:
  • Generating a realistic mixed dataset for detection rule development.
  • Populating the backend database during development.
  • Smoke-testing that all simulators produce valid schema-conformant events.

Usage
─────
    # 200 events, 20% malicious, written to logs/mixed.jsonl
    python run_all.py

    # Custom counts
    python run_all.py --total 500 --malicious-ratio 0.3 --output logs/dataset.jsonl

    # Stdout pretty-print (small count for inspection)
    python run_all.py --total 20 --pretty --no-file

    # Reproducible run
    python run_all.py --seed 42 --total 100
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

from base import load_events_from_file, summarise_events
from powershell import PowerShellMacroSimulator
from wmi import WMIRemoteExecutionSimulator
from certutil import CertutilAbuseSimulator
from normal import NormalTrafficSimulator


# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_OUTPUT = Path(__file__).parent.parent / "logs" / "mixed_sim.jsonl"


def run(
    total: int = 200,
    malicious_ratio: float = 0.20,
    output: Path | None = None,
    pretty: bool = False,
    no_file: bool = False,
    seed: int | None = None,
) -> list[dict[str, Any]]:
    """Run all simulators and return the full event list.

    Parameters
    ----------
    total:
        Total number of events to generate.
    malicious_ratio:
        Fraction (0.0–1.0) of events that are malicious.
    output:
        Output ``.jsonl`` path.  Defaults to ``logs/mixed_sim.jsonl``.
    pretty:
        Pretty-print events to stdout (independent of file output).
    no_file:
        When *True*, suppress file output entirely.
    seed:
        RNG seed for full reproducibility across all simulators.

    Returns
    -------
    list[dict]
        All generated events (shuffled).
    """
    out_path: Path | None = None if no_file else (output or DEFAULT_OUTPUT)

    # ── Build malicious simulators ────────────────────────────────────────────
    mal_sims = [
        PowerShellMacroSimulator(seed=seed),
        PowerShellMacroSimulator(seed=(seed or 0) + 1),   # second instance for variety
        WMIRemoteExecutionSimulator(emit_initiator=False, seed=seed),
        WMIRemoteExecutionSimulator(emit_initiator=True,  seed=(seed or 0) + 2),
        CertutilAbuseSimulator(scenario="download",  seed=seed),
        CertutilAbuseSimulator(scenario="decode",    seed=(seed or 0) + 3),
        CertutilAbuseSimulator(scenario="chain",     seed=(seed or 0) + 4),
    ]

    # ── Generate mixed batch via NormalTrafficSimulator ───────────────────────
    baseline_sim = NormalTrafficSimulator(
        output_file=out_path,
        pretty=False,  # we'll handle pretty-print ourselves
        seed=seed,
    )

    # Temporarily disable file writes inside generate_mixed_batch
    # so we can pretty-print first, then write atomically.
    baseline_sim.output_file = None
    events = baseline_sim.generate_mixed_batch(
        count               = total,
        malicious_ratio     = malicious_ratio,
        malicious_generators= mal_sims,
    )

    # ── Output ────────────────────────────────────────────────────────────────
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        _info(f"Wrote {len(events)} events → {out_path}")

    if pretty:
        for ev in events:
            print(json.dumps(ev, indent=2, ensure_ascii=False))

    # ── Summary ───────────────────────────────────────────────────────────────
    summary = summarise_events(events)
    _print_summary(summary, malicious_ratio, total)

    return events


def _info(msg: str) -> None:
    print(f"\033[36m[INFO]\033[0m  {msg}", file=sys.stderr)


def _print_summary(
    summary: dict[str, Any],
    malicious_ratio: float,
    total: int,
) -> None:
    bar = "═" * 56
    print(f"\n\033[1m{bar}\033[0m", file=sys.stderr)
    print(f"\033[1m  Simulation Summary\033[0m", file=sys.stderr)
    print(f"\033[1m{bar}\033[0m", file=sys.stderr)
    print(f"  Total events      : {summary['total_events']}", file=sys.stderr)
    print(
        f"  Expected malicious: ~{int(total * malicious_ratio)} "
        f"({malicious_ratio:.0%})",
        file=sys.stderr,
    )
    print(f"\n  Events by source:", file=sys.stderr)
    for src, cnt in sorted(summary["by_source"].items(), key=lambda x: -x[1]):
        print(f"    {src:<35} {cnt:>4}", file=sys.stderr)
    print(f"\n  Events by severity:", file=sys.stderr)
    for sev, cnt in sorted(summary["by_severity"].items()):
        print(f"    {sev:<12} {cnt:>4}", file=sys.stderr)
    print(f"\n  Unique hosts : {len(summary['unique_hosts'])}", file=sys.stderr)
    print(f"  Unique users : {len(summary['unique_users'])}", file=sys.stderr)
    print(f"\033[1m{bar}\033[0m\n", file=sys.stderr)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run all simulators and generate a mixed event dataset.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--total", "-n", type=int, default=200,
        help="Total number of events to generate.",
    )
    parser.add_argument(
        "--malicious-ratio", "-m", type=float, default=0.20,
        help="Fraction of events that are malicious (0.0–1.0).",
    )
    parser.add_argument(
        "--output", "-o", type=str, default=None,
        help=f"Output .jsonl file path. Default: {DEFAULT_OUTPUT}",
    )
    parser.add_argument(
        "--no-file", action="store_true",
        help="Do not write to a file (stdout only).",
    )
    parser.add_argument(
        "--pretty", action="store_true",
        help="Pretty-print all events to stdout.",
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="RNG seed for reproducible output.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run(
        total           = args.total,
        malicious_ratio = args.malicious_ratio,
        output          = Path(args.output) if args.output else None,
        pretty          = args.pretty,
        no_file         = args.no_file,
        seed            = args.seed,
    )

