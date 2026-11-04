"""Command line for bde. Run `python -m bde --help` from the project folder.

  python -m bde demo                              the whole thing, end to end
  python -m bde detect   FILE_OR_FOLDER [--out DIR]   find incidents in logs
  python -m bde generate -o OUT.jsonl [--seed N]  make simulated, labelled logs
  python -m bde evaluate [--seeds 1-20]           precision, recall, soak test
  python -m bde rules                             list the detection rules
  python -m bde mapping  [-o FILE]                regenerate the ATT&CK mapping doc
  python -m bde navigator [-o FILE]               ATT&CK Navigator coverage layer
  python -m bde stats    FILE_OR_FOLDER           what is in a log
  python -m bde tree     FILE_OR_FOLDER [opts]    draw the process trees
  python -m bde convert  FILE_OR_FOLDER -o OUT.jsonl
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .event import format_time
from .paths import ROOT
from .readers import read_events, write_jsonl
from .render import pick_charset, render
from .tree import ProcessTree

DEMO_SEED = 7


def cmd_stats(args: argparse.Namespace) -> int:
    events = list(read_events(args.input))
    print(f"Input:  {args.input}")
    if not events:
        print("No events found.")
        return 0
    first = min(e.timestamp for e in events)
    last = max(e.timestamp for e in events)
    hosts = Counter(e.host for e in events)
    print(f"Events: {len(events)}   Hosts: {len(hosts)}")
    print(f"Time range (UTC): {first:%Y-%m-%d %H:%M:%S} to {last:%Y-%m-%d %H:%M:%S}")
    print("\nEvents by type")
    by_type = Counter((e.channel, e.event_id, e.name) for e in events)
    for (channel, event_id, name), count in by_type.most_common():
        source = "Sysmon" if channel.endswith("Sysmon/Operational") else channel or "?"
        print(f"  {count:6}  {source} {event_id:<5} {name}")
    print("\nEvents by host")
    for host, count in hosts.most_common():
        print(f"  {count:6}  {host or '?'}")
    return 0


def cmd_tree(args: argparse.Namespace) -> int:
    tree = ProcessTree.from_events(read_events(args.input))
    chars = pick_charset(sys.stdout, force_ascii=args.ascii)
    lines = render(tree, host=args.host, match=args.match, width=0 if args.full else args.width, chars=chars)
    if not lines:
        if tree.events_used == 0:
            print("No Sysmon events with a ProcessGuid found, so there is no tree to draw.")
            print("Run `python -m bde stats` on the same input to see what it contains.")
        else:
            print("Nothing matched.")
        return 0
    print("All times are UTC.\n")
    print("\n".join(lines).rstrip())
    skipped = tree.events_skipped
    print(f"\n{tree.events_used} Sysmon events used, {skipped} other event{'' if skipped == 1 else 's'} skipped.")
    return 0


def cmd_convert(args: argparse.Namespace) -> int:
    args.output.parent.mkdir(parents=True, exist_ok=True)
    count = write_jsonl(read_events(args.input), args.output)
    print(f"Wrote {count} events to {args.output}")
    return 0


# --- phase 2: generate ---------------------------------------------------------


def parse_chains(text: str) -> tuple[str, ...]:
    """'seen', 'unseen', 'all', 'none', or a list like '1,2,3u'."""
    from .generator import CHAIN_TITLES, SEEN_CHAINS, UNSEEN_CHAINS

    text = text.strip().lower()
    named = {"seen": SEEN_CHAINS, "unseen": UNSEEN_CHAINS, "all": SEEN_CHAINS + UNSEEN_CHAINS, "none": ()}
    if text in named:
        return named[text]
    chains = []
    for part in (p.strip() for p in text.split(",") if p.strip()):
        name = part if part.startswith("chain-") else f"chain-{part}"
        if name not in CHAIN_TITLES:
            raise argparse.ArgumentTypeError(f"unknown chain {part!r}; use 1, 2, 3, 4, 1u, 2u, 3u, seen, unseen, all or none")
        chains.append(name)
    return tuple(chains)


def parse_seeds(text: str) -> list[int]:
    """'1-20', '3', or '1,5,9'."""
    seeds: list[int] = []
    try:
        for part in text.split(","):
            if "-" in part.strip()[1:]:
                low, high = part.split("-", 1)
                seeds += list(range(int(low), int(high) + 1))
            else:
                seeds.append(int(part))
    except ValueError:
        raise argparse.ArgumentTypeError(f"bad seeds {text!r}: use a number, a range like 1-20, or a list like 1,5,9")
    if not seeds:
        raise argparse.ArgumentTypeError("no seeds given")
    return seeds


def _print_instances(scenario) -> None:  # noqa: ANN001
    print("\nGround truth (what the simulation did; the engine never sees these labels):")
    if not scenario.instances:
        print("  no attacks: normal activity only")
    for instance in scenario.instances:
        hosts = " -> ".join(h.split(".")[0] for h in instance.hosts)
        print(f"  {instance.id:<11} {instance.start:%H:%M:%S}  {hosts:<24} {instance.title}")


def cmd_generate(args: argparse.Namespace) -> int:
    from .generator import ScenarioConfig, generate

    config = ScenarioConfig(seed=args.seed, hours=args.hours, workstations=args.workstations, chains=args.chains,
                            twins=not args.no_twins, background=args.background)
    scenario = generate(config)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    count = write_jsonl(scenario.events, args.output)
    malicious = sum(1 for e in scenario.events if e.meta.get("label") == "malicious")
    print(f"Wrote {count} events ({malicious} malicious) from {len(scenario.hosts)} hosts to {args.output}")
    print(f"Seed {config.seed}, {config.hours:g} hours from {format_time(config.start)}")
    # The same seed and options give a byte-identical file on every computer.
    # Compare this fingerprint across machines to prove it.
    print(f"SHA-256 {file_sha256(args.output)}")
    _print_instances(scenario)
    return 0


def file_sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- phases 3 and 4: detect ----------------------------------------------------------


def write_outputs(result, folder: Path, title: str, source: str) -> list[Path]:  # noqa: ANN001
    from .report.html import render_html
    from .report.jsonout import incidents_json
    from .report.navigator import dumps, incidents_layer

    folder.mkdir(parents=True, exist_ok=True)
    files = {
        "report.html": render_html(result, title=title, source=source),
        "incidents.json": incidents_json(result),
        "incidents-layer.json": dumps(incidents_layer(result.incidents)),
    }
    written = []
    for name, text in files.items():
        path = folder / name
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        written.append(path)
    return written


def cmd_detect(args: argparse.Namespace) -> int:
    from .engine import detect
    from .report.text import render_incidents

    result = detect(read_events(args.input))
    mark = "*" if pick_charset(sys.stdout, force_ascii=args.ascii).get("arrow") == "->" else "\u25cf"
    print("\n".join(render_incidents(result, width=0 if args.full else args.width, full=args.full, mark=mark)))
    if args.out:
        written = write_outputs(result, args.out, f"Detection report: {args.input.name}", str(args.input))
        print("\nWrote " + ", ".join(str(p) for p in written))
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    from .engine import RuleSet

    rules = RuleSet.load()
    print(f"{len(rules.sigma)} Sigma rules (rules/sigma), all valid:\n")
    for rule in sorted(rules.sigma, key=lambda r: (-["informational", "low", "medium", "high", "critical"].index(r.level), r.name)):
        print(f"  {rule.level:<8} {rule.name:<40} {', '.join(rule.techniques)}")
    print(f"\n{len(rules.chains)} chain rules (rules/chains):\n")
    for chain in rules.chains:
        steps = " -> ".join(step.name for step in chain.steps)
        print(f"  {chain.level:<8} {chain.name}\n           {steps}  (needs {chain.min_steps}, within {chain.timespan})")
    risk = rules.risk
    print(f"\nRisk scoring (rules/risk.yml): threshold {risk.threshold:g}, half-life {risk.half_life}, "
          f"window {risk.window}, +{risk.tactic_bonus:g} per extra tactic")
    return 0


# --- phase 5: evaluate --------------------------------------------------------------


def cmd_evaluate(args: argparse.Namespace) -> int:
    from .engine import RuleSet
    from .evaluate import format_report, run_evaluation, run_soak

    rules = RuleSet.load()
    if args.external:
        return _scan_external(args.external, rules, args.all_files)
    scores = run_evaluation(args.seeds, hours=args.hours, workstations=args.workstations,
                            unseen=not args.no_unseen, rules=rules)
    soak = run_soak(hours=args.soak_hours, rules=rules) if args.soak_hours > 0 else None
    print("\n".join(format_report(scores, soak)))
    return 0


def _scan_external(folder: Path, rules, show_all: bool = False) -> int:  # noqa: ANN001
    """Public recordings have no per-event labels: report what fired, file by file (phase 7)."""
    from .external import format_report, scan_folder
    from .readers import evtx_backend

    if not folder.exists():
        raise FileNotFoundError(f"no such file or folder: {folder}")
    results = scan_folder(folder, rules)
    if not results:
        print(f"No .evtx, .xml or .jsonl files under {folder}")
        return 0
    if any(r.path.suffix.lower() == ".evtx" for r in results):
        print(f"Reading .evtx files with {evtx_backend()}.\n")
    root = folder if folder.is_dir() else folder.parent
    print("\n".join(format_report(results, rules, root, show_all)))
    return 0


# --- phase 6: mapping, navigator, demo ------------------------------------------------


def cmd_mapping(args: argparse.Namespace) -> int:
    from .report.mapping import render_mapping

    text = render_mapping()
    if args.check:
        current = args.output.read_text(encoding="utf-8") if args.output.exists() else ""
        if current != text:
            print(f"{args.output} is out of date. Run: python -m bde mapping")
            return 1
        print(f"{args.output} is up to date.")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    print(f"Wrote {args.output}")
    return 0


def cmd_navigator(args: argparse.Namespace) -> int:
    from .engine import RuleSet
    from .report.mapping import build_coverage, mapping_run
    from .report.navigator import coverage_layer, dumps

    rules = RuleSet.load()
    scenario, result = mapping_run(rules)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dumps(coverage_layer(build_coverage(rules, scenario, result))))
    print(f"Wrote {args.output}. Load it at https://mitre-attack.github.io/attack-navigator/ "
          "(Open Existing Layer > Upload from local).")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from .engine import RuleSet, detect
    from .evaluate import score_run
    from .generator import CHAIN_TITLES, SEEN_CHAINS, ScenarioConfig, generate
    from .report.mapping import build_coverage, mapping_run
    from .report.navigator import coverage_layer, dumps
    from .report.text import render_incidents

    print("bde demo: simulated LOLBin attacks in a small company network\n")
    print("1. Simulating 3 hours of normal work on 8 computers, with these attacks hidden in it:")
    for chain in SEEN_CHAINS:
        print(f"     {chain}: {CHAIN_TITLES[chain]}")
    scenario = generate(ScenarioConfig(seed=args.seed, chains=SEEN_CHAINS))
    args.out.mkdir(parents=True, exist_ok=True)
    events_file = args.out / "demo-events.jsonl"
    write_jsonl(scenario.events, events_file)
    malicious = sum(1 for e in scenario.events if e.meta.get("label") == "malicious")
    print(f"   {len(scenario.events)} events written to {events_file} ({malicious} of them are the attacks).")

    print("\n2. Running the engine: Sigma rules -> signals -> chain rules, risk scoring, cross-host links.\n")
    rules = RuleSet.load()
    result = detect(read_events(events_file), rules)  # read back from disk, like any other log
    mark = "*" if pick_charset(sys.stdout, force_ascii=args.ascii).get("arrow") == "->" else "\u25cf"
    print("\n".join(render_incidents(result, width=args.width, mark=mark)))

    print("\n3. Scorecard against the ground truth:")
    score = score_run(scenario, detect(scenario.events, rules))
    for instance in score.instances:
        if instance.detected_by:
            print(f"   DETECTED  {instance.id:<10} by {', '.join(instance.detected_by)}, "
                  f"{instance.time_to_detect.total_seconds():.1f} s after its first process started")
        else:
            print(f"   MISSED    {instance.id}")
    detected = sum(1 for i in score.instances if i.detected_by)
    false = score.incidents - score.true_incidents
    print(f"   {detected} of {len(score.instances)} attack chains detected; {false} false alarm"
          f"{'' if false == 1 else 's'}.")

    written = write_outputs(result, args.out, "bde demo report", f"simulated data, seed {args.seed}")
    scenario_all, result_all = mapping_run(rules)
    layer = args.out / "coverage-layer.json"
    with open(layer, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(dumps(coverage_layer(build_coverage(rules, scenario_all, result_all))))
    print("\n4. Files written:")
    for path in [*written, layer]:
        print(f"   {path}")
    print(f"\nOpen {args.out / 'report.html'} in a browser for the full report.")
    return 0 if detected >= 3 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m bde",
                                     description="Behavioral detection engine for living-off-the-land attacks.")
    parser.add_argument("--version", action="version", version=f"bde {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    stats = commands.add_parser("stats", help="count events by type and host")
    stats.add_argument("input", type=Path, help=".evtx, .xml or .jsonl file, or a folder of them")
    stats.set_defaults(func=cmd_stats)

    tree = commands.add_parser("tree", help="draw the process trees")
    tree.add_argument("input", type=Path, help=".evtx, .xml or .jsonl file, or a folder of them")
    tree.add_argument("--host", help="only this host")
    tree.add_argument("--match", metavar="TEXT", help="only branches with a process whose name or command line contains TEXT")
    tree.add_argument("--width", type=int, default=110, help="cut command lines to this many characters (default 110)")
    tree.add_argument("--full", action="store_true", help="never cut command lines")
    tree.add_argument("--ascii", action="store_true", help="draw with plain ASCII characters")
    tree.set_defaults(func=cmd_tree)

    convert = commands.add_parser("convert", help="normalize any input into our JSONL format")
    convert.add_argument("input", type=Path, help=".evtx, .xml or .jsonl file, or a folder of them")
    convert.add_argument("-o", "--output", type=Path, required=True, help="the .jsonl file to write")
    convert.set_defaults(func=cmd_convert)

    generate = commands.add_parser("generate", help="make simulated, labelled Sysmon logs (phase 2)")
    generate.add_argument("-o", "--output", type=Path, default=Path("out/scenario.jsonl"),
                          help="the .jsonl file to write (default out/scenario.jsonl)")
    generate.add_argument("--seed", type=int, default=DEMO_SEED, help=f"random seed (default {DEMO_SEED})")
    generate.add_argument("--hours", type=float, default=3.0, help="how many hours to simulate (default 3)")
    generate.add_argument("--workstations", type=int, default=5, help="3 to 8 workstations (default 5)")
    generate.add_argument("--chains", type=parse_chains, default=parse_chains("seen"),
                          help="which attacks: seen (default), unseen, all, none, or a list like 1,2,3u")
    generate.add_argument("--no-twins", action="store_true", help="leave out the benign look-alikes")
    generate.add_argument("--background", type=float, default=1.0,
                          help="normal-activity level: 0 none, 1 normal (default), 2 twice as busy")
    generate.set_defaults(func=cmd_generate)

    detect = commands.add_parser("detect", help="find incidents in logs (phases 3 and 4)")
    detect.add_argument("input", type=Path, help=".evtx, .xml or .jsonl file, or a folder of them")
    detect.add_argument("--out", type=Path, help="also write report.html, incidents.json and a Navigator layer here")
    detect.add_argument("--width", type=int, default=110, help="cut long lines to this many characters")
    detect.add_argument("--full", action="store_true", help="show every story line, uncut")
    detect.add_argument("--ascii", action="store_true", help="plain ASCII output")
    detect.set_defaults(func=cmd_detect)

    rules = commands.add_parser("rules", help="list (and validate) the detection rules")
    rules.set_defaults(func=cmd_rules)

    evaluate = commands.add_parser("evaluate", help="precision, recall and a soak test on generated data (phase 5)")
    evaluate.add_argument("--seeds", type=parse_seeds, default=parse_seeds("1-20"),
                          help="scenarios to generate: a range like 1-20 (default), or a list like 1,5,9")
    evaluate.add_argument("--hours", type=float, default=3.0, help="hours per scenario (default 3)")
    evaluate.add_argument("--workstations", type=int, default=5, help="workstations per scenario (default 5)")
    evaluate.add_argument("--no-unseen", action="store_true", help="skip the unseen attack variants")
    evaluate.add_argument("--soak-hours", type=float, default=24.0,
                          help="hours of normal-only activity for the soak test (default 24; 0 to skip)")
    evaluate.add_argument("--external", type=Path, metavar="FOLDER",
                          help="instead, run on downloaded public recordings and report what fired (phase 7)")
    evaluate.add_argument("--all-files", action="store_true",
                          help="with --external, list every file, not only those that raised something")
    evaluate.set_defaults(func=cmd_evaluate)

    mapping = commands.add_parser("mapping", help="regenerate the ATT&CK mapping document (phase 6)")
    mapping.add_argument("-o", "--output", type=Path, default=ROOT / "docs" / "attack-mapping.md",
                         help="where to write it (default: docs/attack-mapping.md in the project)")
    mapping.add_argument("--check", action="store_true", help="only check that the file is up to date")
    mapping.set_defaults(func=cmd_mapping)

    navigator = commands.add_parser("navigator", help="write an ATT&CK Navigator layer of rule coverage")
    navigator.add_argument("-o", "--output", type=Path, default=Path("out/coverage-layer.json"))
    navigator.set_defaults(func=cmd_navigator)

    demo = commands.add_parser("demo", help="the end-to-end demo: simulate, detect, score, report")
    demo.add_argument("--out", type=Path, default=Path("out/demo"), help="where to write the files (default out/demo)")
    demo.add_argument("--seed", type=int, default=DEMO_SEED, help=f"random seed (default {DEMO_SEED})")
    demo.add_argument("--width", type=int, default=110, help="cut long lines to this many characters")
    demo.add_argument("--ascii", action="store_true", help="plain ASCII output")
    demo.set_defaults(func=cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    # Command lines in logs can hold characters the terminal can't show;
    # replace those instead of crashing (matters mostly on Windows).
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
