"""Phase 7: run the engine over public recordings of real attacks.

Public datasets have no label on each event, so we can't count true and
false positives the way phase 5 does. What we can measure:

* that every file reads, and how many records the parser had to skip;
* what fired in each file, and which incidents were raised;
* when a file sits in a folder named after an ATT&CK technique (as in
  EVTX-to-MITRE-Attack: "TA0002-Execution/T1059.001-PowerShell/..."), whether
  a rule *for that technique* fired. That is the closest thing to recall that
  unlabelled recordings allow.

Folder names written before ATT&CK v19 use IDs that have since moved (the
"Clear Windows event logs" folder says T1070.001, which is T1685.005 now), so
labels are translated to v20 first; the report lists each translation.

A file whose technique none of our rules claims is **out of scope**: nothing
is expected to fire. If something does, it is either another step of the
same attack (attackers rarely do just one thing) or a false alarm, and a
person has to look at the events to tell which. `python -m bde tree <file>`
helps.

Each file is scanned on its own, because each recording is a separate lab.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .attack import current_technique, technique_name
from .engine import RuleSet, detect
from .readers import SUPPORTED_SUFFIXES, read_events

# "T1059.001-PowerShell", "T1098.xxx-Account manipulation", "..._t1098.evtx".
# The letters around it must not be part of a word, so "ID4688" doesn't count.
_TECHNIQUE = re.compile(r"(?<![A-Za-z0-9])[Tt](\d{4})(?:\.(\d{3}))?(?![0-9])")


def technique_label(path: Path, root: Path) -> str | None:
    """The ATT&CK technique a file's folders or name say it shows, or None.

    The folder closest to the file wins; the file name is tried last.
    """
    parts = path.relative_to(root).parts if path != root else (path.name,)
    for part in [*reversed(parts[:-1]), parts[-1]]:
        match = _TECHNIQUE.search(part)
        if match:
            return f"T{match.group(1)}" + (f".{match.group(2)}" if match.group(2) else "")
    return None


def technique_matches(label: str, technique: str) -> bool:
    """Does a rule tagged `technique` cover a recording labelled `label`?

    The same technique, or one is a sub-technique of the other: a rule tagged
    T1218 covers a T1218.011 recording, and a T1547.001 rule counts for a
    recording labelled only T1547.
    """
    return label == technique or label.startswith(technique + ".") or technique.startswith(label + ".")


@dataclass
class FileResult:
    path: Path
    label: str | None  # ATT&CK v20 technique from the folder or file name
    written: str | None = None  # the label as the folder writes it, if that's an older ID
    events: int = 0
    unreadable: int = 0  # damaged records the parser skipped
    error: str | None = None  # the whole file could not be read
    signals: Counter[str] = field(default_factory=Counter)  # rule name -> count
    techniques: set[str] = field(default_factory=set)  # techniques of the rules that fired
    incidents: list[str] = field(default_factory=list)

    def detected(self) -> bool:
        """Did a rule for the file's own technique fire?"""
        return self.label is not None and any(technique_matches(self.label, t) for t in self.techniques)


def find_files(folder: Path) -> list[Path]:
    if folder.is_file():
        return [folder]
    return sorted(p for p in folder.rglob("*") if p.is_file() and p.suffix.lower() in SUPPORTED_SUFFIXES)


def scan_file(path: Path, root: Path, rules: RuleSet) -> FileResult:
    written = technique_label(path, root)
    label = current_technique(written) if written else None
    result = FileResult(path, label, written if written != label else None)
    stats: dict[str, int] = {}
    try:
        events = list(read_events(path, stats))
    except (ValueError, RuntimeError, OSError) as exc:
        result.error = str(exc)
        return result
    result.events, result.unreadable = len(events), stats.get("unreadable", 0)
    detection = detect(events, rules)
    for signal in detection.signals:
        result.signals[signal.rule.name] += 1
        result.techniques.update(signal.rule.techniques)
    result.incidents = [incident.title for incident in detection.incidents]
    return result


def scan_folder(folder: Path, rules: RuleSet | None = None) -> list[FileResult]:
    rules = rules or RuleSet.load()
    root = folder if folder.is_dir() else folder.parent
    return [scan_file(path, root, rules) for path in find_files(folder)]


def claimed_techniques(rules: RuleSet) -> set[str]:
    """Every technique at least one Sigma rule is tagged with."""
    return {technique for rule in rules.sigma for technique in rule.techniques}


def in_scope(label: str, claimed: Iterable[str]) -> bool:
    return any(technique_matches(label, technique) for technique in claimed)


def format_report(results: list[FileResult], rules: RuleSet, root: Path, show_all: bool = False) -> list[str]:
    """Per-file lines (files that raised something, unless show_all) and a summary."""
    lines: list[str] = []
    for r in results:
        if not (show_all or r.signals or r.error or r.unreadable):
            continue
        name = r.path.relative_to(root).as_posix() if r.path != root else r.path.name
        if r.error:
            lines.append(f"{name}: could not read ({r.error})")
            continue
        extra = f", {r.unreadable} unreadable records" if r.unreadable else ""
        lines.append(f"{name}: {r.events} events{extra}, {sum(r.signals.values())} signals, "
                     f"{len(r.incidents)} incidents")
        lines += [f"    {count:4}  {rule}" for rule, count in r.signals.most_common(5)]
        lines += [f"    -> {title}" for title in r.incidents]

    read = [r for r in results if not r.error]
    flagged = [r for r in read if r.signals]
    with_incidents = [r for r in read if r.incidents]
    lines += [
        "",
        f"{len(results)} files, {sum(r.events for r in read):,} events; "
        f"{sum(r.unreadable for r in read)} unreadable records; {len(results) - len(read)} files could not be read.",
        f"{len(flagged)} files raised at least one signal; {sum(len(r.incidents) for r in read)} incidents "
        f"in {len(with_incidents)} files.",
    ]

    labelled = [r for r in read if r.label]
    if not labelled:
        lines.append("No file has an ATT&CK technique in its folder or file name, so there is no per-technique score.")
        return lines
    claimed = claimed_techniques(rules)
    scoped = [r for r in labelled if in_scope(r.label, claimed)]
    outside = [r for r in labelled if not in_scope(r.label, claimed)]
    detected = [r for r in scoped if r.detected()]
    share = f" ({len(detected) / len(scoped):.1%})" if scoped else ""
    lines += [
        "",
        f"{len(labelled)} files are labelled with an ATT&CK technique (in a folder or file name).",
    ]
    renamed: dict[tuple[str, str], int] = {}
    for r in labelled:
        if r.written:
            renamed[(r.written, r.label)] = renamed.get((r.written, r.label), 0) + 1
    if renamed:
        moves = ", ".join(f"{old} -> {new} ({count} files)" for (old, new), count in sorted(renamed.items()))
        lines.append(f"  Older ATT&CK IDs read as their v20 IDs: {moves}.")
    lines += [
        f"  In scope, a rule claims the technique: {len(scoped)} files, {len(detected)} detected by a rule "
        f"for that technique{share}",
    ]
    by_label: dict[str, list[FileResult]] = {}
    for r in scoped:
        by_label.setdefault(r.label, []).append(r)
    for label in sorted(by_label):
        group = by_label[label]
        hits = sum(r.detected() for r in group)
        name = technique_name(label)
        if name == label:  # not in bde/attack.py
            name = "(parent technique: several kinds)" if "." not in label else "(name not in bde/attack.py)"
        lines.append(f"    {label:<10} {len(group):3} files {hits:3} detected   {name}")
    noisy = [r for r in outside if r.signals]
    lines += [
        f"  Out of scope: {len(outside)} files; {len(noisy)} raised signals anyway. Each is another step of the",
        "  same attack or a false alarm: look at the events to tell which.",
    ]
    unlabelled = len(read) - len(labelled)
    if unlabelled:
        lines.append(f"{unlabelled} files have no technique in their folder or file name.")
    return lines
