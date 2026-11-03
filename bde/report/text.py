"""Incidents as plain text, for the terminal."""

from __future__ import annotations

from collections import Counter

from ..attack import tactic_name
from ..engine import Detection
from .describe import describe_event, how_found, short_host, story, technique_label

MAX_STORY_LINES = 18


def _cut(text: str, width: int) -> str:
    text = " ".join(text.split())
    if width and len(text) > width:
        return text[: width - 3] + "..."
    return text


def render_incidents(result: Detection, width: int = 110, full: bool = False, mark: str = "*") -> list[str]:
    lines: list[str] = []
    hosts = {e.host for e in result.events}
    in_incidents = {id(s) for i in result.incidents for s in i.signals}
    lines.append(f"Read {len(result.events)} events from {len(hosts)} hosts.")
    lines.append(f"{len(result.signals)} signals from {len(result.rules.sigma)} Sigma rules; "
                 f"{len(result.incidents)} incident{'' if len(result.incidents) == 1 else 's'}.")
    lines.append("All times are UTC.")
    for incident in result.incidents:
        lines.append("")
        lines.append(f"{incident.id}  {incident.level.upper()}  {incident.title}")
        lines.append(f"  Hosts      {', '.join(short_host(h) for h in incident.hosts)}")
        lines.append(f"  Detected   {incident.detected_at:%H:%M:%S}   (first signal {incident.first_seen:%H:%M:%S}, "
                     f"last {incident.last_seen:%H:%M:%S})")
        lines.append(f"  Found by   {how_found(incident)}")
        lines.append(f"  Tactics    {', '.join(tactic_name(t) for t in incident.tactics)}")
        techniques = incident.techniques
        lines.append(f"  ATT&CK     {technique_label(techniques[0])}" if techniques else "  ATT&CK     -")
        for technique in techniques[1:]:
            lines.append(f"             {technique_label(technique)}")
        if incident.origin:
            origin = incident.origin
            where = short_host(origin.host) if origin.host else f"unknown computer {origin.source_ip}"
            via = f", via {origin.process.name}" if origin.process else ""
            lines.append(f"  Came from  {where} ({origin.source_ip}) as {origin.account}{via}, "
                         f"logon at {origin.logon.timestamp:%H:%M:%S}")
        if incident.related:
            lines.append(f"  Related    {', '.join(incident.related)}")
        if incident.steps:
            lines.append("  Steps")
            for match in incident.steps:
                tick = "+" if match.matched else "-"
                when = f"{match.satisfied_at:%H:%M:%S}" if match.satisfied_at else "--:--:--"
                lines.append(f"    {tick} {when}  {match.step.name}")
        lines.append("  Story")
        entries = story(incident, result.tree)
        shown = entries if full else entries[:MAX_STORY_LINES]
        for event, rules in shown:
            flag = f" {mark}" if rules else "  "
            text = f"{event.timestamp:%H:%M:%S}{flag} {short_host(event.host):<11} {describe_event(event)}"
            lines.append("    " + _cut(text, 0 if full else width - 4))
        if len(entries) > len(shown):
            lines.append(f"    ... and {len(entries) - len(shown)} more (use --full)")
        for note in incident.notes:
            lines.append(f"  Note: {note}")
    loose = [s for s in result.signals if id(s) not in in_incidents]
    lines.append("")
    if loose:
        counts = Counter(s.rule.name for s in loose)
        lines.append(f"{len(loose)} signals were not part of any incident (single suspicious events, often normal work):")
        for name, count in counts.most_common():
            lines.append(f"  {count:4}  {name}")
    lines.append(f"\nLines marked {mark} in a story triggered a Sigma rule.")
    return lines
