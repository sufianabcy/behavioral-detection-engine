"""One-line, human descriptions of events and incidents, shared by every output."""

from __future__ import annotations

from ..attack import technique_name
from ..correlation import Incident
from ..event import Event, windows_basename
from ..tree import ProcessTree

LOGON_TYPES = {"2": "interactive", "3": "network", "7": "unlock", "10": "remote desktop", "5": "service"}


def short_host(host: str) -> str:
    return host.split(".", 1)[0] if host else "?"


def describe_event(event: Event) -> str:
    """'powershell.exe connects to 203.0.113.9:443 (cdn.update-check.example)' and so on."""
    image = windows_basename(event.get("Image")) or "?"
    if event.is_sysmon:
        if event.event_id == 1:
            parent = windows_basename(event.get("ParentImage")) or "?"
            return f"{parent} starts {image}: {' '.join(event.get('CommandLine').split())}"
        if event.event_id == 3:
            if event.get("Initiated").lower() == "true":
                name = event.get("DestinationHostname")
                where = f"{event.get('DestinationIp')}:{event.get('DestinationPort')}"
                return f"{image} connects to {where}" + (f" ({name})" if name and name != "-" else "")
            return f"{image} accepts a connection from {event.get('SourceIp')} on port {event.get('DestinationPort')}"
        if event.event_id == 11:
            return f"{image} writes {event.get('TargetFilename')}"
        if event.event_id in (12, 13, 14):
            details = event.get("Details")
            return f"{image} sets {event.get('TargetObject')}" + (f" = {details}" if details else "")
        if event.event_id == 22:
            answer = event.get("QueryResults").replace("::ffff:", "").strip(";")
            return f"{image} looks up {event.get('QueryName')}" + (f" -> {answer}" if answer else "")
    if event.channel == "Security":
        if event.event_id == 4624:
            kind = LOGON_TYPES.get(event.get("LogonType"), f"type {event.get('LogonType')}")
            source = event.get("IpAddress")
            origin = f" from {source}" if source and source not in ("-", "127.0.0.1", "::1") else ""
            return f"{kind} logon by {event.get('TargetDomainName')}\\{event.get('TargetUserName')}{origin}"
        if event.event_id == 1102:
            return f"Security log cleared by {event.get('SubjectDomainName')}\\{event.get('SubjectUserName')}"
        if event.event_id == 4688:
            return f"starts {windows_basename(event.get('NewProcessName'))}: {event.get('CommandLine')}"
    return event.name


def technique_label(technique: str) -> str:
    return f"{technique} {technique_name(technique)}"


def how_found(incident: Incident) -> str:
    if incident.kind == "chain":
        return f"chain rule {incident.rule_name}: {incident.matched_steps} of {len(incident.steps)} steps matched"
    return f"risk scoring: score {incident.score:.0f}"


def story(incident: Incident, tree: ProcessTree) -> list[tuple[Event, list[str]]]:
    """The incident's evidence events in time order, each with the rules it triggered."""
    fired: dict[int, list[str]] = {}
    for signal in incident.signals:
        fired.setdefault(id(signal.event), []).append(signal.rule.name)
    return [(event, fired.get(id(event), [])) for event in incident.evidence_events(tree)]
