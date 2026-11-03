"""Incidents as JSON, for other tools (or a SIEM) to read."""

from __future__ import annotations

import json

from ..attack import technique_name
from ..engine import Detection
from ..event import format_time
from .describe import describe_event


def incidents_json(result: Detection) -> str:
    items = []
    for incident in result.incidents:
        items.append({
            "id": incident.id,
            "kind": incident.kind,
            "rule": incident.rule_name,
            "title": incident.title,
            "level": incident.level,
            "hosts": incident.hosts,
            "detected_at": format_time(incident.detected_at),
            "first_seen": format_time(incident.first_seen),
            "last_seen": format_time(incident.last_seen),
            "score": round(incident.score, 1) if incident.score is not None else None,
            "tactics": incident.tactics,
            "techniques": [{"id": t, "name": technique_name(t)} for t in incident.techniques],
            "steps": [{"name": m.step.name, "matched": m.matched,
                       "at": format_time(m.satisfied_at) if m.satisfied_at else None} for m in incident.steps],
            "origin": None if incident.origin is None else {
                "host": incident.origin.host, "source_ip": incident.origin.source_ip,
                "account": incident.origin.account, "logon_at": format_time(incident.origin.logon.timestamp),
                "process": incident.origin.process.name if incident.origin.process else None,
            },
            "related": incident.related,
            "notes": incident.notes,
            "signals": [{"time": format_time(s.time), "host": s.host, "rule": s.rule.name, "level": s.level,
                         "event": describe_event(s.event)} for s in incident.signals],
        })
    return json.dumps({"incidents": items}, indent=2, ensure_ascii=False) + "\n"
