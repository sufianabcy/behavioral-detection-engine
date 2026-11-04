"""A Sigma rule: load it from YAML, check it, and test events against it.

A Sigma rule has three parts that matter to the engine:

* `logsource`: which events it is about (for example category
  `process_creation`, which here means Sysmon event 1);
* `detection`: named **search identifiers** (selections and filters), each a
  set of field tests, plus a `condition` that combines them;
* metadata: `title`, `level` (informational, low, medium, high, critical),
  `tags` (ATT&CK tactics and techniques), `falsepositives`.

We support the parts of Sigma 2.0 our rules need; anything else is refused
with a clear error instead of being silently ignored.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..attack import tactics_from_tags, techniques_from_tags
from ..event import SYSMON_CHANNEL, Event
from .condition import parse_condition
from .values import as_text, compile_test, wildcard_to_regex

LEVELS = ("informational", "low", "medium", "high", "critical")
POWERSHELL_CHANNEL = "Microsoft-Windows-PowerShell/Operational"

# Sigma logsource category -> the (channel, event ID) pairs it covers.
CATEGORIES: dict[str, tuple[tuple[str, int], ...]] = {
    "process_creation": ((SYSMON_CHANNEL, 1), ("Security", 4688)),
    "network_connection": ((SYSMON_CHANNEL, 3),),
    "process_termination": ((SYSMON_CHANNEL, 5),),
    "image_load": ((SYSMON_CHANNEL, 7),),
    "create_remote_thread": ((SYSMON_CHANNEL, 8),),
    "process_access": ((SYSMON_CHANNEL, 10),),
    "file_event": ((SYSMON_CHANNEL, 11),),
    "registry_add": ((SYSMON_CHANNEL, 12),),
    "registry_delete": ((SYSMON_CHANNEL, 12),),
    "registry_set": ((SYSMON_CHANNEL, 13),),
    "registry_rename": ((SYSMON_CHANNEL, 14),),
    "registry_event": ((SYSMON_CHANNEL, 12), (SYSMON_CHANNEL, 13), (SYSMON_CHANNEL, 14)),
    "pipe_created": ((SYSMON_CHANNEL, 17), (SYSMON_CHANNEL, 18)),
    "wmi_event": ((SYSMON_CHANNEL, 19), (SYSMON_CHANNEL, 20), (SYSMON_CHANNEL, 21)),
    "dns_query": ((SYSMON_CHANNEL, 22),),
    "file_delete": ((SYSMON_CHANNEL, 23), (SYSMON_CHANNEL, 26)),
    "ps_script": ((POWERSHELL_CHANNEL, 4104),),
}
SERVICES: dict[str, str] = {
    "security": "Security",
    "system": "System",
    "application": "Application",
    "sysmon": SYSMON_CHANNEL,
    "powershell": POWERSHELL_CHANNEL,
}

# Security event 4688 (process creation without Sysmon) uses other field names.
# Mapping them lets process_creation rules also run on Security-only logs.
SECURITY_4688_FIELDS = {"Image": "NewProcessName", "ParentImage": "ParentProcessName"}

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_NAME = re.compile(r"^[a-z0-9_]+$")


def field_value(event: Event, name: str) -> str | None:
    """The value Sigma sees for field `name` in `event` (None if missing)."""
    if name == "EventID":
        return str(event.event_id)
    if name == "Channel":
        return event.channel
    if name in ("Computer", "Hostname"):
        return event.host
    if name == "Provider_Name":  # System/Provider: which component wrote the event
        return event.meta.get("provider")
    value = event.data.get(name)
    if value is None and event.event_id == 4688 and event.channel == "Security":
        if name in SECURITY_4688_FIELDS:
            value = event.data.get(SECURITY_4688_FIELDS[name])
        elif name == "User" and event.data.get("SubjectUserName"):
            value = f"{event.data.get('SubjectDomainName', '')}\\{event.data['SubjectUserName']}"
    return value


Matcher = Callable[[Event], bool]


def compile_search(name: str, definition: Any) -> Matcher:
    """One search identifier (a selection or filter) -> a test on an event."""
    if isinstance(definition, dict):
        if not definition:
            raise ValueError(f"search {name!r} is empty")
        tests = []
        for key, raw in definition.items():
            field_name, *modifiers = str(key).split("|")
            values = raw if isinstance(raw, list) else [raw]
            if not values:
                raise ValueError(f"search {name!r}: field {field_name!r} has an empty list")
            test = compile_test(field_name, modifiers, values)
            tests.append((field_name, test))
        return lambda event: all(test(field_value(event, f)) for f, test in tests)
    if isinstance(definition, list) and definition and all(isinstance(d, dict) for d in definition):
        parts = [compile_search(name, d) for d in definition]  # a list of maps means "any of them"
        return lambda event: any(part(event) for part in parts)
    if isinstance(definition, list) and definition and all(not isinstance(d, (dict, list)) for d in definition):
        # Keywords: plain strings that may appear anywhere in the event.
        patterns = [re.compile(f".*{wildcard_to_regex(as_text(k))}.*", re.IGNORECASE | re.DOTALL) for k in definition]
        return lambda event: any(p.fullmatch(v) for p in patterns for v in event.data.values())
    raise ValueError(f"search {name!r} must be a map of fields, a list of maps, or a list of keywords")


@dataclass
class SigmaRule:
    title: str
    id: str
    name: str
    level: str
    logsource: dict[str, str]
    detection: dict[str, Any]
    status: str = "experimental"
    description: str = ""
    author: str = ""
    date: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    path: Path | None = None
    sources: tuple[tuple[str, int], ...] = ()  # (channel, event ID) pairs this rule looks at
    _match: Matcher | None = field(default=None, repr=False)

    @property
    def techniques(self) -> list[str]:
        return techniques_from_tags(self.tags)

    @property
    def tactics(self) -> list[str]:
        return tactics_from_tags(self.tags)

    def applies_to(self, event: Event) -> bool:
        return (event.channel, event.event_id) in self.sources or (
            # service-only rules (e.g. service: security) use (channel, 0) to mean "any event ID"
            (event.channel, 0) in self.sources
        )

    def matches(self, event: Event) -> bool:
        assert self._match is not None
        return self.applies_to(event) and self._match(event)

    @classmethod
    def from_dict(cls, data: dict[str, Any], path: Path | None = None) -> SigmaRule:
        where = path.name if path else "rule"
        for key in ("title", "id", "name", "level", "logsource", "detection"):
            if key not in data:
                raise ValueError(f"{where}: missing required field '{key}'")
        if not _UUID.match(str(data["id"])):
            raise ValueError(f"{where}: id must be a lowercase UUID")
        if not _NAME.match(str(data["name"])):
            raise ValueError(f"{where}: name must use only a-z, 0-9 and _")
        if data["level"] not in LEVELS:
            raise ValueError(f"{where}: level must be one of {', '.join(LEVELS)}")
        tags = [str(t) for t in data.get("tags", [])]
        if any(t != t.lower() for t in tags):
            raise ValueError(f"{where}: tags must be lowercase")
        rule = cls(
            title=str(data["title"]),
            id=str(data["id"]),
            name=str(data["name"]),
            level=str(data["level"]),
            logsource={str(k): str(v) for k, v in data["logsource"].items()},
            detection=dict(data["detection"]),
            status=str(data.get("status", "experimental")),
            description=" ".join(str(data.get("description", "")).split()),
            author=str(data.get("author", "")),
            date=str(data.get("date", "")),
            references=[str(r) for r in data.get("references", [])],
            tags=tags,
            falsepositives=[str(f) for f in data.get("falsepositives", [])],
            path=path,
        )
        rule.sources = _sources(rule.logsource, where)
        try:
            rule._match = _compile_detection(rule.detection)
        except ValueError as exc:
            raise ValueError(f"{where}: {exc}") from None
        return rule


def _sources(logsource: dict[str, str], where: str) -> tuple[tuple[str, int], ...]:
    product = logsource.get("product", "windows").lower()
    if product != "windows":
        raise ValueError(f"{where}: only product 'windows' is supported")
    category = logsource.get("category", "").lower()
    service = logsource.get("service", "").lower()
    if category:
        if category not in CATEGORIES:
            raise ValueError(f"{where}: unsupported logsource category {category!r}")
        return CATEGORIES[category]
    if service:
        if service not in SERVICES:
            raise ValueError(f"{where}: unsupported logsource service {service!r}")
        return ((SERVICES[service], 0),)
    raise ValueError(f"{where}: logsource needs a category or a service")


def _compile_detection(detection: dict[str, Any]) -> Matcher:
    conditions = detection.get("condition")
    if conditions is None:
        raise ValueError("detection has no condition")
    searches = {name: compile_search(name, d) for name, d in detection.items() if name not in ("condition", "timeframe")}
    if "timeframe" in detection:
        raise ValueError("'timeframe' belongs in correlation rules, not single-event rules")
    names = list(searches)
    parsed = [parse_condition(c, names) for c in (conditions if isinstance(conditions, list) else [conditions])]

    def match(event: Event) -> bool:
        cache: dict[str, bool] = {}

        def look(name: str) -> bool:
            if name not in cache:
                cache[name] = searches[name](event)
            return cache[name]

        return any(condition(look) for condition in parsed)  # several conditions mean "any of them"

    return match


def load_rule(path: Path) -> SigmaRule:
    with open(path, encoding="utf-8") as handle:
        documents = [d for d in yaml.safe_load_all(handle) if d is not None]
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise ValueError(f"{path.name}: expected exactly one rule (a YAML mapping)")
    return SigmaRule.from_dict(documents[0], path)


def load_rules(folder: Path) -> list[SigmaRule]:
    """Every *.yml rule under `folder`, sorted by file name. Names and IDs must be unique."""
    if not folder.is_dir():
        raise FileNotFoundError(f"no rules folder at {folder}")
    rules = [load_rule(path) for path in sorted(folder.rglob("*.yml"))]
    for attribute in ("name", "id"):
        seen: dict[str, Path | None] = {}
        for rule in rules:
            value = getattr(rule, attribute)
            if value in seen:
                raise ValueError(f"two rules share the {attribute} {value!r}")
            seen[value] = rule.path
    return rules
