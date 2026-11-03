"""Rebuild process trees from Sysmon events.

Every Sysmon process-create event (ID 1) names the new process and its
parent, each by a ProcessGuid. Linking each child to its parent by GUID
rebuilds the tree of "who started what" on each host.

Other Sysmon events that carry a ProcessGuid (network, file, registry, DNS)
are attached to the process that caused them, as its `activity`.

Why GUIDs and not PIDs? Windows reuses process IDs: once a process exits,
its PID can be handed to a brand-new, unrelated process. Linking by PID can
therefore attach a child to the wrong parent. Sysmon's ProcessGuid is unique
for every process start, so it can't collide that way.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from .event import Event, host_matches, windows_basename

# Sysmon event IDs that describe something a process did, and a short label
# for each. Process create (1) is handled separately: it builds the tree.
ACTIVITY_LABELS: dict[int, str] = {3: "net", 11: "file", 12: "reg", 13: "reg", 14: "reg", 22: "dns"}


@dataclass(eq=False)
class ProcessNode:
    """One process on one host."""

    host: str
    guid: str
    image: str = ""  # full path of the executable
    command_line: str = ""
    pid: int | None = None
    user: str = ""
    start: datetime | None = None  # None if we never saw it start
    seen_start: bool = False  # True once we have its own process-create event
    creation: Event | None = None  # that process-create event, for later rules
    parent: ProcessNode | None = None
    children: list[ProcessNode] = field(default_factory=list)
    activity: list[Event] = field(default_factory=list)  # net, file, reg, dns...

    @property
    def name(self) -> str:
        """Executable file name, e.g. 'powershell.exe'."""
        return windows_basename(self.image) or "<unknown process>"

    def first_seen(self) -> datetime | None:
        """Earliest time we know this process existed (for sorting)."""
        times = [self.start] if self.start else []
        times += [event.timestamp for event in self.activity[:1]]
        times += [t for t in (child.first_seen() for child in self.children[:1]) if t]
        return min(times) if times else None


def ancestry(node: ProcessNode) -> list[ProcessNode]:
    """The parents of `node`, nearest first: [parent, grandparent, ...]."""
    chain: list[ProcessNode] = []
    current = node.parent
    while current is not None and current not in chain:  # guard against bad data loops
        chain.append(current)
        current = current.parent
    return chain


def has_ancestor(node: ProcessNode, image_names: Iterable[str], max_depth: int | None = None) -> bool:
    """Return True if a parent, grandparent, ... of `node` has one of `image_names`.

    Rules:
      * compare file names, not full paths: each ancestor's `.name`;
      * ignore upper/lower case: "WINWORD.EXE" matches "winword.exe"
        (Windows file names are case-insensitive);
      * the node itself does not count, only its ancestors;
      * when max_depth is given, look at most that many levels up
        (max_depth=1 means the parent only).

    Phase 4 uses this to ask "is there an Office program anywhere above this
    PowerShell?", which still works when cmd.exe sits in between.
    """
    # Read image_names exactly once, into a set: it may be a generator, which
    # can only be looped over once, and set lookups are fast.
    wanted = {name.casefold() for name in image_names}
    parents = ancestry(node)
    if max_depth is not None:
        parents = parents[:max_depth]
    return any(parent.name.casefold() in wanted for parent in parents)


def is_same_or_descendant(node: ProcessNode, ancestor: ProcessNode) -> bool:
    """True if `node` is `ancestor` itself or was started (directly or not) by it."""
    return node is ancestor or ancestor in ancestry(node)


def lineage(node: ProcessNode) -> list[ProcessNode]:
    """The chain from the oldest known ancestor down to `node`, oldest first."""
    return list(reversed(ancestry(node))) + [node]


def _to_int(text: str) -> int | None:
    text = (text or "").strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


class ProcessTree:
    """All the process trees found in a set of events, across hosts."""

    def __init__(self) -> None:
        self._nodes: dict[tuple[str, str], ProcessNode] = {}
        self.events_used = 0  # Sysmon events with a ProcessGuid
        self.events_skipped = 0  # everything else (e.g. Security-log logons)

    @classmethod
    def from_events(cls, events: Iterable[Event]) -> ProcessTree:
        tree = cls()
        for event in sorted(events, key=lambda e: e.timestamp):  # oldest first
            tree.add(event)
        return tree

    # --- building -----------------------------------------------------------

    def add(self, event: Event) -> None:
        if not event.is_sysmon or event.process_guid is None:
            self.events_skipped += 1
            return
        self.events_used += 1
        if event.event_id == 1:
            self._add_process(event)
        else:
            node = self._get_or_create(event.host, event.process_guid, event.get("Image"))
            node.activity.append(event)

    def _get_or_create(self, host: str, guid: str, image: str = "", pid: int | None = None) -> ProcessNode:
        key = (host.lower(), guid)
        node = self._nodes.get(key)
        if node is None:
            node = ProcessNode(host=host, guid=guid, image=image, pid=pid)
            self._nodes[key] = node
        else:
            node.image = node.image or image
            node.pid = node.pid if node.pid is not None else pid
        return node

    def _add_process(self, event: Event) -> None:
        guid = event.process_guid
        assert guid is not None
        node = self._get_or_create(event.host, guid)
        node.image = event.get("Image") or node.image
        node.command_line = event.get("CommandLine")
        node.pid = _to_int(event.get("ProcessId"))
        node.user = event.get("User")
        node.start = event.timestamp
        node.seen_start = True
        node.creation = event

        parent_guid = event.parent_guid
        if parent_guid is None or parent_guid == guid or node.parent is not None:
            return
        # The parent may have started before the log began, so we may never
        # see its own creation event. The child's event still tells us its
        # image, PID and command line, so we create a placeholder from those.
        parent = self._get_or_create(
            event.host, parent_guid, event.get("ParentImage"), _to_int(event.get("ParentProcessId"))
        )
        parent.command_line = parent.command_line or event.get("ParentCommandLine")
        parent.user = parent.user or event.get("ParentUser")  # newer Sysmon versions only
        if parent is not node and node not in ancestry(parent):
            node.parent = parent
            parent.children.append(node)

    # --- querying -----------------------------------------------------------

    def get(self, host: str, guid: str | None) -> ProcessNode | None:
        """The process with this ProcessGuid on this host, if we know it."""
        if not guid:
            return None
        return self._nodes.get((host.lower(), guid.lower()))

    def node_for(self, event: Event) -> ProcessNode | None:
        """The process that caused `event` (None for non-Sysmon events)."""
        return self.get(event.host, event.process_guid)

    def nodes(self, host: str | None = None) -> list[ProcessNode]:
        found = [n for n in self._nodes.values() if host is None or host_matches(n.host, host)]
        return sorted(found, key=_sort_key)

    def hosts(self) -> list[str]:
        return sorted({node.host for node in self._nodes.values()}, key=str.lower)

    def roots(self, host: str | None = None) -> list[ProcessNode]:
        """Processes with no known parent: the tops of the trees."""
        return [node for node in self.nodes(host) if node.parent is None]

    def find(self, text: str, host: str | None = None) -> list[ProcessNode]:
        """Processes whose image or command line contains `text` (any case)."""
        needle = text.casefold()
        return [
            node
            for node in self.nodes(host)
            if needle in node.image.casefold() or needle in node.command_line.casefold()
        ]


def _sort_key(node: ProcessNode) -> tuple[bool, datetime | str]:
    seen = node.first_seen()
    return (seen is None, seen or node.guid)
