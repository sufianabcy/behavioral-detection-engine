"""Draw process trees as text, like the `tree` command draws folders.

    WKSTN-07.corp.example  (6 processes)
    └── explorer.exe  [pid 4012]  started before the log began
        └── OUTLOOK.EXE  [pid 5004]  09:02:11  CORP\\jsmith
            │     "C:\\Program Files\\...\\OUTLOOK.EXE"
            └── WINWORD.EXE  [pid 5120]  09:14:02  CORP\\jsmith
                      "C:\\Program Files\\...\\WINWORD.EXE" /n "...Invoice_Q3.docm"
"""

from __future__ import annotations

from typing import TextIO

from .event import Event, host_matches
from .tree import ACTIVITY_LABELS, ProcessNode, ProcessTree, ancestry

UNICODE = {"tee": "├── ", "last": "└── ", "pipe": "│   ", "gap": "    ", "arrow": "→", "more": "…"}
ASCII = {"tee": "|-- ", "last": "`-- ", "pipe": "|   ", "gap": "    ", "arrow": "->", "more": "..."}

MAX_ACTIVITY_LINES = 8


def pick_charset(stream: TextIO, force_ascii: bool = False) -> dict[str, str]:
    """Use box-drawing characters only if the output can show them.

    A Mac terminal can. On Windows, output redirected to a file may use a
    legacy code page that has no box-drawing characters, so fall back to ASCII.
    """
    if force_ascii:
        return ASCII
    try:
        "".join(UNICODE.values()).encode(getattr(stream, "encoding", None) or "ascii")
    except (UnicodeEncodeError, LookupError):
        return ASCII
    return UNICODE


def _shorten(text: str, width: int, chars: dict[str, str]) -> str:
    """Fit text into `width` characters by cutting out the middle.

    Both ends of a command line or path usually matter: the start says what
    runs ("powershell.exe -nop -w hidden -enc"), the end says on what
    ("...Invoice_Q3.docm"). So we keep both ends and drop the middle.
    """
    text = " ".join(text.split())  # one line, single spaces
    if not width or len(text) <= width:
        return text
    room = max(width - len(chars["more"]), 2)
    head = (room * 3) // 5
    return text[:head] + chars["more"] + text[len(text) - (room - head):]


def describe_activity(event: Event, chars: dict[str, str]) -> str:
    """One-line summary of a network, file, registry or DNS event."""
    arrow = chars["arrow"]
    if event.event_id == 3:
        outbound = event.get("Initiated").lower() == "true"
        target = f"{event.get('DestinationIp')}:{event.get('DestinationPort')}"
        source = f"{event.get('SourceIp')}:{event.get('SourcePort')}"
        text = f"{event.get('Protocol') or 'conn'} {arrow} {target}" if outbound else f"{event.get('Protocol') or 'conn'} {source} {arrow} here"
        hostname = event.get("DestinationHostname")
        return f"{text} ({hostname})" if outbound and hostname and hostname != "-" else text
    if event.event_id == 11:
        return event.get("TargetFilename")
    if event.event_id in (12, 13, 14):
        return event.get("TargetObject")  # the value written (Details) gets its own line
    if event.event_id == 22:
        results = [part.replace("::ffff:", "") for part in event.get("QueryResults").split(";") if part.strip()]
        return f"{event.get('QueryName')} {arrow} {', '.join(results) or 'no answer'}"
    return event.name


def render(
    tree: ProcessTree,
    *,
    host: str | None = None,
    match: str | None = None,
    width: int = 110,
    chars: dict[str, str] = UNICODE,
) -> list[str]:
    """Return the drawing as a list of lines."""
    lines: list[str] = []
    for host_name in tree.hosts():
        if host and not host_matches(host_name, host):
            continue
        nodes = tree.nodes(host_name)
        matched: set[int] = set()
        visible: set[int] | None = None  # None means "show everything"
        if match:
            hits = tree.find(match, host_name)
            if not hits:
                continue
            matched = {id(node) for node in hits}
            visible = set()
            for node in hits:  # show each hit with its parents and its children
                visible.update(id(n) for n in [node, *ancestry(node), *_descendants(node)])
        lines.append(f"{host_name}  ({len(nodes)} processes)")
        roots = [root for root in tree.roots(host_name) if visible is None or id(root) in visible]
        for index, root in enumerate(roots):
            _draw(root, "", index == len(roots) - 1, lines, visible, matched, width, chars)
        lines.append("")
    return lines


def _descendants(node: ProcessNode) -> list[ProcessNode]:
    found: list[ProcessNode] = []
    stack = list(node.children)
    while stack:
        child = stack.pop()
        found.append(child)
        stack.extend(child.children)
    return found


def _draw(
    node: ProcessNode,
    prefix: str,
    is_last: bool,
    lines: list[str],
    visible: set[int] | None,
    matched: set[int],
    width: int,
    chars: dict[str, str],
) -> None:
    header = f"{node.name}  [pid {node.pid if node.pid is not None else '?'}]"
    if node.seen_start and node.start:
        header += f"  {node.start:%H:%M:%S}"
        if node.user:
            header += f"  {node.user}"
    else:
        header += "  started before the log began"
    if id(node) in matched:
        header += "   <== match"
    lines.append(prefix + (chars["last"] if is_last else chars["tee"]) + header)

    children = [c for c in node.children if visible is None or id(c) in visible]
    child_prefix = prefix + (chars["gap"] if is_last else chars["pipe"])
    detail_prefix = child_prefix + (chars["pipe"] if children else chars["gap"]) + "  "

    if node.command_line:
        lines.append(detail_prefix + _shorten(node.command_line, width, chars))
    shown = [e for e in node.activity if e.event_id in ACTIVITY_LABELS]
    for event in shown[:MAX_ACTIVITY_LINES]:
        label = ACTIVITY_LABELS[event.event_id]
        summary = _shorten(describe_activity(event, chars), width, chars)
        lines.append(f"{detail_prefix}{event.timestamp:%H:%M:%S}  {label:<4} {summary}")
        if event.event_id == 13 and event.get("Details"):
            lines.append(f"{detail_prefix}{'':15}= {_shorten(event.get('Details'), width, chars)}")
    if len(shown) > MAX_ACTIVITY_LINES:
        lines.append(f"{detail_prefix}{chars['more']} and {len(shown) - MAX_ACTIVITY_LINES} more")

    for index, child in enumerate(children):
        _draw(child, child_prefix, index == len(children) - 1, lines, visible, matched, width, chars)


def render_branch(
    node: ProcessNode,
    *,
    parents: int = 2,
    marked: set[int] | None = None,
    width: int = 110,
    chars: dict[str, str] = UNICODE,
) -> list[str]:
    """Draw one branch: `parents` levels above `node`, then everything below it.

    Used by the incident reports to show where an attack sat in the tree.
    Nodes whose id() is in `marked` get the "<== match" marker.
    """
    above = ancestry(node)[:parents]
    visible = {id(n) for n in [node, *above, *_descendants(node)]}
    top = above[-1] if above else node
    lines: list[str] = []
    _draw(top, "", True, lines, visible, marked or set(), width, chars)
    return lines
