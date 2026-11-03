"""A self-contained HTML report: one file, no internet needed, opens in any browser.

Everything a reviewer needs to judge an incident is on the page: the steps
that matched, the story in time order, the process branch it happened in,
the ATT&CK techniques with links, and where the attacker came from.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from html import escape

from ..attack import ATTACK_VERSION, tactic_name, technique_name, technique_url
from ..correlation import Incident
from ..engine import Detection
from ..render import ASCII, render_branch
from .describe import describe_event, how_found, short_host, story

CSS = """
:root { --bg:#f7f7f5; --card:#ffffff; --ink:#1d1d1b; --muted:#5f5f5a; --line:#deded8; --accent:#2457a6;
  --critical:#a3122a; --high:#c24c0c; --medium:#8a6d00; --low:#3d6b35; --informational:#555; --hit:#fff4d6;
  --code:#f0f0ec; }
@media (prefers-color-scheme: dark) { :root { --bg:#151515; --card:#1f1f1f; --ink:#ecece8; --muted:#a6a6a0;
  --line:#383836; --accent:#8db4ff; --critical:#ff6b81; --high:#ff9a5c; --medium:#e0c341; --low:#8fd17e;
  --hit:#3a3220; --code:#262626; } }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
main { max-width:1100px; margin:0 auto; padding:24px 16px 64px; }
h1 { font-size:1.6rem; margin:0 0 4px; } h2 { margin:36px 0 12px; font-size:1.25rem; }
h3 { margin:0; font-size:1.05rem; }
.muted { color:var(--muted); }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-top:16px; }
.stat { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:12px 14px; }
.stat b { display:block; font-size:1.5rem; }
.incident { background:var(--card); border:1px solid var(--line); border-left:6px solid var(--line);
  border-radius:8px; padding:16px; margin:16px 0; }
.incident.critical { border-left-color:var(--critical); } .incident.high { border-left-color:var(--high); }
.badge { display:inline-block; font-size:.75rem; font-weight:700; letter-spacing:.04em; padding:2px 8px;
  border-radius:4px; color:#fff; margin-right:8px; vertical-align:2px; }
.badge.critical { background:var(--critical); } .badge.high { background:var(--high); }
.badge.medium { background:var(--medium); } .badge.low { background:var(--low); }
.badge.informational { background:var(--informational); }
dl { display:grid; grid-template-columns:max-content 1fr; gap:4px 16px; margin:12px 0; }
dt { color:var(--muted); } dd { margin:0; }
.chips a, .chips span { display:inline-block; border:1px solid var(--line); border-radius:999px; padding:1px 10px;
  margin:2px 4px 2px 0; text-decoration:none; color:var(--ink); font-size:.85rem; }
.chips a:hover { border-color:var(--accent); }
table { border-collapse:collapse; width:100%; font-size:.88rem; }
th, td { text-align:left; padding:5px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:600; }
tr.hit td { background:var(--hit); }
td.when, td.host { white-space:nowrap; font-variant-numeric:tabular-nums; }
td.what { word-break:break-word; }
code, pre { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.82rem; }
code { background:var(--code); padding:0 4px; border-radius:3px; }
pre { background:var(--code); padding:12px; border-radius:6px; overflow-x:auto; line-height:1.35; }
ul.steps { list-style:none; padding:0; margin:8px 0; } ul.steps li { margin:2px 0; }
.ok { color:var(--low); font-weight:700; } .miss { color:var(--muted); }
details { margin-top:10px; } summary { cursor:pointer; color:var(--accent); }
.note { border-left:3px solid var(--line); padding-left:10px; color:var(--muted); margin:6px 0; }
footer { margin-top:48px; color:var(--muted); font-size:.85rem; }
"""


def _chips_techniques(techniques: list[str]) -> str:
    return "".join(
        f'<a href="{technique_url(t)}" title="{escape(technique_name(t))}">{escape(t)} '
        f"{escape(technique_name(t))}</a>" for t in techniques
    )


def _incident_html(incident: Incident, result: Detection) -> str:
    parts = [f'<section class="incident {incident.level}" id="{incident.id}">',
             f'<h3><span class="badge {incident.level}">{incident.level.upper()}</span>'
             f"{escape(incident.id)} &middot; {escape(incident.title)}</h3>", "<dl>"]
    rows = [
        ("Hosts", ", ".join(escape(short_host(h)) for h in incident.hosts)),
        ("Detected", f"{incident.detected_at:%Y-%m-%d %H:%M:%S} UTC "
                     f'<span class="muted">(signals from {incident.first_seen:%H:%M:%S} to '
                     f"{incident.last_seen:%H:%M:%S})</span>"),
        ("Found by", escape(how_found(incident))),
        ("Tactics", '<span class="chips">' + "".join(f"<span>{escape(tactic_name(t))}</span>"
                                                     for t in incident.tactics) + "</span>"),
        ("ATT&amp;CK", f'<span class="chips">{_chips_techniques(incident.techniques)}</span>'),
    ]
    if incident.origin:
        origin = incident.origin
        where = escape(short_host(origin.host)) if origin.host else "an unknown computer"
        via = f", connection made by <code>{escape(origin.process.name)}</code>" if origin.process else ""
        rows.append(("Came from", f"{where} ({escape(origin.source_ip)}): {escape(origin.account)} logged on "
                                  f"at {origin.logon.timestamp:%H:%M:%S}{via}"))
    if incident.related:
        rows.append(("Related", ", ".join(f'<a href="#{r}">{r}</a>' for r in incident.related)))
    parts += [f"<dt>{name}</dt><dd>{value}</dd>" for name, value in rows]
    parts.append("</dl>")

    if incident.steps:
        parts.append("<ul class=steps>")
        for match in incident.steps:
            mark = '<span class="ok">&#10003;</span>' if match.matched else '<span class="miss">&#9675;</span>'
            when = f"{match.satisfied_at:%H:%M:%S}" if match.satisfied_at else "not seen"
            description = escape(match.step.description or match.step.name)
            parts.append(f"<li>{mark} <b>{escape(match.step.name)}</b> <span class=muted>({when})</span>: "
                         f"{description}</li>")
        parts.append("</ul>")
    for note in incident.notes:
        parts.append(f'<p class="note">{escape(note)}</p>')

    parts.append("<table><tr><th>Time (UTC)</th><th>Host</th><th>What happened</th><th>Rules</th></tr>")
    for event, rules in story(incident, result.tree):
        css = ' class="hit"' if rules else ""
        parts.append(f"<tr{css}><td class=when>{event.timestamp:%H:%M:%S.%f}"[:-3] + "</td>"
                     f"<td class=host>{escape(short_host(event.host))}</td><td class=what>{escape(describe_event(event))}</td>"
                     f"<td>{'<br>'.join(f'<code>{escape(r)}</code>' for r in rules)}</td></tr>")
    parts.append("</table>")

    branch_root = incident.root
    if branch_root is None:  # risk incidents: draw the branch of the highest-severity signal
        top = max(incident.signals, key=lambda s: (s.severity, -s.time.timestamp()))
        branch_root = result.tree.node_for(top.event)
    if branch_root is not None:
        marked = {id(n) for n in incident.processes(result.tree)}
        drawing = "\n".join(render_branch(branch_root, marked=marked, width=150, chars=ASCII))
        parts.append(f"<details><summary>Process branch</summary><pre>{escape(drawing)}</pre></details>")
    parts.append("</section>")
    return "\n".join(parts)


def render_html(result: Detection, title: str = "Detection report", source: str = "") -> str:
    events = result.events
    hosts = sorted({e.host for e in events}, key=str.lower)
    in_incidents = {id(s) for i in result.incidents for s in i.signals}
    loose = [s for s in result.signals if id(s) not in in_incidents]
    span = (f"{events[0].timestamp:%Y-%m-%d %H:%M} to {events[-1].timestamp:%H:%M} UTC" if events else "no events")
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [
        "<!doctype html><html lang=en><head><meta charset=utf-8>",
        '<meta name=viewport content="width=device-width, initial-scale=1">',
        f"<title>{escape(title)}</title><style>{CSS}</style></head><body><main>",
        f"<h1>{escape(title)}</h1>",
        f'<p class="muted">{escape(source)} &middot; {escape(span)} &middot; generated {generated} &middot; '
        f"MITRE ATT&amp;CK v{ATTACK_VERSION}</p>",
        '<div class="cards">',
        f'<div class="stat"><b>{len(events):,}</b>events</div>',
        f'<div class="stat"><b>{len(hosts)}</b>hosts</div>',
        f'<div class="stat"><b>{len(result.signals)}</b>signals</div>',
        f'<div class="stat"><b>{len(result.incidents)}</b>incidents</div>',
        "</div>",
        "<h2>Incidents</h2>",
    ]
    if not result.incidents:
        out.append("<p>No incidents.</p>")
    for incident in result.incidents:
        out.append(_incident_html(incident, result))

    out.append("<h2>Signals outside any incident</h2>")
    out.append('<p class="muted">Single suspicious events that no chain rule or risk score turned into an '
               "incident. Most are normal admin work that resembles one step of an attack.</p>")
    if loose:
        out.append("<table><tr><th>Time (UTC)</th><th>Host</th><th>Rule</th><th>Level</th><th>Event</th></tr>")
        for signal in loose:
            out.append(f"<tr><td class=when>{signal.time:%H:%M:%S}</td><td class=host>{escape(short_host(signal.host))}</td>"
                       f"<td><code>{escape(signal.rule.name)}</code></td><td>{signal.level}</td>"
                       f"<td class=what>{escape(describe_event(signal.event))}</td></tr>")
        out.append("</table>")
    else:
        out.append("<p>None.</p>")

    seen = Counter(t for i in result.incidents for t in i.techniques)
    out.append("<h2>ATT&amp;CK techniques in these incidents</h2>")
    if seen:
        out.append("<table><tr><th>Technique</th><th>Name</th><th>Incidents</th></tr>")
        for technique in sorted(seen):
            ids = ", ".join(i.id for i in result.incidents if technique in i.techniques)
            out.append(f'<tr><td><a href="{technique_url(technique)}">{technique}</a></td>'
                       f"<td>{escape(technique_name(technique))}</td><td>{ids}</td></tr>")
        out.append("</table>")
    out.append("<footer>Made by bde, the behavioral detection engine course project. Simulated data only: "
               "encoded commands decode to harmless text and every outside address is a reserved "
               "documentation address.</footer>")
    out.append("</main></body></html>")
    return "\n".join(out)
