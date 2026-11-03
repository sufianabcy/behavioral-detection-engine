# Phase 6: The deliverables

The course asks for three things. This is where each one lives:

| Brief | Deliverable | Command |
| --- | --- | --- |
| A detection engine or script | `bde/` and `rules/`, run as `python -m bde detect <logs>` | `python -m bde detect out/s.jsonl --out out/report` |
| An ATT&CK technique mapping document | [docs/attack-mapping.md](attack-mapping.md), generated from the rules, plus an ATT&CK Navigator layer | `python -m bde mapping`, `python -m bde navigator` |
| A demo detecting at least 3 simulated LOLBin attack chains | `python -m bde demo`: 4 chains, scored against ground truth, with an HTML report | `python -m bde demo` |

---

## 1. The demo

```bash
python -m bde demo
```

It runs four stages and prints each one:

1. **Simulate** 3 hours of normal work on 8 computers with the four attack chains hidden in it (seed 7), and write the events to `out/demo/demo-events.jsonl`.
2. **Detect**: read that file back like any other log, and print the incidents.
3. **Score** against the ground truth: which chains were caught, by which incident, how fast, and how many false alarms.
4. **Write** the report files.

On seed 7 it finds all 4 chains with 0 false alarms. It exits with code 1 if fewer than 3 chains are detected, so it doubles as a check.

### Presenting it

A good order for a 10-minute demo or viva:

1. `python -m bde demo` and scroll the output: 4 incidents from 1,375 events.
2. Open `out/demo/report.html`. Walk through INC-001: the steps, the story, the risk note.
3. Show INC-003's "came from WKSTN-23 via powershell.exe" and the link to INC-001. That's the moment the audience sees one intrusion instead of four alerts.
4. Load `coverage-layer.json` in the ATT&CK Navigator and point at the gaps.
5. `python -m bde evaluate`: the numbers, and chain-3u at 0% with the reason.

Be ready for "isn't it easy to detect your own simulation?". The answers are the benign twins, the unseen variants and the soak test (phase 5), and that the gaps are reported.

## 2. The HTML report

`report.html` is one self-contained file: no internet, no scripts, readable on any computer. It follows the system's light or dark setting. For each incident it shows:

| Part | What it tells the analyst |
| --- | --- |
| Level, title, hosts | What it is, how bad, where |
| Detected / signals from ... to | When the engine knew, and how long the activity lasted |
| Found by | Which chain rule (and how many steps), or the risk score |
| Tactics and techniques | ATT&CK labels, linked to attack.mitre.org |
| Came from | The cross-host origin: source computer, account, logon time, process |
| Related | Other incidents in the same intrusion |
| Steps | Each chain step with the time it was satisfied |
| Notes | Merges with risk scoring, and other signals in the same episode |
| Story | The incident's events in time order, signals highlighted, with the rules that fired |
| Process tree | The branch drawn as text, in a fold-out section |

Below the incidents: signals that didn't become part of any incident (the noise phase 4 filtered out), and a table of every technique seen.

The same run also writes `incidents.json`, for other tools, and `incidents-layer.json`, a Navigator layer of the techniques in these incidents.

## 3. The mapping document

[attack-mapping.md](attack-mapping.md) is **generated**, never edited by hand. `python -m bde mapping` builds it from:

- the Sigma rules and chain rules (which techniques each one tags),
- a run on seed 7 with all seven chains (which techniques the simulated attacks actually used, and an example event for each),
- `bde/attack.py` (names and tactics, ATT&CK v20).

Each technique gets one of three statuses:

| Status | Meaning |
| --- | --- |
| **Detected in the simulated chains** | A rule tags it, and a simulated attack used it, and an incident contained that signal |
| **Rule exists, tested by unit tests only** | A rule tags it, but no simulated chain uses it (mshta, domain trusts) |
| **Not detected (gap)** | A simulated attack used it, and nothing detects it |

`tests/test_reports.py::test_mapping_document_is_up_to_date` regenerates the document and compares it with the file. If you change a rule and forget to regenerate, the tests fail. That's how the document stays true.

### ATT&CK v20 changes you should know

The mapping uses ATT&CK Enterprise **v20** (October 2026), which reorganized defense evasion:

- The **Defense Evasion** tactic is split into **Stealth** (TA0005, hiding: obfuscation, hidden windows, proxy execution) and **Defense Impairment** (TA0112, breaking defenses: turning off tools, clearing logs).
- Disable or Modify Tools moved from T1562.001 to **T1685**, and Clear Windows Event Logs from T1070.001 to **T1685.005**.

Older blog posts and Sigma rules use the old IDs. If an examiner asks, this is why ours differ.

## 4. ATT&CK Navigator layers

The [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) shows techniques as a coloured matrix.

```bash
python -m bde navigator          # writes out/coverage-layer.json
```

Open the Navigator, choose **Open Existing Layer → Upload from local**, and pick the file. Green is detected in the chains, yellow is rule-only, red is a gap. `incidents-layer.json` from a detect run shows the techniques of that run's incidents instead, darker for more incidents.

## 5. Code tour

| File | What it does |
| --- | --- |
| `bde/report/describe.py` | One readable line per event ("powershell.exe connects to ...") and each incident's story |
| `bde/report/text.py` | The terminal output of `detect` and `demo` |
| `bde/report/html.py` | The HTML report |
| `bde/report/jsonout.py` | `incidents.json` |
| `bde/report/navigator.py` | Navigator layers (format 4.5) |
| `bde/report/mapping.py` | Coverage statuses and the mapping document |
| `bde/attack.py` | The ATT&CK techniques and tactics we use, v20 |

## 6. Checkpoint questions

1. Why is the mapping document generated instead of written by hand?
2. What's the difference between "rule exists" and "detected in the simulated chains"?
3. Why is the HTML report a single file with no scripts?
4. Why does the report list signals that didn't become incidents?
5. An examiner says T1562.001 is the right ID for turning off Defender. What do you answer?

<details>
<summary>Answers</summary>

1. A hand-written mapping drifts from the rules as soon as someone changes a rule. Generating it, and failing a test when it's stale, means it always describes the code that runs.
2. "Rule exists" only says someone wrote a rule with that tag; the unit tests show it matches hand-made events. "Detected" means a simulated attack used the technique and an incident actually contained the signal, end to end.
3. So it opens anywhere, offline, can be attached to an email or a submission, and can't run anything. A report about attack data shouldn't need to execute code.
4. They show what correlation filtered out, so an analyst (or examiner) can check that nothing important was dropped, and they're a starting point for tuning.
5. That was correct before ATT&CK v20. In v20 (October 2026), Disable or Modify Tools became T1685 under the new Defense Impairment tactic, and T1562.001 redirects there.

</details>
