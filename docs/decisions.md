# Decision log

Every design decision, newest at the bottom. The full option analysis is in the plan: [Detection Engine Rebuild: Options Plan](https://claude.ai/artifact/SGg7WtS2P7GKiHmF9Ram6k).

| # | Date | Area | Decision | Why |
| --- | --- | --- | --- | --- |
| 1 | 2026-11-03 | Plan | Build Path B: Sysmon-shaped events from a generator plus public datasets, Sigma signal rules, process-tree chain correlation, CLI + HTML report | Smallest build that meets the brief honestly; runs on a Mac M2 and on Windows with no VM |
| 2 | 2026-11-03 | Platform | Must run on macOS (Apple Silicon) and Windows: Python only, no shell scripts | Requirement from Sufian; the old bash bootstrap didn't run on Windows |
| 3 | 2026-11-03 | Event model | `Event` keeps Windows' split: System fields plus an EventData dict with Sysmon's own field names | Sigma rules use Sysmon field names, so phase 3 needs no field mapping |
| 4 | 2026-11-03 | Event model | Timestamp = Sysmon `UtcTime` when present, else `System/TimeCreated`; stored as UTC with milliseconds | `UtcTime` is when the action happened; `TimeCreated` is when it was logged |
| 5 | 2026-11-03 | Event model | Ground-truth labels and provenance live in `meta`, never in `data` | Keeps what Windows wrote apart from what we know about it, so rules can't cheat by reading labels |
| 6 | 2026-11-03 | Storage | Our interchange format is JSONL: one event per line, UTF-8, LF line endings | Streams line by line, diffs cleanly, and is byte-identical on Mac and Windows |
| 7 | 2026-11-03 | Process tree | Link processes by (host, ProcessGuid); GUIDs lowercased; all-zero GUID means no parent | PIDs are reused, GUIDs are unique per process start; Sysmon versions differ in GUID case |
| 8 | 2026-11-03 | Process tree | Create placeholder nodes for parents that started before the log began | Real logs start mid-session; the child's event still names the parent's image and PID |
| 9 | 2026-11-03 | Paths | `PureWindowsPath` for paths inside logs, `pathlib.Path` for local files | On macOS, `Path` would not split Windows backslashes |
| 10 | 2026-11-03 | Datasets | Public datasets are downloaded into `data/external/` (git-ignored), never committed | They're GPL-3.0 licensed and large; the repo stays ours |
| 11 | 2026-11-03 | Dependencies | `python-evtx` (pure Python) reads `.evtx` | Installs the same way on an M2 and on Windows, no compiler needed |
| 12 | 2026-11-03 | Layout | Flat `bde/` package, run with `python -m bde` from the project folder | No install step for a first-time user; identical commands on both systems |
| 13 | 2026-11-03 | Output | Text trees cut long lines in the middle, and fall back to ASCII when the terminal can't show box characters | Both ends of a command line matter; some Windows outputs can't encode box characters |
| 14 | 2026-11-03 | Generator | Every part of a scenario gets its own random stream, `derive_seed(seed, label)` via SHA-256; no `hash()`, no set iteration | Same seed gives byte-identical logs on a Mac and on Windows, and adding noise never moves the attacks |
| 15 | 2026-11-03 | Generator | `generate` prints a SHA-256 of the file it wrote; a test pins the seed-7 value | A one-line check that two computers produced the same data |
| 16 | 2026-11-03 | Generator | Every attack step has benign twins, and three unseen variants are never used to write rules | Without look-alikes and unseen data, the evaluation would only measure how well rules fit their own generator (the old build's flaw) |
| 17 | 2026-11-03 | Safety | Encoded payloads decode only to `Write-Output 'SIMULATED-STAGE-2'` or a harmless CIM query; public addresses only from RFC 5737 ranges; domains only `.example`; tests check all three | Logs from this project can be shared and copied without risk |
| 18 | 2026-11-03 | Generator | Chains 3 and 4 start from chain 1's victim, through its implant | Real intrusions spread from a foothold; it gives the cross-host linking something true to find |
| 19 | 2026-11-03 | Ground truth | An attack instance starts at its first labelled event; time to detect starts at its first process start | The plan's start time can be later than the first event (chain 4's mstsc); scoring must use what really happened |
| 20 | 2026-11-03 | Signals | Our own small Sigma evaluator (a subset of Sigma 2.0), not a converter library | pySigma converts rules into SIEM queries, it doesn't evaluate them locally; writing the matcher teaches how Sigma works. Unsupported features are refused, never ignored |
| 21 | 2026-11-03 | Signals | `process_creation` rules also read Security 4688, by mapping its field names | The same rules work on computers without Sysmon, with less detail |
| 22 | 2026-11-03 | Rules | Each rule has a Sigma 2.0 `name`, its file is named after it, and `tests/test_rules.py` has fire and no-fire cases for every rule (a meta-test enforces it) | Rules are code; a rule without a "must stay quiet" case hasn't been tested against normal work |
| 23 | 2026-11-03 | Correlation | Chain rules use our own YAML, modelled on Sigma's `temporal_ordered` correlation, plus a rule Sigma can't express: every step in the anchor's process branch | "This PowerShell called out" is evidence; "something on this host called out" isn't |
| 24 | 2026-11-03 | Correlation | Anchors in one branch within the timespan are one group, anchored at the top-most process | Word → cmd → PowerShell matches the first step twice but is one attack |
| 25 | 2026-11-03 | Correlation | Risk scoring per host: points by level (5/15/35/60), 20-minute half-life, 60-minute window, +10 per extra tactic, threshold 100; the same rule on the same process counts once; an episode ends below 50 | Catches attacks no chain rule describes (chain 4) without letting slow noise or a repeating beacon add up |
| 26 | 2026-11-03 | Correlation | A risk incident that shares signals with a chain incident is merged into it, keeping the earlier detection time and a note | One attack, one incident |
| 27 | 2026-11-03 | Correlation | Cross-host origin from Security 4624 (type 3 or 10) for the account most of the incident's processes run as, with IP → host learned from Sysmon 3 `SourceIp` where `Initiated=true` | No inventory of computers is needed; the logs say which address is whose |
| 28 | 2026-11-03 | ATT&CK | Use ATT&CK Enterprise v20: Stealth (TA0005) and Defense Impairment (TA0112) instead of Defense Evasion; T1685 and T1685.005 instead of T1562.001 and T1070.001 | Current version at build time; old IDs now redirect |
| 29 | 2026-11-03 | Evaluation | An instance is detected if an incident contains a signal from one of its events; an incident is true if any of its signals is malicious; the soak test includes the twins; seen and unseen variants are reported separately | Each number answers one clear question, and the hard cases are in the test |
| 30 | 2026-11-03 | Evaluation | Keep chain 3's `min_steps: 2` although `3` removes every false alarm on our data | Our simulated attacker always does all four steps, so the data can't show what 3 would miss; changing it would be tuning to the generator. Open for Sufian to decide (phase 5 doc) |
| 31 | 2026-11-03 | Mapping | The mapping document is generated from the rules plus a seed-7 run, and a test fails when it's stale; "detected" requires that a simulated attack used the technique | A hand-written mapping drifts; a rule tag alone doesn't prove detection |
| 32 | 2026-11-03 | Report | The HTML report is one file with inline CSS, no scripts, light and dark themes | Opens offline anywhere, safe to attach to a submission |
| 33 | 2026-11-03 | Dependencies | Add PyYAML 6.0.3 | Rules are YAML; it installs from wheels on an M2 and on Windows |
| 34 | 2026-11-03 | Demo | `python -m bde demo` exits with code 1 if fewer than 3 chains are detected | The brief's minimum doubles as an automatic check |
