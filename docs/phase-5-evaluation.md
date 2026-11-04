# Phase 5: Measuring the engine

"It detected the demo" isn't evidence: the demo is one run, and the rules were written while looking at it. Phase 5 measures the engine the way a detection team would, on many scenarios it wasn't tuned on, and reports where it fails as plainly as where it works.

```bash
python -m bde evaluate                 # 20 seeds, seen and unseen variants, plus a 24-hour soak test
python -m bde evaluate --seeds 1-50    # more seeds
```

It takes about 2 seconds.

---

## 1. The measures

Every generated event carries a label (phase 2), so each incident can be checked against the truth:

| Measure | Question it answers | How we count it |
| --- | --- | --- |
| **Recall** (detection rate) | Of the attacks that happened, how many did we catch? | An attack instance counts as detected if at least one incident contains a signal from one of its events |
| **Precision** | Of the incidents we raised, how many were real? | An incident is true if at least one of its signals is on a malicious event |
| **Time to detect (TTD)** | How long did the attacker have before we noticed? | From the attack's first process start to the incident's detection time |
| **Signal precision** | How noisy is phase 3 on its own? | Signals on malicious events ÷ all signals |
| **False alarms per day** | What would an analyst's queue look like? | Incidents in 24 hours of normal work only (the soak test) |

Recall and precision pull against each other. Lowering the risk threshold catches more but raises more false alarms. Reporting only one of them hides the trade-off.

## 2. Results

From `python -m bde evaluate` (seeds 1 to 20, 3 hours each, 5 workstations):

| Chain | Variant | Instances | Detected | Recall | Median TTD | Worst TTD |
| --- | --- | --- | --- | --- | --- | --- |
| chain-1 | seen | 20 | 20 | 100% | 7.3 s | 10.7 s |
| chain-2 | seen | 20 | 20 | 100% | 6.5 s | 8.5 s |
| chain-3 | seen | 20 | 20 | 100% | 1.5 s | 2.0 s |
| chain-4 | seen | 20 | 20 | 100% | 112.5 s | 2.4 min |
| chain-1u | unseen | 20 | 20 | 100% | 6.0 s | 10.6 s |
| chain-2u | unseen | 20 | 20 | 100% | 7.3 s | 8.9 s |
| chain-3u | unseen | 20 | 0 | **0%** | | |

- **Incidents:** 128 raised, 120 true, 8 false: precision **93.8%**.
- **Signals:** 1,559 raised, 1,303 on malicious events: signal precision 83.6%. Phase 4 turns a noisy 84% into a much cleaner 94%.
- **Soak test:** 24 hours of normal work on 11 computers, 15,434 events: **3 false incidents**, 0.19 per 1,000 events, 0.27 per computer per day.

### Reading the results honestly

**Seen chains, 100%.** Expected, and on its own not impressive: these are the attacks the rules were written for. What matters is the rest.

**Unseen chain-1u and chain-2u, 100%.** Excel instead of Word, `-w 1` instead of `-w hidden`, bitsadmin instead of certutil, regsvr32 instead of rundll32: the rules still caught them. They describe behaviour (an Office program somewhere above a script engine; a script host starting a download tool; a system binary calling the internet) rather than exact command lines.

**Unseen chain-3u, 0%: a real gap.** Moving laterally with a remote scheduled task (`schtasks /create /s SRV-FILE-01`) instead of WMI isn't covered by any rule. On the server, the task runs `cmd.exe` under `svchost.exe`, which happens all day. The mapping document lists T1053.005 as a gap. Closing it would need a rule on `schtasks` with `/s` on the source computer, or Security event 4698 (scheduled task created) on the server. We keep the gap visible on purpose: an evaluation where everything is 100% has usually stopped testing anything.

**Chain 4 takes about 2 minutes.** The clock starts when `mstsc.exe` opens the RDP session. The session logs on and the desktop starts before the attacker types the first command, and risk scoring needs three high signals to pass 100. In a real SOC, two minutes before ransomware runs is still useful, but it shows where the risk approach is slower than a chain rule.

### All false alarms have one cause

Every false incident (8 in the evaluation, 3 in the soak test) is the same thing: a rare **management script that runs hidden, encoded PowerShell through WMI** on a server. It completes 2 of the 4 steps of the chain-3 rule (`wmi-starts-shell`, `hides-itself`), and the rule's `min_steps` is 2.

Raising `min_steps` to 3 removes all of them, and on our data chain 3 is still caught every time, about 1.4 seconds later. So why not change it? Because our simulated attacker always does all four steps. A real attacker on a server may skip the outside connection (if the implant on the workstation relays) and run one discovery command. The data can't show what `min_steps: 3` would miss, so the evaluation would reward the change for the wrong reason: tuning to the generator, which is exactly the old build's flaw.

Two better fixes, both used in real SOCs:

1. **Allow-list the management tool** by its parent process or signer, in the rule's filter.
2. **Keep the rule, and suppress by context**: the management script runs as a service account from the management server, while chain 3 runs as a stolen admin from a workstation. The cross-host origin already knows which.

This is a judgement call, and it's yours to make. Either way, write down why.

## 3. Public datasets

Generated data has one weakness: we wrote both the attacks and the rules. Real attack recordings check that the rules work on events from real tools. `--external` runs the engine over a folder of `.evtx` files, such as [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES):

```bash
python -m bde evaluate --external data/external/
```

These files have no per-event labels, so it reports what fired per file, not precision and recall. Use it to answer "does the engine see the attack in this recording, and with which rules?" and compare with the technique in the file's folder name. Phase 1 explains how to download the files; the Windows testing guide adds your own Sysmon logs.

[Phase 7](phase-7-real-data.md) takes this much further: two public datasets, one to develop on and one held out, and a per-technique score for recordings whose folders name an ATT&CK technique.

## 4. Code tour

| File | What it does |
| --- | --- |
| `bde/evaluate.py` | `score_run` (one scenario against its labels), `run_evaluation` (many seeds), `run_soak` (normal work only), `format_report` |
| `bde/__main__.py` | `evaluate` command, including `--external` |
| `tests/test_reports.py` | Scoring and the soak test, on small runs |

## 5. Try it

```bash
python -m bde evaluate
python -m bde evaluate --seeds 1-50 --soak-hours 72
python -m bde evaluate --no-unseen --soak-hours 0     # quick, seen chains only
```

## 6. Checkpoint questions

1. Why can't recall alone tell you whether the engine is good?
2. Signal precision is 84% but incident precision is 94%. What raises it?
3. Why do the unseen variants matter more than the seen ones?
4. Chain-3u scores 0%. Why is it in the evaluation at all?
5. Raising chain 3's `min_steps` to 3 gives 100% precision on our data. Why might that be the wrong conclusion?
6. Why does the soak test contain the benign twins?

<details>
<summary>Answers</summary>

1. A detector that alerts on everything has 100% recall. Recall must be read together with precision (or false alarms per day).
2. Correlation. Most noisy signals (an admin's whoami, the agent's encoded PowerShell) stay single signals: they never complete a chain or reach the risk threshold, so they never become incidents.
3. The rules were written while looking at the seen chains, so of course they match. The unseen variants test whether the rules capture behaviour, which is what generalizes to real attackers.
4. To show the engine's limits honestly, and to test that the evaluation can report a miss. It also points to the next rule worth writing.
5. Our simulated attacker always performs all four steps, so the data can't show what a stricter rule would miss. Choosing a rule because it scores best on your own generator is tuning to the test.
6. They're normal work that looks like attacks. A soak test without them would only contain easy activity and would show zero false alarms, which proves nothing.

</details>
