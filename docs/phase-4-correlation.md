# Phase 4: From signals to incidents

A SOC analyst doesn't want 55 signals. They want **4 incidents**, each telling one story: what happened, on which computers, in what order, and where it came from. Phase 4 builds those stories from the signals, in three ways:

1. **Chain rules**: an ordered sequence of signals in one branch of the process tree (phase 1's trees pay off here).
2. **Risk scoring**: many different suspicious things on one host in a short time, even if no chain rule describes them.
3. **Cross-host linking**: this server incident started from a logon that came from that workstation's PowerShell.

```bash
python -m bde generate -o out/s.jsonl
python -m bde detect out/s.jsonl --out out/report     # then open out/report/report.html
```

---

## 1. Why single signals aren't enough

Look at what phase 3 produces on the demo data: 54 signals, 12 of them from normal work (admins, the management agent, OneDrive). Raising an alert per signal would bury the four real attacks in noise, and analysts would learn to ignore the alerts, which is how real breaches get missed.

The attacks differ from the twins not in any single event but in **what happens around them**:

| Twin | Its attack | What only the attack has |
| --- | --- | --- |
| Agent runs `powershell -EncodedCommand` | chain-1 | Started by Word, then calls out, drops a script, adds a Run key |
| Admin runs certutil with a URL | chain-2 | Started by a downloaded .js, then decode, then rundll32 loads the result |
| IT runs gpupdate over WMI | chain-3 | The WMI child hides itself, calls out and runs discovery |

## 2. Chain rules

A chain rule lists **steps**. Each step is satisfied by one of several signal rules. Here is `rules/chains/chain_office_document_to_powershell.yml`, trimmed:

```yaml
name: chain_office_document_to_powershell
level: critical
timespan: 15m        # everything within 15 minutes of the first step
ordered: true        # steps must happen in this order
min_steps: 3         # at least 3 of the 4 steps
tags: [attack.initial-access, attack.t1566.001]
steps:
  - name: office-starts-script-engine
    signals: [proc_office_spawns_script_engine, proc_powershell_encoded_command, proc_powershell_hidden_window]
    ancestor: [WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE, OUTLOOK.EXE, ...]
  - name: calls-out
    signals: [net_script_engine_public_destination, net_proxy_binary_public_destination]
  - name: drops-payload
    signals: [file_script_engine_drops_payload]
  - name: persists
    signals: [reg_run_key_script_engine]
```

The format is our own, modelled on Sigma 2.0's `temporal_ordered` correlation rules, with one thing Sigma correlations can't express: **every step must happen in the anchor process or one of its descendants**. That's the line between "this PowerShell called out" and "some program on this computer called out".

### How matching works (`match_chain` in `bde/correlation.py`)

1. **Find anchors.** Every signal that satisfies the first step is a possible start. If the step has `ancestor`, the process must have one of those programs somewhere above it. That's your `has_ancestor()` from phase 1, and it's why `Word → cmd → powershell` still counts: cmd sits between them.
2. **Group anchors.** In that same example, both cmd and PowerShell match step 1. They're one attack, not two, so anchors in the same branch within the timespan are grouped under the top-most process.
3. **Collect later steps.** For each later step, take matching signals that are on the same host, inside the timespan, in the anchor's branch, and (if `ordered`) not earlier than the previous step.
4. **Decide.** If at least `min_steps` steps are satisfied, raise an incident. It is detected when the `min_steps`-th step was satisfied, not when the last one was.

`min_distinct: 2` on chain 3's discovery step means two *different* discovery rules (for example whoami and nltest), so one command run twice doesn't count.

### Choosing min_steps

`min_steps` trades speed against false alarms:

- **Lower** detects earlier and survives an attacker who skips a step. Chain 3 uses 2 because attackers vary their discovery.
- **Higher** needs more evidence, so it raises fewer false alarms.

Phase 5 shows the cost of chain 3's choice: a rare management script that runs hidden PowerShell over WMI also completes 2 steps, and causes all of our false alarms.

## 3. Risk scoring

Chain rules only find stories someone wrote down. Chain 4 (ransomware preparation) shows why that isn't enough: the attacker deletes backups, clears logs and turns off Defender, in any order, with any tool. Instead of a chain rule, it is caught by **risk scoring** (`rules/risk.yml`):

- Every signal adds points to its host by level: low 5, medium 15, high 35, critical 60.
- Points **fade**: half are gone after 20 minutes (the *half-life*), and signals older than 60 minutes don't count.
- **Breadth bonus**: +10 for every extra ATT&CK tactic. An intrusion touches many tactics (execution, discovery, impact...); one noisy tool usually stays in one.
- **The same rule on the same process counts once.** A beacon connecting every minute is one behaviour, not twenty.
- When a host reaches **100**, that's an incident. It stays open while the score is above 50, so one burst of activity is one incident, not five.

Example: chain 4 on SRV-APP-02 in the demo. In 90 seconds there are seven high signals (35 points each): Defender turned off, the Security log cleared (seen twice, as the `wevtutil cl` command and as Security event 1102), three recovery-inhibiting commands and one more log cleared. They span two tactics, Defense Impairment and Impact, so +10. The score passes 100 at the third signal and peaks at about 270, a little above 7 × 35 + 10 = 255, because signals from earlier admin work on that server still count, faded. 270 is more than twice the threshold, so the level becomes critical.

Why fade at all? Without it, any busy server would slowly collect enough low signals over a week to cross the threshold. With a half-life, only activity **close in time** adds up.

### When both methods fire

Chain 1 is caught twice: risk scoring passes 100 one second into the attack, and the chain rule completes three seconds later. Two incidents for one attack would be noise, so they're **merged** when they share signals. The chain incident keeps the earlier detection time and gets a note:

> Risk scoring raised this first, at 08:35:29, when the host's score reached 100; the chain rule completed at 08:35:32.

## 4. Cross-host linking

The chain-3 incident is on SRV-FILE-01, but the attacker came from WKSTN-23. Logs show this in three pieces, on two computers:

| Where | Event | What it says |
| --- | --- | --- |
| SRV-FILE-01 | Security **4624**, logon type 3 (network) | `adm-rpatel` logged on from 10.20.1.83 |
| WKSTN-23 | Sysmon **3**, Initiated=true | powershell.exe connected to 10.20.0.21:5985 |
| any host | Sysmon 3, Initiated=true | its SourceIp is that host's own address |

`find_origin` puts them together:

1. **Which account?** The users of the incident's processes vote. On the server they're `adm-rpatel`.
2. **Which logon?** The last 4624 for that account, type 3 (network) or 10 (remote desktop), in the 10 minutes before the activity.
3. **Which computer?** `address_book` learns IP → host from the logs themselves: when a host opens a connection, the SourceIp in its own Sysmon event is its address. 10.20.1.83 is WKSTN-23.
4. **Which process?** On WKSTN-23, the connection to the server's address just before the logon. That's the chain-1 implant's PowerShell.

Finally `_link` connects incidents: chain 3's origin process belongs to incident INC-001's process tree, so the two are **related**, and the report shows "came from WKSTN-23 via powershell.exe". Chain 4 does the same through `mstsc.exe` and a type-10 (RDP) logon.

## 5. Code tour

| File | What it does |
| --- | --- |
| `rules/chains/*.yml` | The three chain rules |
| `rules/risk.yml` | Points, half-life, window, bonus and threshold |
| `bde/correlation.py` | `ChainRule` loading and checks, `match_chain`, `risk_score`/`score_risk`, `address_book`/`find_origin`, `correlate` (merge, origin, numbering, links) |
| `bde/engine.py` | `detect(events)`: tree → signals → incidents, in one call |
| `tests/test_correlation.py` | Hand-built trees for each rule of matching, plus the demo's incidents |

## 6. Try it

```bash
python -m bde generate -o out/s.jsonl
python -m bde detect out/s.jsonl
python -m bde detect out/s.jsonl --full        # every story line, uncut
```

Experiments (put the files back afterwards, `git checkout rules/` does it):

1. In `rules/risk.yml`, set `threshold: 60`. Run `python -m bde evaluate --seeds 1-10 --soak-hours 0`. What happens to precision, and why?
2. In `chain_wmi_remote_shell_discovery.yml`, set `min_steps: 3`. Run the evaluation again. What happens to the false alarms, and to chain 3's time to detect? Would you keep it? (Phase 5 discusses this.)
3. Remove the `ancestor:` line from the chain-1 rule and evaluate again. On our data nothing changes. Why not? What normal activity would a real company have that makes the ancestor check necessary?

## 7. Checkpoint questions

1. Why must chain steps be in the same process branch, not just on the same host?
2. Word → cmd → PowerShell matches step 1 twice. Why doesn't that create two incidents?
3. What does the half-life protect against?
4. Why does a beacon that connects 20 times add points only once?
5. How does the engine know that 10.20.1.83 is WKSTN-23 without a list of computers?
6. Chain 3's rule uses `min_steps: 2`. What do we gain and what do we pay?
7. (Experiment 3) Why does removing the `ancestor` check change nothing on our data?

<details>
<summary>Answers</summary>

1. A busy workstation has many processes. If any process could satisfy any step, a user's browser connecting out plus Word starting a helper could look like a chain. Requiring one branch means one program and what it started did all of it.
2. Anchors in the same branch within the timespan are grouped, and the group is anchored at the top-most process (cmd). One group is one incident.
3. Slow accumulation. Without fading, a server with a few low signals per day would eventually cross the threshold with no attack at all.
4. The score counts behaviours, not events. Each (rule, process) pair adds points once per window, so repetitive but harmless activity can't climb on its own.
5. From its own logs: when WKSTN-23 opens a connection, Sysmon on WKSTN-23 records SourceIp 10.20.1.83. The address book learns the mapping from those events.
6. We gain detection of an attacker who only does two of the four things (for example, shell plus discovery), and earlier detection. We pay with false alarms when a legitimate management script does two of them (hidden PowerShell under WMI). Phase 5 measures that cost.
7. Without the ancestor check, step 1 can start from any encoded or hidden PowerShell, such as the management agent's. But the chain still needs 3 steps, and the agent's PowerShell never calls out, drops a script and sets a Run key. Real companies have software-deployment tools that do exactly that (encoded PowerShell that downloads and installs something), and there the Office-ancestor check is what keeps them out. Our generator has no such twin, which is a limit of the test data worth saying out loud.

</details>
