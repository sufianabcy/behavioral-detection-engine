# Phase 2: The scenario generator

Phase 2 builds a **fake company network that writes Sysmon logs**: normal people doing normal work, a few admins doing things that *look* like attacks, and the attack chains the engine must find. Every event carries a hidden label saying what really happened, so phase 5 can grade the engine like an exam.

```bash
python -m bde generate -o out/scenario.jsonl          # 3 hours, seed 7, the four attack chains
python -m bde tree out/scenario.jsonl --match certutil  # look at what it made
```

Nothing is ever executed. The generator writes text records that have the same shape as real Sysmon events.

---

## 1. Why simulate at all?

To measure a detector you need logs where you **know the answer**: which events are the attack and which are normal. Real logs from a real company don't come with that answer, and public attack datasets (phase 1's EVTX-ATTACK-SAMPLES) contain the attack but almost no normal activity around it, so they can't tell you how often the engine raises false alarms.

A generator gives you both, as much as you want, with the labels attached. The price is realism: the engine can only be as good as the generator is honest. The rules below are what keeps it honest.

## 2. Three rules that make the data a fair test

| Rule | What it means | What goes wrong without it (the old build) |
| --- | --- | --- |
| **Attacks are chains in real process trees** | Every malicious event hangs off a real parent: Outlook starts Word, Word starts PowerShell, PowerShell connects out. Same host, increasing times, linked GUIDs. | The old generator put each malicious event on a random host with a random PID, so there was no chain to find. |
| **Every attack has benign twins** | For each attack step there is normal work that looks similar: admins use certutil to hash files, a remote-management agent runs encoded PowerShell, IT runs gpupdate over WMI. | Without look-alikes, "certutil ran" is a perfect detector, and the scores mean nothing. |
| **Rules never see the labels** | Labels live in `event.meta`, which the rules can't read (decision 5). Unseen variants test what the rules were *not* written for. | Rules tuned on their own generator score 100% and prove nothing. |

## 3. The simulated company

Domain `corp.example`, 8 computers in the default run:

| Host | Who | Role in the story |
| --- | --- | --- |
| WKSTN-07, -15, -21, -23 | jsmith, mlopez, kchen, rpatel | Office workers: email, browsing, Word, Teams |
| WKSTN-12 | adavis | IT admin: scripts, certutil, discovery commands |
| ADMIN-01 | adm-adavis | Jump host for remote admin work (WMI, backups) |
| SRV-FILE-01, SRV-APP-02 | services | Servers: scheduled jobs, file shares, backups |

Internal addresses are 10.20.x.x. Everything "on the internet" uses the reserved documentation ranges and `.example` names (see Safety below).

## 4. The four attack chains

| Chain | Story | Main tools |
| --- | --- | --- |
| **chain-1** Phishing document | Outlook → Word → `cmd /c powershell -nop -w hidden -enc ...` → C2 beacon → drops `svc27.ps1` → Run key | Office, PowerShell, registry |
| **chain-2** Script download | Edge downloads `invoice_1234.js` → wscript → `certutil -urlcache` downloads → `certutil -decode` → `rundll32` runs the DLL → C2 | wscript, certutil, rundll32 |
| **chain-3** WMI lateral movement | The chain-1 implant uses stolen admin `adm-rpatel`: `Invoke-CimMethod Win32_Process Create` → on SRV-FILE-01 `WmiPrvSE.exe` starts hidden PowerShell → C2 → `whoami /all`, `net group /domain`, `nltest` | WMI, PowerShell, discovery |
| **chain-4** Ransomware preparation | From WKSTN-23, `mstsc` (RDP) to SRV-APP-02 as adm-rpatel → `vssadmin delete shadows`, `wbadmin delete catalog`, `bcdedit`, `wevtutil cl`, `Set-MpPreference -DisableRealtimeMonitoring` | Built-in admin tools |

Chains 3 and 4 start **from chain 1's victim**, using its implant. That's how real intrusions spread, and it lets phase 4 link the incidents across hosts.

### Unseen variants

Three more chains are never used to write or tune rules. They test whether the rules generalize:

| Variant | What changes |
| --- | --- |
| chain-1u | Excel instead of Word, `-w 1` instead of `-w hidden`, persistence by scheduled task instead of Run key |
| chain-2u | `bitsadmin` downloads instead of certutil, `regsvr32` runs the DLL instead of rundll32 |
| chain-3u | A remote **scheduled task** (`schtasks /s`) instead of WMI |

Generate them with `--chains all` (or `--chains 1u,2u,3u`).

## 5. The benign twins

| Twin | Looks like | Why it's normal |
| --- | --- | --- |
| Remote-management agent runs `powershell -enc` | chain-1, encoded PowerShell | Management tools encode scripts to avoid quoting problems. It decodes to `Get-CimInstance Win32_OperatingSystem`. |
| OneDrive adds a Run key | chain-1 persistence | Apps start at logon this way every day |
| Opening an email attachment | chain-1 delivery | Word starting from Outlook is normal; Word starting PowerShell is not |
| Printing from Word (`splwow64.exe`) | chain-1, Word starting a child | Word does start helper programs; the question is which |
| IT inventory script, `-ExecutionPolicy Bypass -File` | chain-1, PowerShell with odd flags | Visible window, a named script file, started by a person from Explorer |
| `certutil -hashfile`, `certutil -urlcache` for a CRL | chain-2 | Admins check hashes; Windows fetches certificate revocation lists |
| `rundll32 shell32.dll,Control_RunDLL` | chain-2 | Opening a Control Panel item |
| Logon script under `\\corp.example\NETLOGON\` | chain-2 script host | wscript running the company's own script |
| Admin runs `whoami /all`, `net group /domain`, `nltest` | chain-3 discovery | Admins troubleshoot permissions |
| `Invoke-CimMethod` to run `gpupdate` on a server | chain-3 | Remote WMI for routine admin work |
| Management script over WMI (rare, about every 8 h) | chain-3 | A real false positive we keep on purpose (phase 5) |
| `vssadmin list shadows`, `wbadmin get versions` | chain-4 | Checking backups, not deleting them |

## 6. Seeds and determinism

A **seed** is the number that starts a random sequence. The same seed always gives the same sequence, so `--seed 7` gives the same 1,375 events on your Mac, on Windows, today and next month.

Three details make this hold:

1. **Every part gets its own random stream.** `derive_seed(7, "chain-2")` makes a separate seed for chain 2 from the main seed, using SHA-256. So adding background noise doesn't move the attacks (there's a test for exactly that).
2. **No `hash()`.** Python's `hash("text")` changes every time Python starts (a security feature). We use `hashlib.sha256`, which never changes.
3. **No iterating over sets**, whose order also depends on hashing. Lists and sorted keys only.

`python -m bde generate` prints a SHA-256 fingerprint of the file it wrote. For seed 7 it is:

```
739b8730f8ce3ca70c67221c29c124fc8ac3d1491862a3326b21599f15d1e219
```

If a Windows machine prints the same number, the two computers produced byte-identical logs. The Windows testing guide uses this check.

## 7. Ground truth

Each attack event's `meta` looks like this:

```json
{"label": "malicious", "chain": "chain-1", "instance": "chain-1#1", "variant": "seen",
 "stage": "execution", "techniques": ["T1059.001", "T1027.010"]}
```

Benign events say what normal activity they were, and twins say which chain they imitate:

```json
{"label": "benign", "activity": "remote-management-script", "twin": "chain-1"}
```

The generator also returns a list of **instances** (one per attack that happened), with the hosts and the time of the first event. Phase 5 scores against these.

## 8. Safety

- Encoded PowerShell in attack events decodes to `Write-Output 'SIMULATED-STAGE-2'`. Twins decode to a harmless `Get-CimInstance` query. A test decodes every `-enc` in a scenario and fails on anything else.
- Public addresses come only from `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`, which are reserved for documentation and are never routed on the internet. Domains end in `.example`, which is reserved too. Tests check every address and every domain.
- The "DLL" and "script" files are names in log records. No file content exists anywhere.

## 9. Code tour

| File | What it does |
| --- | --- |
| `bde/generator/rand.py` | `derive_seed()` and `Rand`, the only source of randomness |
| `bde/generator/catalog.py` | Names, paths, users, sites, the safe payloads, program metadata |
| `bde/generator/world.py` | `World`: hosts with running processes; `spawn`, `connect`, `dns`, `create_file`, `set_registry`, `logon` write Sysmon/Security events |
| `bde/generator/benign.py` | Background activities and the twins |
| `bde/generator/attacks.py` | The chains, each a function that tells its story through `World` |
| `bde/generator/scenario.py` | `ScenarioConfig` and `generate()`: places everything in time |
| `tests/test_generator.py` | Determinism, the fingerprint, safety checks, label checks |

## 10. Try it

```bash
python -m bde generate -o out/s.jsonl                         # the default: seed 7, chains 1 to 4
python -m bde generate --chains all -o out/all.jsonl          # with the unseen variants
python -m bde generate --chains none --hours 24 -o out/day.jsonl   # a normal day, no attacks
python -m bde tree out/s.jsonl --host WKSTN-23 --match powershell
python -m bde stats out/s.jsonl
```

Then compare a twin with its attack. Run `python -m bde tree out/s.jsonl --match -enc` and find two PowerShell processes with `-enc`. What differs in their parents?

## 11. Checkpoint questions

1. Why can't you measure false alarms with EVTX-ATTACK-SAMPLES alone?
2. What is a benign twin, and what would the evaluation numbers look like without them?
3. Why does each chain get its own random stream instead of sharing one?
4. Why does the code avoid Python's `hash()`?
5. Chain 3 starts on SRV-FILE-01. Why does the generator start it from chain 1's victim instead of a random computer?
6. Why are the unseen variants never used while writing rules?

<details>
<summary>Answers</summary>

1. Those files record the attack with very little normal activity around it. False alarms come from normal work, so you need lots of normal work with known labels.
2. Normal activity that looks like an attack step, such as an admin running certutil. Without twins, simple rules like "certutil ran" would look perfect: 100% precision on data that never contains the hard cases.
3. So changing one part (more background noise, an extra twin) doesn't shift the others. The attacks stay at the same times and you can compare runs fairly.
4. `hash()` of a string changes every time Python starts, so the data would differ from run to run and between computers.
5. Real intrusions spread from a foothold. Starting from the victim lets phase 4 trace the server incident back to the workstation, and shows the link in the report.
6. If you look at them while writing rules, you tune the rules to them and they stop being a test of generalization. They play the role of an exam you haven't seen.

</details>
