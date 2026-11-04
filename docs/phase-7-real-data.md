# Phase 7: Real attack logs

Phases 1 to 6 were built and measured on data we generated ourselves, so we wrote both the attacks and the rules. Phase 7 runs the engine on recordings of real attack tools, made by other people on real Windows computers. It fixes what those logs broke, then measures the result on a second set of recordings that we looked at only once, after the rules were frozen.

```bash
python -m bde evaluate --external data/external/EVTX-ATTACK-SAMPLES     # the development set
python -m bde evaluate --external data/external/EVTX-to-MITRE-Attack    # the held-out set
```

Each takes a few seconds. Add `--all-files` to list every file, not only those that raised something.

**Results in one paragraph.** Real logs exposed a parser that lost whole files with only a passing warning, and three kinds of values that two parsers write differently. After the fixes and 6 new rules, 13 recordings that raised nothing before now raise signals. On the held-out set, scored once, the engine flags the folder's own technique in **9 of the 68 recordings a rule claims (13%)**. It raises **5 incidents, all real attacks**, and no signal on anything that didn't happen. Most misses have one cause: the evidence is in event types the engine has no rules for, mainly PowerShell's own logs. Five are true misses, and they show which rules to write next.

---

## 1. The idea: a development set and a held-out set

Phase 5 kept some attack variants unseen, so the score couldn't reward rules written to fit the test. Phase 7 does the same with real data:

| | Development set | Held-out set |
| --- | --- | --- |
| Dataset | [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) by sbousseaden | [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) by mdecrevoisier |
| Version used | commit `4ceed2f` (January 2023) | commit `4748560` (May 2026) |
| Recordings | 278 `.evtx` files | 293 `.evtx` files |
| Labels | Folders name the ATT&CK tactic; 3 file names name a technique | Folders name the tactic and technique: `TA0002-Execution/T1059.001-PowerShell/...` |
| License | GPL-3.0 | CC0 (public domain) |
| What we did with it | Looked at everything; fixed the reader and the rules | Scored once, after the rules were frozen |

**Why split?** If you fix rules on the same files you score them on, the score measures how well you remembered those files, not how well the engine detects attacks. So the held-out set stayed closed while we worked. We only used it to compare the two parsers, which reads events but runs no rules.

**How the rules were frozen.** Before the held-out run, the rules and code went into commit `34ece8a` ("rules frozen here"), pushed to GitHub on 4 November 2026 at 00:19 UTC. The run came after it. `git diff 34ece8a -- rules/` is empty: no rule changed after we saw the results.

**Getting the datasets.** Both are on your Mac already, in `data/external/`. To get them on another computer, either `git clone` each repository into `data/external/`, or use **Code → Download ZIP** on GitHub and unzip it there (then rename the folder to drop the `-master` or `-main` at the end, so the commands above work). Git ignores `data/external/`: the development set is GPL-licensed, and recordings don't belong in our repository.

## 2. What real logs broke in the reader

### Records lost without a word

We read every file with both `.evtx` parsers and compared them record by record:

| | python-evtx (phase 6) | evtx (phase 7, written in Rust) |
| --- | --- | --- |
| Events read from all 571 files | 48,495 | 50,176 |
| Records it couldn't decode | 1,681, in 15 held-out files | 0 |
| Time | 201 s | 5 s |

python-evtx could not decode **a single record** in 15 files. Phase 6 printed a warning line for each, but the scan's summary didn't count them, so in a long scan they scrolled past and the files looked like clean logs with nothing suspicious in them. A failure that looks like "no attack here" is worse than a crash, because nobody goes looking.

The engine now reads `.evtx` with the `evtx` package, about 40 times faster. If a record is damaged, the reader skips it and counts it, and the scan's summary line reports how many records and files couldn't be read. python-evtx remains only for Windows on ARM, which has no ready-made `evtx` build (decision 36).

### The same value, written three ways

| Field | python-evtx | evtx | Why it matters |
| --- | --- | --- | --- |
| `ProcessGuid` | `{365abb72-7acc-...}` | `365ABB72-7ACC-...` | The process tree already tidied GUIDs, but rules and saved `.jsonl` files see the raw text |
| `LogonId`, `GrantedAccess` | `0x000000000000f4be`, `0x001fffff` | `0xf4be`, `0x1fffff` | A rule for `GrantedAccess: '0x1fffff'` (a common Sigma check on LSASS access) never matches the first form |
| `Initiated` | `True` | `true` | Our code lowercases it before comparing, but any exact comparison would fail |

None of our rules happened to depend on these, which is exactly why they're dangerous: nothing fails until someone writes the rule that does. Before the fix, only 44 of 571 files gave identical events with both parsers. `canonical_value()` in `bde/readers/windows.py` now writes each kind one way: GUIDs as `{lowercase}` (as Sysmon writes them), hex numbers without leading zeros (as Windows shows them), and `true`/`false`. After it, 481 of 571 files match exactly, and every part of the engine, and any rule added later, sees the same text whichever parser read the log.

The remaining differences are in fields no rule reads. In each case `evtx` is closer to what Windows shows:

- Events with several unnamed values (SQL Server, ESENT and Exchange logs, 51 files): python-evtx puts them all in one field; `evtx` gives one field each (`Data0`, `Data1`, ...).
- Times: python-evtx loses precision converting Windows' 100-nanosecond clock, so 41 event times are 1 ms off. It also read one time's milliseconds as microseconds.
- Binary fields (security descriptors, BitLocker values): Base64 in one, hex in the other.

### One forbidden character

One recording has a raw control byte inside a privilege list. XML forbids it, so the whole event failed to parse (21 events in one file). The reader now replaces such characters with `�` and keeps the event.

### Two packages, one folder

The two parsers install as folders named `evtx` and `Evtx`. macOS and Windows treat those as the same name, so installing both in one environment breaks both. `requirements.txt` installs exactly one of them (decision 36). If your `.venv` was made before phase 7, recreate it: `python -m venv --clear .venv`, then install `requirements.txt` again.

## 3. The development set: what we changed

| | Before (phase 6) | After (phase 7) |
| --- | --- | --- |
| Time to read and scan 278 files | 2 min 41 s | 4 s |
| Events | 37,364 | 37,364 |
| Files that raised at least one signal | 53 | 66 |
| Signals | 89 | 117 |
| Incidents (all real attacks) | 4 | 4 |

We went through the recordings that raised nothing and asked, for each: is the attack in events we read, and is it something our rules should cover? Where the answer was yes, we wrote or widened a rule:

| Rule | New or widened | Recordings it now catches | Technique |
| --- | --- | --- | --- |
| `proc_mshta_local_hta_or_dcom` | new | 3: mshta running a dropped HTA, LethalHTA over DCOM | T1218.005 |
| `proc_rundll32_proxy_execution` | new | 6: zipfldr `RouteTheCall`, advpack `RegisterOCX`, pcwutl `LaunchApplication`, `RunHTMLApplication` | T1218.011 |
| `proc_powershell_base64_inline` | new | 3: `FromBase64String` fed into `IEX` or a decompressor | T1059.001, T1027.010 |
| `sys_event_log_cleared` | new | 1, plus one lab artifact (below): System event 104, a log other than Security cleared | T1685.005 |
| `reg_startup_folder_redirected` | new | 1: the Startup folder pointed somewhere else | T1547.001 |
| `wmi_event_consumer_created` | new | 3: Sysmon 20, a permanent WMI event consumer | T1546.003 |
| `proc_script_host_runs_user_script` | widened to VBScript and `/E:` | 4 | T1059.005 |
| `net_proxy_binary_public_destination` | widened to WMIC | 1 more: WMIC fetching an XSL stylesheet from the internet | T1220 |

Each new rule has fire and no-fire tests like every other rule, and the simulated evaluation from phase 5 gives exactly the same results as before: 80 of 80 seen chains, 40 of 60 unseen, 93.8% incident precision. A fix for real data that broke the simulated benchmark would only swap one overfit for another.

**Lab artifacts.** 24 recordings start with the researcher clearing the Security log (event 1102) to get a clean recording, and one with a System log clear (104). Our log-clear rules rightly report them. In a real network a cleared log always deserves a look; here they are part of how the lab worked, not of the attack.

**What we left alone, on purpose:** downloads with bitsadmin and desktopimgdownldr (bitsadmin is phase 5's unseen variant, so a rule for it would spoil that test), browsers starting shells, lab traffic between private addresses (our network rules look for public destinations), old Security 4688 events with no parent process, PowerShell's own logs (no rules yet), scheduled tasks (phase 5's known gap), and the many credential-theft and UAC-bypass recordings, which are outside this project's scope.

## 4. The held-out set, scored once

### How a file is scored

The held-out folders name a technique, but not which events show it. So we score files, not events, and wrote the method down before the run:

- A file's **label** is the technique in its closest folder (or its file name).
- It is **in scope** when a rule claims that technique, or its parent, or one of its sub-techniques.
- It is **detected** when a rule tagged with that technique fired on the file.
- A file out of scope that raises signals is either another step of the same attack or a false alarm; a person checks which.

### Results

| | Before (phase 6) | After (phase 7) |
| --- | --- | --- |
| `.evtx` parser | python-evtx | evtx |
| Time for all 293 files | 45 s | 2 s |
| Events read | 11,131 | 12,812 |
| Files where no record could be read | 15 | 0 |
| Files that raised at least one signal | 40 | 45 |
| Incidents | 3, all real attacks | 5, all real attacks |
| Detected, of the 42 files in scope as frozen | 4 | 6 (14%) |
| Detected, of the 68 files in scope after the ID fix below | 7 | 9 (13%) |

Both versions are scored on the same files, the ones the new rules put in scope, so the comparison is fair. The new reader with the old rules also detects 7 of 68. So the parser change added 1,681 events but no detections here: those events are in logs no rule reads yet. Both new detections come from rules written for the development set: inline Base64 PowerShell (an encoded Metasploit payload) and the WMI event consumer (PowerLurk). Rules written on one dataset caught attacks in another, which is the evidence that they describe behaviour rather than those particular files.

The new version raised 169 signals. 90 of them are in one recording where every event log was cleared at once (one System 104 event per log).

### One bookkeeping bug, found after the run

The held-out folders use ATT&CK IDs from before version 19. "Clear Windows event logs" is filed under T1070.001, which is T1685.005 now, and the Defender tampering folder says T1562.001, which is T1685 now. The frozen method compared IDs as written, so it put 26 recordings out of scope that our rules do claim. The scanner now translates old IDs first, using a table in `bde/attack.py` (`RENAMED`), and prints each translation:

```
Older ATT&CK IDs read as their v20 IDs: T1070.001 -> T1685.005 (4 files), T1562.001 -> T1685 (9 files),
T1562.002 -> T1685.001 (13 files), T1562.004 -> T1686 (6 files).
```

This changed the bookkeeping, not the engine: the same rules fire on the same events. We report both numbers, 6 of 42 as frozen and 9 of 68 after the fix.

### Why only 13%?

We looked at all 59 misses one by one. They fall into four groups:

| Why it was missed | Files | Examples |
| --- | --- | --- |
| The evidence is only in event types no rule reads | 39 | PowerShell's script logs (13 files), Active Directory object auditing (4661, 4662, 5136), file-share access (5145), SQL Server audit (33205), Defender's own log (5007) |
| The folder's technique is broader than what our rules claim | 11 | Sticky-keys backdoors and a netsh helper filed under T1546 (we claim only its WMI sub-technique), installing WSL under T1564, `auditpol` under T1685.001 |
| Seen, but filed under another technique | 4 | CrackMapExec's obfuscated PowerShell flagged as a WMI-started hidden shell, with an incident; a certutil download, which we call T1105 and the folder calls T1140 |
| **True misses**: the evidence is in events we read | 5 | `sc config WinDefend start= disabled`, `Set-MpPreference -EnableControlledFolderAccess Disabled`, a Defender service turned off in the registry, Impacket's wmiexec in 4688 events with no parent process |

Put another way: in the 18 recordings where the evidence is in events the rules read and a rule describes the behaviour, the engine flagged 13 and missed 5. The full list is at the end of this page.

The true misses are the next rules worth writing. Several are close to rules we have: `proc_defender_disabled` only knows `-Disable... $true`, not `-Enable... Disabled`.

### Everything outside scope

Of the 225 recordings out of scope or without a label, 29 raised signals. 24 of them raised only a log-clear signal, and in each the clear is the file's first event: the lab again. The other 5 are real attack steps in recordings labelled with something else, such as an LSASS dump started through WMI with rundll32 and two full attack recordings (EternalRomance, WMIexec) where the engine also raised incidents. No signal fired on activity that didn't happen.

## 5. What to take into your report

- **A folder label is weak ground truth.** It names one technique for a whole file, it can be a parent that covers many behaviours, its ID can be out of date, and the file may show other steps too. Count with it, then read the misses.
- **Coverage depends on log sources.** The mapping document says T1059.001 is covered, and it is, for process creation. It is not, for PowerShell's own logs, which hold the evidence in 13 held-out files. Say which events a rule needs, not only which technique it detects.
- **Real recordings carry lab artifacts.** A log cleared before recording is a real event that isn't part of the attack.
- **Report the number you froze.** A held-out set measures the engine once. As soon as you look at its misses and write rules for them, it becomes a development set, and the next honest measurement needs new data.

## 6. Code tour

| File | What it does |
| --- | --- |
| `bde/readers/windows.py` | `evtx_backend()` picks the parser; `read_evtx()` skips and counts damaged records; `canonical_value()` writes typed values one way |
| `bde/external.py` | Scans a folder of recordings; reads technique labels from folder and file names; scores files in and out of scope |
| `bde/attack.py` | `RENAMED` and `current_technique()`: ATT&CK IDs that moved in version 19 |
| `bde/sigma/rule.py` | Adds the `Provider_Name` field (which component wrote the event) |
| `rules/sigma/` | 29 rules: the 6 new ones and 2 widened ones above |
| `tests/test_external.py` | Labels, scope, the report, ID translation |
| `tests/test_readers.py` | Canonical values, forbidden characters, damaged records, a missing parser |
| `tests/test_real_evtx.py` | One real recording (CC0, in `tests/fixtures/real/`), read with whichever parser is installed |

## 7. Try it, and a hands-on piece

```bash
python -m bde evaluate --external data/external/EVTX-to-MITRE-Attack
python -m bde evaluate --external data/external/EVTX-ATTACK-SAMPLES --all-files
python -m bde tree "data/external/EVTX-ATTACK-SAMPLES/Execution/exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx"
```

**Your turn: write the rule for one true miss.** The recording `ID4688-Defender service deactivation attempt.evtx` (under `T1562.001-...`) runs `sc config WinDefend start= disabled`, and the same for `Sense` and `mpssvc`.

1. Look at it first: `python -m bde tree "<path to the file>"`.
2. Create `rules/sigma/proc_security_service_disabled.yml`. Copy the layout of `proc_defender_disabled.yml` and match `sc.exe` with a command line that contains `config`, `start=` and `disabled`, and one of the services. Tag it `attack.defense-impairment` and `attack.t1685`.
3. In `tests/test_rules.py`, add a case it must fire on, and one it must stay quiet on, such as an admin running `sc config wuauserv start= disabled` to stop Windows Update. A test fails until both exist.
4. Run `python -m pytest`, then `python -m bde mapping` (the mapping test asks for it), then the held-out scan. The T1685 row should go from 0 to 1 detected.

Then notice what happened: you read a held-out file to write the rule, so that 1 is no longer a held-out result. Phase 7's number stays 9 of 68. The new rule needs new data to be measured.

## 8. Checkpoint questions

1. Why split public recordings into a development set and a held-out set, and why push the frozen rules before scoring?
2. Phase 6 could read nothing from 15 files and only printed a warning line for each. Why is that dangerous, and how does the scan show it now?
3. One parser writes `0x001fffff`, the other `0x1fffff`. Why does it matter, and where is it fixed?
4. The held-out score is 13%. Give two reasons that don't mean "the rules are bad".
5. After the run we fixed the old-ID bookkeeping and the number changed. Why is that acceptable, when changing a rule would not be?
6. 24 recordings outside scope raised only a log-clear signal. Are they false alarms?
7. The inline Base64 rule was written on the development set and fired on a held-out recording. What does that show?

<details>
<summary>Answers</summary>

1. Rules fixed on the files they're scored on measure memory of those files. A set that stays closed until the rules are frozen gives one honest measurement. Pushing first records, with a timestamp you can't edit later, which rules were measured.
2. An unread file looks like a clean log: "0 signals" means "no attack here" to anyone skimming, and a warning between hundreds of lines is easy to miss. The summary line now counts unreadable records and unreadable files, and the new parser reads every record of these 571 files.
3. A rule compares strings. `GrantedAccess: '0x1fffff'` never matches `0x001fffff`, so the rule would silently work with one parser and not the other. `canonical_value()` in `bde/readers/windows.py` writes hex numbers, GUIDs and booleans one way.
4. Any two of: the evidence is in event types we have no rules for (39 files, 13 of them PowerShell's own logs); the folder's technique is broader than what our rules claim (11); the engine saw the attack but filed it under another technique (4); the folder used old ATT&CK IDs (fixed). Only 5 are true misses.
5. The fix changed how files are counted, not what the engine detects: the same rules fire on the same events. We say so and report both numbers. Changing a rule after seeing the misses would tune the engine to the test.
6. No. The log really was cleared, and the rule is right to report it. It isn't part of the attack, because the researcher did it before recording, which is why we call them lab artifacts.
7. That the rule describes a behaviour (Base64 text decoded and run in one command), not the files it was written on. It's the best evidence in this phase that the new rules generalise.

</details>

---

<details>
<summary>All 68 in-scope held-out recordings, by result</summary>

**Detected (9):** ID1-WMI spwaning PowerShell process - WMImplant · ID4688-Encoded PowerShell MSF payload via process execution · ID4688-Group discovery via commandline · ID4688-Delete VSS backup (WMI) · ID4688-Delete Window backup (webadmin) · ID19-20-WMI registration via PowerLurk · ID104-1102-Event log cleared · ID4688-Clear event log attempt (native) · ID4688-Clear event log attempt (wmi)

**True misses (5):** ID1-WMIexec process execution · ID4688-5145-WMIexec execution via SMB · ID13-Defender service configuration disabled · ID4688-Defender critical features disabled (command) · ID4688-Defender service deactivation attempt

**Seen, filed under another technique (4):** 4624,4674,4688- CrackMap Exec SMB mimikatz · ID1-CrackMapExec payload execution · ID4688-SQL Server payload injectection for reverse shell (MSF) · ID4688-Certutil download

**The folder's technique is broader than what our rules claim (11):** ID4688-Obfuscated payload transfer via service name - Tchopper · ID4688-Edge payload download via command · ID1-CMD executed via sticky key call · ID11-New sethc file created from CMD copy · ID12,13-Stickey key registry update · ID13-WMIimplant registry crash control · ID4688-Stickey command reg update + execution · ID4688-netsh helper DLL · ID4688-Linux Subsystem installation (WSL) · ID4688-Audit policy clear attempt · ID4688-Audit policy deactivation attempt

**The evidence is only in event types no rule reads (39):** ID5145-DNS hosts files access via network share · ID400-800-CrackMapExec payload execution · ID4103-4104-CrackMapExec payload execution · ID3-7-10-Suspicious DLL loaded (CME+Mimikatz) · ID4103-4104-Payload download via PowerShell · ID800-4103-Interactive PipeShell over named pipe · ID4661-Local group enumeration with RID brutforce with CME · ID4661-SAM sensitive domain users & groups discovery · ID4662-Domain group enumeration CME · ID4799-4624-Local admin group enumerated by SharpHound · ID800-4103-4104-Domain group discovery via PowerShell · ID800-4103-4104-Local group discovery via PowerShell · ID800,4103,4104-Active Directory Forest PowerShell class · ID800-4103-4104-Delete VSS backup (PowerShell) · ID4656-Failed sethc replacement by CMD · ID5136-AdminSDholder backdoor obfuscation · ID5136-AdminSDholder permissions changed · ID800-4103-4104-WMI registration via PowerLurk · ID12-LSA Protect mode enabled RunAsPPL · ID4622-New SSP loaded in LSA · ID4664-symbolic link created · ID1-SYSMON driver unload (FilterManager) · ID5007-Defender threat exclusion (native) · ID8-Module Virtualization disabled (Credential Guard) · ID800-4103-4104 Defender critical features disabled (PowerShell) · ID800-4103-4104 Defender default action allow any (PowerShell) · ID800-4103-4104 Defender exclusion added (PowerShell) · six ID33205 SQL Server audit recordings · ID4719-Audit policy deactivation · ID4739-Domain policy changed by non system account · ID4885,4876,4877,5123,5124-ADCS PKI OCSP · ID4908-Special group table changed · ID541-DNS server auditing changed · ID800-4103-4104-Clear event log attempt

The file names are the dataset's own, spelling included. Which group a miss belongs in was decided by hand after the run, by reading each file's events.

</details>
