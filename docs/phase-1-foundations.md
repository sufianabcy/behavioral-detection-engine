# Phase 1: Foundations

Phase 1 teaches the engine to **read Windows logs and rebuild who started what**. No detection yet: before you can spot an attack chain, you need clean events and the process trees they form.

When you finish this phase you can run:

```bash
python -m bde tree data/samples/macro_chain_demo.jsonl
```

and see the sample attack as a tree: Outlook saves an attachment, Word opens it, Word starts a hidden PowerShell, and PowerShell then looks up a domain, connects out, drops a script and adds a Run key.

---

## 1. What a Windows event looks like

Every Windows event has two parts:

| Part | What it holds | Example |
| --- | --- | --- |
| **System** | The same fields for every event | `EventID` 1, `TimeCreated`, `Computer` WKSTN-07, `Channel` Microsoft-Windows-Sysmon/Operational |
| **EventData** | Name/value pairs that depend on the event type | `Image`, `CommandLine`, `ProcessGuid`, `ParentImage`, ... |

Here is a trimmed Sysmon process-create event, as Windows stores it (the full one is in `tests/fixtures/sysmon_export.xml`):

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2026-11-03T09:14:05.1101834Z" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WKSTN-07.corp.example</Computer>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-11-03 09:14:05.093</Data>
    <Data Name="ProcessGuid">{3F1C2A90-71F9-6543-2D01-000000000A00}</Data>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -nop -w hidden -enc VwByAGkA...</Data>
    <Data Name="User">CORP\jsmith</Data>
    <Data Name="ParentProcessGuid">{3F1C2A90-71F6-6543-2C01-000000000A00}</Data>
    <Data Name="ParentImage">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data>
  </EventData>
</Event>
```

Read it as a sentence: *on WKSTN-07 at 09:14:05, user jsmith's Word started PowerShell with a hidden window and an encoded command.* That one sentence is already suspicious, and it all comes from the EventData.

Note the two times. `UtcTime` (in EventData) is when the process started. `TimeCreated` (in System) is when Windows wrote the event down, which can be slightly later. The engine uses `UtcTime` when it exists.

## 2. The Sysmon events this project uses

[Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) is a free Microsoft tool that writes much richer events than Windows does by default. We use five of its event IDs:

| Sysmon ID | Event | What it tells you | In the sample |
| --- | --- | --- | --- |
| 1 | Process create | Which program started, its full command line, its parent | Word starting PowerShell |
| 3 | Network connection | A process connected to an IP and port | PowerShell to 203.0.113.10:443 |
| 11 | File create | A process wrote a new file | PowerShell dropping `upd.ps1` |
| 13 | Registry value set | A process changed a registry value | PowerShell adding a Run key |
| 22 | DNS query | A process looked up a domain name | `cdn.update.example` |

Event IDs only mean this inside the Sysmon log. Other logs reuse the same small numbers for unrelated things, which is why every `Event` also carries its `channel`. Chain 3 (WMI) will also use **Security event 4624**, a logon, which is in the sample on WKSTN-12.

## 3. Why ProcessGuid beats PID

Every process gets a **process ID (PID)**, a number like 6232. When a process exits, Windows can hand the same number to a new, unrelated process. If the tree linked children to parents by PID, a child could end up under the wrong parent:

```
09:00  a.exe starts with PID 4242
09:10  from_a.exe starts; its parent PID is 4242       (correct: a.exe)
09:20  a.exe exits
09:30  b.exe starts and gets PID 4242 again
09:40  from_b.exe starts; its parent PID is 4242       (PID alone can't tell a.exe from b.exe)
```

Sysmon solves this with a **ProcessGuid**: a long ID that is unique for every process start, plus a **ParentProcessGuid** on every process-create event. The tree links by GUID, so this can't happen. `test_reused_pid_does_not_confuse_the_tree` in `tests/test_tree.py` replays exactly the timeline above.

## 4. The normalizer and our JSONL format

Logs arrive in different containers: binary `.evtx` files, XML exports, and (from phase 2) our own generator. The **normalizer** (`bde/readers/`) turns all of them into one Python object, `Event` (`bde/event.py`):

```
Event(event_id=1, timestamp=2026-11-03 09:14:05.093 UTC,
      host="WKSTN-07.corp.example", channel="Microsoft-Windows-Sysmon/Operational",
      data={"Image": "C:\\...\\powershell.exe", "CommandLine": "...", ...},
      meta={"label": "malicious", "chain": "chain-1", "stage": "execution"})
```

`data` keeps Sysmon's own field names on purpose. The Sigma rules in phase 3 are written against those exact names (`Image`, `CommandLine`, `ParentImage`), so the rules will work on our events without any translation.

`meta` holds things Windows didn't write: which file an event came from, and for generated data the **ground-truth label** (malicious or benign, which chain, which stage). Phase 5 uses those labels to measure how well the engine does.

On disk we store events as **JSON Lines**: one JSON object per line, UTF-8, Unix line endings. `python -m bde convert some.evtx -o some.jsonl` turns a slow-to-parse `.evtx` into this format once, so later runs are fast.

## 5. How the process tree is built

`bde/tree.py` does four things:

1. Sorts all events by time, oldest first.
2. For each **process-create** event (ID 1), creates a node for the new process and links it to its parent by `ParentProcessGuid`.
3. If the parent never appeared in the log (it started before logging began, like `explorer.exe` in the sample), creates a **placeholder** from what the child's event says about it: its image, PID and command line. That's what "started before the log began" means in the output.
4. For every other Sysmon event that has a `ProcessGuid` (network, file, registry, DNS), attaches it to that process as **activity**.

Events with no ProcessGuid, like the Security logon, are counted as skipped. The tree can't place them, but phase 4 will still use them.

## 6. Code tour

| File | What it does |
| --- | --- |
| `bde/event.py` | The `Event` class, time parsing, and small helpers (`windows_basename`, `clean_guid`) |
| `bde/readers/windows.py` | Reads `.evtx` files (through python-evtx) and XML exports into `Event`s |
| `bde/readers/jsonl.py` | Reads and writes our JSONL format |
| `bde/readers/__init__.py` | `read_events(path)`: picks the right reader by file extension; also reads whole folders |
| `bde/tree.py` | `ProcessTree`, `ProcessNode`, `ancestry()`, `has_ancestor()`, `lineage()` |
| `bde/render.py` | Draws trees as text, cutting long lines in the middle so both ends stay visible |
| `bde/__main__.py` | The command line: `stats`, `tree`, `convert` |
| `data/samples/macro_chain_demo.jsonl` | 12 hand-made events: chain 1 on WKSTN-07, normal admin work on WKSTN-12 |
| `tests/` | Tests for every module (phase 1's are `test_event.py`, `test_readers.py`, `test_tree.py`, `test_has_ancestor.py`) |

## 7. Windows and Mac details in this phase

- **Paths inside logs are Windows paths, even on your Mac.** `pathlib.Path` follows the rules of the computer the code runs on, so on macOS it would not split `C:\Windows\System32\cmd.exe` at the backslashes. The code uses `PureWindowsPath` for paths found in logs, and `Path` only for files on your own disk.
- **Always say `encoding="utf-8"`.** Python on Windows has historically defaulted to an older code page, which garbles non-English text. Every file the code opens names its encoding.
- **XML exports from Windows can be UTF-16.** `wevtutil ... > out.xml` in Windows PowerShell 5 saves UTF-16; the XML reader detects that.
- **Box-drawing characters fall back to ASCII** when the output can't show them, for example when output is redirected to a file on an older Windows setup. `--ascii` forces it.

## 8. Try it

From the project folder, with the virtual environment active (setup steps are in the README):

```bash
python -m bde stats data/samples/macro_chain_demo.jsonl
python -m bde tree  data/samples/macro_chain_demo.jsonl
python -m bde tree  data/samples/macro_chain_demo.jsonl --match certutil
python -m bde convert tests/fixtures/sysmon_export.xml -o out/fixture.jsonl
```

### Then try real attack data

1. Open [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) in your browser. It holds about 200 `.evtx` files recorded while real attack tools ran, grouped in folders by ATT&CK tactic.
2. Open a folder such as *Execution* or *Lateral Movement*, pick a file whose name mentions **sysmon**, and use **Download raw file**.
3. Save it into `data/external/` (create the folder; git ignores it, because the datasets are GPL-licensed and shouldn't be copied into your repo).
4. Explore it:

```bash
python -m bde stats data/external/<file>.evtx
python -m bde tree  data/external/<file>.evtx --match powershell
```

If `tree` says there are no Sysmon events, `stats` will show what the file holds instead. Some files only contain Security-log events, which have no ProcessGuid, so phase 1 can't draw them. If anything errors out, send me the file name and the message.

## 9. Checkpoint questions

Answer these in your own words first. They are also good viva practice. Model answers are below the questions.

1. Which part of a Windows event is the same for every event type, and which part changes?
2. Why does the tree link processes by ProcessGuid and not by PID? Describe a concrete case where PID linking goes wrong.
3. In the sample, `explorer.exe` shows "started before the log began". What does that mean, and where did the tree get its PID from?
4. Under the attack PowerShell you see `dns`, `net`, `file` and `reg` lines. Which Sysmon event IDs produced them, and what would an analyst conclude from that sequence?
5. Why does the code use `PureWindowsPath` for `Image` paths but `Path` for files on your disk?
6. WKSTN-12 also runs PowerShell and certutil. Besides the program names, what makes that tree look harmless? (This is the question phase 3 turns into rules.)

<details>
<summary>Model answers</summary>

1. The **System** part is the same for every event: EventID, TimeCreated, Computer, Channel and a few more. The **EventData** part changes with the event type: a process start has `Image` and `CommandLine`, a network event has `DestinationIp` and `DestinationPort`.
2. A PID is only unique while the process is running. When it exits, Windows can give the same number to a new, unrelated process, so a later child that names "parent PID 4242" could be attached to the wrong parent: in the timeline in section 3, `from_b.exe` would land under `a.exe`. A ProcessGuid is unique for every process start and is never reused, so the link can't go wrong. That's the case `test_reused_pid_does_not_confuse_the_tree` replays.
3. explorer.exe started before logging began (it starts at logon, and the sample begins later), so no process-create event for it exists in the log. The tree made a **placeholder** node from what its child's event says about its parent: `ParentImage`, `ParentProcessId` and `ParentCommandLine` in Outlook's process-create event. That's where the PID comes from.
4. `dns` is Sysmon **22** (DNS query), `net` is **3** (network connection), `file` is **11** (file create) and `reg` is **13** (registry value set). In that order they read: look up a server, connect to it, save a script that was probably downloaded, and make it run at every logon. That's command and control, ingress tool transfer and persistence, all from a PowerShell that Word started. An analyst would treat the host as compromised.
5. Paths inside logs are Windows paths, whatever computer reads them. `pathlib.Path` follows the rules of the computer running the code, so on a Mac it treats `\` as an ordinary character and can't split `C:\Windows\System32\cmd.exe` into folder and file name. `PureWindowsPath` always uses Windows rules. Files on your own disk are local paths, so `Path` is right for them.
6. The context. PowerShell is started by a person from Explorer (not by Word), in a visible window, runs a named script rather than an encoded blob, and certutil computes a hash (`-hashfile`) instead of downloading from a URL. Nothing connects outside the company, writes a script to a user folder or adds a Run key. Phase 3's rules and phase 2's benign twins are built around exactly these differences.

</details>

## 10. `has_ancestor()`

Detection rules constantly ask "does this process descend from X?". An Office program anywhere above PowerShell is a classic phishing sign, even if `cmd.exe` sits in between. Phase 4's chain-1 rule uses this function for exactly that (its `ancestor:` list).

This started as an exercise; it is now written in `bde/tree.py`:

```python
wanted = {name.casefold() for name in image_names}   # read the names once, into a set
parents = ancestry(node)                             # parents, nearest first
if max_depth is not None:
    parents = parents[:max_depth]                    # max_depth=1: the parent only
return any(parent.name.casefold() in wanted for parent in parents)
```

Three details are worth understanding:

- **`casefold()`**, not `lower()`: Windows file names ignore case, and `casefold()` is Python's case-insensitive comparison for any language.
- **The set is built first.** `image_names` may be a generator, which can be read only once. Reading it inside the loop would work for the first parent and find nothing for the next. `test_accepts_any_iterable_of_names` checks this.
- **The node itself isn't checked.** `ancestry()` starts from the parent, so PowerShell isn't its own ancestor.

```bash
python -m pytest tests/test_has_ancestor.py -v
```
