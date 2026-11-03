# Windows testing guide

This guide is for testing the engine on a Windows computer. It was built on a Mac, so the questions are: does everything work the same on Windows, and what does it find in **real** Windows logs?

There are three parts. Only Part A is needed; B and C go further.

| Part | What you do | Time | Needs admin? |
| --- | --- | --- | --- |
| **A. Does it work?** | Install, run the tests, run the demo, check the output is identical to the Mac's | 20 min | No |
| **B. Real logs** (optional) | Install Sysmon, use the computer normally for a while, run the engine on its logs | 30 min + some hours of normal use | Yes |
| **C. Safe attack steps** (optional, a VM is best) | Run a few harmless commands that look like attack steps, and see whether the engine notices | 20 min | Partly |

Nothing in this project runs real attack code. Part C's commands only print text, read information or write a small text file, and the guide removes everything afterwards.

At the end there's a **results checklist** to send back.

---

## Part A: Does it work?

### A1. Install Python

1. Open <https://www.python.org/downloads/windows/> and download the latest Python 3 (3.11 or newer).
2. Run the installer. On the first screen, tick **"Add python.exe to PATH"**, then **Install Now**.
3. Open **PowerShell** (Start menu → type `PowerShell`) and check:

   ```powershell
   py --version
   ```

   It should print `Python 3.11` or higher.

### A2. Get the project

Either with git:

```powershell
cd $HOME\Documents
git clone https://github.com/sufianabcy/behavioral-detection-engine.git
cd behavioral-detection-engine
```

or without git: on the GitHub page, **Code → Download ZIP**, unzip it into `Documents`, and `cd` into the unzipped folder.

> If Sufian sends you a branch name (for example `v2-rebuild`), use `git clone -b v2-rebuild ...`, or pick that branch on GitHub before downloading the ZIP. You're in the right place when the folder has `bde`, `rules`, `docs` and `tests` folders.

### A3. Set up a virtual environment

A virtual environment keeps this project's packages separate from the rest of the computer.

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

You should now see `(.venv)` at the start of the prompt. If PowerShell says running scripts is disabled, run this once and try the second line again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Every time you open a new PowerShell window later, `cd` back to the folder and run `.venv\Scripts\Activate.ps1` again.

### A4. Run the tests

```powershell
python -m pytest
```

**Expected:** `256 passed` (the time will vary). Anything failed or skipped: copy the whole output into the results.

### A5. Run the demo

```powershell
python -m bde demo
```

**Expected**, near the end:

```
   4 of 4 attack chains detected; 0 false alarms.
```

Then open the report:

```powershell
start out\demo\report.html
```

It opens in the browser. Check that it looks right: four incident cards, readable text, no broken characters. Try switching Windows to dark mode (Settings → Personalization → Colors) and reloading; the report should follow.

### A6. Check the output is byte-identical to the Mac's

The generator is deterministic: the same seed must give exactly the same file on every computer.

```powershell
python -m bde generate -o out\s.jsonl
```

The third line of output is a fingerprint. **Expected:**

```
SHA-256 739b8730f8ce3ca70c67221c29c124fc8ac3d1491862a3326b21599f15d1e219
```

Cross-check it with Windows' own tool (it prints the same number in capitals):

```powershell
Get-FileHash out\s.jsonl
```

If the numbers differ, that's an important finding: note both.

### A7. Windows-specific checks

These test things that behave differently on Windows.

1. **Box-drawing characters in the console:**

   ```powershell
   python -m bde tree data\samples\macro_chain_demo.jsonl
   python -m bde tree data\samples\macro_chain_demo.jsonl --ascii
   ```

   The first should draw lines like `├──`. If you see `?` or garbled characters instead, note it (and which program: Windows Terminal, PowerShell window or Command Prompt). The second uses plain `|--`.

2. **Output redirected to a file:**

   ```powershell
   python -m bde detect out\s.jsonl > out\detect.txt
   notepad out\detect.txt
   ```

   It should not crash, and the text should be readable.

3. **A Windows XML export** (UTF-16, the format `wevtutil` writes in PowerShell 5):

   ```powershell
   python -m bde convert tests\fixtures\sysmon_export.xml -o out\fixture.jsonl
   ```

   Expected: `Wrote 3 events`.

4. **The mapping document matches the rules:**

   ```powershell
   python -m bde mapping --check
   ```

   Expected: `... is up to date.`

5. **The evaluation:**

   ```powershell
   python -m bde evaluate
   ```

   Expected, among other lines: `seen chains overall: 80 of 80 detected (100.0%)` and `Incidents: 128 raised, 120 true, 8 false alarms -> precision 93.8%`.

That's Part A done.

---

## Part B: Real logs (optional)

Here the engine reads real Sysmon logs from your computer. The question is **how many false alarms it raises on normal use**. On simulated data it's about 3 per day for 11 computers; real life will be different, and that's worth knowing.

### Before you start: privacy

Real logs record what you do: program names, command lines, file paths, user and computer names. The config below keeps this small (no websites, no document names, no DNS), but:

- Keep the exported logs on your computer. Don't commit them to git or upload them. The `data\external\` folder is ignored by git, so save them there.
- For the results, send the **engine's output** (the summary lines and incident titles), not the raw logs, unless you're comfortable sharing them.
- You can remove Sysmon completely at the end (step B6).

### B1. Install Sysmon

Sysmon is a free Microsoft tool that writes detailed logs about process starts, connections and more.

1. Download it from <https://learn.microsoft.com/sysinternals/downloads/sysmon> (**Download Sysmon**, a zip file) and unzip it, for example to `C:\Tools\Sysmon`.
2. Open **PowerShell as administrator** (right-click PowerShell → Run as administrator).
3. Install it with this project's small config:

   ```powershell
   cd C:\Tools\Sysmon
   .\Sysmon64.exe -accepteula -i $HOME\Documents\behavioral-detection-engine\tools\sysmon-minimal.xml
   ```

   Use `Sysmon64a.exe` instead on an ARM computer (for example a Surface Pro X or a Copilot+ PC with Snapdragon). Change the path if you put the project somewhere else.

   If it complains about the schema version, run `.\Sysmon64.exe -s`, look at the `schemaversion` it prints on the first lines, put that number in `tools\sysmon-minimal.xml`, and install again.

4. Check it's logging:

   ```powershell
   Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5
   ```

   You should see recent events (ID 1 is a process start).

### B2. Use the computer normally

Work as usual for a few hours, or a day: browse, open documents, run updates. The more normal activity, the better the test.

### B3. Export the logs

In the **administrator** PowerShell:

```powershell
cd $HOME\Documents\behavioral-detection-engine
mkdir data\external -Force
wevtutil epl Microsoft-Windows-Sysmon/Operational data\external\sysmon.evtx
wevtutil epl Security data\external\security.evtx
```

The second file adds logons (event 4624); the engine uses them for the cross-host link. You can close the administrator window now.

### B4. Run the engine

Back in your normal PowerShell with `(.venv)` active:

```powershell
python -m bde stats data\external\sysmon.evtx
python -m bde convert data\external -o out\real.jsonl
python -m bde detect out\real.jsonl --out out\real
```

`convert` reads the `.evtx` files once (that's the slow part, a minute or two for a big log) and saves them in the engine's own format. If `detect` finds incidents, open `out\real\report.html` and have a look.

Also run the external-data scan, which lists what fired per file:

```powershell
python -m bde evaluate --external data\external
```

### B5. What to note

- How long Sysmon ran, and roughly what you did in that time.
- From `stats`: how many events, how many hosts.
- From `detect`: how many signals and incidents.
- For each incident: its title, and what normal thing caused it, if you can tell from the report. **Every incident here is a false alarm** (unless the computer really is compromised!), so each one is useful information for tuning the rules.

### B6. Remove Sysmon (when you're done)

In an administrator PowerShell:

```powershell
cd C:\Tools\Sysmon
.\Sysmon64.exe -u
```

Delete `data\external\*.evtx` and `out\real*` if you don't want to keep the logs.

---

## Part C: Safe attack steps (optional)

This part runs a few **harmless** commands that look like steps of the simulated attacks, and checks that the engine notices them in real Sysmon logs. Nothing downloads, nothing is disabled, and everything is undone at the end.

**Do this in a virtual machine or a spare test computer if you can.** The commands are harmless, but running attack-like commands on a computer you depend on is a bad habit, and antivirus may occasionally flag the encoded command. Part C needs Sysmon from Part B (B1).

Open a normal (not administrator) PowerShell. Run the steps within about 10 minutes of each other, so they're close in time.

### C1. Hidden, encoded PowerShell (chain 1's execution step)

```powershell
Start-Process powershell.exe -ArgumentList '-nop -w hidden -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFMASQBNAFUATABBAFQARQBEAC0AUwBUAEEARwBFAC0AMgAnAA=='
```

This starts a hidden PowerShell that runs `Write-Output 'SIMULATED-STAGE-2'` and exits. You can check the decoding yourself:

```powershell
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFMASQBNAFUATABBAFQARQBEAC0AUwBUAEEARwBFAC0AMgAnAA=='))
```

### C2. Discovery commands (chain 3's last step)

```powershell
whoami /all
nltest /dclist:
net group "Domain Admins" /domain
```

On a computer that isn't in a company domain, the last two print an error. That's fine: Sysmon logs the command anyway, and that's what the engine reads.

### C3. certutil decodes a file (chain 2's decode step)

```powershell
Set-Content C:\Users\Public\bde-test.txt ([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('BDE TEST FILE')))
certutil -decode C:\Users\Public\bde-test.txt C:\Users\Public\bde-test.out
Get-Content C:\Users\Public\bde-test.out
```

The last line prints `BDE TEST FILE`.

### C4. A Run key set by PowerShell (chain 1's persistence step)

```powershell
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name BDE-Test -Value 'powershell.exe -w hidden -c Write-Output BDE-TEST' -PropertyType String
Remove-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name BDE-Test
```

The value is removed straight away; Sysmon has already logged that it was set.

### C5. Look-alikes that should stay quiet

These are normal admin commands that resemble attack steps. They should **not** produce signals.

```powershell
certutil -hashfile C:\Windows\System32\notepad.exe SHA256
whoami
```

### C6. Export and detect

In an **administrator** PowerShell, from the project folder:

```powershell
wevtutil epl Microsoft-Windows-Sysmon/Operational data\external\sysmon-partc.evtx
```

Then in your normal PowerShell with `(.venv)` active:

```powershell
python -m bde detect data\external\sysmon-partc.evtx --out out\partc
```

**Expected signals** (in the incident story or in "Signals outside any incident" in `out\partc\report.html`):

| Step | Rule(s) that should fire |
| --- | --- |
| C1 | `proc_powershell_encoded_command`, `proc_powershell_hidden_window` |
| C2 | `proc_whoami_privileges`, `proc_nltest_domain_discovery`, `proc_domain_group_discovery` |
| C3 | `proc_certutil_decode` |
| C4 | `reg_run_key_script_engine`, `reg_run_key_modified` |
| C5 | none |

If C1 to C4 happened within about 10 minutes, **risk scoring** should also raise one incident ("Risky activity on <your computer>"), because those steps span several ATT&CK tactics. No **chain** incident is expected: the chains need things Part C deliberately leaves out, such as Word starting PowerShell or a connection to the internet.

### C7. Clean up

```powershell
Remove-Item C:\Users\Public\bde-test.txt, C:\Users\Public\bde-test.out
```

Then remove Sysmon as in B6 if you're finished.

---

## Results checklist

Copy this into a message and fill it in. "Same as expected" is a perfectly good answer.

```
Computer: Windows 10 / 11, version ____ ; x64 or ARM: ____
Python version (py --version): ____
How you got the project: git clone / ZIP, branch: ____

PART A
A4 tests:            ___ passed, ___ failed, ___ skipped   (expected 256 passed)
A5 demo:             "_ of 4 attack chains detected; _ false alarms"   (expected 4 of 4, 0)
A5 report.html:      looks right? dark mode works?  ____
A6 fingerprint:      ____________________   (expected 739b8730...d1e219)
A6 Get-FileHash:     matches?  yes / no
A7.1 tree drawing:   lines OK / garbled (which terminal?) ____
A7.2 redirect:       OK / error ____
A7.3 XML convert:    "Wrote 3 events"?  ____
A7.4 mapping check:  up to date?  ____
A7.5 evaluate:       seen 80 of 80?  precision 93.8%?  ____
Anything odd: ____

PART B (optional)
Sysmon version and how long it ran: ____
What the computer was used for meanwhile: ____
stats: ___ events
detect: ___ signals, ___ incidents
Each incident: title, and what normal activity caused it: ____

PART C (optional)
VM or real computer: ____
Rules that fired for C1, C2, C3, C4: ____
Anything fired for C5?  ____
Risk incident raised?  ____
Anything that didn't fire but should have: ____
```

## If something goes wrong

| Problem | Fix |
| --- | --- |
| `py` isn't recognized | Reinstall Python and tick "Add python.exe to PATH", or use the full path, e.g. `C:\Users\<you>\AppData\Local\Programs\Python\Python313\python.exe` |
| `Activate.ps1 cannot be loaded` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or use Command Prompt and `.venv\Scripts\activate.bat` |
| `No module named bde` | You're not in the project folder. `cd` to the folder that contains `bde` |
| `No module named yaml` or `evtx` | The virtual environment isn't active, or the install didn't run: `.venv\Scripts\Activate.ps1`, then `python -m pip install -r requirements.txt` |
| `wevtutil` says access is denied | Use an administrator PowerShell for the export commands |
| Sysmon says the config is invalid | See B1 step 3 about the schema version, and send the error text |
| Antivirus blocks C1 | Note it in the results (that's interesting too) and skip to C2 |
