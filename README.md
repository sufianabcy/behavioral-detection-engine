# Behavioral Detection Engine (v2)

A course project that detects living-off-the-land (LOLBin) attacks, where attackers misuse built-in Windows tools such as PowerShell, WMI and certutil, by reading **behaviour in Windows logs** instead of looking for malware files. Every detection is mapped to MITRE ATT&CK (Enterprise v20).

The engine runs on **macOS (including Apple Silicon M1/M2/M3) and Windows**. It only *reads* logs; it never runs attack code.

```
logs (.evtx, XML, JSONL)
  -> normalizer and process trees        phase 1
  -> Sigma rules: signals                phase 3
  -> chain rules, risk scoring,
     cross-host links: incidents         phase 4
  -> text, HTML, JSON, ATT&CK Navigator  phase 6
```

A scenario generator (phase 2) simulates a small company network with attacks hidden in normal work, and phase 5 measures the engine against that ground truth.

## Results

On the demo (seed 7, 1,375 events) the engine raises **4 incidents for the 4 attack chains, with 0 false alarms**, and traces the server attacks back to the first infected workstation. Over 20 seeds it detects 80 of 80 seen chains and 40 of 60 unseen variants (one variant, lateral movement by remote scheduled task, is a documented gap), with 93.8% incident precision. 24 hours of normal work produce 3 false incidents, all from one known cause. Details: [phase 5](docs/phase-5-evaluation.md).

On public recordings of real attack tools (phase 7), scored once on a held-out dataset after the rules were frozen, it flags the folder's own ATT&CK technique in **9 of the 68 recordings a rule claims** and raises **5 incidents, all real attacks**. Most misses are attacks recorded only in logs it has no rules for yet, such as PowerShell's own logs; every miss is explained in [phase 7](docs/phase-7-real-data.md).

## Status

| Phase | What it adds | Explainer |
| --- | --- | --- |
| 1. Foundations | Event model, normalizer (.evtx, XML, JSONL), process trees | [phase-1-foundations.md](docs/phase-1-foundations.md) |
| 2. Scenario generator | 4 attack chains, 3 unseen variants, benign twins, labels, seeds | [phase-2-scenarios.md](docs/phase-2-scenarios.md) |
| 3. Signals | A small Sigma evaluator and 23 rules | [phase-3-signals.md](docs/phase-3-signals.md) |
| 4. Correlation | Chain rules over the process tree, risk scoring, cross-host origin | [phase-4-correlation.md](docs/phase-4-correlation.md) |
| 5. Evaluation | Recall, precision, time to detect, soak test, public datasets | [phase-5-evaluation.md](docs/phase-5-evaluation.md) |
| 6. Deliverables | Demo, HTML report, ATT&CK mapping document, Navigator layers | [phase-6-deliverables.md](docs/phase-6-deliverables.md) |
| 7. Real attack logs | Public recordings as development and held-out sets, a faster `.evtx` parser, 6 new rules | [phase-7-real-data.md](docs/phase-7-real-data.md) |

All seven phases are done. Also: the [ATT&CK mapping](docs/attack-mapping.md) (generated), the [decision log](docs/decisions.md), and the [Windows testing guide](docs/windows-testing-guide.md).

## Setup on a Mac (M1, M2, M3)

You need Python **3.11 or newer**. Check first:

```bash
python3 --version
```

If it says 3.9 (Apple's built-in version) or anything below 3.11, install a newer one, either from [python.org](https://www.python.org/downloads/macos/) (the "universal2" installer runs natively on Apple Silicon) or with Homebrew: `brew install python@3.12`. Then, in Terminal:

```bash
cd ~/Documents/Course-folders/Malware/behavioral-detection-engine-v2
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

You'll see `(.venv)` at the start of the prompt. Run `source .venv/bin/activate` again in every new Terminal window.

Made `.venv` before phase 7? The `.evtx` parser changed, so recreate it: run `deactivate` if `(.venv)` is showing, then `python3 -m venv --clear .venv`, then activate it and install `requirements.txt` again.

## Setup on Windows

Install Python 3.11 or newer from [python.org](https://www.python.org/downloads/windows/) and tick "Add python.exe to PATH". Then, in PowerShell:

```powershell
cd <path>\behavioral-detection-engine-v2
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell refuses to run `Activate.ps1`, either run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use Command Prompt with `.venv\Scripts\activate.bat` instead. If `.venv` was made before phase 7, recreate it first with `py -m venv --clear .venv`. The [Windows testing guide](docs/windows-testing-guide.md) walks through everything step by step.

## Run it

From the project folder, with `.venv` active. The commands are the same on both systems.

```bash
python -m bde demo                                   # the whole thing: simulate, detect, score, report
python -m bde generate -o out/s.jsonl                # simulated logs (seed 7, chains 1 to 4)
python -m bde detect out/s.jsonl --out out/report    # incidents, plus report.html, incidents.json, a Navigator layer
python -m bde evaluate                               # 20 seeds and a 24-hour soak test (about 2 s)
python -m bde evaluate --external data/external/EVTX-to-MITRE-Attack   # real recordings, scored by ATT&CK label
python -m bde rules                                  # list and validate the rules
python -m bde mapping                                # regenerate docs/attack-mapping.md
python -m bde navigator                              # ATT&CK Navigator layer of rule coverage

python -m bde tree out/s.jsonl --host WKSTN-23 --match powershell   # explore process trees
python -m bde stats some_log.evtx                    # what's in a log
python -m bde convert some_log.evtx -o out/log.jsonl # normalize once, reuse fast
python -m bde --help                                 # every command; each has --help too
```

Inputs can be `.evtx` files, XML exports from Event Viewer or `wevtutil`, our `.jsonl` format, or a folder of them. After the demo, open `out/demo/report.html` in a browser.

## Run the tests

```bash
python -m pytest
```

Expect **321 passed** in a few seconds. They include a check that `python -m bde generate` produces byte-identical output on every computer, safety checks on everything the generator writes, fire and no-fire cases for every rule, a real `.evtx` recording read with whichever parser is installed, and a check that the mapping document matches the rules.

## Project layout

```
bde/                  the engine (a Python package)
  event.py            the normalized Event
  readers/            .evtx, XML and JSONL readers (the normalizer)
  tree.py             process-tree builder, has_ancestor()
  render.py           text drawing of trees
  generator/          the simulated company: normal work, twins, attack chains
  sigma/              the Sigma rule evaluator
  signals.py          runs Sigma rules over events
  correlation.py      chain rules, risk scoring, cross-host origin
  engine.py           detect(events): the whole pipeline
  evaluate.py         recall, precision, time to detect, soak test
  external.py         scans folders of public recordings and scores them by ATT&CK label
  attack.py           ATT&CK v20 techniques and tactics
  report/             text, HTML, JSON, Navigator layers, mapping document
  __main__.py         the command line
rules/
  sigma/              29 Sigma rules (one per file)
  chains/             3 chain rules
  risk.yml            risk scoring settings
data/samples/         a small hand-made sample (ours, safe to share)
data/external/        public datasets you download (git-ignored)
docs/                 phase explainers, mapping, decisions, Windows guide
tools/                a minimal Sysmon config for collecting real logs
tests/                pytest tests and fixtures
```

## Safety

- Nothing here executes attack code. Simulated events are text records.
- Encoded PowerShell in simulated events decodes to `Write-Output 'SIMULATED-STAGE-2'` (attacks) or a harmless `Get-CimInstance Win32_OperatingSystem` query (normal admin tools). A test decodes every one.
- All "internet" addresses use reserved documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and reserved `.example` domains. A test checks every address and domain.
- Public datasets are event logs only; this project never downloads malware. They stay in `data/external/`, except one public-domain recording of an admin tool (PsExec) that the tests read, in `tests/fixtures/real/`.
