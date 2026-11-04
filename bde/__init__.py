"""bde: a behavioral detection engine for LOLBin attack chains.

  event.py        the normalized Event that every log source is turned into
  readers/        the normalizer: .evtx, XML exports and our JSONL -> Event
  tree.py         rebuilds process trees from Sysmon events
  render.py       draws those trees as text
  generator/      simulated company network: normal work, look-alikes and attacks (phase 2)
  sigma/          a small Sigma rule evaluator (phase 3)
  signals.py      runs the Sigma rules over events (phase 3)
  correlation.py  chain rules, risk scoring, cross-host links (phase 4)
  engine.py       the whole pipeline in one call: detect(events)
  evaluate.py     precision, recall, time to detect, soak test (phase 5)
  external.py     scans public recordings and scores them by ATT&CK label (phase 7)
  attack.py       the ATT&CK v20 techniques and tactics we use
  report/         text, HTML, JSON, Navigator layers, mapping document (phase 6)
  __main__.py     the command line: python -m bde --help
"""

__version__ = "0.3.0"
