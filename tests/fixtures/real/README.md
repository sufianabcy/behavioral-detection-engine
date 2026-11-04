# A real recording, for the reader tests

`psexec_as_system_sysmon.evtx` is one public recording, copied unchanged from
[EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack)
by mdecrevoisier, which is dedicated to the public domain under
[CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/). Thank you.

- Original path: `EVTX_full_APT_attack_steps/ID11,13,17,18-PSexec as system execution.evtx`
- Dataset version: commit `474856008f037ccd42753f02a631b42690195829`
- SHA-256: `2652560b4da35c983974408316b15a5932c6e69fa21a5193c769622874039886`

It holds 15 Sysmon events from a lab computer: Sysinternals PsExec starting
`cmd.exe` as SYSTEM through its PSEXESVC service. There is no attack code in
it, only the log of an admin tool running.

It is here so that the tests read a real binary `.evtx` file, with whichever
parser is installed, on every computer that runs them (`tests/test_real_evtx.py`).
Phase 7 explains why that matters. The rest of the public recordings stay out
of this repository, in `data/external/`.
