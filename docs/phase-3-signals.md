# Phase 3: Signals with Sigma rules

Phase 3 adds the first layer of detection: **signals**. A signal is one rule matching one event, such as "certutil downloaded something from a URL". Signals are deliberately small and a bit noisy. On their own they are hints; phase 4 decides which hints, together, are an attack.

```bash
python -m bde rules                       # list and validate every rule
python -m pytest tests/test_rules.py -v   # each rule against events that must and must not trigger it
```

---

## 1. What Sigma is

[Sigma](https://sigmahq.io) is an open, vendor-neutral format for detection rules, written in YAML. A rule written in Sigma can be converted to Splunk, Elastic, Microsoft Sentinel and others, which is why most published detection content (for example the [SigmaHQ rule repository](https://github.com/SigmaHQ/sigma)) uses it. Learning it is a skill that transfers directly to SOC work.

Here is one of our rules, `rules/sigma/proc_certutil_download.yml`, trimmed:

```yaml
title: certutil downloads a file from a URL
name: proc_certutil_download
id: 277efcb9-8958-4688-aa4f-63512b8f9e23
level: high
logsource:
  product: windows
  category: process_creation     # = Sysmon event 1 (and Security 4688)
detection:
  selection_img:
    - Image|endswith: '\certutil.exe'
    - OriginalFileName: 'CertUtil.exe'   # still matches if the file was renamed
  selection_flag:
    CommandLine|windash|contains:
      - ' -urlcache '
      - ' -verifyctl '
      - ' -url '
  selection_url:
    CommandLine|contains: ['http://', 'https://', 'ftp://']
  condition: all of selection_*
tags:
  - attack.command-and-control
  - attack.t1105
falsepositives:
  - Admins fetching a certificate revocation list (CRL) by hand
```

Read the `detection` as:

- Each named block (`selection_img`, `selection_flag` ...) is a **search identifier**.
  - Inside a block, all fields must match (AND).
  - A list of values means any of them (OR).
  - A list of blocks, like `selection_img`, means any block.
- `condition` combines the blocks with `and`, `or`, `not`, brackets, `1 of selection_*` and `all of them`.
- Field names are **Sysmon's own** (`Image`, `CommandLine`, `ParentImage`). That's why phase 1 kept them in `Event.data` (decision 3).

## 2. Modifiers

The part after `|` changes how a value is compared. We support the ones our rules need:

| Modifier | Meaning | Example |
| --- | --- | --- |
| *(none)* | Whole value, ignoring case | `Image: 'C:\Windows\System32\cmd.exe'` |
| `contains`, `startswith`, `endswith` | Part of the value | `Image|endswith: '\powershell.exe'` |
| `all` | Every listed value must match, not any | `CommandLine|contains|all: [' group', '/domain']` |
| `windash` | `-` may also be `/` or a Unicode dash | `-urlcache` also matches `/urlcache` |
| `re` (+ `i`, `m`, `s`) | Regular expression (+ flags) | the encoded-command rule |
| `cased` | Case matters | |
| `exists` | Field present or absent | `User|exists: true` |
| `cidr` | IP address in a network | `DestinationIp|cidr: 10.0.0.0/8` |
| `gt`, `gte`, `lt`, `lte` | Numbers | |

Plain values support wildcards: `*` is any run of characters, `?` one character, and `\*` a literal star. `null` matches a missing or empty field.

Anything we don't support (for example `base64offset`, or aggregations after `|` in the condition) is **refused with an error**, never silently ignored. A rule that half-loads would be worse than a rule that doesn't load.

## 3. How the evaluator works

`bde/sigma/` plus `bde/signals.py` is under 600 lines:

1. **`values.py`** turns one field test into a Python function. `CommandLine|windash|contains: ' -urlcache '` becomes a compiled regular expression that matches every dash variant anywhere in the value, ignoring case.
2. **`condition.py`** parses the condition text into a tree with the usual precedence (`not` binds tighter than `and`, which binds tighter than `or`), like a tiny programming language. It is a *recursive-descent parser*: one function per grammar level.
3. **`rule.py`** loads the YAML, validates it (UUID id, `name` in a-z0-9_, known level, lowercase tags), maps `logsource` to the events it reads, and compiles everything once.
4. **`bde/signals.py`** indexes rules by the (channel, event ID) they read, so each event only meets the rules that could match it, and records every match as a `Signal`.

`process_creation` rules also read **Security event 4688** (process creation without Sysmon), by mapping its field names (`NewProcessName` → `Image`). That lets the same rules run on logs from computers without Sysmon, with less detail.

## 4. The 23 rules

These are the rules phase 3 wrote. Phase 7 added six more and widened two after testing on real recordings; its [section 3](phase-7-real-data.md#3-the-development-set-what-we-changed) lists them.

| Area | Rules | Level |
| --- | --- | --- |
| Office and scripts | `proc_office_spawns_script_engine`, `proc_script_host_runs_user_script`, `proc_script_host_spawns_lolbin` | high, medium, high |
| PowerShell | `proc_powershell_encoded_command`, `proc_powershell_hidden_window` | medium |
| Network | `net_script_engine_public_destination`, `net_proxy_binary_public_destination` | medium, high |
| Files and registry | `file_script_engine_drops_payload`, `reg_run_key_script_engine`, `reg_run_key_modified` | medium, high, low |
| certutil, rundll32, mshta | `proc_certutil_download`, `proc_certutil_decode`, `proc_rundll32_user_folder_dll`, `proc_mshta_remote_or_inline` | high, medium, high, high |
| WMI | `proc_wmiprvse_spawns_shell`, `proc_remote_wmi_process_create` | high, medium |
| Discovery | `proc_whoami_privileges`, `proc_domain_group_discovery`, `proc_nltest_domain_discovery` | low, medium, medium |
| Ransomware preparation | `proc_inhibit_system_recovery`, `proc_event_log_cleared_wevtutil`, `sec_security_log_cleared`, `proc_defender_disabled` | high |

`python -m bde rules` prints them with their ATT&CK techniques. The generated [attack-mapping.md](attack-mapping.md) explains each technique.

### Levels are a promise about noise

- **high**: rarely seen in normal work. Word starting PowerShell, rundll32 loading a DLL from `C:\Users\Public`.
- **medium**: suspicious but has normal uses. Encoded PowerShell: management agents do it too.
- **low**: common, only interesting with company. `whoami /all`, any Run key change.

Phase 4's risk scoring turns these levels into points, so the levels must be honest.

## 5. Writing rules that don't drown you

Each rule went through the same three questions:

1. **What does the attacker have to do?** Not what a particular tool happens to do. Chain 2 *must* fetch a file and *must* run the DLL; the file name is up to them.
2. **What normal activity is closest?** Those are the benign twins from phase 2, and the "must not fire" cases in `tests/test_rules.py`.
3. **What separates them?** Usually context: the parent process, the folder, the flag, the destination.

Examples from our rules:

| Rule | The twin it must ignore | The separating detail |
| --- | --- | --- |
| `proc_script_host_spawns_lolbin` | Logon script mapping a drive | `filter_logon_script`: the parent runs from `\NETLOGON\` |
| `proc_domain_group_discovery` | Fires twice per command | `net.exe` starts `net1.exe` with the same arguments; the filter drops the child |
| `net_script_engine_public_destination` | PowerShell remoting between company computers | `cidr` filter for private address ranges |
| `reg_run_key_script_engine` | OneDrive adds a Run key | The value must start a script engine, or be set by one |

Some twins **cannot** be told apart by one event. The remote-management agent's `powershell -EncodedCommand` matches `proc_powershell_encoded_command` exactly like the attack does. That's fine: the signal fires, and phase 4 sees that nothing else follows it.

## 6. Tests

- `tests/test_sigma.py`: modifiers, wildcards, the condition parser, and every way a broken rule must be refused.
- `tests/test_rules.py`: each of the 23 rules against events that must fire and events that must stay quiet. `test_every_rule_has_cases` fails if you add a rule without cases, and `test_rules_only_tag_known_techniques` fails on a technique ID that isn't in `bde/attack.py`.

## 7. Try it

```bash
python -m bde rules
python -m bde generate -o out/s.jsonl
python -m bde detect out/s.jsonl --full | less    # the signals are the * lines in each story
```

Write your own rule. Copy `rules/sigma/proc_whoami_privileges.yml` to `rules/sigma/proc_systeminfo.yml`, give it a new UUID (`python -c "import uuid; print(uuid.uuid4())"`) and `name: proc_systeminfo`, and match `\systeminfo.exe`. Run `python -m bde rules`, then the tests. The meta-test will tell you to add cases.

## 8. Checkpoint questions

1. In a Sigma `detection`, what does a list of values mean, and what does a list of blocks mean?
2. Why do our rules match `OriginalFileName` as well as `Image`?
3. What does `windash` protect against?
4. Why does the evaluator refuse unknown modifiers instead of ignoring them?
5. The remote-management agent's encoded PowerShell fires `proc_powershell_encoded_command`. Is that a bug in the rule? What handles it?
6. Why is `proc_whoami_privileges` only `low`?

<details>
<summary>Answers</summary>

1. A list of values is OR: any value may match. A list of blocks (maps) is also OR: any block may match, while all fields inside one block must match (AND).
2. `Image` is the file's path, which an attacker can change by copying `certutil.exe` to `C:\Users\Public\x.exe`. `OriginalFileName` comes from the program's embedded version information, which the copy keeps.
3. Windows programs accept `/flag` as well as `-flag`, and some accept Unicode dashes. Without `windash`, `certutil /urlcache` would slip past a rule written for `-urlcache`.
4. Ignoring part of a rule changes what it matches without anyone noticing. Refusing it means you learn immediately that the rule doesn't work here.
5. No. On that one event the twin and the attack are identical. The signal is correct; the incident decision belongs to phase 4, which sees that the agent's PowerShell does nothing else suspicious.
6. Admins and support staff run it routinely. It only matters together with other discovery and execution signals, and the risk score adds it up in that case.

</details>
