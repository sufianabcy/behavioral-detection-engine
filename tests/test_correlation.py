"""Phase 4: turning signals into incidents.

The first half builds tiny process trees by hand, so each test shows one
rule of the correlation layer. The second half checks the full demo scenario.
"""

from datetime import datetime, timedelta, timezone

import pytest

from bde.correlation import address_book, parse_duration, risk_score, score_risk
from bde.engine import RuleSet, detect
from bde.evaluate import score_run
from bde.event import SYSMON_CHANNEL, Event
from bde.generator import ScenarioConfig, generate
from bde.signals import Signal

T0 = datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)
HOST = "WKSTN-07.corp.example"
SYS32 = "C:\\Windows\\System32\\"
PS = SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe"
WORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
EXPLORER = "C:\\Windows\\explorer.exe"
ENC = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFMASQBNAFUATABBAFQARQBEAC0AUwBUAEEARwBFAC0AMgAnAA=="
RUN_KEY = "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"


class Story:
    """Builds Sysmon events for one host, a few seconds apart."""

    def __init__(self, host=HOST):
        self.host = host
        self.events: list[Event] = []
        self.count = 0

    def _event(self, event_id, seconds, data):
        self.events.append(Event(event_id, T0 + timedelta(seconds=seconds), self.host, SYSMON_CHANNEL, data))

    def start(self, seconds, image, command, parent=None, user="CORP\\jsmith"):
        self.count += 1
        guid = f"{{00000000-0000-0000-0000-{self.count:012d}}}"
        parent_guid, parent_image = (parent if parent else ("{00000000-0000-0000-0000-999999999999}", EXPLORER))
        self._event(1, seconds, {
            "ProcessGuid": guid, "ProcessId": str(1000 + self.count), "Image": image, "CommandLine": command,
            "User": user, "ParentProcessGuid": parent_guid, "ParentImage": parent_image, "ParentProcessId": "900",
        })
        return guid, image

    def connect(self, seconds, process, ip, port=443, source_ip="10.20.1.37"):
        self._event(3, seconds, {"ProcessGuid": process[0], "Image": process[1], "Initiated": "true",
                                 "SourceIp": source_ip, "DestinationIp": ip, "DestinationPort": str(port)})

    def drop(self, seconds, process, path):
        self._event(11, seconds, {"ProcessGuid": process[0], "Image": process[1], "TargetFilename": path})

    def run_key(self, seconds, process, details):
        self._event(13, seconds, {"ProcessGuid": process[0], "Image": process[1], "TargetObject": RUN_KEY,
                                  "Details": details, "EventType": "SetValue"})


@pytest.fixture(scope="module")
def rules():
    return RuleSet.load()


def incidents_of(rules, story, kind=None):
    found = detect(story.events, rules).incidents
    return [i for i in found if kind is None or i.kind == kind]


def macro_attack(story, gap=2.0, through_cmd=False):
    word = story.start(0, WORD, '"WINWORD.EXE" /n invoice.docm')
    parent = word
    if through_cmd:
        parent = story.start(1, SYS32 + "cmd.exe", "cmd.exe /c powershell ...", parent=word)
    ps = story.start(2, PS, f"powershell.exe -nop -w hidden -enc {ENC}", parent=parent)
    story.connect(2 + gap, ps, "203.0.113.10")
    story.drop(2 + 2 * gap, ps, "C:\\Users\\jsmith\\AppData\\Roaming\\upd.ps1")
    story.run_key(2 + 3 * gap, ps, "powershell.exe -w hidden -File upd.ps1")
    return ps


# --- small hand-built cases ------------------------------------------------------------


def test_parse_duration():
    assert parse_duration("15m") == timedelta(minutes=15)
    assert parse_duration("90s") == timedelta(seconds=90)
    assert parse_duration("2h") == timedelta(hours=2)
    with pytest.raises(ValueError):
        parse_duration("15 minutes")


def test_full_macro_chain_is_one_incident(rules):
    story = Story()
    macro_attack(story)
    chains = incidents_of(rules, story, "chain")
    assert len(chains) == 1
    incident = chains[0]
    assert incident.rule_name == "chain_office_document_to_powershell"
    assert incident.matched_steps == 4
    assert "T1566.001" in incident.techniques  # from the chain rule's own tags


def test_office_ancestor_found_through_cmd(rules):
    """Word -> cmd -> PowerShell: has_ancestor looks past the direct parent."""
    story = Story()
    macro_attack(story, through_cmd=True)
    chains = incidents_of(rules, story, "chain")
    assert len(chains) == 1  # cmd and PowerShell both match step 1, but it's one attack
    assert chains[0].root.name.lower() == "cmd.exe"  # grouped under the top-most anchor


def test_no_office_ancestor_no_macro_chain(rules):
    story = Story()
    ps = story.start(0, PS, f"powershell.exe -nop -w hidden -enc {ENC}")  # started from explorer
    story.connect(2, ps, "203.0.113.10")
    story.drop(4, ps, "C:\\Users\\jsmith\\AppData\\Roaming\\upd.ps1")
    story.run_key(6, ps, "powershell.exe -w hidden -File upd.ps1")
    assert incidents_of(rules, story, "chain") == []


def test_steps_outside_the_timespan_do_not_count(rules):
    story = Story()
    macro_attack(story, gap=8 * 60)  # 8 minutes between steps: the last two fall outside 15 minutes
    assert incidents_of(rules, story, "chain") == []


def test_other_branches_do_not_complete_a_chain(rules):
    """The call-out, file and Run key come from a *different* PowerShell."""
    story = Story()
    word = story.start(0, WORD, '"WINWORD.EXE" /n invoice.docm')
    story.start(2, PS, f"powershell.exe -nop -w hidden -enc {ENC}", parent=word)
    other = story.start(3, PS, "powershell.exe -nop -w hidden -c x")  # under explorer
    story.connect(4, other, "203.0.113.10")
    story.drop(6, other, "C:\\Users\\jsmith\\AppData\\Roaming\\upd.ps1")
    story.run_key(8, other, "powershell.exe -w hidden -File upd.ps1")
    assert incidents_of(rules, story, "chain") == []


def test_ordered_chain_ignores_steps_that_come_too_early(rules):
    """The file drop and Run key happen before the call-out: only 2 steps in order."""
    story = Story()
    word = story.start(0, WORD, '"WINWORD.EXE" /n invoice.docm')
    ps = story.start(2, PS, f"powershell.exe -nop -w hidden -enc {ENC}", parent=word)
    story.drop(3, ps, "C:\\Users\\jsmith\\AppData\\Roaming\\upd.ps1")
    story.run_key(4, ps, "powershell.exe -w hidden -File upd.ps1")
    story.connect(5, ps, "203.0.113.10")
    assert incidents_of(rules, story, "chain") == []


# --- risk scoring -----------------------------------------------------------------------------


def signal(rules, name, event):
    rule = next(r for r in rules.sigma if r.name == name)
    assert rule.matches(event)
    return Signal(rule, event)


def whoami(story, seconds, user="CORP\\jsmith"):
    process = story.start(seconds, SYS32 + "whoami.exe", "whoami /all", user=user)
    return story.events[-1], process


def test_risk_points_fade_by_half_each_half_life(rules):
    story = Story()
    ps = story.start(0, PS, f"powershell.exe -enc {ENC}", parent=("{0-0-0-0-1}", SYS32 + "wbem\\WmiPrvSE.exe"))
    high = signal(rules, "proc_wmiprvse_spawns_shell", story.events[-1])  # high = 35 points
    config = rules.risk
    assert risk_score([high], high.time, config) == pytest.approx(35)
    assert risk_score([high], high.time + config.half_life, config) == pytest.approx(17.5)
    assert risk_score([high], high.time + config.window + timedelta(seconds=1), config) == 0
    assert ps


def test_each_extra_tactic_adds_a_bonus(rules):
    story = Story()
    event, _ = whoami(story, 0)
    discovery = signal(rules, "proc_whoami_privileges", event)  # low = 5, discovery
    story.start(1, PS, "powershell.exe -w hidden -c x")
    stealth = signal(rules, "proc_powershell_hidden_window", story.events[-1])  # medium = 15, stealth
    now = stealth.time
    expected = 5 * 0.5 ** ((now - discovery.time) / rules.risk.half_life) + 15 + rules.risk.tactic_bonus
    assert risk_score([discovery, stealth], now, rules.risk) == pytest.approx(expected)


def test_same_rule_on_same_process_counts_once(rules):
    story = Story()
    wmi = ("{0-0-0-0-1}", SYS32 + "wbem\\WmiPrvSE.exe")
    story.start(0, PS, f"powershell.exe -enc {ENC}", parent=wmi)
    event = story.events[-1]
    repeated = [signal(rules, "proc_wmiprvse_spawns_shell", event) for _ in range(5)]
    assert score_risk(repeated, rules.risk) == []  # 35 points, not 175


def test_many_processes_cross_the_threshold_and_open_one_incident(rules):
    story = Story()
    wmi = ("{0-0-0-0-1}", SYS32 + "wbem\\WmiPrvSE.exe")
    signals = []
    for second in range(0, 40, 10):  # four different shells under WmiPrvSE, 10 s apart
        story.start(second, PS, f"powershell.exe -enc {ENC}", parent=wmi)
        signals.append(signal(rules, "proc_wmiprvse_spawns_shell", story.events[-1]))
    incidents = score_risk(signals, rules.risk)
    assert len(incidents) == 1
    assert incidents[0].detected_at == signals[2].time  # the third high signal passes 100
    assert len(incidents[0].signals) == 4  # later signals join the open episode


def test_a_new_episode_starts_after_the_score_fades(rules):
    story = Story()
    wmi = ("{0-0-0-0-1}", SYS32 + "wbem\\WmiPrvSE.exe")
    signals = []
    for second in (0, 10, 20, 3 * 3600, 3 * 3600 + 10, 3 * 3600 + 20):
        story.start(second, PS, f"powershell.exe -enc {ENC}", parent=wmi)
        signals.append(signal(rules, "proc_wmiprvse_spawns_shell", story.events[-1]))
    assert len(score_risk(signals, rules.risk)) == 2


def test_address_book_learns_ips_from_outgoing_connections():
    a, b = Story("WKSTN-07.corp.example"), Story("WKSTN-12.corp.example")
    a.connect(0, a.start(0, PS, "x"), "10.20.0.21", 5985, source_ip="10.20.1.37")
    b.connect(0, b.start(0, PS, "x"), "10.20.0.21", 445, source_ip="10.20.1.52")
    incoming = Event(3, T0, "SRV-FILE-01.corp.example", SYSMON_CHANNEL,
                     {"Initiated": "false", "SourceIp": "10.20.1.37", "DestinationIp": "10.20.0.21"})
    book = address_book(a.events + b.events + [incoming])
    assert book == {"10.20.1.37": "WKSTN-07.corp.example", "10.20.1.52": "WKSTN-12.corp.example"}


# --- the demo scenario ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def demo(rules):
    scenario = generate()
    return scenario, detect(scenario.events, rules)


def by_chain(demo, chain):
    scenario, result = demo
    score = score_run(scenario, result)
    instance = next(r for r in score.instances if r.chain == chain)
    return next(i for i in result.incidents if i.id == instance.detected_by[0])


def test_demo_detects_every_chain_without_false_alarms(demo):
    scenario, result = demo
    score = score_run(scenario, result)
    assert all(r.detected for r in score.instances)
    assert score.false_incidents == []
    assert len(result.incidents) == 4


def test_risk_and_chain_incidents_are_merged(demo):
    chain1 = by_chain(demo, "chain-1")
    assert chain1.kind == "chain"
    assert any("risk" in note.lower() for note in chain1.notes)
    _, result = demo
    same_host = [i for i in result.incidents if i.host == chain1.host and i.first_seen < chain1.last_seen]
    assert same_host == [chain1]


def test_lateral_movement_traced_back_to_the_first_victim(demo):
    chain1, chain3 = by_chain(demo, "chain-1"), by_chain(demo, "chain-3")
    origin = chain3.origin
    assert origin is not None
    assert origin.host == chain1.host
    assert origin.account == "adm-rpatel"
    assert origin.process is not None and origin.process.name.lower() == "powershell.exe"
    assert chain1.id in chain3.related and chain3.id in chain1.related


def test_rdp_session_traced_to_mstsc(demo):
    chain4 = by_chain(demo, "chain-4")
    assert chain4.kind == "risk" and chain4.level == "critical"
    assert chain4.origin is not None and chain4.origin.process is not None
    assert chain4.origin.process.name.lower() == "mstsc.exe"
    assert "T1490" in chain4.techniques and "T1685.005" in chain4.techniques


def test_unseen_excel_variant_is_still_caught(rules):
    scenario = generate(ScenarioConfig(seed=7, chains=("chain-1u",), twins=False))
    result = detect(scenario.events, rules)
    names = {i.rule_name for i in result.incidents}
    assert "chain_office_document_to_powershell" in names


def test_unseen_remote_task_variant_is_a_known_gap(rules):
    """Chain 3u uses schtasks /s instead of WMI. No rule covers it yet: this is
    the documented gap. If you add a rule that catches it, flip this test."""
    scenario = generate(ScenarioConfig(seed=7, chains=("chain-3u",), twins=False))
    result = detect(scenario.events, rules)
    assert not score_run(scenario, result).instances[0].detected
