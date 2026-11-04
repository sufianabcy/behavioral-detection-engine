"""A real .evtx recording, read with whichever parser is installed (phase 7).

The other reader tests use XML text. This one reads the binary format itself,
from a public recording (see fixtures/real/README.md): PsExec starting a
SYSTEM shell, as Sysmon logged it. The same assertions must hold with the
evtx package (macOS, Windows, Linux) and with python-evtx (Windows on ARM).
"""

from collections import Counter

from bde.engine import detect
from bde.event import parse_time
from bde.readers import read_events
from bde.tree import ProcessTree
from helpers import ROOT

PSEXEC = ROOT / "tests" / "fixtures" / "real" / "psexec_as_system_sysmon.evtx"
HOST = "fs03vuln.offsec.lan"


def test_every_record_of_a_real_recording_is_read():
    stats: dict[str, int] = {}
    events = list(read_events(PSEXEC, stats))
    assert stats == {}  # no record was unreadable
    assert Counter(e.event_id for e in events) == {1: 2, 11: 1, 13: 3, 17: 4, 18: 4, 22: 1}
    assert {e.host for e in events} == {HOST}


def test_values_are_the_same_whichever_parser_read_them():
    first = next(read_events(PSEXEC))
    assert first.get("Image") == "C:\\TOOLS\\PsExec64.exe"
    assert first.get("CommandLine") == "PsExec64.exe  -i -s cmd"
    assert first.process_guid == "{a57649d1-db54-61ab-775c-dc0100000000}"  # braces, lower case
    assert first.get("LogonId") == "0x83ef56"  # no leading zeros
    assert first.timestamp == parse_time("2021-12-04 21:19:16.741")


def test_a_real_recording_becomes_a_process_tree():
    tree = ProcessTree.from_events(read_events(PSEXEC))
    psexec = next(n for n in tree.nodes(HOST) if n.name == "PsExec64.exe")
    system_shell = next(n for n in tree.nodes(HOST) if n.name == "cmd.exe" and n.seen_start)
    assert system_shell.user == "NT AUTHORITY\\SYSTEM"
    # The service PsExec installed started the shell. Its own start isn't in
    # the recording, so the tree knows it only from the shell's event and from
    # the pipes it created.
    service = system_shell.parent
    assert service.name == "PSEXESVC.exe" and not service.seen_start
    assert [e.event_id for e in service.activity] == [17, 17, 17, 17]
    assert Counter(e.event_id for e in psexec.activity) == {18: 3, 13: 1, 11: 1, 22: 1}


def test_an_admin_tool_running_raises_no_incident():
    assert detect(read_events(PSEXEC)).incidents == []
