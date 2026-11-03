import codecs
import shutil

import pytest

from bde.event import parse_time
from bde.readers import parse_event_xml, read_events, read_jsonl, read_xml_file, write_jsonl
from helpers import SAMPLE, XML_EXPORT


def test_xml_export_yields_every_event():
    assert [e.event_id for e in read_xml_file(XML_EXPORT)] == [1, 3, 4624]


def test_process_create_event_is_normalized():
    event = next(read_xml_file(XML_EXPORT))
    assert event.is_sysmon
    assert event.host == "WKSTN-07.corp.example"
    assert event.get("ParentImage").endswith("WINWORD.EXE")
    assert event.process_guid == "{3f1c2a90-71f9-6543-2d01-000000000a00}"  # lowercased
    # Sysmon's UtcTime (when it happened) wins over TimeCreated (when logged).
    assert event.timestamp == parse_time("2026-11-03 09:14:05.093")
    assert event.meta == {"source_file": "sysmon_export.xml", "record_id": 48211, "provider": "Microsoft-Windows-Sysmon"}
    assert "Microsoft® Windows®" in event.get("Product")  # non-ASCII text survives


def test_events_without_utctime_use_timecreated():
    logon = list(read_xml_file(XML_EXPORT))[2]
    assert not logon.is_sysmon
    assert logon.name == "Logon"
    assert logon.timestamp == parse_time("2026-11-03T09:04:58.3104412Z")


def test_wevtutil_style_utf16_export_without_a_root_element(tmp_path):
    # wevtutil prints bare <Event> elements one after another, and PowerShell 5
    # saves redirected output as UTF-16. Both must still work.
    body = XML_EXPORT.read_text(encoding="utf-8")
    events_only = body.split("<Events>")[1].split("</Events>")[0]
    path = tmp_path / "wevtutil.xml"
    path.write_bytes(codecs.BOM_UTF16_LE + events_only.encode("utf-16-le"))
    assert [e.event_id for e in read_xml_file(path)] == [1, 3, 4624]


def test_xml_without_namespace_is_fine():
    event = parse_event_xml(
        "<Event><System><EventID>11</EventID><TimeCreated SystemTime='2026-11-03T09:00:00Z'/>"
        "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>H</Computer></System>"
        "<EventData><Data Name='TargetFilename'>C:\\Users\\Public\\a.txt</Data></EventData></Event>"
    )
    assert event.event_id == 11
    assert event.get("TargetFilename") == "C:\\Users\\Public\\a.txt"


def test_userdata_fields_are_flattened():
    # Event 1102 ("audit log cleared") stores its fields in UserData, not EventData.
    event = parse_event_xml(
        "<Event><System><EventID>1102</EventID><TimeCreated SystemTime='2026-11-03T09:00:00Z'/>"
        "<Channel>Security</Channel><Computer>H</Computer></System>"
        "<UserData><LogFileCleared><SubjectUserName>admin</SubjectUserName></LogFileCleared></UserData></Event>"
    )
    assert event.get("SubjectUserName") == "admin"


def test_event_without_any_timestamp_is_dropped():
    assert parse_event_xml("<Event><System><EventID>1</EventID></System></Event>") is None


def test_jsonl_round_trip_keeps_everything_and_uses_unix_line_endings(tmp_path):
    events = list(read_xml_file(XML_EXPORT))
    out = tmp_path / "events.jsonl"
    assert write_jsonl(events, out) == 3
    assert [e.to_dict() for e in read_jsonl(out)] == [e.to_dict() for e in events]
    assert b"\r\n" not in out.read_bytes()


def test_jsonl_errors_name_the_line(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text('{"EventID": 1}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="line 1"):
        list(read_jsonl(path))


def test_read_events_picks_the_reader_by_extension_and_reads_folders(tmp_path):
    shutil.copy(XML_EXPORT, tmp_path / "a.xml")
    shutil.copy(SAMPLE, tmp_path / "b.jsonl")
    (tmp_path / "notes.txt").write_text("ignored", encoding="utf-8")
    assert len(list(read_events(tmp_path))) == 3 + 12


def test_read_events_reports_bad_input(tmp_path):
    with pytest.raises(FileNotFoundError):
        list(read_events(tmp_path / "missing.evtx"))
    (tmp_path / "log.csv").write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="don't know how to read"):
        list(read_events(tmp_path / "log.csv"))


def test_a_file_that_is_not_evtx_is_rejected_clearly(tmp_path):
    fake = tmp_path / "renamed.evtx"
    fake.write_text("this is plain text, not an event log\n" * 50, encoding="utf-8")
    with pytest.raises(ValueError, match="not a valid .evtx file"):
        list(read_events(fake))


def test_sample_file_has_labels_for_later_phases():
    events = list(read_events(SAMPLE))
    assert len(events) == 12
    malicious = [e for e in events if e.meta.get("label") == "malicious"]
    assert len(malicious) == 7
    assert {e.meta["chain"] for e in malicious} == {"chain-1"}
