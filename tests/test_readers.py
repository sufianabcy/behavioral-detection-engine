import codecs
import shutil
import sys

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


# --- Phase 7: what real recordings taught the reader -------------------------

from bde.readers import windows  # noqa: E402  (kept next to the tests that use it)

GOOD_RECORD = (
    "<Event><System><EventID>4688</EventID><TimeCreated SystemTime='2026-11-03T09:00:00Z'/>"
    "<Channel>Security</Channel><Computer>H</Computer></System>"
    "<EventData><Data Name='NewProcessName'>C:\\Windows\\System32\\cmd.exe</Data></EventData></Event>"
)


@pytest.mark.parametrize("raw, canonical", [
    ("365ABB72-3D4A-9F6E-0000-0010F9E15E00", "{365abb72-3d4a-9f6e-0000-0010f9e15e00}"),
    ("{365abb72-3d4a-9f6e-0000-0010f9e15e00}", "{365abb72-3d4a-9f6e-0000-0010f9e15e00}"),
    ("0x00000000000003e7", "0x3e7"),
    ("0X3E7", "0x3e7"),
    ("True", "true"),
    ("False", "false"),
    ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\cmd.exe"),  # ordinary text is untouched
    ("0x12 and more", "0x12 and more"),
    ("TRUE", "TRUE"),
    ("", ""),
])
def test_typed_values_are_written_one_way_whichever_tool_read_them(raw, canonical):
    assert windows.canonical_value(raw) == canonical


def test_canonical_values_apply_to_event_fields():
    event = parse_event_xml(
        "<Event><System><EventID>4624</EventID><TimeCreated SystemTime='2026-11-03T09:00:00Z'/>"
        "<Channel>Security</Channel><Computer>H</Computer></System><EventData>"
        "<Data Name='TargetLogonId'>0x00000000000A1B2C</Data>"
        "<Data Name='LogonGuid'>5E1D0E6B-0B8A-4C55-9D3C-1A2B3C4D5E6F</Data>"
        "<Data Name='ElevatedToken'>True</Data></EventData></Event>"
    )
    assert event.get("TargetLogonId") == "0xa1b2c"
    assert event.get("LogonGuid") == "{5e1d0e6b-0b8a-4c55-9d3c-1a2b3c4d5e6f}"
    assert event.get("ElevatedToken") == "true"


def test_a_character_xml_forbids_does_not_lose_the_event():
    # A real recording had a raw \x0f byte inside a privilege list. XML 1.0
    # forbids it, so without the clean-up the whole event would be unreadable.
    event = parse_event_xml(GOOD_RECORD.replace("cmd.exe</Data>", "cmd.exe\x0f</Data>"))
    assert event.get("NewProcessName") == "C:\\Windows\\System32\\cmd.exe\ufffd"


def test_evtx_backend_names_the_installed_parser():
    assert windows.evtx_backend() in ("evtx", "python-evtx")


def test_a_missing_evtx_parser_is_explained(monkeypatch):
    for name in ("evtx", "Evtx", "Evtx.Evtx"):
        monkeypatch.setitem(sys.modules, name, None)  # makes "import <name>" fail
    with pytest.raises(RuntimeError, match="requirements.txt"):
        windows.evtx_backend()


def test_an_empty_evtx_file_has_no_events(tmp_path):
    empty = tmp_path / "empty.evtx"
    empty.write_bytes(b"")
    assert list(read_events(empty)) == []


def test_damaged_records_are_skipped_and_counted(tmp_path, monkeypatch, caplog):
    # A recording can hold a few records the parser can't decode. Those are
    # skipped one by one, counted, and the rest of the file is still read.
    log = tmp_path / "damaged.evtx"
    log.write_bytes(b"ElfFile\x00" + bytes(4088))

    def records(path):
        yield GOOD_RECORD
        yield None  # the parser could not decode this record
        yield "<Event><System>"  # this one came out as broken XML
        yield GOOD_RECORD

    monkeypatch.setattr(windows, "_records_rust", records)
    monkeypatch.setattr(windows, "_records_python", records)
    stats: dict[str, int] = {}
    events = list(read_events(log, stats))
    assert [e.event_id for e in events] == [4688, 4688]
    assert stats == {"unreadable": 2}
    assert "skipped 2 unreadable records in damaged.evtx" in caplog.text
