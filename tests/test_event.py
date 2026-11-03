import json
from datetime import datetime, timezone

import pytest

from bde.event import SYSMON_CHANNEL, Event, clean_guid, format_time, parse_time, windows_basename


@pytest.mark.parametrize(
    "text, expected",
    [
        ("2026-11-03 09:14:05.093", datetime(2026, 11, 3, 9, 14, 5, 93000, tzinfo=timezone.utc)),
        ("2026-11-03T09:14:05.0934170Z", datetime(2026, 11, 3, 9, 14, 5, 93417, tzinfo=timezone.utc)),
        ("2026-11-03T09:14:05Z", datetime(2026, 11, 3, 9, 14, 5, tzinfo=timezone.utc)),
        ("2026-11-03T10:14:05+01:00", datetime(2026, 11, 3, 9, 14, 5, tzinfo=timezone.utc)),
    ],
)
def test_parse_time_understands_windows_timestamp_styles(text, expected):
    assert parse_time(text) == expected


def test_parse_time_rejects_nonsense():
    with pytest.raises(ValueError):
        parse_time("yesterday")


def test_format_time_is_utc_with_milliseconds():
    assert format_time(parse_time("2026-11-03T09:14:05.0934170Z")) == "2026-11-03T09:14:05.093Z"


@pytest.mark.parametrize(
    "path, name",
    [
        (r"C:\Windows\System32\cmd.exe", "cmd.exe"),
        (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", "WINWORD.EXE"),
        ("powershell.exe", "powershell.exe"),
        ("", ""),
    ],
)
def test_windows_basename_splits_backslashes_on_any_os(path, name):
    # On a Mac, pathlib.Path would treat the whole string as one file name.
    assert windows_basename(path) == name


def test_clean_guid_normalizes_case_braces_and_null():
    assert clean_guid("{3F1C2A90-71F9-6543-2D01-000000000A00}") == "{3f1c2a90-71f9-6543-2d01-000000000a00}"
    assert clean_guid("3f1c2a90-71f9-6543-2d01-000000000a00") == "{3f1c2a90-71f9-6543-2d01-000000000a00}"
    assert clean_guid("{00000000-0000-0000-0000-000000000000}") is None
    assert clean_guid("") is None
    assert clean_guid(None) is None


def test_event_survives_a_json_round_trip():
    event = Event(
        event_id=1,
        timestamp=parse_time("2026-11-03T09:14:05.093Z"),
        host="WKSTN-07.corp.example",
        channel=SYSMON_CHANNEL,
        data={"Image": r"C:\Windows\System32\cmd.exe", "CommandLine": 'cmd.exe /c "echo hi"'},
        meta={"label": "benign"},
    )
    assert Event.from_dict(json.loads(event.to_json())) == event


def test_from_dict_names_the_missing_key():
    with pytest.raises(ValueError, match="EventID"):
        Event.from_dict({"Time": "2026-11-03T09:14:05Z", "Computer": "H", "Channel": SYSMON_CHANNEL})


def test_event_names_depend_on_the_channel():
    stamp = parse_time("2026-11-03T09:00:00Z")
    assert Event(1, stamp, "H", SYSMON_CHANNEL).name == "Process create"
    assert Event(4624, stamp, "H", "Security").name == "Logon"
    # Event ID 1 means something else in other logs.
    assert Event(1, stamp, "H", "System").name == "System event 1"
