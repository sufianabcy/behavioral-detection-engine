from bde.event import NULL_GUID, SYSMON_CHANNEL, Event, parse_time
from bde.render import ASCII, UNICODE, _shorten, pick_charset, render
from bde.tree import ProcessTree, ancestry
from helpers import H1, H2, node_named


def process_event(time, guid, pid, image, parent_guid, parent_pid, parent_image, host="H"):
    return Event(
        event_id=1,
        timestamp=parse_time(time),
        host=host,
        channel=SYSMON_CHANNEL,
        data={
            "ProcessGuid": guid,
            "ProcessId": str(pid),
            "Image": image,
            "CommandLine": image,
            "ParentProcessGuid": parent_guid,
            "ParentProcessId": str(parent_pid),
            "ParentImage": parent_image,
        },
    )


def test_both_hosts_are_found(sample_tree):
    assert sample_tree.hosts() == [H1, H2]


def test_macro_chain_lineage(sample_tree):
    powershell = node_named(sample_tree, H1, "powershell.exe")
    assert [n.name for n in ancestry(powershell)] == ["WINWORD.EXE", "OUTLOOK.EXE", "explorer.exe"]


def test_parent_seen_only_as_a_parent_becomes_a_placeholder(sample_tree):
    explorer = sample_tree.roots(H1)[0]
    assert explorer.name == "explorer.exe"
    assert not explorer.seen_start
    assert explorer.pid == 4012  # learned from the child's ParentProcessId


def test_activity_hangs_on_the_process_that_did_it(sample_tree):
    powershell = node_named(sample_tree, H1, "powershell.exe")
    assert [e.event_id for e in powershell.activity] == [22, 3, 11, 13]  # dns, net, file, registry


def test_benign_admin_tree(sample_tree):
    certutil = node_named(sample_tree, H2, "certutil.exe")
    assert [n.name for n in ancestry(certutil)] == ["powershell.exe", "explorer.exe"]


def test_logon_event_is_counted_but_not_used(sample_tree):
    assert (sample_tree.events_used, sample_tree.events_skipped) == (11, 1)


def test_reused_pid_does_not_confuse_the_tree():
    # Windows reuses PIDs: two unrelated processes both get PID 4242.
    # Linking by PID would attach the children to the wrong parent;
    # linking by ProcessGuid keeps them apart.
    events = [
        process_event("2026-11-03T09:00:00Z", "{a}", 4242, r"C:\a.exe", NULL_GUID, 4, "System"),
        process_event("2026-11-03T09:10:00Z", "{a-child}", 5000, r"C:\from_a.exe", "{a}", 4242, r"C:\a.exe"),
        process_event("2026-11-03T09:30:00Z", "{b}", 4242, r"C:\b.exe", NULL_GUID, 4, "System"),
        process_event("2026-11-03T09:40:00Z", "{b-child}", 5001, r"C:\from_b.exe", "{b}", 4242, r"C:\b.exe"),
    ]
    tree = ProcessTree.from_events(events)
    assert node_named(tree, "H", "from_a.exe").parent.name == "a.exe"
    assert node_named(tree, "H", "from_b.exe").parent.name == "b.exe"


def test_null_parent_guid_means_no_parent():
    event = process_event("2026-11-03T09:00:00Z", "{a}", 10, r"C:\a.exe", NULL_GUID, 4, "System")
    tree = ProcessTree.from_events([event])
    assert [n.name for n in tree.roots()] == ["a.exe"]


def test_input_order_does_not_matter(sample_tree):
    from bde.readers import read_events
    from helpers import SAMPLE

    reversed_tree = ProcessTree.from_events(reversed(list(read_events(SAMPLE))))
    powershell = node_named(reversed_tree, H1, "powershell.exe")
    assert [n.name for n in ancestry(powershell)] == ["WINWORD.EXE", "OUTLOOK.EXE", "explorer.exe"]


def test_find_ignores_case(sample_tree):
    assert {n.host for n in sample_tree.find("POWERSHELL")} == {H1, H2}


def test_render_draws_the_whole_chain(sample_tree):
    text = "\n".join(render(sample_tree, width=0, chars=ASCII))
    assert "`-- powershell.exe  [pid 6232]  09:14:05  CORP\\jsmith" in text
    assert "net  tcp -> 203.0.113.10:443 (cdn.update.example)" in text
    assert "started before the log began" in text


def test_render_match_keeps_parents_and_hides_unrelated_branches(sample_tree):
    text = "\n".join(render(sample_tree, match="certutil", chars=ASCII))
    assert "certutil.exe" in text and "<== match" in text
    assert "explorer.exe" in text  # its ancestors stay visible
    assert "WINWORD" not in text  # the other host's tree is hidden


def test_shorten_keeps_both_ends():
    text = _shorten("A" * 50 + "Invoice_Q3.docm", 30, UNICODE)
    assert len(text) == 30
    assert text.startswith("AAAA") and text.endswith(".docm") and "…" in text


def test_ascii_fallback_when_the_output_cannot_show_box_characters():
    class LegacyConsole:
        encoding = "cp1252"  # a classic Windows code page

    class ModernTerminal:
        encoding = "utf-8"

    assert pick_charset(LegacyConsole()) is ASCII
    assert pick_charset(ModernTerminal()) is UNICODE
