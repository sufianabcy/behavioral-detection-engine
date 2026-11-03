"""Phase 2: the scenario generator.

Three kinds of test:
  * determinism: the same seed gives the same events, on any computer;
  * safety: nothing generated could do harm if someone copied it out;
  * ground truth: the labels the evaluation relies on are complete and honest.
"""

import hashlib
import ipaddress
import re
from datetime import timedelta

import pytest

from bde.generator import SEEN_CHAINS, UNSEEN_CHAINS, ScenarioConfig, generate
from bde.generator.catalog import DOCUMENTATION_NETWORKS, SAFE_DECODED_SCRIPTS, decode_powershell
from bde.generator.rand import Rand, derive_seed
from bde.readers import write_jsonl
from bde.tree import ProcessTree

# The SHA-256 of `python -m bde generate` with default options (seed 7).
# If this test fails after you changed the generator on purpose, update the
# constant (and the Windows testing guide, which quotes it). If it fails on
# another computer without any change, the output isn't portable: a real bug.
SEED_7_SHA256 = "739b8730f8ce3ca70c67221c29c124fc8ac3d1491862a3326b21599f15d1e219"

ALL_CHAINS = SEEN_CHAINS + UNSEEN_CHAINS


@pytest.fixture(scope="module")
def everything():
    """One scenario with every chain, seen and unseen, so each test sees all of them."""
    return generate(ScenarioConfig(seed=11, chains=ALL_CHAINS))


def sha256_of_scenario(scenario, tmp_path) -> str:
    path = tmp_path / "scenario.jsonl"
    write_jsonl(scenario.events, path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- determinism ----------------------------------------------------------------


def test_derive_seed_is_stable_and_label_specific():
    assert derive_seed(7, "chain-1") == derive_seed(7, "chain-1")
    assert derive_seed(7, "chain-1") != derive_seed(7, "chain-2")
    assert derive_seed(7, "chain-1") != derive_seed(8, "chain-1")
    # sha256-based, so it never changes between Python runs (hash() would)
    assert derive_seed(0, "x") == int.from_bytes(hashlib.sha256(b"0/x").digest()[:8], "big")


def test_rand_helpers_stay_in_range():
    r = Rand(1)
    for _ in range(500):
        assert 3 <= r.int_between(3, 5) <= 5
        assert 1.0 <= r.uniform(1.0, 2.0) < 2.0
        gap = r.seconds(0.5, 1.5)
        assert timedelta(milliseconds=500) <= gap <= timedelta(milliseconds=1500)
    assert sorted(r.shuffled(range(10))) == list(range(10))
    assert r.weighted([("only", 1.0)]) == "only"
    with pytest.raises(ValueError):
        r.choice([])


def test_same_seed_same_bytes(tmp_path):
    first = sha256_of_scenario(generate(ScenarioConfig(seed=3)), tmp_path)
    second = sha256_of_scenario(generate(ScenarioConfig(seed=3)), tmp_path)
    assert first == second


def test_different_seed_different_scenario(tmp_path):
    assert sha256_of_scenario(generate(ScenarioConfig(seed=3)), tmp_path) != sha256_of_scenario(
        generate(ScenarioConfig(seed=4)), tmp_path
    )


def test_seed_7_fingerprint(tmp_path):
    assert sha256_of_scenario(generate(), tmp_path) == SEED_7_SHA256


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
def test_attacks_do_not_move_when_background_changes(seed):
    """Each chain has its own random stream, so noise doesn't shift the attacks."""
    quiet = generate(ScenarioConfig(seed=seed, chains=ALL_CHAINS, background=0, twins=False))
    busy = generate(ScenarioConfig(seed=seed, chains=ALL_CHAINS, background=2))
    assert [(i.id, i.start, i.hosts) for i in quiet.instances] == [(i.id, i.start, i.hosts) for i in busy.instances]


# --- shape of the data ------------------------------------------------------------


def test_events_are_sorted_with_millisecond_times(everything):
    times = [e.timestamp for e in everything.events]
    assert times == sorted(times)
    assert all(t.microsecond % 1000 == 0 for t in times)


def test_benign_tail_is_trimmed_at_the_end_time(everything):
    end = everything.config.start + timedelta(hours=everything.config.hours)
    assert all(e.timestamp <= end for e in everything.events if e.meta["label"] == "benign")


def test_every_process_has_a_known_parent(everything):
    """Every process start names a parent that started earlier or before the log began."""
    tree = ProcessTree.from_events(everything.events)
    for event in everything.events:
        if event.is_sysmon and event.event_id == 1:
            node = tree.node_for(event)
            assert node is not None and node.parent is not None, event.data["CommandLine"]
            assert node.parent.name, "parent without an image name"


def test_process_guids_are_unique(everything):
    starts = [(e.host, e.process_guid) for e in everything.events if e.is_sysmon and e.event_id == 1]
    assert len(starts) == len(set(starts))


# --- safety ----------------------------------------------------------------------------

_ENCODED = re.compile(r"\s-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE)


def test_every_encoded_command_is_harmless(everything):
    blobs = [m.group(1) for e in everything.events for m in _ENCODED.finditer(e.get("CommandLine"))]
    assert blobs, "expected some encoded PowerShell in the scenario"
    for blob in blobs:
        assert decode_powershell(blob) in SAFE_DECODED_SCRIPTS


def _allowed_ip(text: str) -> bool:
    text = text.removeprefix("::ffff:")
    address = ipaddress.ip_address(text)
    if address.is_private or address.is_loopback or address.is_unspecified:
        return True  # inside the fake company
    return any(address in ipaddress.ip_network(net) for net in DOCUMENTATION_NETWORKS)


def test_public_addresses_are_documentation_ranges_only(everything):
    checked = 0
    for event in everything.events:
        for name in ("SourceIp", "DestinationIp", "IpAddress"):
            value = event.get(name)
            if value and value != "-":
                assert _allowed_ip(value), f"{name}={value} in {event.to_json()}"
                checked += 1
        for result in filter(None, event.get("QueryResults").split(";")):
            assert _allowed_ip(result.strip()), result
    assert checked > 100


def test_domain_names_are_reserved_example_names(everything):
    for event in everything.events:
        for name in ("QueryName", "DestinationHostname", "SourceHostname"):
            value = event.get(name)
            if value and value != "-":
                assert value.lower().endswith(".example"), f"{name}={value}"
        for server in re.findall(r"https?://([^/\s\"':]+)", event.get("CommandLine")):
            if re.fullmatch(r"[\d.]+", server):
                assert _allowed_ip(server), server
            else:
                assert server.lower().endswith(".example"), server


# --- ground truth ------------------------------------------------------------------------


def test_one_instance_per_requested_chain(everything):
    assert sorted(i.chain for i in everything.instances) == sorted(ALL_CHAINS)
    for instance in everything.instances:
        assert instance.variant == ("unseen" if instance.chain.endswith("u") else "seen")


def test_malicious_events_carry_complete_labels(everything):
    instances = {i.id: i for i in everything.instances}
    malicious = [e for e in everything.events if e.meta["label"] == "malicious"]
    assert malicious
    for event in malicious:
        meta = event.meta
        assert meta["instance"] in instances
        instance = instances[meta["instance"]]
        assert meta["chain"] == instance.chain and meta["variant"] == instance.variant
        assert meta["stage"] and meta["techniques"]
        assert all(re.fullmatch(r"T\d{4}(\.\d{3})?", t) for t in meta["techniques"])
        assert event.host in instance.hosts


def test_every_instance_has_events_and_starts_on_time(everything):
    for instance in everything.instances:
        own = [e for e in everything.events if e.meta.get("instance") == instance.id]
        assert own, instance.id
        assert min(e.timestamp for e in own) >= instance.start


def test_benign_events_never_carry_attack_labels(everything):
    for event in everything.events:
        if event.meta["label"] == "benign":
            assert "chain" not in event.meta and "instance" not in event.meta
            assert event.meta.get("activity")


def test_twins_exist_for_each_seen_chain(everything):
    twinned = {e.meta["twin"] for e in everything.events if e.meta.get("twin")}
    assert {"chain-1", "chain-2", "chain-3", "chain-4"} <= twinned


def test_twins_switch_removes_the_scheduled_twins_only():
    """twins=False drops the scheduled look-alikes (admin scripts, certutil hashing...).

    Everyday work that resembles an attack, such as opening an email
    attachment, is part of normal background and stays.
    """
    with_twins = generate(ScenarioConfig(seed=2, chains=()))
    without = generate(ScenarioConfig(seed=2, chains=(), twins=False))
    assert with_twins.instances == [] and without.instances == []
    assert all(e.meta["label"] == "benign" for e in with_twins.events + without.events)
    scheduled = {e.meta["activity"] for e in with_twins.events} - {e.meta["activity"] for e in without.events}
    assert {"admin-script", "admin-certutil", "remote-admin-wmi", "remote-management-script"} <= scheduled


@pytest.mark.parametrize("bad, message", [
    ({"chains": ("chain-9",)}, "unknown chain"),
    ({"workstations": 2}, "workstations"),
    ({"hours": 0.5}, "hours"),
    ({"background": -1}, "background"),
])
def test_config_is_checked(bad, message):
    with pytest.raises(ValueError, match=message):
        ScenarioConfig(**bad)
