"""Tests for has_ancestor() in bde/tree.py (the phase 1 exercise, now built).

Run only these with:  python -m pytest tests/test_has_ancestor.py -v
"""

import pytest

from bde.tree import has_ancestor, is_same_or_descendant, lineage
from helpers import H1, H2, node_named


def check(node, image_names, max_depth=None):
    return has_ancestor(node, image_names, max_depth)


@pytest.fixture(scope="module")
def nodes(sample_tree):
    return {
        "attack_powershell": node_named(sample_tree, H1, "powershell.exe"),
        "explorer": node_named(sample_tree, H1, "explorer.exe"),
        "admin_certutil": node_named(sample_tree, H2, "certutil.exe"),
    }


def test_finds_the_direct_parent(nodes):
    assert check(nodes["attack_powershell"], ["WINWORD.EXE"]) is True


def test_ignores_upper_and_lower_case(nodes):
    assert check(nodes["attack_powershell"], ["winword.exe"]) is True
    assert check(nodes["attack_powershell"], ["WinWord.Exe"]) is True


def test_looks_further_up_than_the_parent(nodes):
    assert check(nodes["attack_powershell"], ["outlook.exe"]) is True  # the grandparent


def test_max_depth_limits_how_far_up_it_looks(nodes):
    assert check(nodes["attack_powershell"], ["outlook.exe"], max_depth=1) is False
    assert check(nodes["attack_powershell"], ["outlook.exe"], max_depth=2) is True


def test_the_node_itself_does_not_count(nodes):
    assert check(nodes["attack_powershell"], ["powershell.exe"]) is False


def test_benign_admin_tool_has_no_office_ancestor(nodes):
    assert check(nodes["admin_certutil"], ["winword.exe", "excel.exe", "outlook.exe"]) is False


def test_a_root_has_no_ancestors(nodes):
    assert check(nodes["explorer"], ["explorer.exe"]) is False


def test_accepts_any_iterable_of_names(nodes):
    # A generator can only be read once. If your answer loops over
    # image_names for every ancestor, this test will catch it.
    assert check(nodes["attack_powershell"], (name for name in ["excel.exe", "outlook.exe"])) is True
    assert check(nodes["attack_powershell"], {"winword.exe"}) is True


def test_lineage_runs_oldest_first(nodes):
    names = [n.name for n in lineage(nodes["attack_powershell"])]
    assert names == ["explorer.exe", "OUTLOOK.EXE", "WINWORD.EXE", "powershell.exe"]


def test_is_same_or_descendant(nodes):
    assert is_same_or_descendant(nodes["attack_powershell"], nodes["explorer"])
    assert is_same_or_descendant(nodes["explorer"], nodes["explorer"])
    assert not is_same_or_descendant(nodes["explorer"], nodes["attack_powershell"])
