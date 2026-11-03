"""Paths and small helpers shared by the tests."""

from pathlib import Path

from bde.tree import ProcessNode, ProcessTree

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "samples" / "macro_chain_demo.jsonl"
XML_EXPORT = ROOT / "tests" / "fixtures" / "sysmon_export.xml"
H1 = "WKSTN-07.corp.example"  # the attacked workstation in the sample
H2 = "WKSTN-12.corp.example"  # an admin doing normal work


def node_named(tree: ProcessTree, host: str, name: str) -> ProcessNode:
    """The first process on `host` whose file name is `name` (any case)."""
    return next(n for n in tree.nodes(host) if n.name.lower() == name.lower())
