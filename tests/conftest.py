"""Shared pytest fixtures."""

import pytest

from bde.readers import read_events
from bde.tree import ProcessTree
from helpers import SAMPLE


@pytest.fixture(scope="session")
def sample_tree() -> ProcessTree:
    """The process trees of the hand-made sample (data/samples)."""
    return ProcessTree.from_events(read_events(SAMPLE))
