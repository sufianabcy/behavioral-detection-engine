"""Seeded random numbers that come out the same on every computer.

Python only promises one thing about `random.Random(seed)`: its `random()`
method gives the same sequence for the same seed on every platform and
version. Helpers such as `randint()` or `choice()` are allowed to change
between Python versions. So every helper below is built on `random()` alone,
which keeps `bde generate --seed 7` byte-identical on a Mac and on Windows.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Sequence
from datetime import timedelta
from typing import TypeVar

T = TypeVar("T")


def derive_seed(seed: int, label: str) -> int:
    """A new seed for a named sub-stream, e.g. derive_seed(7, "chain-1").

    Each chain gets its own stream, so adding background noise doesn't shift
    where the attacks land. (hashlib, not hash(): hash() of a string changes
    every time Python starts.)
    """
    digest = hashlib.sha256(f"{seed}/{label}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


class Rand:
    def __init__(self, seed: int) -> None:
        self._r = random.Random(seed)

    def random(self) -> float:
        """A float in [0, 1)."""
        return self._r.random()

    def uniform(self, low: float, high: float) -> float:
        return low + (high - low) * self.random()

    def int_between(self, low: int, high: int) -> int:
        """An int in [low, high], both ends included."""
        return min(high, low + int(self.random() * (high - low + 1)))

    def chance(self, probability: float) -> bool:
        return self.random() < probability

    def choice(self, items: Sequence[T]) -> T:
        if not items:
            raise ValueError("choice() from an empty list")
        return items[self.int_between(0, len(items) - 1)]

    def weighted(self, items: Sequence[tuple[T, float]]) -> T:
        """Pick one of (item, weight) pairs, in proportion to the weights."""
        total = sum(weight for _, weight in items)
        point = self.random() * total
        for item, weight in items:
            point -= weight
            if point < 0:
                return item
        return items[-1][0]

    def shuffled(self, items: Sequence[T]) -> list[T]:
        result = list(items)
        for i in range(len(result) - 1, 0, -1):  # Fisher-Yates
            j = self.int_between(0, i)
            result[i], result[j] = result[j], result[i]
        return result

    def seconds(self, low: float, high: float) -> timedelta:
        """A random gap between low and high seconds, in whole milliseconds."""
        return timedelta(milliseconds=self.int_between(round(low * 1000), round(high * 1000)))

    def hex(self, digits: int) -> str:
        return "".join("0123456789abcdef"[self.int_between(0, 15)] for _ in range(digits))

    def word(self, length: int, alphabet: str = "abcdefghijklmnopqrstuvwxyz") -> str:
        return "".join(alphabet[self.int_between(0, len(alphabet) - 1)] for _ in range(length))
