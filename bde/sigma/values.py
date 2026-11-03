"""How one Sigma field test matches one value.

A detection item like

    CommandLine|windash|contains:
      - ' -urlcache '
      - ' -verifyctl '

means: the CommandLine field *contains* any of these strings, where each
leading '-' may also be written '/' (Windows tools accept both). The part
before the first '|' is the field; the rest are **modifiers**.

Sigma's defaults, which this file follows:
  * string matches ignore upper/lower case (unless the `cased` modifier is used);
  * `*` in a value matches any run of characters and `?` any one character;
    write `\\*` or `\\?` for a literal star or question mark;
  * a list of values means "any of them" (unless the `all` modifier is used);
  * `null` matches a field that is missing or empty.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from typing import Any

Test = Callable[[str | None], bool]

STRING_MODIFIERS = {"contains", "startswith", "endswith"}
REGEX_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
NUMBER_MODIFIERS = {"gt", "gte", "lt", "lte"}
KNOWN_MODIFIERS = STRING_MODIFIERS | set(REGEX_FLAGS) | NUMBER_MODIFIERS | {
    "all", "re", "windash", "cased", "exists", "cidr",
}

# Characters Windows command lines accept in place of '-' before a flag.
WINDASH_CHARACTERS = ("-", "/", "–", "—", "―")


def as_text(value: Any) -> str:
    """YAML values -> the text we compare against (True -> 'true', 4624 -> '4624')."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def wildcard_to_regex(value: str) -> str:
    """Sigma wildcards to a regex fragment: '*' -> '.*', '?' -> '.', '\\*' -> literal '*'."""
    out = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if char == "*" else "." if char == "?" else re.escape(char))
        i += 1
    return "".join(out)


def windash_variants(value: str) -> list[str]:
    """'-urlcache -f' -> every way of writing those dashes, e.g. '/urlcache /f'."""
    variants = [""]
    for char in value:
        options = WINDASH_CHARACTERS if char == "-" else (char,)
        variants = [v + option for v in variants for option in options]
        if len(variants) > 625:  # 4 dashes; more would explode, and never happens in real rules
            raise ValueError(f"too many '-' in windash value {value!r}")
    return variants


def compile_test(field: str, modifiers: list[str], raw_values: list[Any]) -> Test:
    """Build the function that tests one field's value against this item."""
    unknown = [m for m in modifiers if m not in KNOWN_MODIFIERS]
    if unknown:
        raise ValueError(f"field {field!r}: unsupported modifier {unknown[0]!r}")
    need_all = "all" in modifiers

    if "exists" in modifiers:
        if len(raw_values) != 1 or not isinstance(raw_values[0], bool):
            raise ValueError(f"field {field!r}: 'exists' takes true or false")
        wanted = raw_values[0]
        return lambda value: bool(value) == wanted

    if "cidr" in modifiers:
        networks = [ipaddress.ip_network(as_text(v), strict=False) for v in raw_values]

        def in_networks(value: str | None) -> bool:
            try:
                address = ipaddress.ip_address((value or "").strip())
            except ValueError:
                return False
            hits = [address in network for network in networks if network.version == address.version]
            return all(hits) and len(hits) == len(networks) if need_all else any(hits)

        return in_networks

    numeric = [m for m in modifiers if m in NUMBER_MODIFIERS]
    if numeric:
        compare = {"gt": float.__gt__, "gte": float.__ge__, "lt": float.__lt__, "lte": float.__le__}[numeric[0]]
        limits = [float(v) for v in raw_values]

        def number_test(value: str | None) -> bool:
            try:
                number = float(value or "")
            except ValueError:
                return False
            results = [compare(number, limit) for limit in limits]
            return all(results) if need_all else any(results)

        return number_test

    if "re" in modifiers:
        flags = 0
        for modifier in modifiers:
            flags |= REGEX_FLAGS.get(modifier, 0)
        patterns = [re.compile(as_text(v), flags) for v in raw_values]
        return _combine([lambda value, p=p: value is not None and p.search(value) is not None for p in patterns],
                        need_all)

    position = next((m for m in modifiers if m in STRING_MODIFIERS), None)
    flags = re.DOTALL | (0 if "cased" in modifiers else re.IGNORECASE)
    tests: list[Test] = []
    for raw in raw_values:
        if raw is None:
            tests.append(lambda value: value is None or value == "")
            continue
        variants = windash_variants(as_text(raw)) if "windash" in modifiers else [as_text(raw)]
        fragment = "|".join(f"(?:{wildcard_to_regex(v)})" for v in variants)
        if position == "contains":
            fragment = f".*(?:{fragment}).*"
        elif position == "startswith":
            fragment = f"(?:{fragment}).*"
        elif position == "endswith":
            fragment = f".*(?:{fragment})"
        pattern = re.compile(fragment, flags)
        tests.append(lambda value, p=pattern: value is not None and p.fullmatch(value) is not None)
    return _combine(tests, need_all)


def _combine(tests: list[Test], need_all: bool) -> Test:
    if need_all:
        return lambda value: all(test(value) for test in tests)
    return lambda value: any(test(value) for test in tests)
