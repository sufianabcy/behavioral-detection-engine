"""Parse and evaluate a Sigma `condition`, such as

    selection and not filter
    1 of selection_*
    all of them
    (selection_img and selection_cli) or selection_ofn

Grammar (lowest priority first), like the Sigma specification:

    expr     := and_expr ("or" and_expr)*
    and_expr := not_expr ("and" not_expr)*
    not_expr := "not" not_expr | primary
    primary  := "(" expr ")" | quantity "of" target | NAME
    quantity := "1" | "all" | "any" | a number
    target   := "them" | NAME, where NAME may end in * (selection_*)

`them` means every search identifier except those starting with "_".
The parser turns the text into a small tree of Python functions.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable

# A compiled condition takes "is identifier X true?" and answers True/False.
Lookup = Callable[[str], bool]
Node = Callable[[Lookup], bool]

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9_*\-.]+)")


def tokenize(text: str) -> list[str]:
    tokens, position = [], 0
    text = text.strip()
    while position < len(text):
        match = _TOKEN.match(text, position)
        if not match:
            if text[position:].lstrip().startswith("|"):
                raise ValueError("aggregations after '|' are not supported (Sigma 2 uses correlation rules instead)")
            raise ValueError(f"unexpected text in condition at {text[position:]!r}")
        tokens.append(match.group(1))
        position = match.end()
    return tokens


def parse_condition(text: str, identifiers: list[str]) -> Node:
    """Compile `text`; `identifiers` are the search names defined in the rule."""
    tokens = tokenize(text)
    position = 0

    def peek() -> str | None:
        return tokens[position].lower() if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        if position >= len(tokens):
            raise ValueError(f"condition ends too early: {text!r}")
        position += 1
        return tokens[position - 1]

    def expr() -> Node:
        node = and_expr()
        while peek() == "or":
            take()
            left, right = node, and_expr()
            node = lambda look, a=left, b=right: a(look) or b(look)
        return node

    def and_expr() -> Node:
        node = not_expr()
        while peek() == "and":
            take()
            left, right = node, not_expr()
            node = lambda look, a=left, b=right: a(look) and b(look)
        return node

    def not_expr() -> Node:
        if peek() == "not":
            take()
            inner = not_expr()
            return lambda look, a=inner: not a(look)
        return primary()

    def primary() -> Node:
        token = take()
        lowered = token.lower()
        if token == "(":
            node = expr()
            if take() != ")":
                raise ValueError(f"missing ')' in condition {text!r}")
            return node
        if token == ")":
            raise ValueError(f"unexpected ')' in condition {text!r}")
        if peek() == "of" and (lowered in ("all", "any") or lowered.isdigit()):
            take()  # "of"
            target = take()
            if target.lower() == "them":
                names = [name for name in identifiers if not name.startswith("_")]
            else:
                names = [name for name in identifiers if fnmatch.fnmatchcase(name, target)]
            if not names:
                raise ValueError(f"'{token} of {target}' matches no search identifier")
            if lowered == "all":
                return lambda look, n=tuple(names): all(look(name) for name in n)
            needed = 1 if lowered == "any" else int(lowered)
            return lambda look, n=tuple(names), k=needed: sum(1 for name in n if look(name)) >= k
        if lowered in ("and", "or", "not", "of"):
            raise ValueError(f"unexpected '{token}' in condition {text!r}")
        if token not in identifiers:
            raise ValueError(f"condition uses {token!r}, which the detection doesn't define")
        return lambda look, name=token: look(name)

    node = expr()
    if position != len(tokens):
        raise ValueError(f"unexpected {tokens[position]!r} in condition {text!r}")
    return node
