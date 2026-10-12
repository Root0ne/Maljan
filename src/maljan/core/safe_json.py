"""JSON for report documents at any depth: written and read without raising on nesting.

A sandbox report is the remote end's choice, nesting included. ``json.dumps``
and ``json.loads`` recurse once per level and raise ``RecursionError`` some
thousands of levels down; pydantic's serializer and validator, which store the
ledger and the report, refuse a value nested past about 250 levels. A report
nested deeper than that must still be read, laid out and handed to the
analysts, so every path that writes a sandbox document or a part of one out as
text goes through :func:`dumps`, and every path that reads a report body goes
through :func:`loads`.

* :func:`dumps` writes exactly what ``json.dumps`` writes for any value nested
  no deeper than :data:`DEPTH_GUARD` containers: the value itself is handed to
  ``json.dumps``, so the bytes are the same bytes. A deeper value is written
  with each container below the guard replaced by :data:`DEEPER_MARK`, a
  marked placeholder saying what was not written, never dropped in silence and
  never a raise. The text it writes is always one every reader of the
  platform reads back, pydantic included.
* :func:`loads` reads what ``json.loads`` reads, the same values. A body
  nested too deeply for ``json.loads`` is read again by an iterative reader
  with an explicit stack, so it costs time linear in the body and no call
  depth.

Both walks are iterative: no step of either recurses.
"""

from __future__ import annotations

import json
import re
from json.decoder import scanstring  # type: ignore[attr-defined]
from json.scanner import NUMBER_RE
from typing import Any

# The deepest nesting, in containers, written out as it is. pydantic's JSON
# reader, which reads the stored ledger and report back, refuses a text nested
# past 200 levels in all, and a ledger entry or a report holds a tool's answer
# a few levels down; the guard leaves forty of them for that. The platform's
# deepest stored sandbox report nests 112 levels. A container below this depth
# is written as :data:`DEEPER_MARK`.
DEPTH_GUARD = 160

# What a container nested below :data:`DEPTH_GUARD` is written as.
DEEPER_MARK = f"[nested deeper than {DEPTH_GUARD} levels: not written out]"

_CONTAINERS = (dict, list, tuple)


def exceeds_depth(value: Any, limit: int = DEPTH_GUARD) -> bool:
    """Whether ``value`` holds a container nested deeper than ``limit`` containers.

    The value itself, when a container, is at depth 1. Walked with a stack,
    each value visited at most once, stopping at the first container too deep.
    """
    if not isinstance(value, _CONTAINERS):
        return False
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            return True
        children = node.values() if isinstance(node, dict) else node
        below = depth + 1
        stack.extend((child, below) for child in children if isinstance(child, _CONTAINERS))
    return False


def within_depth(value: Any, limit: int = DEPTH_GUARD) -> Any:
    """``value`` itself where it nests no deeper than ``limit``; else a copy marked below it.

    The copy keeps every key in its order and every value down to ``limit``
    containers; each container below is :data:`DEEPER_MARK`. A tuple is copied
    as a list, which JSON writes alike. Built with a stack, never recursion.
    """
    if not exceeds_depth(value, limit):
        return value
    holder: list[Any] = [None]
    stack: list[tuple[Any, Any, Any, int]] = [(value, holder, 0, 1)]
    while stack:
        node, parent, key, depth = stack.pop()
        if isinstance(node, dict):
            if depth > limit:
                parent[key] = DEEPER_MARK
                continue
            out: dict[Any, Any] = dict.fromkeys(node)
            parent[key] = out
            stack.extend((child, out, name, depth + 1) for name, child in node.items())
        elif isinstance(node, list | tuple):
            if depth > limit:
                parent[key] = DEEPER_MARK
                continue
            items: list[Any] = [None] * len(node)
            parent[key] = items
            stack.extend((child, items, index, depth + 1) for index, child in enumerate(node))
        else:
            parent[key] = node
    return holder[0]


def dumps(value: Any, **kwargs: Any) -> str:
    """``json.dumps(value, **kwargs)``, never raising on nesting (see the module docstring)."""
    return json.dumps(within_depth(value), **kwargs)


def loads(text: str | bytes | bytearray) -> Any:
    """``json.loads(text)``; a body nested too deeply for it is read again iteratively."""
    try:
        return json.loads(text)
    except RecursionError:
        if isinstance(text, bytes | bytearray):
            # Decoded as ``json.loads`` decodes bytes.
            text = text.decode(json.detect_encoding(text), "surrogatepass")
        return _loads_iteratively(text)


_WHITESPACE = re.compile(r"[ \t\n\r]*")
_LITERALS: tuple[tuple[str, Any], ...] = (
    ("null", None),
    ("true", True),
    ("false", False),
    ("NaN", float("nan")),
    ("Infinity", float("inf")),
    ("-Infinity", float("-inf")),
)


def _skip(text: str, index: int) -> int:
    match = _WHITESPACE.match(text, index)
    return match.end() if match is not None else index


def _key(text: str, index: int) -> tuple[str, int]:
    """An object's key and the index after its colon and the whitespace that follows."""
    if text[index : index + 1] != '"':
        raise json.JSONDecodeError("Expecting property name enclosed in double quotes", text, index)
    key, index = scanstring(text, index + 1)
    index = _skip(text, index)
    if text[index : index + 1] != ":":
        raise json.JSONDecodeError("Expecting ':' delimiter", text, index)
    return key, _skip(text, index + 1)


def _scalar(text: str, index: int) -> tuple[Any, int]:
    """The string, number or literal at ``index``, as ``json.loads`` reads it."""
    if text[index : index + 1] == '"':
        found: tuple[str, int] = scanstring(text, index + 1)
        return found
    number = NUMBER_RE.match(text, index)
    if number is not None:
        integer, fraction, exponent = number.groups()
        if fraction or exponent:
            return float(integer + (fraction or "") + (exponent or "")), number.end()
        return int(integer), number.end()
    for word, meaning in _LITERALS:
        if text.startswith(word, index):
            return meaning, index + len(word)
    raise json.JSONDecodeError("Expecting value", text, index)


def _loads_iteratively(text: str) -> Any:
    """``text`` read as ``json.loads`` reads it, with an explicit stack instead of recursion."""
    # Each open container, with the key its next value is stored under.
    stack: list[list[Any]] = []
    index = _skip(text, 0)
    while True:
        opener = text[index : index + 1]
        value: Any
        if opener == "{":
            index = _skip(text, index + 1)
            if text[index : index + 1] == "}":
                value, index = {}, index + 1
            else:
                key, index = _key(text, index)
                stack.append([{}, key])
                continue
        elif opener == "[":
            index = _skip(text, index + 1)
            if text[index : index + 1] == "]":
                value, index = [], index + 1
            else:
                stack.append([[], None])
                continue
        else:
            value, index = _scalar(text, index)
        # A whole value: store it in its container, closing every container it completes.
        while True:
            if not stack:
                index = _skip(text, index)
                if index != len(text):
                    raise json.JSONDecodeError("Extra data", text, index)
                return value
            top = stack[-1]
            container = top[0]
            if isinstance(container, dict):
                container[top[1]] = value
            else:
                container.append(value)
            index = _skip(text, index)
            delimiter = text[index : index + 1]
            if delimiter == ",":
                index = _skip(text, index + 1)
                if isinstance(container, dict):
                    top[1], index = _key(text, index)
                break
            if delimiter == ("}" if isinstance(container, dict) else "]"):
                stack.pop()
                value, index = container, index + 1
                continue
            raise json.JSONDecodeError("Expecting ',' delimiter", text, index)
