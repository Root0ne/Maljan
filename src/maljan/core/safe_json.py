"""JSON for report documents at any depth: written and read without raising on nesting.

A sandbox report is the remote end's choice, nesting included. ``json.dumps``
and ``json.loads`` recurse once per level and raise ``RecursionError`` some
thousands of levels down; pydantic's JSON reader, which reads the stored ledger
and report back, refuses a text nested past 200 levels. A report nested deeper
than that must still be read, laid out and handed to the analysts, so every
path that reads a report body goes through :func:`loads`, and every path that
writes a sandbox document or a part of one out as text goes through
:func:`dumps`.

* :func:`loads` reads what ``json.loads`` reads, the same values, for any body
  nested no deeper than :data:`DEPTH_GUARD` containers. A container nested
  below the guard is read as :data:`DEEPER_MARK`, a marked placeholder, at
  read time: no consumer after it ever holds a value nested deeper than the
  guard, so none can recurse past it. A body nested too deeply for
  ``json.loads`` is read by an iterative reader that validates the whole body
  but keeps an open-container entry only down to the guard (the levels below
  it as runs of one bracket, a long run read in one step), so its time and
  memory are linear in the body and it uses no call depth.
* :func:`dumps` writes exactly what ``json.dumps`` writes for any value nested
  no deeper than the guard: the value itself is handed to ``json.dumps``, so
  the bytes are the same bytes. A deeper value (one built in process) is
  written as a marked copy: each container below the guard as
  :data:`DEEPER_MARK`, a container that holds itself written once and its
  return as :data:`CYCLE_MARK` (where ``json.dumps`` would raise), and a
  container reached along a second path written once and then as
  :data:`SHARED_MARK`. Never a raise.

Every walk is iterative and linear in the distinct containers a value holds:
a container reached along several paths is measured once and copied once, so
a value that shares containers costs no more than the containers it has. A
value within the guard that shares containers is handed to ``json.dumps``
itself, which writes a shared container at each place it appears, as dev
wrote it: a report body is a tree once read, and the platform's readers hold
its parts by reference only where each part is written once.
"""

from __future__ import annotations

import json
import logging
import re
from json.decoder import scanstring  # type: ignore[attr-defined]
from json.scanner import NUMBER_RE
from typing import Any

# The deepest nesting, in containers, read and written out as it is. pydantic's
# JSON reader, which reads the stored ledger and report back, refuses a text
# nested past 200 levels in all, and a ledger entry or a report holds a tool's
# answer a few levels down; the guard leaves forty of them for that. The
# platform's deepest stored sandbox report nests 112 levels. A container below
# this depth is read and written as :data:`DEEPER_MARK`.
DEPTH_GUARD = 160

# What a container nested below :data:`DEPTH_GUARD` is read and written as.
DEEPER_MARK = f"[nested deeper than {DEPTH_GUARD} levels: not kept]"
# What a container that holds itself is written as where it returns.
CYCLE_MARK = "[a container that holds itself: written once, not again]"
# What a container reached along a second path is written as, in a marked copy.
SHARED_MARK = "[the same container as written earlier: not written again]"

_CONTAINERS = (dict, list, tuple)

logger = logging.getLogger(__name__)


def _children(node: Any) -> Any:
    return node.values() if isinstance(node, dict) else node


def _height(value: Any) -> int | None:
    """How many containers deep ``value`` nests; ``None`` where a container holds itself.

    A post-order walk with a stack, each distinct container measured once (by
    identity), so shared containers cost nothing more.
    """
    if not isinstance(value, _CONTAINERS):
        return 0
    heights: dict[int, int] = {}
    open_: set[int] = set()
    stack: list[tuple[Any, bool]] = [(value, False)]
    while stack:
        node, closing = stack.pop()
        key = id(node)
        if closing:
            open_.discard(key)
            below = [heights[id(c)] for c in _children(node) if isinstance(c, _CONTAINERS)]
            heights[key] = 1 + max(below, default=0)
            continue
        if key in heights:
            continue
        if key in open_:
            # Reached again before it closed: it is inside itself.
            return None
        open_.add(key)
        stack.append((node, True))
        stack.extend(
            (child, False)
            for child in _children(node)
            if isinstance(child, _CONTAINERS) and id(child) not in heights
        )
    return heights[id(value)]


def exceeds_depth(value: Any, limit: int = DEPTH_GUARD) -> bool:
    """Whether ``value`` nests deeper than ``limit`` containers, or holds itself.

    The value itself, when a container, is at depth 1. Linear in the distinct
    containers ``value`` holds.
    """
    height = _height(value)
    return height is None or height > limit


def within_depth(value: Any, limit: int = DEPTH_GUARD) -> Any:
    """``value`` itself where it nests no deeper than ``limit``; else a marked copy.

    The copy keeps every key in its order and every value down to ``limit``
    containers; each container below is :data:`DEEPER_MARK`, a container
    reached again inside itself is :data:`CYCLE_MARK`, and a container reached
    again along another path is :data:`SHARED_MARK`: each distinct container
    is copied once, so the copy is linear in them. A tuple is copied as a
    list, which JSON writes alike. Built with a stack, never recursion.
    """
    if not exceeds_depth(value, limit):
        return value
    holder: list[Any] = [None]
    copied: set[int] = set()
    on_path: set[int] = set()
    # Each entry: (node, parent, key, depth), or (None, None, id, 0) to close a container.
    stack: list[tuple[Any, Any, Any, int]] = [(value, holder, 0, 1)]
    while stack:
        node, parent, key, depth = stack.pop()
        if parent is None:
            on_path.discard(key)
            continue
        if not isinstance(node, _CONTAINERS):
            parent[key] = node
            continue
        if depth > limit:
            parent[key] = DEEPER_MARK
            continue
        node_id = id(node)
        if node_id in on_path:
            parent[key] = CYCLE_MARK
            continue
        if node_id in copied:
            parent[key] = SHARED_MARK
            continue
        out: Any
        if isinstance(node, dict):
            out = dict.fromkeys(node)
            entries = list(node.items())
        else:
            out = [None] * len(node)
            entries = list(enumerate(node))
        parent[key] = out
        copied.add(node_id)
        on_path.add(node_id)
        stack.append((None, None, node_id, 0))
        stack.extend((child, out, name, depth + 1) for name, child in reversed(entries))
    return holder[0]


def dumps(value: Any, **kwargs: Any) -> str:
    """``json.dumps(value, **kwargs)``, never raising on nesting (see the module docstring)."""
    return json.dumps(within_depth(value), **kwargs)


def _tree_deeper_than(value: Any, limit: int) -> bool:
    """Whether a tree ``value`` (what ``json.loads`` returns) nests deeper than ``limit``.

    A depth-first walk holding one iterator per open level, stopping at the
    guard: no record per container, so its memory is the guard's depth, and
    its time linear in the value. Only for a tree (a value read from text):
    one that shares or holds itself is measured by :func:`exceeds_depth`.
    """
    if not isinstance(value, dict | list):
        return False
    stack = [iter(_children(value))]
    while stack:
        for child in stack[-1]:
            if isinstance(child, dict | list):
                if len(stack) >= limit:
                    return True
                stack.append(iter(_children(child)))
                break
        else:
            stack.pop()
    return False


def loads(text: str | bytes | bytearray) -> Any:
    """``json.loads(text)``, each container below :data:`DEPTH_GUARD` read as :data:`DEEPER_MARK`.

    A body nested too deeply for ``json.loads`` is read by the iterative reader.
    Where the guard marks anything, a warning says how many containers it
    marked (once per body).
    """
    try:
        value = json.loads(text)
    except RecursionError:
        if isinstance(text, bytes | bytearray):
            # Decoded as ``json.loads`` decodes bytes.
            text = text.decode(json.detect_encoding(text), "surrogatepass")
        marked = [0]
        value = _loads_iteratively(text, marked=marked)
        _say_marked(marked[0])
        return value
    if not _tree_deeper_than(value, DEPTH_GUARD):
        return value
    copy = within_depth(value)
    _say_marked(_count_marks(copy))
    return copy


def _count_marks(value: Any) -> int:
    """How many :data:`DEEPER_MARK` values a tree within the guard holds."""
    count = 0
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, dict | list):
            stack.extend(_children(node))
        elif node == DEEPER_MARK:
            count += 1
    return count


def _say_marked(count: int) -> None:
    if count:
        logger.warning(
            "A report body nests deeper than %d levels: %d containers below that depth were "
            "read as a marked placeholder and are not kept.",
            DEPTH_GUARD,
            count,
        )


_WHITESPACE = re.compile(r"[ \t\n\r]*")
_LITERALS: tuple[tuple[str, Any], ...] = (
    ("null", None),
    ("true", True),
    ("false", False),
    ("NaN", float("nan")),
    ("Infinity", float("inf")),
    ("-Infinity", float("-inf")),
)
# A run of array openers with the whitespace among them, and a run of one
# closer: below the guard a run is consumed in one step (one character class,
# which the C regex engine walks holding no state per character), so a long
# run of brackets costs no Python step per bracket.
_ARRAY_OPENERS = re.compile(r"[\[ \t\n\r]+")
_CLOSER_RUN = {"]": re.compile(r"\]+"), "}": re.compile(r"\}+")}


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


def _loads_iteratively(
    text: str, limit: int = DEPTH_GUARD, *, marked: list[int] | None = None
) -> Any:
    """``text`` read as ``json.loads`` reads it, with an explicit stack instead of recursion.

    Every character is validated as ``json.loads`` validates it. Containers
    down to ``limit`` are kept, each with one stack entry; a container below is
    read as :data:`DEEPER_MARK`, its contents parsed and dropped, and the
    dropped levels are held as one byte each (the bracket that opened it) in a
    ``bytearray``, never more bytes than the body has brackets; a run of one
    bracket is added and closed in one step. Time and memory linear in
    ``text``. ``marked[0]``, where given, counts the marks written.
    """
    counter = marked if marked is not None else [0]
    # Each kept open container, with the key its next value is stored under.
    stack: list[list[Any]] = []
    # The brackets of the open containers below the guard, innermost last.
    dropped = bytearray()
    index = _skip(text, 0)
    while True:
        opener = text[index : index + 1]
        value: Any
        if opener == "[" and (dropped or len(stack) >= limit):
            # A run of arrays opened below the guard, read in one step.
            run = _ARRAY_OPENERS.match(text, index)
            assert run is not None
            count, index = text.count("[", index, run.end()), run.end()
            if text[index : index + 1] != "]":
                _open_arrays(dropped, count)
                continue
            # The innermost is empty: a whole value, the mark its parent holds.
            _open_arrays(dropped, count - 1)
            value, index = DEEPER_MARK, index + 1
            counter[0] += 1 if not dropped else 0
        elif opener in ("{", "["):
            index = _skip(text, index + 1)
            closer = "}" if opener == "{" else "]"
            if text[index : index + 1] == closer:
                index += 1
                if dropped or len(stack) >= limit:
                    value = DEEPER_MARK
                    counter[0] += 1 if not dropped else 0
                else:
                    value = {} if closer == "}" else []
            else:
                if opener == "{":
                    key, index = _key(text, index)
                if dropped or len(stack) >= limit:
                    dropped.append(ord(opener))
                else:
                    stack.append([{}, key] if opener == "{" else [[], None])
                continue
        else:
            value, index = _scalar(text, index)
        # A whole value: store it in its container, closing every container it completes.
        while True:
            if dropped:
                is_object = dropped[-1] == _OBJECT
            elif stack:
                is_object = isinstance(stack[-1][0], dict)
            else:
                index = _skip(text, index)
                if index != len(text):
                    raise json.JSONDecodeError("Extra data", text, index)
                return value
            if not dropped:
                top = stack[-1]
                if is_object:
                    top[0][top[1]] = value
                else:
                    top[0].append(value)
            index = _skip(text, index)
            delimiter = text[index : index + 1]
            if delimiter == ",":
                index = _skip(text, index + 1)
                if is_object:
                    key, index = _key(text, index)
                    if not dropped:
                        stack[-1][1] = key
                break
            if delimiter == ("}" if is_object else "]"):
                if dropped:
                    # Every container of the run this closer begins, closed in one step;
                    # the outermost one closed is the mark its parent holds.
                    index = _close_dropped(text, index, dropped)
                    value = DEEPER_MARK
                    counter[0] += 1 if not dropped else 0
                else:
                    index += 1
                    value = stack.pop()[0]
                continue
            raise json.JSONDecodeError("Expecting ',' delimiter", text, index)


_OBJECT = ord("{")
# Array openers added in pieces of this many, so adding a run holds no copy of it.
_ARRAYS = b"[" * 65_536


def _open_arrays(dropped: bytearray, count: int) -> None:
    """``count`` more dropped arrays, one byte each, added without a temporary copy of the run."""
    while count > 0:
        piece = min(count, len(_ARRAYS))
        dropped += _ARRAYS[:piece] if piece < len(_ARRAYS) else _ARRAYS
        count -= piece


_OTHER_OPENER = {"]": b"{", "}": b"["}


def _close_dropped(text: str, index: int, dropped: bytearray) -> int:
    """Close the innermost dropped containers the closers at ``index`` close; the index after.

    The closer at ``index`` matches the innermost dropped container (the
    caller checked). A run of that one closer, with no whitespace in it,
    closes in one step every innermost dropped container it matches: the run
    is read no further than the dropped containers, and the matching ones are
    the innermost bytes up to the last opener of the other kind, found by one
    search over no more bytes than the run. Each character is scanned a
    constant number of times.
    """
    closer = text[index]
    run = _CLOSER_RUN[closer].match(text, index, index + len(dropped))
    count = run.end() - index if run is not None else 1
    start = len(dropped) - count
    other = dropped.rfind(_OTHER_OPENER[closer], start)
    if other >= 0:
        count = len(dropped) - other - 1
    del dropped[len(dropped) - count :]
    return index + count
