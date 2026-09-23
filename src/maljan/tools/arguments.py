"""Reading a search argument without the quotes a model wrapped it in.

A model that has just read a JSON answer, or that writes a search the way a
person types one into a search box, wraps the value in quotes, and a quoted
needle matches nothing the unquoted one would. The analysis server already
reads ``carved_path`` this way, and this is the same reading for the arguments
a tool searches for or looks up by.

A pair of quotes that encloses the whole value comes off — the same quote
character at both ends and nowhere between them — and nothing else changes: no
unescaping, no case folding, no whitespace inside the quotes touched, and any
other value is passed through exactly as it arrived. The repair is never
silent: every structured answer to a call whose argument was read this way
carries, first, ``read_as``, the value each such argument was read as; a tool
that answers in prose names the value it looked up. The ledger keeps the
arguments as the model wrote them, so the record holds both.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, NamedTuple

# The quote characters a model wraps a value in. The analysis server's
# ``carved_path`` reading uses the same three.
SURROUNDING_QUOTES = ('"', "'", "`")

# Where an answer says what a quoted argument was read as. At the front of the
# answer, for the reason ``read_path`` is: a key behind a long list does not
# survive the cut an oversized answer is given.
READ_AS_KEY = "read_as"

# What each tool that takes such an argument says about it. Written once so no
# two descriptions can come to disagree about what the argument is.
UNQUOTED_NOTE = (
    "Pass {names} as the raw text or pattern itself, unquoted. One pair of quotes "
    "around the whole value is read as not part of it, and {record}."
)
_RECORDED_AS_KEY = "the answer's ``read_as`` says so when that happened"
_RECORDED_IN_TEXT = "the answer names the value that was looked up"


def unquoted(value: str) -> str:
    """``value`` without the pair of quotes that encloses it, or unchanged.

    The pair encloses the value when the same quote character opens and closes
    it and does not occur between them: ``"a" or "b"`` is two quoted parts, not
    one quoted value, and is left as written. Whitespace outside the pair goes
    with it; whitespace inside stays, because inside the quotes it is part of
    what was searched for.
    """
    text = value.strip()
    if len(text) < 2 or text[0] not in SURROUNDING_QUOTES or text[-1] != text[0]:
        return value
    inner = text[1:-1]
    return value if text[0] in inner else inner


def _read(value: Any) -> Any:
    """A string, or each string of a list, read without its quotes."""
    if isinstance(value, str):
        return unquoted(value)
    if isinstance(value, list):
        return [unquoted(item) if isinstance(item, str) else item for item in value]
    return value


class Unquoted(NamedTuple):
    """The arguments as they are passed on, and the ones whose reading changed."""

    values: dict[str, Any]
    read_as: dict[str, Any]


def read_unquoted(arguments: Mapping[str, Any], names: tuple[str, ...]) -> Unquoted:
    """``arguments`` with each of ``names`` read without its surrounding quotes."""
    values = dict(arguments)
    read_as: dict[str, Any] = {}
    for name in names:
        if name not in values:
            continue
        read = _read(values[name])
        if read != values[name]:
            values[name] = read
            read_as[name] = read
    return Unquoted(values, read_as)


def with_read_as(answer: Any, read_as: Mapping[str, Any]) -> Any:
    """``answer`` saying first what its quoted arguments were read as.

    Only a dict answer is given the key; a text answer already names the value
    it was asked about, and a sentence glued to it would stop a structured
    error in it parsing.
    """
    if not read_as or not isinstance(answer, dict):
        return answer
    return {READ_AS_KEY: dict(read_as), **answer}


def says_unquoted(*names: str, text_answer: bool = False) -> Callable[[Any], Any]:
    """Append the one sentence about ``names`` to a tool's description.

    ``text_answer`` is for a tool that answers in prose, which carries no
    ``read_as`` key and names the value it looked up instead. Applied under
    ``@mcp.tool()``, which reads ``__doc__`` when it registers.
    """
    listed = ", ".join(f"``{name}``" for name in names)
    record = _RECORDED_IN_TEXT if text_answer else _RECORDED_AS_KEY
    note = UNQUOTED_NOTE.format(names=listed, record=record)

    def apply(fn: Any) -> Any:
        fn.__doc__ = f"{(fn.__doc__ or '').rstrip()}\n\n{note}"
        return fn

    return apply
