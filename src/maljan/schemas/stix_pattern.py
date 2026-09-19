"""Read what a STIX pattern compares, in one place, for everybody who asks.

Two readers of the same syntax used to live here: the validator split a pattern
on its quotes to ask whether each value is grounded in the run's evidence, and
the STIX renderer split it again to ask whether each endpoint may be exported.
Neither read an escaped quote — ``[file:name = 'it\\'s.exe']`` came back as the
literal ``it\\`` — and they had already drifted about what a quoted key is: the
validator decided it from the object path, the renderer from the property name.
Two readings of one pattern is how one of them publishes what the other vetoes.

This is a reader, not a grammar. It answers three questions about each quoted
value a comparison carries — which object path it is compared against, with
which operator, and what the value itself is once its escapes are undone — and
where it cannot answer them it says so, in :attr:`Comparison.readable`. A
caller declines an unreadable comparison; nothing here guesses.

What it deliberately skips rather than misreads:

* a **quoted key inside an object path** — ``file:hashes.'MD5'`` names an
  algorithm and ``file:extensions['pe']`` names an extension. A quote opening
  where the path is still being written continues the path; a value is what
  follows the comparison operator.
* a **qualifier's own literal** — ``[…] START '2026-01-01T00:00:00Z' STOP …``
  quotes two timestamps after the observation expression has closed. They
  belong to the qualifier, not to the comparison before them, and crediting
  them to it declined a sound indicator for an endpoint nobody had written.

One record per value, so an ``IN ('a', 'b')`` list — which writes its path once
and quotes twice — yields one record for each value, each carrying that shared
path and operator. A pattern is not one comparison, and a caller answers for
every value in it.

The scan is a single left-to-right pass, so a pattern quoting a thousand values
costs a thousand steps rather than a thousand squared.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# An object path written outside the quotes: the type, then the property. The
# property steps through plain names, list indices and quoted keys, because
# ``network-traffic:dst_ref.value``, ``domain-name:resolves_to_refs[*].value``
# and ``file:extensions['pe'].pe_imphash`` are all one path. Case carries no
# meaning in a STIX object path and a judge writes ``[URL:value = …]`` often
# enough that reading it as some other kind would be a hole.
_OBJECT_PATH_RE = re.compile(
    r"([a-z0-9-]+):([a-z0-9_]+(?:\.[a-z0-9_]+|\.'[^']*'|\[[^\]]*\])*)",
    re.IGNORECASE,
)

# The two characters a STIX literal escapes. A backslash before anything else
# is a backslash: a judge writes ``'C:\Windows\system32\x.exe'`` unescaped far
# more often than it writes a path that needed escaping, and reading every
# backslash as an escape would eat the separators out of it.
_ESCAPABLE = ("'", "\\")

# A bracket that opens a step through a property, rather than the one that
# opens an observation expression: a property name is written right before it.
_INDEX_STEP_RE = re.compile(r"[A-Za-z0-9_]\[$")


@dataclass(frozen=True)
class Comparison:
    """One quoted value, and what the pattern compares it against.

    ``readable`` is false when the reader could not say what this value is
    compared against — an unterminated quote, or a value with no object path
    written before it anywhere in the pattern. The caller declines it; it is
    never guessed at and never silently published.
    """

    object_type: str
    prop: str
    operator: str
    literal: str
    readable: bool

    @property
    def path(self) -> str:
        """The object path this value is compared against, lowercased."""
        return f"{self.object_type}:{self.prop}" if self.object_type else ""


def read_comparisons(pattern: str) -> list[Comparison]:
    """Every quoted value in ``pattern``, in the order it is written."""
    text = str(pattern or "")
    found: list[Comparison] = []
    outside: list[str] = []
    object_type = ""
    prop = ""
    operator = ""
    observation_closed = False
    index = 0
    while index < len(text):
        char = text[index]
        if char != "'":
            outside.append(char)
            index += 1
            continue
        literal, index, closed = _read_quoted(text, index)
        before = "".join(outside)
        if closed and _opens_a_key(before):
            # A key continues the path rather than answering it, and the path
            # regex above reads it back as one.
            outside.append(f"'{literal}'")
            continue
        outside = []
        paths = list(_OBJECT_PATH_RE.finditer(before))
        if paths:
            object_type = paths[-1].group(1).lower()
            prop = paths[-1].group(2).lower()
            operator = before[paths[-1].end() :].strip().lower()
            observation_closed = False
        else:
            # No new path: either the value list of the comparison before this
            # one goes on, or the observation expression has closed and what
            # follows belongs to a qualifier.
            observation_closed = observation_closed or "]" in before
            if observation_closed:
                continue
        found.append(
            Comparison(
                object_type=object_type,
                prop=prop,
                operator=operator,
                literal=literal,
                readable=closed and bool(object_type),
            )
        )
    return found


def _opens_a_key(before: str) -> bool:
    """Whether the quote about to open continues an object path.

    ``file:hashes.'MD5'`` and ``file:extensions['pe']`` step through a key; the
    ``[`` that opens an observation expression steps through nothing, so a
    bracket is a key's only when a property name is written right before it.
    """
    text = before.rstrip()
    return text.endswith(".") or _INDEX_STEP_RE.search(text) is not None


def _read_quoted(text: str, start: int) -> tuple[str, int, bool]:
    """The literal opening at ``text[start]``, where it ends, and whether it closed."""
    value: list[str] = []
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text) and text[index + 1] in _ESCAPABLE:
            value.append(text[index + 1])
            index += 2
            continue
        if char == "'":
            return "".join(value), index + 1, True
        value.append(char)
        index += 1
    return "".join(value), len(text), False
