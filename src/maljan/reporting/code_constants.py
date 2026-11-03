"""The 32-bit values the sample stores in its own bytes that the run's tools read and named.

A drafted YARA rule that matches on the published indicators matches nothing
when the sample keeps them encoded: the strings are in the decoded text, not in
the file, and the rule then matches its sample by its hash alone, which says
nothing a hash lookup does not. What the file does hold, as it is, are the
values its code works with, and two kinds of answer state such values with the
places they stand (the consumer ``code_constants`` of
``core.builtin_declarations.CONSUMER_KINDS``):

* **A decoder's seed** (kind ``decoded_strings``, declared value ``seed``). A
  result decoded under a seed-and-length header states the seed, which the
  header stores in front of each encoded text. One seed is read once, with the
  number of results that state it.
* **A function-name hash** (kind ``api_hash_resolution``, declared values
  ``value`` and ``algorithm``). Each hit is a value stored in the file that
  equals a hash of a function or module name under one or more algorithms,
  with every place it stands (``occurrences``).

Each answer's rows and values are read where its declaration points them, and
where it points none, where the built-in tool of that kind keeps them; never by
a tool's name.

What is not read:

* an answer about a file the run carved out of the sample (the ``carved``
  argument its tool declares): it is about another file;
* a failed call, or an answer that states an error;
* a hash hit none of whose algorithms resolves a second distinct value in the
  same answer: a program that resolves functions by hash uses one algorithm for
  many, and a value alone under its algorithm is a chance match. The resolver's
  own ``lone_hits`` are not read either;
* a hit stated with no place in the file;
* a value too plain to tell one file from another: below 0x10000, or of fewer
  than three distinct bytes.

A function-name hash says how a program finds its imports, which many programs
share; it is drafted only together with a seed (``detection_signatures``). Each
value is kept once, at the first answer that states it, seeds first and then
hashes, each in the order of the ledger.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Mapping
from typing import Any

from maljan.core.tool_declarations import select
from maljan.reporting import tool_kinds
from maljan.reporting.call_bindings import _field, _file_of
from maljan.reporting.models import CodeConstant

# The consumer whose declared kinds are read here, and the two of them.
_CONSUMER = "code_constants"
_DECODED = "decoded_strings"
_HASHES = "api_hash_resolution"
# Where the built-in tool of each kind keeps its rows and values, read where a
# declaration names none.
_DEFAULT_ROWS = {_DECODED: "/results/*", _HASHES: "/hits/*"}
_SEED = "/parameters/seed"
_VALUE = "/value"
_ALGORITHM = "/readings/*/algorithm"
_NAME = "/readings/*/name"
_OFFSETS = "/occurrences/*/offset"
_ROW_OFFSET = "/offset"
_SCHEME = "/scheme"

# A value below this is a count, a size or a flag far more often than a seed.
_LEAST = 0x10000
# The fewest distinct bytes a value keeps to tell one file from another.
_LEAST_DISTINCT_BYTES = 3
# How many distinct values one algorithm resolves in an answer before a hit
# under it is read.
_LEAST_PER_ALGORITHM = 2
# How many names one hash's meaning lists, and the longest word it prints.
_NAMES_SAID = 3
# The characters a word never carries: format characters (a bidi override, a
# zero-width joiner) and line and paragraph separators.
_DROPPED = frozenset({"Cf", "Zl", "Zp"})
_WORD_CHARS = 64


def code_constants_from_ledger(ledger: Iterable[Any] | None) -> list[CodeConstant]:
    """Every distinct 32-bit value the sample stores that a decoder or a hash resolver states."""
    seeds: list[CodeConstant] = []
    hashes: list[CodeConstant] = []
    seen: set[int] = set()
    for entry in ledger or ():
        if not bool(_field(entry, "ok")) or not tool_kinds.is_of(entry, _CONSUMER):
            continue
        facts = tool_kinds.facts_of(entry)
        if facts is None or _file_of(entry, facts):
            continue
        data = _field(entry, "structured")
        if not isinstance(data, Mapping) or data.get("error"):
            continue
        rows = [
            row
            for row in select(data, facts.rows or _DEFAULT_ROWS.get(facts.kind, ""))
            if isinstance(row, Mapping)
        ]
        values = facts.values or {}
        said = _Said(
            entry=str(_field(entry, "entry_id") or _field(entry, "id") or ""),
            tool=tool_kinds.stated_name(entry, facts),
        )
        if facts.kind == _DECODED:
            seeds.extend(_seeds(rows, str(values.get("seed") or _SEED), said, seen))
        elif facts.kind == _HASHES:
            hashes.extend(
                _hashes(
                    rows,
                    str(values.get("value") or _VALUE),
                    str(values.get("algorithm") or _ALGORITHM),
                    str(values.get("name") or _NAME),
                    said,
                    seen,
                )
            )
    return [*seeds, *hashes]


def little_endian(value: Any) -> bytes | None:
    """The four bytes a value is stored as, little-endian; ``None`` for no 32-bit value."""
    number = _number(value)
    if number is None:
        return None
    return number.to_bytes(4, "little")


class _Said:
    """The answer a value is read from: its entry and its tool's stated name."""

    def __init__(self, entry: str, tool: str) -> None:
        self.entry = entry
        self.tool = tool


def _seeds(
    rows: list[Mapping[str, Any]], path: str, said: _Said, seen: set[int]
) -> list[CodeConstant]:
    """The seeds a decoder's results state, each once, with how many results state it."""
    counted: dict[int, list[Mapping[str, Any]]] = {}
    for row in rows:
        number = _first_number(row, path)
        if number is None or not _telling(number) or number in seen:
            continue
        counted.setdefault(number, []).append(row)
    out: list[CodeConstant] = []
    for number, stating in counted.items():
        seen.add(number)
        schemes = sorted({_word(_first(row, _SCHEME)) for row in stating} - {""})
        under = f", {', '.join(schemes)}" if schemes else ""
        count = len(stating)
        out.append(
            CodeConstant(
                value=f"{number:#010x}",
                role="seed",
                meaning=(
                    f"the decoder seed stored in the header of {count} encoded "
                    f"string{'s' if count != 1 else ''}{under}"
                ),
                entry=said.entry,
                tool=said.tool,
                first_offset=_word(_first(stating[0], _ROW_OFFSET)),
                places=count,
            )
        )
    return out


def _hashes(
    rows: list[Mapping[str, Any]],
    value_path: str,
    algorithm_path: str,
    name_path: str,
    said: _Said,
    seen: set[int],
) -> list[CodeConstant]:
    """The values a hash resolver's hits state under an algorithm that resolves two or more."""
    read: list[tuple[int, list[str], list[Any], Mapping[str, Any]]] = []
    resolved: dict[str, set[int]] = {}
    # Only a value that is read at all counts toward its algorithm's two: a
    # plain value, or one stated with no place, is no second resolution.
    for row in rows:
        number = _first_number(row, value_path)
        if number is None or not _telling(number):
            continue
        offsets = [o for o in select(row, _OFFSETS) if o not in (None, "")]
        if not offsets:
            continue
        algorithms = sorted({_word(a) for a in select(row, algorithm_path)} - {""})
        for algorithm in algorithms:
            resolved.setdefault(algorithm, set()).add(number)
        read.append((number, algorithms, offsets, row))
    out: list[CodeConstant] = []
    for number, algorithms, offsets, row in read:
        if not any(len(resolved[a]) >= _LEAST_PER_ALGORITHM for a in algorithms):
            continue
        if number in seen:
            continue
        seen.add(number)
        names: list[str] = []
        for name in select(row, name_path):
            word = _word(name)
            if word and word not in names:
                names.append(word)
        listed = ", ".join(names[:_NAMES_SAID])
        if len(names) > _NAMES_SAID:
            listed += f" and {len(names) - _NAMES_SAID} more"
        out.append(
            CodeConstant(
                value=f"{number:#010x}",
                role="hash",
                meaning=f"a function-name hash ({listed or 'no name stated'})",
                entry=said.entry,
                tool=said.tool,
                first_offset=_word(offsets[0]),
                places=len(offsets),
            )
        )
    return out


def _first(row: Mapping[str, Any], path: str) -> Any:
    found = select(row, path)
    return found[0] if found else None


def _first_number(row: Mapping[str, Any], path: str) -> int | None:
    return _number(_first(row, path))


def _number(value: Any) -> int | None:
    """A 32-bit value given as an int, as ``0x``-prefixed hexadecimal or as decimal text."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        text = value.strip().lower()
        try:
            number = int(text, 16) if text.startswith("0x") else int(text, 10)
        except ValueError:
            return None
    else:
        return None
    return number if 0 <= number <= 0xFFFFFFFF else None


def _telling(number: int) -> bool:
    """Whether a value can tell one file from another: not small, and of three distinct bytes."""
    stored = number.to_bytes(4, "little")
    return number >= _LEAST and len(set(stored)) >= _LEAST_DISTINCT_BYTES


def _word(value: Any) -> str:
    """A tool's word on one line: whitespace collapsed, markup and separators replaced, capped."""
    flat = " ".join(str(value if value is not None else "").split())
    kept = "".join(c for c in flat if unicodedata.category(c) not in _DROPPED)
    return "".join("_" if c in '`|<>*[]{}\\"/' or c < " " else c for c in kept)[:_WORD_CHARS]
