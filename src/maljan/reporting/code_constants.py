"""The 32-bit values the sample stores in its own bytes that the run's tools read and named.

A drafted YARA rule that matches on the published indicators matches nothing
when the sample keeps them encoded: the strings are in the decoded text, not in
the file, and the rule then matches its sample by its hash alone, which says
nothing a hash lookup does not. What the file does hold, as it is, are the
values its code works with, and two kinds of answer state such values with the
places they stand:

* **A decoder's seed** (kind ``decoded_strings``). A result decoded under a
  seed-and-length header states the seed (``parameters.seed``), which the
  header stores in front of each encoded text. One seed is read once, with the
  number of results that state it.
* **A function-name hash** (kind ``api_hash_resolution``). Each hit is a value
  stored in the file (``value``) that equals a hash of a function or module
  name, with every place it stands (``occurrences``). A lone hit, whose
  algorithm resolves nothing else in the file, is a chance match and is not
  read.

Read by the answer's kind, never by a tool's name, and only from an answer
about the sample itself: one about a file the run carved out of it (the
``carved`` argument its tool declares) is about another file. A value too plain
to tell one file from another is not read: one below 0x10000, or one with fewer
than three distinct bytes. Each value is kept once, at the first answer that
states it, seeds first and then hashes, each in the order of the ledger.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from maljan.reporting import tool_kinds
from maljan.reporting.call_bindings import _field, _file_of
from maljan.reporting.models import CodeConstant

# The answer kinds read here, and where each states its values.
_DECODED = "decoded_strings"
_HASHES = "api_hash_resolution"

# A value below this is a count, a size or a flag far more often than a seed.
_LEAST = 0x10000
# The fewest distinct bytes a value keeps to tell one file from another.
_LEAST_DISTINCT_BYTES = 3
# How many names one hash's meaning lists, and the longest name it prints.
_NAMES_SAID = 3
_NAME_CHARS = 64


def code_constants_from_ledger(ledger: Iterable[Any] | None) -> list[CodeConstant]:
    """Every distinct 32-bit value the sample stores that a decoder or a hash resolver states."""
    seeds: list[CodeConstant] = []
    hashes: list[CodeConstant] = []
    seen: set[int] = set()
    for entry in ledger or ():
        if not bool(_field(entry, "ok")):
            continue
        facts = tool_kinds.facts_of(entry)
        if facts is None or facts.kind not in (_DECODED, _HASHES):
            continue
        if _file_of(entry, facts):
            continue
        data = _field(entry, "structured")
        if not isinstance(data, Mapping) or data.get("error"):
            continue
        entry_id = str(_field(entry, "entry_id") or _field(entry, "id") or "")
        tool = tool_kinds.stated_name(entry, facts)
        if facts.kind == _DECODED:
            seeds.extend(_seeds(data, entry_id, tool, seen))
        else:
            hashes.extend(_hashes(data, entry_id, tool, seen))
    return [*seeds, *hashes]


def little_endian(value: str) -> bytes | None:
    """The four bytes a value is stored as, little-endian; ``None`` for no 32-bit value."""
    number = _number(value)
    if number is None:
        return None
    return number.to_bytes(4, "little")


def _seeds(data: Mapping[str, Any], entry_id: str, tool: str, seen: set[int]) -> list[CodeConstant]:
    """The seeds a decoder's results state, each once, with how many results state it."""
    counted: dict[int, list[Any]] = {}
    for row in _rows(data.get("results")):
        parameters = row.get("parameters")
        if not isinstance(parameters, Mapping):
            continue
        number = _number(parameters.get("seed"))
        if number is None or not _telling(number) or number in seen:
            continue
        counted.setdefault(number, []).append(row)
    out: list[CodeConstant] = []
    for number, rows in counted.items():
        seen.add(number)
        schemes = sorted(
            {_clean(str(row.get("scheme") or ""))[:_NAME_CHARS] for row in rows} - {""}
        )
        under = f", {', '.join(schemes)}" if schemes else ""
        count = len(rows)
        out.append(
            CodeConstant(
                value=f"{number:#010x}",
                meaning=(
                    f"the decoder seed stored in the header of {count} encoded "
                    f"string{'s' if count != 1 else ''}{under}"
                ),
                entry=entry_id,
                tool=tool,
                first_offset=_clean(str(rows[0].get("offset") or ""))[:_NAME_CHARS],
                places=count,
            )
        )
    return out


def _hashes(
    data: Mapping[str, Any], entry_id: str, tool: str, seen: set[int]
) -> list[CodeConstant]:
    """The values a hash resolver's hits state, each once, with the names each is a hash of."""
    out: list[CodeConstant] = []
    for hit in _rows(data.get("hits")):
        number = _number(hit.get("value"))
        if number is None or not _telling(number) or number in seen:
            continue
        places = _rows(hit.get("occurrences"))
        if not places:
            continue
        seen.add(number)
        names: list[str] = []
        for reading in _rows(hit.get("readings")):
            name = _clean(str(reading.get("name") or ""))[:_NAME_CHARS]
            if name and name not in names:
                names.append(name)
        said = ", ".join(names[:_NAMES_SAID])
        if len(names) > _NAMES_SAID:
            said += f" and {len(names) - _NAMES_SAID} more"
        out.append(
            CodeConstant(
                value=f"{number:#010x}",
                meaning=f"a function-name hash ({said or 'no name stated'})",
                entry=entry_id,
                tool=tool,
                first_offset=_clean(str(places[0].get("offset") or ""))[:_NAME_CHARS],
                places=len(places),
            )
        )
    return out


def _rows(value: Any) -> list[Mapping[str, Any]]:
    return [row for row in value if isinstance(row, Mapping)] if isinstance(value, list) else []


def _number(value: Any) -> int | None:
    """A 32-bit value written as hexadecimal text, or ``None``."""
    if isinstance(value, bool) or not isinstance(value, str):
        return None
    try:
        number = int(value.strip(), 16)
    except ValueError:
        return None
    return number if 0 <= number <= 0xFFFFFFFF else None


def _telling(number: int) -> bool:
    """Whether a value can tell one file from another: not small, and of three distinct bytes."""
    stored = number.to_bytes(4, "little")
    return number >= _LEAST and len(set(stored)) >= _LEAST_DISTINCT_BYTES


def _clean(text: str) -> str:
    """A tool's word on one line: whitespace collapsed, markup and separators replaced."""
    flat = " ".join(text.split())
    return "".join("_" if c in '`|<>*[]{}\\"/' or c < " " else c for c in flat)
