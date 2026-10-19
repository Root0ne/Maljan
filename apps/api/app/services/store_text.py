"""The one place characters PostgreSQL refuses are taken out of what the worker stores.

PostgreSQL refuses U+0000 in a ``text`` column and in a ``jsonb`` value
(``\\u0000`` is an unsupported escape there), and it refuses a lone surrogate
(U+D800 to U+DFFF), which UTF-8 cannot encode, in both as well. One refused
value refuses the whole statement: the report, its findings, its ledger, its
transcript and the completion that goes with them in one transaction. Both
reach those values from the sample itself — a PE version string, a sandbox
buffer, a decoded string a tool quoted — so they are not rare and not the
run's fault.

Every string a stored row carries, in a plain column or anywhere inside a JSON
column (keys included), has each such character written out as the triage
pack writes a control character (``pack_escaped``: ``\\x00`` for a NUL,
``\\xd800`` for a surrogate), so a reader still sees where the sample had one.
Two keys of one mapping that become one key are both kept, the later under a
disambiguated key (:data:`COLLISION_KEY`). A plain column cut to its width is
cut again when the written-out form made it longer. The rows are sanitised
before anything is digested from them, so a ledger seal covers what is stored.
Each pass counts what it did (:class:`Replaced`); the caller records the
count, so nothing here is silent.

One walk over each value, each string scanned once: linear in what is stored.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from maljan.utils.written_forms import pack_escaped

# The characters PostgreSQL refuses in text and jsonb: the NUL and every
# surrogate code point (only a lone one can reach a Python ``str``).
NUL = "\x00"
_SURROGATE_FIRST = 0xD800
_SURROGATE_LAST = 0xDFFF
_REFUSED = re.compile(f"[{NUL}{chr(_SURROGATE_FIRST)}-{chr(_SURROGATE_LAST)}]")

# How a stored value writes a NUL instead: the triage pack's own spelling of
# it, so one character has one written form across everything a run records.
# A surrogate is written the same way (``pack_escaped``), four hex digits.
NUL_WRITTEN = pack_escaped(NUL)

# A key that collides, once written out, with a key already in its mapping is
# kept under this form, numbered from 2 until it is unique.
COLLISION_KEY = "{key} (collision {n})"

# Where a stored report's run summary records what was replaced, when anything
# was. Absent from a report whose values needed nothing, so every report stored
# before this existed reads the same.
RUN_SUMMARY_KEY = "store_nul_replaced"


@dataclass
class Replaced:
    """What one or more sanitising passes did."""

    nul: int = 0
    surrogate: int = 0
    collided_keys: int = 0
    recut: int = 0

    @property
    def total(self) -> int:
        return self.nul + self.surrogate + self.collided_keys + self.recut

    def add(self, other: Replaced) -> None:
        self.nul += other.nul
        self.surrogate += other.surrogate
        self.collided_keys += other.collided_keys
        self.recut += other.recut

    def record(self) -> dict[str, Any]:
        """The run summary's record of it."""
        return {
            "nul": self.nul,
            "surrogate": self.surrogate,
            "collided_keys": self.collided_keys,
            "recut": self.recut,
            "written_as": NUL_WRITTEN,
        }


def _written(match: re.Match[str], tally: Replaced) -> str:
    ch = match.group()
    if ch == NUL:
        tally.nul += 1
    else:
        tally.surrogate += 1
    return pack_escaped(ch)


def _clean(value: Any, tally: Replaced) -> Any:
    if isinstance(value, str):
        if _REFUSED.search(value) is None:
            return value
        return _REFUSED.sub(lambda m: _written(m, tally), value)
    if isinstance(value, Mapping):
        before = tally.total
        out: dict[Any, Any] = {}
        for key, item in value.items():
            new_key = _clean(key, tally)
            if new_key in out:
                n = 2
                while COLLISION_KEY.format(key=new_key, n=n) in out:
                    n += 1
                new_key = COLLISION_KEY.format(key=new_key, n=n)
                tally.collided_keys += 1
            out[new_key] = _clean(item, tally)
        return out if tally.total != before else value
    if isinstance(value, list | tuple):
        before = tally.total
        members = [_clean(item, tally) for item in value]
        if tally.total == before:
            return value
        return members if isinstance(value, list) else type(value)(members)
    return value


def storable(value: Any) -> tuple[Any, Replaced]:
    """``value`` with every refused character in its strings written out, and the tally.

    Strings, mapping keys and values, lists and tuples are walked; every other
    value is returned as it is. A value that needed nothing comes back as the
    same object, so nothing about a clean value changes, not even its identity.
    """
    tally = Replaced()
    return _clean(value, tally), tally


def without_nul(value: Any) -> tuple[Any, int]:
    """``storable`` with the tally as one number."""
    cleaned, tally = storable(value)
    return cleaned, tally.total


def sanitise_row(row: Any) -> Replaced:
    """Write out every refused character in every mapped column of ``row``.

    ``row`` is an ORM object not yet flushed. Only a column whose value
    changed is assigned again, so a clean row is left untouched; a changed
    string column with a width (``String(n)``) is cut to it again, because the
    value was cut to it before the written-out form made it longer.
    """
    from sqlalchemy import inspect

    tally = Replaced()
    for attr in inspect(row).mapper.column_attrs:
        current = getattr(row, attr.key, None)
        before = tally.total
        cleaned = _clean(current, tally)
        if tally.total == before:
            continue
        width = getattr(attr.columns[0].type, "length", None)
        if isinstance(cleaned, str) and isinstance(width, int) and len(cleaned) > width:
            cleaned = cleaned[:width]
            tally.recut += 1
        setattr(row, attr.key, cleaned)
    return tally


def recorded(run_summary: Any, replaced: Replaced, *, events: int = 0) -> Any:
    """``run_summary`` with ``replaced`` recorded under :data:`RUN_SUMMARY_KEY`.

    ``events`` is what the job's live feed had replaced by then. A new mapping,
    so the ORM sees a changed JSON column; ``run_summary`` as it was when
    nothing was replaced.
    """
    if not replaced.total and not events:
        return run_summary
    base = dict(run_summary) if isinstance(run_summary, Mapping) else {}
    base[RUN_SUMMARY_KEY] = {**replaced.record(), "events": events}
    return base
