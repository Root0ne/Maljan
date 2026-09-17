"""The shape of a corroboration row, and how a stored one is read.

A row is ``{asserted_by: [deterministic sources], claimed_by: [agents]}``,
two flat lists and no score. A summary stored before the two lists carried a
flat list of sources; it is read as claimed by all of them, which is what a
list that never distinguished a rule from an agent meant.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def corroboration_row(row: Mapping[str, Any] | Sequence[str] | None) -> dict[str, list[str]]:
    """One corroboration row in the current shape, whichever shape it was stored in."""
    if isinstance(row, Mapping):
        return {
            "asserted_by": [str(x) for x in row.get("asserted_by") or []],
            "claimed_by": [str(x) for x in row.get("claimed_by") or []],
        }
    return {"asserted_by": [], "claimed_by": [str(x) for x in (row or [])]}


def corroboration_sources(row: Mapping[str, Any] | Sequence[str] | None) -> list[str]:
    """Every source of one corroboration row, whichever shape the row has."""
    normalised = corroboration_row(row)
    return [*normalised["asserted_by"], *normalised["claimed_by"]]
