"""The shape of a corroboration row, and how a stored one is read.

A row is ``{asserted_by: [deterministic sources], claimed_by: [agents]}``,
two flat lists and no score. A summary stored before the two lists carried a
flat list of sources; it is read as claimed by all of them, which is what a
list that never distinguished a rule from an agent meant.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


def corroboration_row(row: Mapping[str, Any] | Sequence[str] | None) -> dict[str, Any]:
    """One corroboration row in the current shape, whichever shape it was stored in.

    ``retired_in`` — the ATT&CK release that retired the id, when a source
    asserted one the catalogue no longer has — and ``associated_by`` — the
    API catalogue's association, which is reference and not a source —
    travel with the row.
    """
    if isinstance(row, Mapping):
        out: dict[str, Any] = {
            "asserted_by": [str(x) for x in row.get("asserted_by") or []],
            "claimed_by": [str(x) for x in row.get("claimed_by") or []],
        }
        if row.get("retired_in"):
            out["retired_in"] = str(row["retired_in"])
        if row.get("associated_by"):
            out["associated_by"] = [str(x) for x in row["associated_by"]]
        return out
    return {"asserted_by": [], "claimed_by": [str(x) for x in (row or [])]}


def corroboration_sources(row: Mapping[str, Any] | Sequence[str] | None) -> list[str]:
    """Every source of one corroboration row, whichever shape the row has."""
    normalised = corroboration_row(row)
    return [*normalised["asserted_by"], *normalised["claimed_by"]]


def technique_label(technique_id: str, row: Mapping[str, Any] | None) -> str:
    """The id as a table prints it, with the retired note when the row carries one."""
    retired = row.get("retired_in") if isinstance(row, Mapping) else None
    return f"{technique_id} (retired in ATT&CK {retired})" if retired else technique_id
