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
        if row.get("not_published"):
            out["not_published"] = str(row["not_published"])
        return out
    return {"asserted_by": [], "claimed_by": [str(x) for x in (row or [])]}


def rule_match_only(report: Any) -> dict[str, str]:
    """The published techniques only a rule match stands behind, each with its note.

    ``{technique_id: "rule match only (yara `name`, 1 string), no analyst
    claim"}``: a technique a deterministic rule asserted and no analyst
    claimed. The publish rule is unchanged — the judge named it and a rule
    matched it — and what a reader is told is how much matched. Such a
    technique grounds no capability word (``validation.CapabilityGrounding``):
    a one-string match is not evidence of the capability its name says.
    """
    corroboration = (getattr(report, "run_summary", None) or {}).get("corroboration") or {}
    strings = getattr(report, "rule_match_strings", None) or {}
    out: dict[str, str] = {}
    for mapping in getattr(report, "ttp_mappings", None) or []:
        tid = str(getattr(mapping, "technique_id", "") or "")
        row = corroboration_row(corroboration.get(tid))
        if not row["asserted_by"] or row["claimed_by"]:
            continue
        parts: list[str] = []
        for source in dict.fromkeys(row["asserted_by"]):
            rules = (
                [r for r in strings.get(tid, []) if isinstance(r, dict)] if source == "yara" else []
            )
            if rules:
                parts.extend(
                    f"{source} `{r.get('rule')}`, {int(r.get('strings') or 0)} "
                    f"string{'' if int(r.get('strings') or 0) == 1 else 's'}"
                    for r in rules
                )
            else:
                parts.append(str(source))
        out[tid] = f"rule match only ({'; '.join(parts)}), no analyst claim"
    return out


def corroboration_sources(row: Mapping[str, Any] | Sequence[str] | None) -> list[str]:
    """Every source of one corroboration row, whichever shape the row has."""
    normalised = corroboration_row(row)
    return [*normalised["asserted_by"], *normalised["claimed_by"]]


def technique_label(technique_id: str, row: Mapping[str, Any] | None) -> str:
    """The id as a table prints it, with whatever the row has to say about it.

    Two notes, in words rather than by omission: the release that retired the
    id, and — since a run printed three enterprise-only techniques on an
    Android sample with nothing saying so — that the id was claimed and not
    published, with the reason the check gave.
    """
    parts: list[str] = []
    if isinstance(row, Mapping):
        if row.get("retired_in"):
            parts.append(f"retired in ATT&CK {row['retired_in']}")
        if row.get("not_published"):
            parts.append(f"claimed, not published: {row['not_published']}")
    return f"{technique_id} ({'; '.join(parts)})" if parts else technique_id


# The sentence for an id that reaches the report having been named by nothing
# the published list knows about. It is not a check's own answer — the checks
# that had one wrote it — so it says exactly what is known.
UNPUBLISHED_WITHOUT_A_REASON = (
    "it was named by a producer and is not in this run's published technique list"
)


def mark_unpublished(
    corroboration: Mapping[str, Any] | None,
    published: set[str] | frozenset[str],
    reasons: Mapping[str, str] | None = None,
) -> dict[str, dict[str, Any]]:
    """``corroboration`` with every id outside the published list saying so.

    ``published`` is the validated ``ttp_mappings``, the one list every
    technique surface of the report is built from; ``reasons`` is what the
    checks wrote against the ids they rejected, read off the capability matrix.
    An id in neither — dropped by its analyst in revision, so no check was ever
    asked about it — gets the sentence that is true of it.
    """
    out: dict[str, dict[str, Any]] = {}
    for tid, row in (corroboration or {}).items():
        normalised = corroboration_row(row)
        upper = str(tid).strip().upper()
        if upper not in published:
            normalised["not_published"] = (reasons or {}).get(upper, UNPUBLISHED_WITHOUT_A_REASON)
        out[tid] = normalised
    return out


def published_count(corroboration: Mapping[str, Any] | None) -> int:
    """How many of the named techniques this run published."""
    return sum(
        1
        for row in (corroboration or {}).values()
        if not corroboration_row(row).get("not_published")
    )
