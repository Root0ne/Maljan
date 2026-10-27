"""The shape of a corroboration row, and how a stored one is read.

A row is ``{asserted_by: [deterministic sources], claimed_by: [agents]}``,
two flat lists and no score. A summary stored before the two lists carried a
flat list of sources; it is read as claimed by all of them, which is what a
list that never distinguished a rule from an agent meant.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from functools import cache
from typing import Any


def corroboration_row(row: Mapping[str, Any] | Sequence[str] | None) -> dict[str, Any]:
    """One corroboration row in the current shape, whichever shape it was stored in.

    ``retired_in`` — the ATT&CK release that retired the id, when a source
    asserted one the catalogue no longer has — and ``associated_by`` — the
    API catalogue's association, which is reference and not a source —
    travel with the row, as do ``evidence_roots`` and ``roots_not_read``.
    """
    if isinstance(row, Mapping):
        out: dict[str, Any] = {
            "asserted_by": [str(x) for x in row.get("asserted_by") or []],
            "claimed_by": [str(x) for x in row.get("claimed_by") or []],
        }
        if row.get("retired_in"):
            out["retired_in"] = str(row["retired_in"])
        if row.get("retired_reason"):
            out["retired_reason"] = str(row["retired_reason"])
        if row.get("associated_by"):
            out["associated_by"] = [str(x) for x in row["associated_by"]]
        if row.get("not_published"):
            out["not_published"] = str(row["not_published"])
        # The distinct evidence roots the sources read (``analysis.evidence_roots``),
        # and why a cited entry gave none: facts beside the two lists.
        if row.get("evidence_roots"):
            out["evidence_roots"] = [str(x) for x in row["evidence_roots"]]
        if row.get("roots_not_read"):
            out["roots_not_read"] = [str(x) for x in row["roots_not_read"]]
        # The ledger entries and sandbox items its statements cite, each one
        # source however many agents cite it (``validation.technique_sources``):
        # kept when the row was read with them, an empty list included.
        if isinstance(row.get("sources"), list):
            out["sources"] = [str(x) for x in row["sources"]]
            out["independent_sources"] = int(
                row.get("independent_sources", len(out["sources"])) or 0
            )
        if isinstance(row.get("source_kinds"), Mapping):
            out["source_kinds"] = {str(k): int(v) for k, v in row["source_kinds"].items()}
        if row.get("support"):
            out["support"] = str(row["support"])
        if isinstance(row.get("independent_sayers"), int):
            out["independent_sayers"] = int(row["independent_sayers"])
        return out
    return {"asserted_by": [], "claimed_by": [str(x) for x in (row or [])]}


# The supports under which no source is behaviour: never corroborated.
NOT_OBSERVED_SUPPORTS = frozenset({"capability", "unobserved"})


def corroborated(row: Mapping[str, Any] | Sequence[str] | None) -> bool:
    """Whether a technique is corroborated: two sayers and two sources of their own.

    At least two sayers (``independent_sayers``: analyst layers with a
    statement of their own and the asserting rules; on a row stored before
    it, the named sources), and, for a row
    read with its sources, at least two independent ones (each ledger entry
    or sandbox item once however many agents cite it, sources reading one
    place joined) with some source more than an artefact of the file or an
    external assessment (``support`` neither ``capability`` nor
    ``unobserved``). A row with statements and no cited source has none. A
    row stored before sources were read keeps the count of named sources.
    """
    normalised = corroboration_row(row)
    sayers = normalised.get("independent_sayers")
    if (sayers if isinstance(sayers, int) else len(corroboration_sources(row))) < 2:
        return False
    if "sources" not in normalised:
        return True
    return (
        int(normalised.get("independent_sources", 0)) >= 2
        and normalised.get("support") not in NOT_OBSERVED_SUPPORTS
    )


@cache
def _stored_signature_layers() -> frozenset[str]:
    """The names a corroboration row gives the shipped signature-rule tools.

    A rule-strings row stored before rows recorded the layer that matched
    them was written only by a shipped signature-rule tool, so it is read as
    that tool's: the label its shipped declaration gave (``source`` of a
    ``signature_rules`` declaration that asserts techniques), read from the
    frozen legacy reading, so a later change to a shipped declaration leaves
    a stored row as it read.
    """
    from maljan.core.declared_reading import legacy_by_name

    return frozenset(
        facts.source
        for facts in legacy_by_name().values()
        if facts.kind == "signature_rules" and facts.asserts_techniques and facts.source
    )


def _rule_row_layers(row: Mapping[str, Any]) -> frozenset[str]:
    """The asserting layer a rule-strings row was matched by (``source``), as a set.

    A row stored without one is read as the shipped signature-rule tool's.
    """
    layer = str(row.get("source") or "")
    return frozenset({layer}) if layer else _stored_signature_layers()


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
            rules = [
                r
                for r in strings.get(tid, [])
                if isinstance(r, dict) and source in _rule_row_layers(r)
            ]
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
        if row.get("retired_reason"):
            parts.append(str(row["retired_reason"]))
        elif row.get("retired_in"):
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


# What each kind of source is called where a row counts them, singular and plural.
_KIND_WORDS: dict[str, tuple[str, str]] = {
    "artefact": (
        "artefact of the file (a name, string, table or index row)",
        "artefacts of the file (names, strings, tables or index rows)",
    ),
    "report": ("external assessment of the whole file", "external assessments of the whole file"),
    "unplaced": ("citation that gives no root", "citations that give no root"),
}
_KIND_ORDER = ("artefact", "report", "unplaced")
NO_BEHAVIOUR_SOURCE = "no sandbox observation, code listing or rule match stands behind it"


def support_label(support: str) -> str:
    """The words a published technique's support is named by: ``capability, not observed``."""
    if support == "capability":
        return "capability, not observed"
    if support == "unobserved":
        return "not observed"
    return ""


def sources_phrase(kinds: Mapping[str, int] | None, total: int) -> str:
    """``3 sources: 2 artefacts of the file (…), 1 citation that gives no root``.

    The kinds a technique with no behaviour source has, each counted, in one
    order; the total alone where the kinds were not recorded.
    """
    said = f"{total} source{'' if total == 1 else 's'}"
    parts = [
        f"{int(n)} {_KIND_WORDS[kind][0 if int(n) == 1 else 1]}"
        for kind in _KIND_ORDER
        if (n := (kinds or {}).get(kind))
    ]
    return f"{said}: {', '.join(parts)}" if parts else said


def support_sentence(support: str, kinds: Mapping[str, int] | None, total: int) -> str:
    """One sentence on a technique no source of which is behaviour, or ``""``.

    It names the label, counts its sources by kind and says that no sandbox
    observation, code listing or rule match stands behind it: the facts the
    judge, the report models, the ATT&CK table and the export are told alike.
    """
    label = support_label(support)
    if not label:
        return ""
    return f"{label}: {sources_phrase(kinds, total)}; {NO_BEHAVIOUR_SOURCE}"
