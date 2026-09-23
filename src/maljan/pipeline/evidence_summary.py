"""What each technique id was claimed by, put in front of the judge.

Deliberately no arithmetic. Hand a judge one weighted number per technique and
it treats that number as the answer and its own reading of the evidence as
commentary — and nobody can say where the number came from, because it comes
from a table of constants rather than from the sample.

So the block carries the same information without the summing: the technique
id, every source that named it, and what each source said its own confidence
was. Two analysts and a capa rule agreeing is three lines; what that is worth
is the judge's decision, which is the judge's job.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from maljan.analysis.technique_ids import (
    TECHNIQUE_ID_EXACT_RE,
    api_capability_hits,
    sigma_technique_ids,
    technique_ids_in,
)

# How many techniques the block names. The judge's prompt is already a
# multi-kilobyte assembly and the tail of a confidence-ordered list is noise;
# the count of what was left out is printed instead.
MAX_TECHNIQUES = 25

# How many sources are listed per technique before the rest are counted.
MAX_SOURCES_PER_TECHNIQUE = 6

# The tools whose technique id is a statement about this sample, and the name a
# corroboration row gives each: a capa rule, a Sigma rule or a YARA TTP rule
# that fired on it, the LOLBin table matching one of its command lines, a
# sandbox signature raised while it ran. Nothing else asserts. ``attck_lookup``,
# ``attck_validate`` and ``resolve_technique`` answer what an id is, not what
# the sample does; ``similar_cases`` and ``family_lookup`` return techniques of
# other samples; ``api_capability`` is the catalogue's association, read apart
# by ``catalogue_associations``. A tool this table does not name is not a source.
ASSERTING_SOURCES: dict[str, str] = {
    "capa": "capa",
    "sigma_match": "sigma",
    "sigma_match_sandbox": "sigma",
    "yara_scan": "yara",
    "lolbin_lookup": "lolbin",
    "sandbox_signatures": "sandbox",
}


def summarise(isrs: dict[str, Any] | None, ledger: Sequence[Any] | None = None) -> str:
    """The evidence summary block, or "" when nothing named a technique."""
    rows = collect(isrs, ledger)
    if not rows:
        return ""

    lines = [
        "EVIDENCE SUMMARY — which sources named each technique, and how sure each one was.",
        "These are the sources' own numbers. Nothing here is combined or weighted; the",
        "verdict's confidence is yours to set.",
    ]
    shown = sorted(rows.items(), key=lambda item: (-len(item[1]), item[0]))
    for tid, sources in shown[:MAX_TECHNIQUES]:
        head = sources[:MAX_SOURCES_PER_TECHNIQUE]
        rest = len(sources) - len(head)
        rendered = "; ".join(
            f"{name} ({confidence:.2f})" if confidence is not None else name
            for name, confidence in head
        )
        tail = f"; +{rest} more" if rest > 0 else ""
        lines.append(f"- {tid}: {len(sources)} source(s) — {rendered}{tail}")
    if len(shown) > MAX_TECHNIQUES:
        lines.append(f"- (+{len(shown) - MAX_TECHNIQUES} further techniques not listed)")
    return "\n".join(lines)


def collect(
    isrs: dict[str, Any] | None, ledger: Sequence[Any] | None = None
) -> dict[str, list[tuple[str, float | None]]]:
    """``{technique_id: [(source, its own confidence or None), ...]}``.

    A tool entry carries no confidence of its own — a capa rule either matched
    or it did not — so its second element is ``None`` rather than a number
    invented to fill the column.
    """
    rows: dict[str, list[tuple[str, float | None]]] = {}
    seen: dict[str, set[str]] = {}

    def add(tid: str, source: str, confidence: float | None) -> None:
        if not TECHNIQUE_ID_EXACT_RE.match(tid):
            return
        if source in seen.setdefault(tid, set()):
            return
        seen[tid].add(source)
        rows.setdefault(tid, []).append((source, confidence))

    for name, isr in (isrs or {}).items():
        source = str(getattr(isr, "agent_id", "") or name)
        for claim in getattr(isr, "claims", None) or []:
            if not getattr(claim, "technique_id_valid", True):
                continue
            tid = str(getattr(claim, "technique_id", "") or "").strip().upper()
            if tid:
                add(tid, source, _as_confidence(getattr(claim, "confidence", None)))
        for finding in getattr(isr, "findings", None) or []:
            confidence = _as_confidence(getattr(finding, "confidence", None))
            for raw in getattr(finding, "technique_ids", None) or []:
                add(str(raw).strip().upper(), source, confidence)

    invalid = invalid_technique_ids(ledger)
    for entry in ledger or []:
        tool = _base_tool_name(getattr(entry, "tool", ""))
        if tool not in ASSERTING_SOURCES:
            continue
        for tid in _technique_ids(getattr(entry, "structured", None)):
            if tid not in invalid:
                add(tid, tool, None)

    return rows


EVIDENCE_ID_RE = re.compile(r"^ev_[0-9]+$")


def yara_rule_strings(ledger: Sequence[Any] | None) -> dict[str, list[dict[str, Any]]]:
    """``{technique_id: [{"rule": name, "strings": n}, ...]}`` for the YARA rules that assert one.

    ``strings`` is how many of the rule's own strings matched — distinct
    identifiers, not offsets — which is what a reader needs to weigh a
    technique a rule alone put in the report: one string in a large file is a
    different finding from a rule whose whole condition matched. Read from the
    scan's structured answer as the tool wrote it.
    """
    found: dict[str, list[dict[str, Any]]] = {}
    for entry in ledger or []:
        if _base_tool_name(getattr(entry, "tool", "")) != "yara_scan":
            continue
        structured = getattr(entry, "structured", None)
        matches = structured.get("matches") if isinstance(structured, dict) else None
        for match in matches or []:
            if not isinstance(match, dict):
                continue
            raw_meta = match.get("meta")
            meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
            identifiers = {
                str(item.get("identifier") or "")
                for item in match.get("strings") or []
                if isinstance(item, dict)
            } - {""}
            for tid in technique_ids_in(meta.get("technique_id")):
                rows = found.setdefault(tid, [])
                row = {"rule": str(match.get("rule") or ""), "strings": len(identifiers)}
                if row not in rows:
                    rows.append(row)
    return found


def technique_evidence(
    isrs: dict[str, Any] | None, ledger: Sequence[Any] | None = None
) -> dict[str, list[str]]:
    """``{technique_id: [ledger id, ...]}``: the entries the record ties to it.

    Two ties are read, both as the record holds them. An analyst finding that
    names a technique in ``technique_ids`` cites its entries in
    ``evidence_ids``. An asserting tool's entry, such as a capa rule or a Sigma
    match, names the technique in its structured output, and the entry's own
    id is the evidence. Nothing is read out of text: a claim's
    ``evidence_ref`` is a sentence, and an id in it stays in the sentence.

    Each list is deduplicated and in ledger order. An id the ledger does not
    hold is left out, because a reference nobody can follow is not evidence,
    and an empty ledger holds none: a run with no tool calls ties nothing. A
    technique nothing ties to an entry has no key.

    A finding's ``evidence_ids`` belong to the finding as a whole, so a
    finding naming two techniques ties each of its entries to both. The tie
    says the finding cites the entry, not that the entry names the technique.
    """
    order: dict[str, int] = {}
    for index, entry in enumerate(ledger or []):
        eid = _entry_id(entry)
        if eid and eid not in order:
            order[eid] = index

    found: dict[str, set[str]] = {}

    def add(tid: str, eid: Any) -> None:
        tid = str(tid or "").strip().upper()
        eid = str(eid or "").strip()
        if not TECHNIQUE_ID_EXACT_RE.match(tid) or not EVIDENCE_ID_RE.match(eid):
            return
        if eid not in order:
            return
        found.setdefault(tid, set()).add(eid)

    for isr in (isrs or {}).values():
        for finding in getattr(isr, "findings", None) or []:
            cited = list(getattr(finding, "evidence_ids", None) or [])
            for tid in getattr(finding, "technique_ids", None) or []:
                for eid in cited:
                    add(tid, eid)

    invalid = invalid_technique_ids(ledger)
    for entry in ledger or []:
        if _base_tool_name(getattr(entry, "tool", "")) not in ASSERTING_SOURCES:
            continue
        for tid in _technique_ids(getattr(entry, "structured", None)):
            if tid not in invalid:
                add(tid, _entry_id(entry))

    return {tid: sorted(ids, key=order.__getitem__) for tid, ids in found.items()}


def _entry_id(entry: Any) -> str:
    """A ledger entry's own id, ``ev_0007``, under either name the entry types use."""
    return str(getattr(entry, "id", None) or getattr(entry, "entry_id", None) or "").strip()


def invalid_technique_ids(ledger: Sequence[Any] | None) -> set[str]:
    """Every id a ledger entry of this run answered as not a technique.

    ``attck_lookup`` says ``valid: false`` beside the id, ``attck_validate``
    lists the id under ``invalid``. An id any source marks invalid is never
    counted as asserted, whichever rule named it.
    """
    found: set[str] = set()
    for entry in ledger or []:
        structured = getattr(entry, "structured", None)
        if not isinstance(structured, dict):
            continue
        if structured.get("valid") is False:
            tid = str(structured.get("technique_id") or "").strip().upper()
            if tid:
                found.add(tid)
        for row in structured.get("invalid") or []:
            if isinstance(row, dict):
                tid = str(row.get("id") or "").strip().upper()
                if tid:
                    found.add(tid)
    return found


def _base_tool_name(tool: Any) -> str:
    """The tool's own name, without the ``<server>__`` a name collision adds."""
    return str(tool or "").rsplit("__", 1)[-1]


def catalogue_associations(ledger: Sequence[Any] | None) -> dict[str, list[str]]:
    """``{technique_id: ["api_capability"]}`` for the rules the import set cleared.

    Reference, not evidence: the table says these APIs are listed under the
    technique, and a reader may weigh that; nothing counts it as a source.
    """
    out: dict[str, list[str]] = {}
    for entry in ledger or []:
        if str(getattr(entry, "tool", "") or "") != "api_capability":
            continue
        for hit in api_capability_hits(getattr(entry, "structured", None)):
            out.setdefault(hit["technique_id"], ["api_capability"])
    return out


def _as_confidence(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _technique_ids(structured: Any, depth: int = 0) -> set[str]:
    """Every ATT&CK id a tool result asserts, in the shapes the tools emit.

    capa writes ``attck`` as a list of decorated strings, a Sigma match
    writes ``tags`` like ``attack.t1055.012``, the LOLBin table and the
    API-to-technique rules write a bare ``technique_id``; all three are read
    as they are written (``analysis.technique_ids``). Nothing outside those
    keys counts, so a technique quoted in a description is not an assertion.
    """
    if depth > 6:
        return set()
    found: set[str] = set()
    if isinstance(structured, dict):
        for key, value in structured.items():
            if key in ("technique_id", "attck", "technique_ids"):
                found.update(technique_ids_in(value))
            elif key == "tags":
                found.update(sigma_technique_ids({"tags": value}))
            else:
                found |= _technique_ids(value, depth + 1)
    elif isinstance(structured, list):
        for item in structured:
            found |= _technique_ids(item, depth + 1)
    return found
