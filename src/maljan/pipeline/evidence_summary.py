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
    ids_in_field,
    sigma_technique_ids,
    technique_ids_in,
)
from maljan.core.declared_reading import bare_name, facts_of, read_by_name, reads_as
from maljan.core.tool_declarations import select
from maljan.memory.attck_loader import technique_label

# Every technique and every source is named. The judge's prompt this block
# goes into is sized from the judge's own window, and it is shortened there,
# with a notice, only when the window cannot hold it.

# The tools whose technique id is a statement about this sample are the ones
# that declare ``asserts_techniques`` (a rule that matched it, a table matching
# one of its command lines, a sandbox signature raised while it ran), each
# under the name its declaration gives a corroboration row (``source``; the
# tool's own name when it gives none). Nothing else asserts: a reference
# lookup answers what an id is, not what the sample does, and the catalogue's
# association is read apart by ``catalogue_associations``. An entry written
# before facts were stored is read by the facts the platform ships for its
# name (``core.declared_reading``).


def asserting_source(entry: Any) -> str | None:
    """The name a corroboration row gives ``entry``'s tool, or ``None`` when it asserts nothing."""
    facts = facts_of(entry)
    if facts is None or not facts.asserts_techniques:
        return None
    return facts.source or bare_name(getattr(entry, "tool", ""))


def asserting_labels(ledger: Sequence[Any] | None) -> dict[str, str]:
    """``{tool name: corroboration name}`` for the asserting tools of ``ledger``.

    :func:`collect` names an asserting tool by its own name; a corroboration
    row names it by this (``sigma`` for both Sigma tools).
    """
    labels: dict[str, str] = {}
    for entry in ledger or []:
        source = asserting_source(entry)
        if source is not None:
            labels.setdefault(bare_name(getattr(entry, "tool", "")), source)
    return labels


def asserted_techniques(entry: Any) -> set[str]:
    """Every technique id an asserting entry's answer names, where its tool declares them.

    An entry with no stored facts is read in the shapes the platform's own
    tools emit (:func:`_technique_ids`), as it always was.
    """
    structured = getattr(entry, "structured", None)
    if read_by_name(entry):
        return _technique_ids(structured)
    facts = facts_of(entry)
    found: set[str] = set()
    for held in facts.techniques if facts is not None else ():
        for value in select(structured, held.path):
            found.update(ids_in_field(value, held.format))
    return found


def _source_facts(row: Any) -> str:
    """The sources a corroboration row traces its technique to, as the judge is told them.

    Each source is one ledger entry or sandbox item however many sources
    above name the technique from it (``validation.technique_sources``), and
    a row whose sources are all artefacts of the file says so. ``""`` for a
    row that names no source.
    """
    from maljan.analysis.corroboration import support_sentence

    if not isinstance(row, dict) or not isinstance(row.get("sources"), list):
        return ""
    held = [str(x) for x in row["sources"]]
    if not held:
        return " [its statements cite no ledger entry or sandbox item]"
    said = f" [traced to {len(held)} cited source(s), each counted once: {', '.join(held)}"
    independent = row.get("independent_sources")
    if isinstance(independent, int) and independent != len(held):
        said += f"; {independent} of them independent, sources reading one place counted once"
    sentence = support_sentence(str(row.get("support") or ""), row.get("source_kinds"), len(held))
    if sentence:
        said += f"; {sentence}"
    return said + "]"


def summarise(
    isrs: dict[str, Any] | None,
    ledger: Sequence[Any] | None = None,
    traced: dict[str, Any] | None = None,
) -> str:
    """The evidence summary block, or "" when nothing named a technique.

    ``traced`` is the run's corroboration rows (``validation.corroboration``):
    with them, each line also states the ledger sources its technique traces
    to, a fact beside the sources that named it.
    """
    rows = collect(isrs, ledger)
    if not rows:
        return ""

    lines = [
        "EVIDENCE SUMMARY — which sources named each technique, and how sure each one was.",
        "These are the sources' own numbers. Nothing here is combined or weighted; the",
        "verdict's confidence is yours to set.",
    ]
    shown = sorted(rows.items(), key=lambda item: (-len(item[1]), item[0]))
    for tid, sources in shown:
        rendered = "; ".join(
            f"{name} ({confidence:.2f})" if confidence is not None else name
            for name, confidence in sources
        )
        lines.append(
            f"- {technique_label(tid)}: {len(sources)} source(s) — {rendered}"
            + _source_facts((traced or {}).get(tid))
        )
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

    invalid = invalid_technique_ids(ledger)
    refused = refused_technique_ids(isrs, invalid)
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
                tid = str(raw).strip().upper()
                if tid not in refused:
                    add(tid, source, confidence)

    for entry in ledger or []:
        if asserting_source(entry) is None:
            continue
        tool = bare_name(getattr(entry, "tool", ""))
        for tid in asserted_techniques(entry):
            if tid not in invalid:
                add(tid, tool, None)

    return rows


EVIDENCE_ID_RE = re.compile(r"^ev_[0-9]+$")

# The consumer tables of ``builtin_declarations.CONSUMER_KINDS`` read here: a
# signature rule scan, whose matches carry the rule's own strings, and the API
# catalogue, whose rows are associations.
_SIGNATURE_RULES = "evidence_summary.yara_rule_strings"
_API_CATALOGUE = "evidence_summary.catalogue_associations"


def yara_rule_strings(ledger: Sequence[Any] | None) -> dict[str, list[dict[str, Any]]]:
    """``{technique_id: [{"rule": name, "strings": n, "source": layer}, ...]}`` for the
    signature rules that assert one.

    ``strings`` is how many of the rule's own strings matched — distinct
    identifiers, not offsets — which is what a reader needs to weigh a
    technique a rule alone put in the report: one string in a large file is a
    different finding from a rule whose whole condition matched. ``source`` is
    the name the corroboration row gives the asserting tool
    (:func:`asserting_source`), so each row is read with the layer that matched
    it; a row of an entry that asserts no technique carries none and is read
    under the shipped signature-rule label, as a stored row is. Read from the
    scan's structured answer as the tool wrote it.
    """
    found: dict[str, list[dict[str, Any]]] = {}
    for entry in ledger or []:
        if not reads_as(entry, _SIGNATURE_RULES):
            continue
        # An entry whose declaration asserts no technique gives no layer: its
        # rows are read as a stored row is, under the shipped signature-rule
        # label (``corroboration._rule_row_layers``), as they always were.
        layer = asserting_source(entry)
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
                row: dict[str, Any] = {
                    "rule": str(match.get("rule") or ""),
                    "strings": len(identifiers),
                }
                if layer:
                    row["source"] = layer
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

    invalid = invalid_technique_ids(ledger)
    refused = refused_technique_ids(isrs, invalid)
    for isr in (isrs or {}).values():
        for finding in getattr(isr, "findings", None) or []:
            cited = list(getattr(finding, "evidence_ids", None) or [])
            for tid in getattr(finding, "technique_ids", None) or []:
                if str(tid or "").strip().upper() in refused:
                    continue
                for eid in cited:
                    add(tid, eid)

    for entry in ledger or []:
        if asserting_source(entry) is None:
            continue
        for tid in asserted_techniques(entry):
            if tid not in invalid:
                add(tid, _entry_id(entry))

    return {tid: sorted(ids, key=order.__getitem__) for tid, ids in found.items()}


def _entry_id(entry: Any) -> str:
    """A ledger entry's own id, ``ev_0007``, under either name the entry types use."""
    return str(getattr(entry, "id", None) or getattr(entry, "entry_id", None) or "").strip()


def unverified_claim_ids(isr: Any) -> set[str]:
    """The technique ids ``isr``'s own claims carry flagged as not in the catalogue.

    The analyst was told the id is not a technique and kept it
    (``technique_id_valid=False``); the same id named in a finding is the
    same unverified id (``refused_technique_ids``).
    """
    return {
        str(getattr(claim, "technique_id", "") or "").strip().upper()
        for claim in getattr(isr, "claims", None) or []
        if getattr(claim, "technique_id", None) and not getattr(claim, "technique_id_valid", True)
    }


def refused_technique_ids(isrs: dict[str, Any] | None, invalid: set[str]) -> set[str]:
    """The ids no finding is counted under: ``invalid``, and every id any claim flagged.

    Whether an id is a technique is a fact about the id, not about the analyst
    who wrote it: one analyst's claim flagged as not in the catalogue makes the
    id unverified in every finding of the run.
    """
    refused = set(invalid)
    for isr in (isrs or {}).values():
        refused |= unverified_claim_ids(isr)
    return refused


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


def catalogue_associations(ledger: Sequence[Any] | None) -> dict[str, list[str]]:
    """``{technique_id: [tool]}`` for the rules the import set cleared.

    ``tool`` is the catalogue tool's own name, as the entry that associated
    the technique first recorded it (the pack's ``api_capability``).
    Reference, not evidence: the table says these APIs are listed under the
    technique, and a reader may weigh that; nothing counts it as a source.
    """
    out: dict[str, list[str]] = {}
    for entry in ledger or []:
        if not reads_as(entry, _API_CATALOGUE):
            continue
        tool = bare_name(getattr(entry, "tool", ""))
        for hit in api_capability_hits(getattr(entry, "structured", None)):
            out.setdefault(hit["technique_id"], [tool])
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
