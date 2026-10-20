"""ISR merging utilities for hierarchical chunk-and-summarize analysis.

Problem: When a large malware sample is split into N chunks, each chunk
produces an independent AgentISR with its own claims, technique IDs, and
confidence scores. These must be intelligently merged into a single
authoritative ISR before the negotiation loop.

Design:
  merge_chunk_isrs() implements a three-step hierarchical merge:

  1. Claim deduplication: Claims referring to the same technique_id (same
     MITRE technique) from different chunks are deduplicated. The claim with
     the highest confidence is kept as the representative; others are discarded.

  2. Evidence consolidation: For claims without a technique_id, exact
     duplicates (same claim text after lowercasing + stripping) are removed.
     Non-duplicate claims are sorted by confidence and the top MAX_CLAIMS
     are retained to avoid prompt bloat.

  3. Dissent reconciliation: All dissent_items across all chunks are merged
     and deduplicated. This ensures that a legitimate dispute raised in one
     chunk's context is preserved.

  The resulting merged ISR receives:
    - revision_round = max(chunk ISR revision_rounds)
    - agent_id and domain from the first chunk ISR
    - every chunk's findings and artifacts, each exact duplicate once
    - the CLAIM blocks of every chunk whose confidence was not read, and the
      claim headings under its DISPUTES section, for the validation turn
    - when no chunk yielded a claim, the chunks' prose and the status a chunk
      reported for itself; beside claims, that prose is stated as unread.

Every claim is kept: no count cap. The judge's prompt is sized from the
judge's own window, and it says so when it has to shorten what it shows.
"""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel

from maljan.core.logger import logger
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _ranks_above(claim: ClaimEvidence, kept: ClaimEvidence) -> bool:
    """Whether ``claim`` takes the place of ``kept`` as the one claim for their technique.

    A claim that reads as absence, kept when its analyst was asked, never takes
    the place of one that does not: the positive claim is what the technique
    is published from, and the higher number on "does not contain any obvious
    persistence mechanisms" is not a firmer statement that the sample persists.
    Otherwise the higher confidence wins, as before.
    """
    if claim.kept_after_absence_question != kept.kept_after_absence_question:
        return not claim.kept_after_absence_question
    return claim.confidence > kept.confidence


def _once[M: BaseModel](items: Iterable[M]) -> list[M]:
    """``items`` in order, each exact duplicate (same fields) kept once."""
    seen: set[str] = set()
    out: list[M] = []
    for item in items:
        key = item.model_dump_json()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def merge_chunk_isrs(chunk_isrs: list[AgentISR]) -> AgentISR:
    """Merge multiple per-chunk AgentISRs into a single consolidated ISR.

    Args:
        chunk_isrs: Ordered list of AgentISR objects — one per chunk, in the
                    order the chunks were analyzed. Must be non-empty.

    Returns:
        A single AgentISR that represents the combined findings across all
        chunks. The merged ISR is suitable for direct injection into the
        negotiation loop.

    Raises:
        ValueError: If chunk_isrs is empty.
    """
    if not chunk_isrs:
        raise ValueError("merge_chunk_isrs() requires at least one AgentISR.")

    if len(chunk_isrs) == 1:
        return chunk_isrs[0]

    first = chunk_isrs[0]
    agent_id = first.agent_id
    domain = first.domain
    max_round = max(isr.revision_round for isr in chunk_isrs)

    logger.info(
        "Merging %d chunk ISRs for agent='%s' domain='%s'.",
        len(chunk_isrs),
        agent_id,
        domain,
    )

    # ------------------------------------------------------------------
    # Step 1: Collect all claims, bucket by technique_id
    # ------------------------------------------------------------------
    # Keyed claims: technique_id -> best ClaimEvidence (highest confidence)
    technique_claims: dict[str, ClaimEvidence] = {}
    # Unkeyed claims: no technique_id — stored flat, deduped by text
    unkeyed_claims: list[ClaimEvidence] = []
    seen_claim_texts: set[str] = set()

    for isr in chunk_isrs:
        for claim in isr.claims:
            if claim.technique_id is not None:
                existing = technique_claims.get(claim.technique_id)
                if existing is None or _ranks_above(claim, existing):
                    technique_claims[claim.technique_id] = claim
            else:
                normalized = claim.claim.lower().strip()
                if normalized not in seen_claim_texts:
                    seen_claim_texts.add(normalized)
                    unkeyed_claims.append(claim)

    # ------------------------------------------------------------------
    # Step 2: Consolidate
    # ------------------------------------------------------------------
    # Keyed claims come first (they have explicit TTPs — higher value)
    keyed_sorted = sorted(
        technique_claims.values(),
        key=lambda c: c.confidence,
        reverse=True,
    )
    unkeyed_sorted = sorted(
        unkeyed_claims,
        key=lambda c: c.confidence,
        reverse=True,
    )

    # Every claim is kept. A count cap here dropped an analyst's claims past
    # the twentieth, lowest confidence first and said so only at debug level;
    # what reads the merged ISR next — the judge's prompt — is sized from its
    # own window and says so when it must shorten.
    all_claims = keyed_sorted + unkeyed_sorted

    # ------------------------------------------------------------------
    # Step 3: Merge dissent items (deduped)
    # ------------------------------------------------------------------
    seen_dissent: set[str] = set()
    merged_dissent: list[str] = []
    for isr in chunk_isrs:
        for item in isr.dissent_items:
            normalized = item.strip().lower()
            if normalized not in seen_dissent:
                seen_dissent.add(normalized)
                merged_dissent.append(item)

    merged = AgentISR(
        agent_id=agent_id,
        domain=domain,
        claims=all_claims,
        dissent_items=merged_dissent,
        revision_round=max_round,
        findings=_once(f for isr in chunk_isrs for f in isr.findings),
        artifacts=_once(a for isr in chunk_isrs for a in isr.artifacts),
    )
    # Each chunk's answer is part of the merged one: claims a chunk began and
    # did not have read are not in the merged findings either.
    reasons = [str(getattr(isr, "claims_unread_reason", "") or "") for isr in chunk_isrs]
    # The prose of a chunk that parsed into no claim, and the status it
    # reported for itself, describe the merged answer only when no chunk
    # yielded a claim; beside claims, the prose is stated as not in them.
    prose = [isr.unparsed_answer for isr in chunk_isrs if isr.unparsed_answer]
    if all_claims:
        if prose:
            reasons.append(
                f"{len(prose)} of {len(chunk_isrs)} parts answered in prose that parsed "
                "into no claim; that prose is not in the merged findings."
            )
    else:
        reporting = [isr for isr in chunk_isrs if isr.status]
        told = next((isr for isr in reporting if isr.unparsed_answer), None)
        told = told or (reporting[0] if reporting else None)
        if told is not None:
            merged.status = told.status
            merged.status_reason = told.status_reason
    merged.note_claims_unread(" ".join(reason for reason in dict.fromkeys(reasons) if reason))
    merged.note_parse(
        unparsed_answer="" if all_claims else "\n\n".join(prose),
        blocks_without_confidence=sum(isr.blocks_without_confidence for isr in chunk_isrs),
        confidence_unreadable=[v for isr in chunk_isrs for v in isr.confidence_unreadable],
    )
    merged.note_claims_under_disputes(
        sum(int(getattr(isr, "claims_under_disputes", 0) or 0) for isr in chunk_isrs)
    )
    # Asked when every chunk that wrote such headings was asked about them.
    if merged.claims_under_disputes and all(
        isr.claims_under_disputes_asked for isr in chunk_isrs if isr.claims_under_disputes
    ):
        merged.note_claims_under_disputes_asked()

    keyed_kept = sum(1 for c in all_claims if c.technique_id)
    unkeyed_kept = len(all_claims) - keyed_kept
    logger.info(
        "Merged ISR for '%s': %d claims kept (%d with TTP, %d unkeyed), %d dissent items.",
        agent_id,
        len(all_claims),
        keyed_kept,
        unkeyed_kept,
        len(merged_dissent),
    )

    return merged
