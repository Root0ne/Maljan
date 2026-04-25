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
    - A metadata annotation showing how many chunks were merged.

MAX_CLAIMS cap: 20 claims per merged ISR is the default. The LLM judge
prompt budget is finite; more than 20 claims per agent rarely adds value
and inflates the system prompt significantly.
"""

from __future__ import annotations

from maljan.core.logger import logger
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

# Maximum number of claims to retain in the merged ISR.
# Claims beyond this cap are dropped (lowest confidence first).
MAX_MERGED_CLAIMS: int = 20


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
                if existing is None or claim.confidence > existing.confidence:
                    technique_claims[claim.technique_id] = claim
            else:
                normalized = claim.claim.lower().strip()
                if normalized not in seen_claim_texts:
                    seen_claim_texts.add(normalized)
                    unkeyed_claims.append(claim)

    # ------------------------------------------------------------------
    # Step 2: Consolidate and cap
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

    all_claims = keyed_sorted + unkeyed_sorted
    if len(all_claims) > MAX_MERGED_CLAIMS:
        dropped = len(all_claims) - MAX_MERGED_CLAIMS
        logger.debug(
            "Merged ISR for '%s': dropping %d low-confidence claims (cap=%d).",
            agent_id,
            dropped,
            MAX_MERGED_CLAIMS,
        )
        all_claims = all_claims[:MAX_MERGED_CLAIMS]

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
    )

    logger.info(
        "Merged ISR for '%s': %d claims (%d with TTP, %d unkeyed), %d dissent items.",
        agent_id,
        len(all_claims),
        len(keyed_sorted[:MAX_MERGED_CLAIMS]),
        len(unkeyed_sorted[:max(0, MAX_MERGED_CLAIMS - len(keyed_sorted))]),
        len(merged_dissent),
    )

    return merged
