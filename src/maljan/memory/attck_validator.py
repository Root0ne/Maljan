"""ATT&CK TTP validator for agent claim validation.

Provides a high-level interface that agent nodes and the JudgeAgent can use to
ground TTP mappings in the authoritative MITRE ATT&CK knowledge base.

Key capabilities:
  1. validate_ttp_id(): Check if a technique ID exists at all.
  2. validate_claim(): Score a claim's evidence against the ATT&CK definition.
  3. suggest_techniques(): Suggest top-k relevant techniques for a behavioral description.

The validator lazily initializes the ATTCKIndex on first use to avoid startup
latency when the memory module is not needed (e.g., pure text analysis runs).

Usage (in agents or nodes):
    from maljan.memory.attck_validator import ATTCKValidator

    validator = ATTCKValidator.get_instance()
    is_valid = validator.validate_ttp_id("T1055.001")
    score = validator.validate_claim("T1055.001", "WriteProcessMemory API call at 0x401234")
    suggestions = validator.suggest_techniques("dns tunneling exfiltration", top_k=3)
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from maljan.core.logger import logger
from maljan.memory.attck_index import ATTCKIndex, SearchResult
from maljan.memory.attck_loader import ATTCKTechnique

if TYPE_CHECKING:
    from maljan.memory.ttp_validation import TTPValidationSummary
    from maljan.schemas.isr_models import AgentISR

# Confidence threshold below which a TTP mapping is flagged as suspicious
HALLUCINATION_SCORE_THRESHOLD: float = 0.05


class ATTCKValidator:
    """Thread-safe singleton validator backed by the ATT&CK TF-IDF index.

    Use ATTCKValidator.get_instance() to obtain the shared instance.
    The index is initialized lazily on first use.
    """

    _instance: ATTCKValidator | None = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self, index: ATTCKIndex) -> None:
        self._index = index

    # ------------------------------------------------------------------
    # Singleton factory
    # ------------------------------------------------------------------

    @staticmethod
    def _build_index(backend: str | None, force_refresh: bool) -> ATTCKIndex:
        """Build the ATT&CK index for the requested backend.

        ``backend == "semantic"`` uses dense BGE embeddings; anything else
        (default) uses the TF-IDF index. The semantic class is imported lazily
        so the embedding model is only loaded when that backend is selected.
        """
        if backend == "semantic":
            from maljan.memory.semantic_attck_index import SemanticATTCKIndex

            logger.info("ATTCKValidator: using SEMANTIC (embedding) ATT&CK index.")
            return SemanticATTCKIndex.from_loader(force_refresh=force_refresh)
        return ATTCKIndex.from_loader(force_refresh=force_refresh)

    @classmethod
    def get_instance(
        cls, force_refresh: bool = False, backend: str | None = None
    ) -> ATTCKValidator:
        """Return the shared ATTCKValidator, building the index if needed.

        ``backend`` selects the index implementation ("tfidf" default, or
        "semantic" for dense embeddings). The first caller to build the
        singleton fixes the backend; later callers reuse it (pass
        ``force_refresh=True`` to switch backends in tests).

        Thread-safety:
            ``force_refresh`` ALWAYS acquires the lock so that a refresh
            cannot race with another caller that observes a stale instance
            outside the lock. The previous implementation skipped the lock
            when the singleton already existed, allowing two threads to
            rebuild the index simultaneously.
        """
        if force_refresh:
            with cls._lock:
                logger.info("Force-refreshing ATTCKValidator (rebuilding index)...")
                cls._instance = cls(cls._build_index(backend, force_refresh=True))
                return cls._instance

        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    logger.info("Initializing ATTCKValidator (loading index)...")
                    cls._instance = cls(cls._build_index(backend, force_refresh=False))
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Drop the cached singleton (intended for test isolation)."""
        with cls._lock:
            cls._instance = None

    @classmethod
    def from_index(cls, index: ATTCKIndex) -> ATTCKValidator:
        """Create a validator from a pre-built index. Used in tests."""
        return cls(index)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_ttp_id(self, technique_id: str) -> bool:
        """Return True if the technique ID exists in the current ATT&CK release.

        A False return means the agent hallucinated a non-existent TTP ID.

        Args:
            technique_id: e.g., "T1055" or "T1055.001"

        Returns:
            True if the ID is valid and not deprecated/revoked.
        """
        exists = self._index.technique_exists(technique_id)
        if not exists:
            logger.warning(
                "ATT&CK validation: '%s' not found. Possible hallucination.", technique_id
            )
        return exists

    def validate_claim(
        self,
        technique_id: str,
        evidence_text: str,
    ) -> tuple[bool, float]:
        """Validate that a proposed TTP is supported by the evidence text.

        Returns:
            Tuple of (is_plausible: bool, confidence_score: float).
            is_plausible is False when the technique ID is unknown or the
            evidence-to-definition similarity is below HALLUCINATION_SCORE_THRESHOLD.
        """
        if not self.validate_ttp_id(technique_id):
            return False, 0.0

        score = self._index.validate_and_score(technique_id, evidence_text)
        is_plausible = score >= HALLUCINATION_SCORE_THRESHOLD

        if not is_plausible:
            tech = self._index.get_by_id(technique_id)
            tech_name = tech.name if tech else "unknown"
            logger.warning(
                "Low ATT&CK alignment: '%s' (%s) score=%.3f for evidence: %s",
                technique_id,
                tech_name,
                score,
                evidence_text[:80],
            )

        return is_plausible, score

    def suggest_techniques(
        self,
        behavioral_description: str,
        top_k: int = 5,
        filter_tactics: list[str] | None = None,
    ) -> list[SearchResult]:
        """Suggest ATT&CK techniques relevant to a behavioral description.

        Useful for the JudgeAgent to ground TTP mapping without hallucination.

        Args:
            behavioral_description: e.g., "binary writes shellcode to memory and
                                    creates remote thread in target process".
            top_k: Number of results to return.
            filter_tactics: Optional tactic filter (e.g., ["defense-evasion"]).

        Returns:
            Ranked list of SearchResult objects.
        """
        return self._index.search(
            behavioral_description, top_k=top_k, filter_tactics=filter_tactics
        )

    def validate_isr_reports(
        self,
        isr_reports: dict[str, AgentISR],
        suggestion_top_k: int = 3,
    ) -> TTPValidationSummary:
        """Validate all ClaimEvidence.technique_id fields across every agent ISR.

        For each claim that has a non-None technique_id:
          - Check if the ID exists in ATT&CK.
          - Score how well the evidence text aligns with the ATT&CK definition.
          - If the ID is unknown, suggest top-k alternatives from TF-IDF search.

        Args:
            isr_reports: Mapping of agent_id to AgentISR (from pipeline state).
            suggestion_top_k: How many alternative techniques to suggest when an
                              ID is invalid or low-alignment.

        Returns:
            TTPValidationSummary with per-claim results and aggregate stats.
        """
        from maljan.memory.ttp_validation import TTPClaimValidation, TTPValidationSummary

        claim_results: list[TTPClaimValidation] = []

        for isr in isr_reports.values():
            for claim in isr.claims:
                if claim.technique_id is None:
                    continue

                is_valid, score = self.validate_claim(claim.technique_id, claim.evidence_ref)

                # Suggest alternatives if ID is unknown or evidence doesn't fit
                suggestions: list[str] = []
                if not is_valid:
                    alt_results = self.suggest_techniques(
                        claim.evidence_ref + " " + claim.claim, top_k=suggestion_top_k
                    )
                    suggestions = [r.technique.technique_id for r in alt_results]

                claim_results.append(
                    TTPClaimValidation(
                        agent_id=isr.agent_id,
                        technique_id=claim.technique_id,
                        claim_text=claim.claim[:120],
                        evidence_ref=claim.evidence_ref,
                        is_valid_id=self.validate_ttp_id(claim.technique_id),
                        alignment_score=score,
                        is_plausible=is_valid,
                        suggested_ids=suggestions,
                    )
                )

        total = len(claim_results)
        valid_ids = sum(1 for r in claim_results if r.is_valid_id)
        invalid_ids = total - valid_ids
        low_alignment = sum(1 for r in claim_results if r.is_suspicious)

        summary = TTPValidationSummary(
            total_claims=total,
            valid_ids=valid_ids,
            invalid_ids=invalid_ids,
            low_alignment=low_alignment,
            results=claim_results,
        )

        logger.info(
            "TTP validation: %d/%d valid IDs, %d hallucinations, %d low-alignment.",
            valid_ids,
            total,
            invalid_ids,
            low_alignment,
        )
        return summary

    def correct_isr_reports(
        self,
        isr_reports: dict[str, AgentISR],
        *,
        min_alignment: float = HALLUCINATION_SCORE_THRESHOLD,
        skip_agents: frozenset[str] = frozenset({"yara_layer", "sigma_layer"}),
    ) -> int:
        """Deterministically re-ground each LLM claim's technique_id in place.

        Unlike validate_isr_reports (which only advises), this MUTATES
        ``claim.technique_id`` so the corrected ID propagates to the cascade,
        the judge's grounding, the report, and the STIX bundle. It moves the
        loop-prone ID-recall sub-task off the small model: the analyst only has
        to describe behaviour, and the full-catalog TF-IDF index assigns the ID.

        Correction policy (per claim with a non-None technique_id):
          - Invalid ID (not in the ATT&CK catalog): replace with the top
            evidence-derived suggestion; drop to None if the search is empty
            (a hallucinated ID is worse than no ID).
          - Valid but low-alignment ID (< ``min_alignment``): replace ONLY when a
            candidate suggestion is *strictly* better aligned with the evidence —
            never overwrite a weak-but-plausible ID with a noisier guess.
          - Valid, well-aligned, or None: left untouched.

        Layer-0 deterministic sources in ``skip_agents`` are skipped because
        their IDs come straight from rule matches and are authoritative.

        Returns the number of claims whose technique_id was changed. Fail-safe:
        any error returns the count accumulated so far without raising.
        """
        corrected = 0
        try:
            for isr in isr_reports.values():
                if isr.agent_id in skip_agents:
                    continue
                for claim in isr.claims:
                    tid = claim.technique_id
                    if tid is None:
                        continue
                    query = f"{claim.evidence_ref} {claim.claim}".strip()

                    if not self._index.technique_exists(tid):
                        results = self._index.search(query, top_k=1)
                        new_id = results[0].technique.technique_id if results else None
                        if new_id != tid:
                            logger.info(
                                "ATT&CK autocorrect [%s]: invalid '%s' -> '%s'.",
                                isr.agent_id,
                                tid,
                                new_id,
                            )
                            claim.technique_id = new_id
                            corrected += 1
                        continue

                    score = self._index.validate_and_score(tid, claim.evidence_ref)
                    if score >= min_alignment:
                        continue

                    best_id: str | None = None
                    best_score = score
                    for result in self._index.search(query, top_k=3):
                        cand = result.technique.technique_id
                        if cand == tid:
                            continue
                        cand_score = self._index.validate_and_score(cand, claim.evidence_ref)
                        if cand_score > best_score:
                            best_id, best_score = cand, cand_score
                    if best_id is not None:
                        logger.info(
                            "ATT&CK autocorrect [%s]: low-align '%s' (%.3f) -> '%s' (%.3f).",
                            isr.agent_id,
                            tid,
                            score,
                            best_id,
                            best_score,
                        )
                        claim.technique_id = best_id
                        corrected += 1
        except Exception as exc:  # noqa: BLE001
            logger.debug("correct_isr_reports failed: %s", exc, exc_info=True)
            return corrected

        if corrected:
            logger.info("ATT&CK autocorrect: corrected %d technique id(s).", corrected)
        return corrected

    def get_technique(self, technique_id: str) -> ATTCKTechnique | None:
        """Return the full ATTCKTechnique object for a given ID."""
        return self._index.get_by_id(technique_id)

    @property
    def technique_count(self) -> int:
        """Number of techniques in the current index."""
        return self._index.size
