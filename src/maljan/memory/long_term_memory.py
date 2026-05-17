"""Long-Term Memory abstractions for Maljan — Phase 5.

Defines the StoredCase dataclass and the MemoryStore Protocol that all
backend implementations must satisfy. The Protocol is runtime-checkable so
isinstance() guards in tests and container code work without importing concrete
backends.

Design goals:
  - Zero external dependencies in this module (importable everywhere).
  - Protocol-based: swappable backends without changing caller code.
  - StoredCase captures all signals needed for few-shot retrieval: the
    free-text summary (used for similarity search), extracted technique IDs
    (for TTP-level deduplication), malware category (from schema_pruner),
    and the full STIX bundle JSON (for future cross-case correlation).

MemoryStore.retrieve() contract:
  - Returns at most top_k cases ordered by descending relevance score.
  - Returns [] when the store is empty or query is blank.
  - Never raises on empty store — callers do not need to guard.

MemoryStore.store() contract:
  - Upserts by sample_id: storing the same sample_id twice replaces the
    older entry. This prevents the store from growing unboundedly during
    repeated analysis runs on the same sample.

Helper build_stored_case():
  - Convenience factory that creates a StoredCase from pipeline artifacts
    (ISR reports dict + STIX Bundle JSON string). Callers (app.py, nodes.py)
    use this after give_verdict() to persist results without manual field
    construction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from maljan.schemas.isr_models import AgentISR


# ---------------------------------------------------------------------------
# StoredCase — unit of long-term memory
# ---------------------------------------------------------------------------


@dataclass
class StoredCase:
    """A single persisted analysis result for long-term retrieval.

    Attributes:
        sample_id:          Unique identifier for the analysed sample.
        summary_text:       Free-text representation used for similarity
                            search. Should include claim text, evidence
                            references, and technique descriptions.
        technique_ids:      ATT&CK technique IDs found in this analysis.
        malware_category:   Inferred malware category string from SchemaPruner
                            (e.g. "RANSOMWARE", "RAT", "UNKNOWN").
        stix_bundle_json:   JSON-serialized STIX 2.1 Bundle for this sample.
        created_at:         UTC timestamp of when this case was stored.
    """

    sample_id: str
    summary_text: str
    technique_ids: list[str] = field(default_factory=list)
    malware_category: str = "UNKNOWN"
    stix_bundle_json: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# MemoryStore Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class MemoryStore(Protocol):
    """Backend-agnostic interface for long-term case memory.

    All concrete implementations (InMemoryStore, QdrantStore) must satisfy
    this Protocol. The @runtime_checkable decorator enables isinstance()
    checks in tests and container code.

    Implementations:
        InMemoryStore  -- pure-Python cosine similarity (no infra required)
        QdrantStore    -- Qdrant vector database (requires Docker + qdrant-client)
    """

    def store(self, case: StoredCase) -> None:
        """Persist a case. Upserts by sample_id (replaces existing entry)."""
        ...

    def retrieve(
        self,
        query: str,
        top_k: int = 3,
        exclude_sample_id: str | None = None,
    ) -> list[StoredCase]:
        """Return the top_k most similar stored cases for the given query.

        Args:
            query:  Free-text search query (typically the ISR summary text).
            top_k:  Maximum number of cases to return. May return fewer when
                    the store contains fewer than top_k entries.
            exclude_sample_id: Optional sha256 to filter out (audit
                2026-05-17, LTM-01): prevents a sample's prior run from
                being injected as a "weighted prior" for itself.

        Returns:
            List of StoredCase objects, ordered by descending relevance.
            Empty list when store is empty or query is blank.
        """
        ...

    def count(self) -> int:
        """Return the number of cases currently in the store."""
        ...

    def clear(self) -> None:
        """Remove all stored cases. Primarily used in tests."""
        ...


# ---------------------------------------------------------------------------
# Helper: build_stored_case
# ---------------------------------------------------------------------------


def build_stored_case(
    sample_id: str,
    isr_reports: dict[str, AgentISR],
    stix_bundle_json: str = "",
    malware_category: str = "UNKNOWN",
) -> StoredCase:
    """Build a StoredCase from pipeline artifacts.

    Convenience factory intended for use in app.py or pipeline nodes after
    give_verdict() produces the final STIX bundle:

        from maljan.memory.long_term_memory import build_stored_case

        case = build_stored_case(
            sample_id=sample_id,
            isr_reports=state["isr_reports"],
            stix_bundle_json=bundle.model_dump_json(),
            malware_category=inferred_category,
        )
        memory_store.store(case)

    The summary_text is constructed by concatenating all claim text, evidence
    references, and technique IDs from every ISR report. This produces a
    rich, keyword-dense string for similarity search.

    Args:
        sample_id:          Identifier for the analysed sample.
        isr_reports:        Dict of agent_name -> AgentISR produced by pipeline.
        stix_bundle_json:   JSON string of the final Bundle (may be empty).
        malware_category:   Inferred malware category from SchemaPruner.

    Returns:
        StoredCase ready to pass to MemoryStore.store().
    """
    technique_ids: list[str] = []
    text_parts: list[str] = []

    for agent_name, isr in isr_reports.items():
        text_parts.append(f"[{agent_name.upper()}]")
        for claim in isr.claims:
            text_parts.append(claim.claim)
            if claim.evidence_ref:
                text_parts.append(claim.evidence_ref)
            if claim.technique_id:
                text_parts.append(claim.technique_id)
                if claim.technique_id not in technique_ids:
                    technique_ids.append(claim.technique_id)

    summary_text = " ".join(text_parts)

    return StoredCase(
        sample_id=sample_id,
        summary_text=summary_text,
        technique_ids=technique_ids,
        malware_category=malware_category,
        stix_bundle_json=stix_bundle_json,
    )
