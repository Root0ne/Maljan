"""Unit tests for Phase 5 Long-Term Memory (RAG) framework.

Tests:
  StoredCase:
    - Creation with defaults
    - technique_ids, malware_category, stix_bundle_json fields

  build_stored_case():
    - Extracts technique_ids from ISR reports
    - Builds summary_text from claims + evidence_refs
    - Handles empty ISR reports
    - Deduplicates technique_ids

  InMemoryStore:
    - store() and count()
    - retrieve() returns similar cases
    - retrieve() empty store -> []
    - retrieve() blank query -> []
    - retrieve() respects top_k
    - retrieve() orders by descending similarity
    - store() upsert: same sample_id replaces old entry
    - clear() resets count to 0
    - exact text match scores highest
    - MemoryStore Protocol isinstance check

  QdrantStore:
    - Raises QdrantNotAvailableError when qdrant-client is absent

  JudgeAgent._build_memory_context():
    - None memory_store returns ""
    - None isr_reports returns ""
    - Empty store returns ""
    - With cases returns formatted block
    - Block contains expected section headers
    - Block contains technique IDs from stored cases
    - Retrieval exception returns "" (graceful degradation)

  ServiceContainer.get_memory_store():
    - Returns InMemoryStore by default
    - Returns cached instance on second call
    - MemoryConfig backend=memory selects InMemoryStore
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from maljan.memory.in_memory_store import InMemoryStore
from maljan.memory.long_term_memory import MemoryStore, StoredCase, build_stored_case

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_case(
    sample_id: str = "s1",
    summary: str = "ransomware encryption C2 beacon",
    technique_ids: list[str] | None = None,
    malware_category: str = "RANSOMWARE",
) -> StoredCase:
    return StoredCase(
        sample_id=sample_id,
        summary_text=summary,
        technique_ids=technique_ids or ["T1486"],
        malware_category=malware_category,
    )


def _make_isr(claims_data: list[dict]) -> object:
    """Build a minimal AgentISR mock for build_stored_case tests."""
    from maljan.schemas.isr_models import AgentISR, ClaimEvidence

    claims = [
        ClaimEvidence(
            claim=d["claim"],
            evidence_ref=d.get("evidence_ref", ""),
            confidence=d.get("confidence", 0.8),
            technique_id=d.get("technique_id"),
        )
        for d in claims_data
    ]
    return AgentISR(
        agent_id="test",
        domain="static",
        claims=claims,
        dissent_items=[],
        revision_round=0,
    )


# ---------------------------------------------------------------------------
# StoredCase
# ---------------------------------------------------------------------------


class TestStoredCase:
    def test_default_malware_category(self) -> None:
        case = StoredCase(sample_id="s1", summary_text="hello")
        assert case.malware_category == "UNKNOWN"

    def test_default_technique_ids_empty(self) -> None:
        case = StoredCase(sample_id="s1", summary_text="hello")
        assert case.technique_ids == []

    def test_default_stix_bundle_json_empty(self) -> None:
        case = StoredCase(sample_id="s1", summary_text="hello")
        assert case.stix_bundle_json == ""

    def test_created_at_is_set(self) -> None:
        case = StoredCase(sample_id="s1", summary_text="hello")
        assert case.created_at is not None


# ---------------------------------------------------------------------------
# build_stored_case
# ---------------------------------------------------------------------------


class TestBuildStoredCase:
    def test_extracts_technique_ids(self) -> None:
        isr = _make_isr(
            [
                {"claim": "Encrypts files", "technique_id": "T1486"},
                {"claim": "Deletes shadow copies", "technique_id": "T1490"},
            ]
        )
        case = build_stored_case("test_1", {"static": isr})
        assert "T1486" in case.technique_ids
        assert "T1490" in case.technique_ids

    def test_builds_summary_text_from_claims(self) -> None:
        isr = _make_isr([{"claim": "Encrypts files", "evidence_ref": "CryptoAPI"}])
        case = build_stored_case("test_1", {"static": isr})
        assert "Encrypts files" in case.summary_text
        assert "CryptoAPI" in case.summary_text

    def test_empty_isr_produces_empty_summary(self) -> None:
        case = build_stored_case("test_1", {})
        assert case.summary_text.strip() == ""
        assert case.technique_ids == []

    def test_deduplicates_technique_ids(self) -> None:
        isr = _make_isr(
            [
                {"claim": "Claim A", "technique_id": "T1486"},
                {"claim": "Claim B", "technique_id": "T1486"},
            ]
        )
        case = build_stored_case("test_1", {"static": isr})
        assert case.technique_ids.count("T1486") == 1

    def test_sets_sample_id(self) -> None:
        case = build_stored_case("my_sample", {})
        assert case.sample_id == "my_sample"

    def test_sets_malware_category(self) -> None:
        case = build_stored_case("s1", {}, malware_category="RAT")
        assert case.malware_category == "RAT"

    def test_sets_stix_bundle_json(self) -> None:
        case = build_stored_case("s1", {}, stix_bundle_json='{"type":"bundle"}')
        assert case.stix_bundle_json == '{"type":"bundle"}'


# ---------------------------------------------------------------------------
# InMemoryStore
# ---------------------------------------------------------------------------


class TestInMemoryStore:
    def test_store_increments_count(self) -> None:
        store = InMemoryStore()
        store.store(_make_case("s1"))
        assert store.count() == 1

    def test_retrieve_empty_store(self) -> None:
        store = InMemoryStore()
        assert store.retrieve("ransomware") == []

    def test_retrieve_blank_query(self) -> None:
        store = InMemoryStore()
        store.store(_make_case("s1"))
        assert store.retrieve("") == []
        assert store.retrieve("   ") == []

    def test_retrieve_returns_similar_case(self) -> None:
        store = InMemoryStore()
        store.store(_make_case("s1", "ransomware encryption C2 beacon T1486"))
        results = store.retrieve("ransomware encryption")
        assert len(results) == 1
        assert results[0].sample_id == "s1"

    def test_retrieve_respects_top_k(self) -> None:
        store = InMemoryStore()
        for i in range(5):
            store.store(_make_case(f"s{i}", f"ransomware encryption sample {i}"))
        results = store.retrieve("ransomware encryption", top_k=2)
        assert len(results) == 2

    def test_retrieve_orders_by_similarity_descending(self) -> None:
        store = InMemoryStore()
        store.store(_make_case("exact", "ransomware encryption shadow copy T1486 T1490"))
        store.store(_make_case("partial", "malware sample"))
        results = store.retrieve("ransomware encryption shadow copy", top_k=2)
        assert results[0].sample_id == "exact"

    def test_store_upsert_replaces_same_sample_id(self) -> None:
        store = InMemoryStore()
        store.store(_make_case("s1", "original text"))
        store.store(_make_case("s1", "updated text"))
        assert store.count() == 1
        results = store.retrieve("updated text")
        assert results[0].sample_id == "s1"
        assert "updated" in results[0].summary_text

    def test_clear_resets_count(self) -> None:
        store = InMemoryStore()
        store.store(_make_case("s1"))
        store.store(_make_case("s2"))
        store.clear()
        assert store.count() == 0

    def test_clear_makes_retrieve_return_empty(self) -> None:
        store = InMemoryStore()
        store.store(_make_case("s1", "ransomware"))
        store.clear()
        assert store.retrieve("ransomware") == []

    def test_memory_store_protocol_isinstance(self) -> None:
        store = InMemoryStore()
        assert isinstance(store, MemoryStore)

    def test_repr_contains_count(self) -> None:
        store = InMemoryStore()
        store.store(_make_case("s1"))
        assert "1" in repr(store)


# ---------------------------------------------------------------------------
# QdrantStore
# ---------------------------------------------------------------------------


class TestQdrantStore:
    def test_raises_when_qdrant_client_not_installed(self) -> None:
        from maljan.memory.qdrant_store import QdrantNotAvailableError, QdrantStore

        with patch.dict("sys.modules", {"qdrant_client": None}):
            with pytest.raises((QdrantNotAvailableError, ImportError)):
                QdrantStore(url="http://localhost:6333")


# ---------------------------------------------------------------------------
# JudgeAgent._build_memory_context
# ---------------------------------------------------------------------------


class TestBuildMemoryContext:
    from maljan.agents.judge_agent import JudgeAgent

    def _make_isr_reports(self) -> dict:
        isr = _make_isr(
            [
                {"claim": "Encrypts user files", "technique_id": "T1486"},
            ]
        )
        return {"static": isr}

    def test_none_memory_store_returns_empty(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        result = JudgeAgent._build_memory_context({}, None)
        assert result == ""

    def test_none_isr_reports_returns_empty(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        store = InMemoryStore()
        result = JudgeAgent._build_memory_context(None, store)
        assert result == ""

    def test_empty_store_returns_empty(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        store = InMemoryStore()
        result = JudgeAgent._build_memory_context(self._make_isr_reports(), store)
        assert result == ""

    def test_with_cases_returns_nonempty_block(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        store = InMemoryStore()
        store.store(_make_case("past_1", "ransomware encryption files T1486"))
        result = JudgeAgent._build_memory_context(self._make_isr_reports(), store)
        assert result != ""

    def test_block_contains_section_headers(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        store = InMemoryStore()
        store.store(_make_case("past_1", "ransomware encryption files T1486"))
        result = JudgeAgent._build_memory_context(self._make_isr_reports(), store)
        assert "LONG-TERM MEMORY" in result
        assert "END LONG-TERM MEMORY" in result

    def test_block_contains_technique_ids(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        store = InMemoryStore()
        store.store(_make_case("past_1", "ransomware encryption", ["T1486", "T1490"]))
        result = JudgeAgent._build_memory_context(self._make_isr_reports(), store)
        assert "T1486" in result

    def test_block_contains_sample_id(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        store = InMemoryStore()
        store.store(_make_case("my_past_sample", "ransomware T1486"))
        result = JudgeAgent._build_memory_context(self._make_isr_reports(), store)
        assert "my_past_sample" in result

    def test_retrieval_exception_returns_empty(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        broken_store = MagicMock()
        broken_store.retrieve.side_effect = RuntimeError("Qdrant unavailable")
        result = JudgeAgent._build_memory_context(self._make_isr_reports(), broken_store)
        assert result == ""


# ---------------------------------------------------------------------------
# ServiceContainer.get_memory_store
# ---------------------------------------------------------------------------


class TestContainerGetMemoryStore:
    def test_returns_in_memory_store_by_default(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(config=Settings(), mock=True)
        store = container.get_memory_store()
        assert isinstance(store, InMemoryStore)

    def test_returns_cached_instance_on_second_call(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(config=Settings(), mock=True)
        store1 = container.get_memory_store()
        store2 = container.get_memory_store()
        assert store1 is store2

    def test_memory_config_backend_memory_selects_inmemory(self) -> None:
        from maljan.core.config import MemoryConfig, Settings
        from maljan.core.container import ServiceContainer

        cfg = Settings(memory=MemoryConfig(backend="memory"))
        container = ServiceContainer(config=cfg, mock=True)
        store = container.get_memory_store()
        assert isinstance(store, InMemoryStore)
