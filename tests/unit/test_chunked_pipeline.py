"""Unit tests for Phase 3 Chunked Pipeline Integration.

Tests:
  - chunk_merger.merge_chunk_isrs() — deduplication, confidence selection,
    dissent reconciliation, MAX_MERGED_CLAIMS cap
  - BaseAnalyst.safe_analyze_isr_chunked() — single chunk fast path, multi
    chunk merge path, partial failure handling
  - ServiceContainer.load_chunked() — single text fast path, chunked path
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from maljan.analysis.chunk_merger import MAX_MERGED_CLAIMS, merge_chunk_isrs
from maljan.loaders.binary_chunker import ChunkStrategy, TextChunk
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_isr(
    agent_id: str = "static",
    domain: str = "static",
    claims: list[ClaimEvidence] | None = None,
    dissent_items: list[str] | None = None,
    revision_round: int = 0,
) -> AgentISR:
    return AgentISR(
        agent_id=agent_id,
        domain=domain,  # type: ignore[arg-type]
        claims=claims or [],
        dissent_items=dissent_items or [],
        revision_round=revision_round,
    )


def _claim(
    technique_id: str | None,
    confidence: float,
    claim_text: str = "claim",
    evidence: str = "ref",
) -> ClaimEvidence:
    return ClaimEvidence(
        claim=claim_text,
        evidence_ref=evidence,
        confidence=confidence,
        technique_id=technique_id,
    )


def _make_chunk(
    index: int,
    total: int,
    content: str = "data",
    domain: str = "static",
) -> TextChunk:
    return TextChunk(
        index=index,
        total=total,
        strategy=ChunkStrategy.SLIDING_WINDOW,
        content=content,
        char_count=len(content),
        token_estimate=len(content) // 4,
        domain=domain,
    )


# ---------------------------------------------------------------------------
# merge_chunk_isrs — basic cases
# ---------------------------------------------------------------------------

class TestMergeChunkISRsBasic:
    def test_empty_list_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one"):
            merge_chunk_isrs([])

    def test_single_isr_returned_unchanged(self) -> None:
        isr = _make_isr(claims=[_claim("T1055", 0.8)])
        result = merge_chunk_isrs([isr])
        assert result is isr

    def test_agent_id_from_first_isr(self) -> None:
        isrs = [_make_isr(agent_id="static"), _make_isr(agent_id="static")]
        assert merge_chunk_isrs(isrs).agent_id == "static"

    def test_domain_from_first_isr(self) -> None:
        isrs = [_make_isr(domain="static"), _make_isr(domain="static")]
        assert merge_chunk_isrs(isrs).domain == "static"

    def test_revision_round_is_max(self) -> None:
        isrs = [
            _make_isr(revision_round=0),
            _make_isr(revision_round=2),
            _make_isr(revision_round=1),
        ]
        assert merge_chunk_isrs(isrs).revision_round == 2

    def test_no_claims_across_chunks(self) -> None:
        isrs = [_make_isr(), _make_isr()]
        result = merge_chunk_isrs(isrs)
        assert result.claims == []


# ---------------------------------------------------------------------------
# merge_chunk_isrs — TTP deduplication (keyed claims)
# ---------------------------------------------------------------------------

class TestMergeChunkISRsTTPDedup:
    def test_same_ttp_keeps_highest_confidence(self) -> None:
        isrs = [
            _make_isr(claims=[_claim("T1055", 0.60)]),
            _make_isr(claims=[_claim("T1055", 0.90)]),
        ]
        result = merge_chunk_isrs(isrs)
        assert len([c for c in result.claims if c.technique_id == "T1055"]) == 1
        t1055_claim = next(c for c in result.claims if c.technique_id == "T1055")
        assert t1055_claim.confidence == pytest.approx(0.90)

    def test_different_ttps_both_kept(self) -> None:
        isrs = [
            _make_isr(claims=[_claim("T1055", 0.8)]),
            _make_isr(claims=[_claim("T1547", 0.7)]),
        ]
        result = merge_chunk_isrs(isrs)
        tids = {c.technique_id for c in result.claims}
        assert tids == {"T1055", "T1547"}

    def test_ttp_claims_sorted_by_confidence_first(self) -> None:
        isrs = [
            _make_isr(claims=[_claim("T1547", 0.60)]),
            _make_isr(claims=[_claim("T1055", 0.95)]),
        ]
        result = merge_chunk_isrs(isrs)
        # TTP claims come first, highest confidence leads
        assert result.claims[0].technique_id == "T1055"


# ---------------------------------------------------------------------------
# merge_chunk_isrs — unkeyed claim deduplication
# ---------------------------------------------------------------------------

class TestMergeChunkISRsUnkeyedDedup:
    def test_duplicate_unkeyed_claims_removed(self) -> None:
        same_claim = _claim(None, 0.7, claim_text="process injection detected")
        isrs = [
            _make_isr(claims=[same_claim]),
            _make_isr(claims=[same_claim]),
        ]
        result = merge_chunk_isrs(isrs)
        unkeyed = [c for c in result.claims if c.technique_id is None]
        assert len(unkeyed) == 1

    def test_different_unkeyed_claims_both_kept(self) -> None:
        isrs = [
            _make_isr(claims=[_claim(None, 0.7, claim_text="claim A")]),
            _make_isr(claims=[_claim(None, 0.8, claim_text="claim B")]),
        ]
        result = merge_chunk_isrs(isrs)
        unkeyed = [c for c in result.claims if c.technique_id is None]
        assert len(unkeyed) == 2

    def test_unkeyed_dedup_is_case_insensitive(self) -> None:
        isrs = [
            _make_isr(claims=[_claim(None, 0.7, claim_text="Process Injection Detected")]),
            _make_isr(claims=[_claim(None, 0.8, claim_text="process injection detected")]),
        ]
        result = merge_chunk_isrs(isrs)
        unkeyed = [c for c in result.claims if c.technique_id is None]
        assert len(unkeyed) == 1


# ---------------------------------------------------------------------------
# merge_chunk_isrs — MAX_MERGED_CLAIMS cap
# ---------------------------------------------------------------------------

class TestMergeChunkISRsCap:
    def test_excess_claims_capped(self) -> None:
        # Create MAX_MERGED_CLAIMS + 5 unique claims
        claims = [_claim(f"T{1000 + i:04d}", 0.5) for i in range(MAX_MERGED_CLAIMS + 5)]
        isrs = [_make_isr(claims=claims)]
        merge_chunk_isrs(isrs)  # single ISR returns unchanged — no cap triggered
        # Wrap in two ISRs to trigger merge path
        isrs2 = [
            _make_isr(claims=claims[:MAX_MERGED_CLAIMS + 3]),
            _make_isr(claims=claims[MAX_MERGED_CLAIMS + 3:]),
        ]
        result2 = merge_chunk_isrs(isrs2)
        assert len(result2.claims) <= MAX_MERGED_CLAIMS

    def test_highest_confidence_claims_survive_cap(self) -> None:
        # Low-confidence claims should be dropped first
        low = [_claim(f"T{2000 + i:04d}", 0.1) for i in range(5)]
        high = [_claim(f"T{3000 + i:04d}", 0.9) for i in range(MAX_MERGED_CLAIMS)]
        isrs = [
            _make_isr(claims=high),
            _make_isr(claims=low),
        ]
        result = merge_chunk_isrs(isrs)
        surviving_ids = {c.technique_id for c in result.claims}
        # All high-confidence TTP claims should survive
        for h in high[:MAX_MERGED_CLAIMS]:
            assert h.technique_id in surviving_ids


# ---------------------------------------------------------------------------
# merge_chunk_isrs — dissent reconciliation
# ---------------------------------------------------------------------------

class TestMergeChunkISRsDissent:
    def test_dissent_items_merged(self) -> None:
        isrs = [
            _make_isr(dissent_items=["dispute A"]),
            _make_isr(dissent_items=["dispute B"]),
        ]
        result = merge_chunk_isrs(isrs)
        assert "dispute A" in result.dissent_items
        assert "dispute B" in result.dissent_items

    def test_duplicate_dissent_items_deduped(self) -> None:
        isrs = [
            _make_isr(dissent_items=["dispute A", "dispute B"]),
            _make_isr(dissent_items=["dispute A"]),
        ]
        result = merge_chunk_isrs(isrs)
        assert result.dissent_items.count("dispute A") == 1

    def test_no_dissent_items(self) -> None:
        isrs = [_make_isr(), _make_isr()]
        assert merge_chunk_isrs(isrs).dissent_items == []


# ---------------------------------------------------------------------------
# BaseAnalyst.safe_analyze_isr_chunked()
# ---------------------------------------------------------------------------

class TestSafeAnalyzeISRChunked:
    """Test safe_analyze_isr_chunked() on a concrete minimal BaseAnalyst subclass."""

    class _ConcreteAnalyst:
        """Minimal concrete implementation (avoids importing real agents)."""

        def __init__(self) -> None:
            self.name = "static"
            self.logger = MagicMock()
            self._call_count = 0

        def analyze_isr(self, data: str) -> AgentISR:
            self._call_count += 1
            return _make_isr(
                claims=[_claim(f"T{1000 + self._call_count:04d}", 0.8)],
            )

        def safe_analyze_isr(self, data: str) -> AgentISR:
            return self.analyze_isr(data)

        def _infer_domain(self):
            return "static"

        # Attach the real method from BaseAnalyst
        from maljan.agents.base_agent import BaseAnalyst
        safe_analyze_isr_chunked = BaseAnalyst.safe_analyze_isr_chunked

    @pytest.fixture
    def analyst(self) -> _ConcreteAnalyst:
        return self._ConcreteAnalyst()

    def test_empty_chunks_returns_empty_isr(self, analyst: _ConcreteAnalyst) -> None:
        result = analyst.safe_analyze_isr_chunked([])
        assert result.claims == []

    def test_single_chunk_calls_safe_analyze_isr(self, analyst: _ConcreteAnalyst) -> None:
        chunks = [_make_chunk(0, 1)]
        result = analyst.safe_analyze_isr_chunked(chunks)
        assert analyst._call_count == 1
        assert result is not None

    def test_multi_chunk_calls_analyze_isr_per_chunk(self, analyst: _ConcreteAnalyst) -> None:
        chunks = [_make_chunk(i, 3) for i in range(3)]
        result = analyst.safe_analyze_isr_chunked(chunks)
        assert analyst._call_count == 3
        assert len(result.claims) == 3  # one claim per chunk, all different TTPs

    def test_multi_chunk_result_is_merged(self, analyst: _ConcreteAnalyst) -> None:
        chunks = [_make_chunk(i, 2) for i in range(2)]
        result = analyst.safe_analyze_isr_chunked(chunks)
        # Merged ISR should have claims from both chunks
        assert len(result.claims) >= 1


# ---------------------------------------------------------------------------
# ServiceContainer.load_chunked()
# ---------------------------------------------------------------------------

class TestServiceContainerLoadChunked:
    def _make_container(self, text: str = "sample data") -> MagicMock:
        """Build a mock container with loader._chunker and _data_cache."""
        container = MagicMock()
        mock_chunk = _make_chunk(0, 1, content=text)
        container.loader._chunker.chunk.return_value = [mock_chunk]
        container.loader.load_chunked.return_value = [mock_chunk]
        container._data_cache = {}
        # Bind the real method
        from maljan.core.container import ServiceContainer
        container.load_chunked = ServiceContainer.load_chunked.__get__(container)
        return container

    def test_calls_load_chunked_on_first_access(self) -> None:
        container = self._make_container()
        result = container.load_chunked("hash1", "static")
        container.loader.load_chunked.assert_called_once_with("hash1", "static")
        assert len(result) == 1

    def test_uses_cached_text_if_available(self) -> None:
        container = self._make_container()
        container._data_cache[("hash1", "static")] = "cached text"
        result = container.load_chunked("hash1", "static")
        # Should use chunker directly, NOT call load_chunked
        container.loader._chunker.chunk.assert_called_once_with("static", "cached text")
        container.loader.load_chunked.assert_not_called()
        assert len(result) == 1
