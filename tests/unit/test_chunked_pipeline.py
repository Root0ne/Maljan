"""Unit tests for Phase 3 Chunked Pipeline Integration.

Tests:
  - chunk_merger.merge_chunk_isrs() — deduplication, confidence selection,
    dissent reconciliation, every claim kept
  - BaseAnalyst.safe_analyze_isr_chunked() — single chunk fast path, multi
    chunk merge path, partial failure handling
  - ServiceContainer.load_chunked() — single text fast path, chunked path
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from maljan.analysis.chunk_merger import merge_chunk_isrs
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
# merge_chunk_isrs — every claim is kept
# ---------------------------------------------------------------------------


class TestMergeChunkISRsKeepsEveryClaim:
    def test_no_claim_is_dropped_for_a_count(self) -> None:
        claims = [_claim(f"T{1000 + i:04d}", 0.5) for i in range(45)]
        result = merge_chunk_isrs([_make_isr(claims=claims[:30]), _make_isr(claims=claims[30:])])
        assert {c.technique_id for c in result.claims} == {c.technique_id for c in claims}

    def test_low_confidence_claims_are_kept_after_the_high_ones(self) -> None:
        low = [_claim(f"T{2000 + i:04d}", 0.1) for i in range(5)]
        high = [_claim(f"T{3000 + i:04d}", 0.9) for i in range(25)]
        result = merge_chunk_isrs([_make_isr(claims=high), _make_isr(claims=low)])
        assert len(result.claims) == 30
        assert [c.confidence for c in result.claims[:25]] == [0.9] * 25


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

    @pytest.fixture(autouse=True)
    def _no_suggestions(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An id the catalogue rejects is offered ranked alternatives, and the
        ranking is the one thing here that builds the ATT&CK index. These tests
        are about chunk merging."""
        from maljan.tools import knowledge

        monkeypatch.setattr(knowledge, "resolve_technique", lambda *a, **k: {"candidates": []})

    class _ConcreteAnalyst:
        """Minimal concrete implementation (avoids importing real agents)."""

        def __init__(self) -> None:
            self.name = "static"
            self.logger = MagicMock()
            self._call_count = 0
            # The gate drains the structured findings channel onto the merged
            # ISR; a duck-typed stub needs the two buffers it drains.
            self._findings_buffer: list = []
            self._artifacts_buffer: list = []
            self.validation_findings: list = []
            self.validation_retries = 0

        def analyze_isr(self, data: str) -> AgentISR:
            self._call_count += 1
            return _make_isr(
                claims=[_claim(f"T{1000 + self._call_count:04d}", 0.8)],
            )

        def safe_analyze_isr(self, data: str) -> AgentISR:
            return self.analyze_isr(data)

        def _infer_domain(self):
            return "static"

        def _system_prompt(self, fallback, tools=None):
            return "system"

        def _truncate_input(self, text: str) -> str:
            return text

        # Attach the real method from BaseAnalyst
        from maljan.agents.base_agent import BaseAnalyst

        safe_analyze_isr_chunked = BaseAnalyst.safe_analyze_isr_chunked
        # The wrapper now runs the §4 Item 4 consistency gate (off by default =
        # no-op); borrow it too so this duck-typed stub stays compatible.
        _apply_consistency_gate = BaseAnalyst._apply_consistency_gate
        _drain_findings = BaseAnalyst._drain_findings
        # And the validation loop, which the wrapper runs on the merged ISR.
        _validate_isr = BaseAnalyst._validate_isr

    @pytest.fixture
    def analyst(self) -> _ConcreteAnalyst:
        return self._ConcreteAnalyst()

    def test_empty_chunks_raises_analyst_error(self, analyst: _ConcreteAnalyst) -> None:
        # Hardened behaviour (P4-11): an empty chunk list is a hard input
        # error rather than a silent "no findings" success.
        from maljan.core.exceptions import AnalystError

        with pytest.raises(AnalystError):
            analyst.safe_analyze_isr_chunked([])

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

    def test_the_merged_validation_runs_under_the_agent_s_lock(
        self, analyst: _ConcreteAnalyst
    ) -> None:
        """A delegated ask of the same agent waits until the validation turn is done.

        The validation turn marks the findings buffer and slices it in
        ``_parse``; an ask landing in between would carry this ISR's findings
        onto its own answer, or its findings onto this one.
        """
        import threading
        import time

        from maljan.agents.base_agent import lock_for

        analyst.delegation_lock = threading.RLock()
        order: list[str] = []
        validating = threading.Event()

        def _validate(isr: AgentISR, evidence: str, **_kw: object) -> AgentISR:
            order.append("validation starts")
            validating.set()
            time.sleep(0.3)
            order.append("validation ends")
            return isr

        def _ask() -> None:
            validating.wait(5)
            with lock_for(analyst):
                order.append("ask")

        analyst._validate_isr = _validate  # type: ignore[method-assign]
        asker = threading.Thread(target=_ask)
        asker.start()
        analyst.safe_analyze_isr_chunked([_make_chunk(i, 2) for i in range(2)])
        asker.join(5)

        assert order == ["validation starts", "validation ends", "ask"]

    def test_a_cut_in_chunk_one_reaches_the_merged_check_after_a_short_chunk_two(
        self, analyst: _ConcreteAnalyst
    ) -> None:
        """Each chunk's loop records its own answer; chunk 2's must not erase chunk 1's cut."""
        cut_text = "CLAIM: one\nEVIDENCE: [ev_0001]\nCLAIM: tw"
        answers = iter([(32768, cut_text), None])
        real_analyze = analyst.analyze_isr

        def _analyze(data: str) -> AgentISR:
            isr = real_analyze(data)
            # What ``_record_usage`` leaves after each chunk's last answer.
            analyst._last_answer_cut = next(answers)
            return isr

        seen: list[tuple[object, dict[str, object]]] = []

        def _validate(isr: AgentISR, evidence: str, **kw: object) -> AgentISR:
            seen.append((analyst._last_answer_cut, dict(kw)))
            return isr

        analyst.analyze_isr = _analyze  # type: ignore[method-assign]
        analyst._validate_isr = _validate  # type: ignore[method-assign]
        analyst.safe_analyze_isr_chunked([_make_chunk(i, 2) for i in range(2)])

        # Chunk 1's cut is asked about inside chunk 1; the merged check gets no cut.
        assert seen == [
            ((32768, cut_text), {"chunk": "chunk 1 of 2", "only_cut": True}),
            (None, {}),
        ]

    def test_a_chunk_that_raises_after_a_cut_leaves_no_cut_for_the_next(
        self, analyst: _ConcreteAnalyst
    ) -> None:
        real_analyze = analyst.analyze_isr
        calls: list[int] = []
        seen: list[object] = []

        def _analyze(data: str) -> AgentISR:
            calls.append(1)
            if len(calls) == 1:
                analyst._last_answer_cut = (32768, "CLAIM: cut")
                raise RuntimeError("the loop failed after its answer")
            return real_analyze(data)

        def _validate(isr: AgentISR, evidence: str, **kw: object) -> AgentISR:
            seen.append(analyst._last_answer_cut)
            return isr

        analyst.analyze_isr = _analyze  # type: ignore[method-assign]
        analyst._validate_isr = _validate  # type: ignore[method-assign]
        analyst.safe_analyze_isr_chunked([_make_chunk(i, 2) for i in range(2)])

        assert seen == [None]

    def test_a_later_chunk_is_told_what_the_earlier_ones_called(
        self, analyst: _ConcreteAnalyst
    ) -> None:
        """Chunk 2 re-ran ten decompiles chunk 1 had done: it is now told, and they are not run."""
        from maljan.agents.base_agent import EARLIER_CHUNKS_HEAD
        from maljan.schemas.evidence import LedgerEntry

        analyst._evidence_entries = []
        prompts: list[str] = []
        seeds: list[list[str]] = []
        real_analyze = analyst.analyze_isr

        def _analyze(data: str) -> AgentISR:
            prompts.append(data)
            seeds.append([e.id for e in getattr(analyst, "_prior_chunk_calls", None) or []])
            n = len(analyst._evidence_entries) + 1
            analyst._evidence_entries.append(
                LedgerEntry(
                    id=f"ev_{n:04d}",
                    agent="static",
                    tool="decompile_function",
                    args={"address": f"0x{n:04x}"},
                    ok=n != 2,
                    output=f"int FUN_{n:04x}(void)\n{{ return {n}; }}",
                    remediation=None if n != 2 else "load the program first",
                )
            )
            return real_analyze(data)

        analyst.analyze_isr = _analyze  # type: ignore[method-assign]
        analyst.safe_analyze_isr_chunked([_make_chunk(i, 3) for i in range(3)])

        first_call = '- decompile_function({"address": "0x0001"}) \u2192 ev_0001'
        failed_call = '- decompile_function({"address": "0x0002"}) \u2192 ev_0002 (failed)'
        assert EARLIER_CHUNKS_HEAD not in prompts[0]
        assert EARLIER_CHUNKS_HEAD in prompts[1]
        assert first_call in prompts[1]
        assert first_call in prompts[2]
        assert failed_call in prompts[2]
        assert f"{first_call}: int FUN_0001(void) {{ return 1; }}" in prompts[1]
        assert f"{failed_call}: the call failed; load the program first" in prompts[2]
        assert seeds == [[], ["ev_0001"], ["ev_0001", "ev_0002"]]
        # The calls of this analysis alone, and none left behind for a later loop.
        assert getattr(analyst, "_prior_chunk_calls", None) in (None, [])

    def test_the_loop_seeds_its_repeat_guard_with_them(self) -> None:
        from maljan.agents.evidence_recorder import seeded_repeat_guard
        from maljan.schemas.evidence import LedgerEntry

        guard = seeded_repeat_guard(
            [LedgerEntry(id="ev_0004", tool="decompile_function", args={"address": "0x1"})]
        )

        assert guard.answered_by("decompile_function", {"address": "0x1"}) == "ev_0004"
        assert guard.answered_by("decompile_function", {"address": "0x2"}) is None

    def test_the_analyst_loop_builds_its_guard_from_the_earlier_chunks(self) -> None:
        import inspect

        from maljan.agents import base_agent

        source = inspect.getsource(base_agent.BaseAnalyst.execute_tool_loop)
        assert 'seeded_repeat_guard(getattr(self, "_prior_chunk_calls", None))' in source


# ---------------------------------------------------------------------------
# ServiceContainer.load_chunked()
# ---------------------------------------------------------------------------


class TestServiceContainerLoadChunked:
    def _make_container(self, text: str = "sample data") -> MagicMock:
        """Build a mock container with loader.chunk_text and _data_cache.

        The real ``ServiceContainer.load_chunked`` short-circuits to
        ``loader.chunk_text(...)`` when the parsed-text cache is warm,
        otherwise calls ``loader.load_chunked(...)`` which internally
        re-parses + chunks.
        """
        import threading

        container = MagicMock()
        mock_chunk = _make_chunk(0, 1, content=text)
        container.loader.chunk_text.return_value = [mock_chunk]
        container.loader.load_chunked.return_value = [mock_chunk]
        container._data_cache = {}
        container._lock = threading.Lock()
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
        # Cache hit ⇒ chunk_text() is called directly; load_chunked is bypassed.
        container.loader.chunk_text.assert_called_once_with("static", "cached text")
        container.loader.load_chunked.assert_not_called()
        assert len(result) == 1
