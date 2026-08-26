"""Unit tests for _build_revision_context() — Phase 3 Revision Grounding.

Verifies:
  - Single-chunk path: returns raw chunk content (backward-compatible)
  - Multi-chunk path: returns ISR summary with context header
  - Multi-chunk path: prefers revised report over initial report
  - Multi-chunk path: falls back to load_data when no summary exists
  - Graceful degradation: load_chunked failure falls back to load_data
  - Context header format validation
"""

from __future__ import annotations

from unittest.mock import MagicMock

from maljan.loaders.binary_chunker import ChunkStrategy, TextChunk
from maljan.pipeline.nodes import _build_revision_context

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_chunk(
    index: int,
    total: int,
    content: str = "raw analysis data",
    domain: str = "static",
    strategy: ChunkStrategy = ChunkStrategy.SLIDING_WINDOW,
) -> TextChunk:
    return TextChunk(
        index=index,
        total=total,
        strategy=strategy,
        content=content,
        char_count=len(content),
        token_estimate=len(content) // 4,
        domain=domain,
    )


def _make_container(chunks: list[TextChunk]) -> MagicMock:
    container = MagicMock()
    container.load_chunked.return_value = chunks
    container.load_data.return_value = "fallback raw data"
    return container


def _make_state(
    file_hash: str = "abc123",
    reports: dict | None = None,
    revised_reports: dict | None = None,
) -> dict:
    return {
        "file_hash": file_hash,
        "reports": reports or {},
        "revised_reports": revised_reports or {},
    }


# ---------------------------------------------------------------------------
# Single-chunk path (backward-compatible)
# ---------------------------------------------------------------------------


class TestSingleChunkPath:
    def test_returns_chunk_content(self) -> None:
        """Single chunk → returns raw chunk text, not load_data fallback."""
        chunks = [_make_chunk(0, 1, content="single chunk content")]
        container = _make_container(chunks)
        state = _make_state()

        result = _build_revision_context(state, container, "static")

        assert result == "single chunk content"

    def test_does_not_call_load_data(self) -> None:
        """Single chunk → load_data() must NOT be called."""
        chunks = [_make_chunk(0, 1)]
        container = _make_container(chunks)

        _build_revision_context(_make_state(), container, "static")

        container.load_data.assert_not_called()

    def test_calls_load_chunked_with_correct_args(self) -> None:
        chunks = [_make_chunk(0, 1)]
        container = _make_container(chunks)
        state = _make_state(file_hash="hash123")

        _build_revision_context(state, container, "dynamic")

        container.load_chunked.assert_called_once_with("hash123", "dynamic")


# ---------------------------------------------------------------------------
# Multi-chunk path
# ---------------------------------------------------------------------------


class TestMultiChunkPath:
    def test_returns_isr_summary_not_raw_data(self) -> None:
        """Multi-chunk → returns ISR summary, NOT raw data."""
        chunks = [_make_chunk(i, 3) for i in range(3)]
        container = _make_container(chunks)
        state = _make_state(
            reports={"static": "Initial analysis found T1055 process injection."},
        )

        result = _build_revision_context(state, container, "static")

        assert "Initial analysis found T1055 process injection." in result
        assert container.load_data.call_count == 0

    def test_context_header_present(self) -> None:
        """Multi-chunk result must contain the CHUNKED ANALYSIS CONTEXT header."""
        chunks = [_make_chunk(i, 3) for i in range(3)]
        container = _make_container(chunks)
        state = _make_state(reports={"static": "ISR summary text"})

        result = _build_revision_context(state, container, "static")

        assert "[CHUNKED ANALYSIS CONTEXT" in result

    def test_context_header_includes_chunk_count(self) -> None:
        chunks = [_make_chunk(i, 4) for i in range(4)]
        container = _make_container(chunks)
        state = _make_state(reports={"static": "some summary"})

        result = _build_revision_context(state, container, "static")

        assert "chunks=4" in result

    def test_context_header_includes_strategy(self) -> None:
        chunks = [_make_chunk(i, 2, strategy=ChunkStrategy.FUNCTION_BOUNDARY) for i in range(2)]
        container = _make_container(chunks)
        state = _make_state(reports={"static": "summary"})

        result = _build_revision_context(state, container, "static")

        assert "FUNCTION_BOUNDARY" in result

    def test_context_header_includes_domain(self) -> None:
        chunks = [_make_chunk(i, 2, domain="dynamic") for i in range(2)]
        container = _make_container(chunks)
        state = _make_state(reports={"dynamic": "dynamic summary"})

        result = _build_revision_context(state, container, "dynamic")

        assert "domain=dynamic" in result

    def test_prefers_revised_report_over_initial_report(self) -> None:
        """When revised_reports exist, they should be used (more up-to-date)."""
        chunks = [_make_chunk(i, 2) for i in range(2)]
        container = _make_container(chunks)
        state = _make_state(
            reports={"static": "Old initial report."},
            revised_reports={"static": "Updated revised report with new evidence."},
        )

        result = _build_revision_context(state, container, "static")

        assert "Updated revised report with new evidence." in result
        assert "Old initial report." not in result

    def test_falls_back_to_initial_report_when_no_revised(self) -> None:
        chunks = [_make_chunk(i, 2) for i in range(2)]
        container = _make_container(chunks)
        state = _make_state(
            reports={"static": "Initial report text."},
            revised_reports={},  # no revision yet
        )

        result = _build_revision_context(state, container, "static")

        assert "Initial report text." in result

    def test_falls_back_to_load_data_when_no_summary(self) -> None:
        """Multi-chunk but no summary in state → falls back to load_data()."""
        chunks = [_make_chunk(i, 3) for i in range(3)]
        container = _make_container(chunks)
        state = _make_state(reports={}, revised_reports={})  # no summary

        result = _build_revision_context(state, container, "static")

        container.load_data.assert_called_once()
        assert result == "fallback raw data"

    def test_summary_appears_after_header(self) -> None:
        """The consolidated summary section marker must precede the summary text."""
        chunks = [_make_chunk(i, 2) for i in range(2)]
        container = _make_container(chunks)
        state = _make_state(reports={"static": "My ISR summary"})

        result = _build_revision_context(state, container, "static")

        header_pos = result.find("[CHUNKED ANALYSIS CONTEXT")
        summary_pos = result.find("My ISR summary")
        assert header_pos != -1
        assert summary_pos != -1
        assert header_pos < summary_pos


# ---------------------------------------------------------------------------
# Graceful degradation
# ---------------------------------------------------------------------------


class TestGracefulDegradation:
    def test_load_chunked_exception_falls_back_to_load_data(self) -> None:
        """If load_chunked() raises, must fall back to load_data() silently."""
        container = MagicMock()
        container.load_chunked.side_effect = RuntimeError("chunker crashed")
        container.load_data.return_value = "fallback data"

        result = _build_revision_context(_make_state(), container, "static")

        assert result == "fallback data"
        container.load_data.assert_called_once()

    def test_empty_chunk_list_not_produced_by_chunker(self) -> None:
        """BinaryChunker always returns at least 1 chunk; test normal path."""
        # This is a sanity check: chunker never returns empty list.
        # A single-element result should trigger the single-chunk path.
        chunks = [_make_chunk(0, 1, content="only one")]
        container = _make_container(chunks)

        result = _build_revision_context(_make_state(), container, "static")

        assert result == "only one"

    def test_does_not_raise_on_missing_file_hash(self) -> None:
        """Missing file_hash in state → graceful handling."""
        chunks = [_make_chunk(0, 1)]
        container = _make_container(chunks)
        state = {}  # no file_hash

        # Should not raise; load_chunked will be called with ""
        result = _build_revision_context(state, container, "static")
        assert isinstance(result, str)
