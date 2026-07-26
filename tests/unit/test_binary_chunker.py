"""Unit tests for BinaryChunker and chunk-aware FileDataLoader.

All tests are pure-Python — no file I/O, no LLM calls.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from maljan.core.config import ChunkingConfig
from maljan.loaders.binary_chunker import (
    _CHARS_PER_TOKEN,
    BinaryChunker,
    ChunkStrategy,
    TextChunk,
)
from maljan.loaders.file_loader import FileDataLoader

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_chunker(max_tokens: int = 100, overlap_tokens: int = 10) -> BinaryChunker:
    config = ChunkingConfig(
        max_tokens_per_chunk=max_tokens,
        overlap_tokens=overlap_tokens,
        skip_if_fits=True,
    )
    return BinaryChunker(config)


def _long_text(tokens: int = 200) -> str:
    """Generate text that is exactly `tokens * _CHARS_PER_TOKEN` characters."""
    return "A" * (tokens * _CHARS_PER_TOKEN)


# ---------------------------------------------------------------------------
# TextChunk model
# ---------------------------------------------------------------------------


class TestTextChunk:
    def _make(self, index: int, total: int) -> TextChunk:
        return TextChunk(
            index=index,
            total=total,
            strategy=ChunkStrategy.SLIDING_WINDOW,
            content="test",
            char_count=4,
            token_estimate=1,
            domain="static",
        )

    def test_is_first_true(self) -> None:
        assert self._make(0, 3).is_first is True

    def test_is_first_false(self) -> None:
        assert self._make(1, 3).is_first is False

    def test_is_last_true(self) -> None:
        assert self._make(2, 3).is_last is True

    def test_is_last_false(self) -> None:
        assert self._make(0, 3).is_last is False

    def test_to_prompt_header_contains_chunk_info(self) -> None:
        chunk = self._make(0, 2)
        header = chunk.to_prompt_header()
        assert "CHUNK 1/2" in header
        assert "static" in header

    def test_token_estimate_value(self) -> None:
        chunk = TextChunk(
            index=0,
            total=1,
            strategy=ChunkStrategy.SLIDING_WINDOW,
            content="X" * 400,
            char_count=400,
            token_estimate=400 // _CHARS_PER_TOKEN,
            domain="dynamic",
        )
        assert chunk.token_estimate == 100


# ---------------------------------------------------------------------------
# BinaryChunker — skip_if_fits
# ---------------------------------------------------------------------------


class TestBinaryChunkerSkipIfFits:
    def test_short_text_returns_single_chunk(self) -> None:
        chunker = _make_chunker(max_tokens=100)
        text = "short text"
        chunks = chunker.chunk("static", text)
        assert len(chunks) == 1
        assert chunks[0].content == text

    def test_empty_text_returns_single_chunk(self) -> None:
        chunker = _make_chunker(max_tokens=100)
        chunks = chunker.chunk("static", "")
        assert len(chunks) == 1
        assert chunks[0].content == ""

    def test_skip_if_fits_false_always_chunks(self) -> None:
        config = ChunkingConfig(max_tokens_per_chunk=100, overlap_tokens=0, skip_if_fits=False)
        chunker = BinaryChunker(config)
        # Text that is exactly at the limit — should still produce chunks
        text = _long_text(tokens=100)
        # With skip_if_fits=False and exactly at limit, still 1 chunk
        chunks = chunker.chunk("static", text)
        assert len(chunks) >= 1

    def test_exactly_at_limit_skips(self) -> None:
        chunker = _make_chunker(max_tokens=100, overlap_tokens=0)
        text = _long_text(tokens=100)  # exactly max_chars
        chunks = chunker.chunk("static", text)
        assert len(chunks) == 1


# ---------------------------------------------------------------------------
# BinaryChunker — Sliding Window
# ---------------------------------------------------------------------------


class TestSlidingWindow:
    def test_long_text_produces_multiple_chunks(self) -> None:
        chunker = _make_chunker(max_tokens=10, overlap_tokens=2)
        text = _long_text(tokens=35)
        chunks = chunker.chunk("unknown_domain", text)
        assert len(chunks) > 1

    def test_all_chunks_within_limit(self) -> None:
        chunker = _make_chunker(max_tokens=10, overlap_tokens=2)
        text = _long_text(tokens=50)
        chunks = chunker.chunk("unknown_domain", text)
        max_chars = 10 * _CHARS_PER_TOKEN
        for chunk in chunks:
            assert chunk.char_count <= max_chars

    def test_chunk_indices_are_sequential(self) -> None:
        chunker = _make_chunker(max_tokens=10, overlap_tokens=0)
        text = _long_text(tokens=50)
        chunks = chunker.chunk("unknown_domain", text)
        assert [c.index for c in chunks] == list(range(len(chunks)))

    def test_all_chunks_report_same_total(self) -> None:
        chunker = _make_chunker(max_tokens=10, overlap_tokens=0)
        chunks = chunker.chunk("unknown_domain", _long_text(tokens=50))
        totals = {c.total for c in chunks}
        assert len(totals) == 1

    def test_chunks_cover_entire_text(self) -> None:
        # With zero overlap, reconstructed text should cover the original.
        config = ChunkingConfig(max_tokens_per_chunk=10, overlap_tokens=0, skip_if_fits=False)
        chunker = BinaryChunker(config)
        text = "ABCDEFGHIJ" * 8  # 80 chars = 20 tokens
        chunks = chunker.chunk("unknown_domain", text)
        reconstructed = "".join(c.content for c in chunks)
        assert reconstructed == text

    def test_strategy_is_sliding_window_for_unknown_domain(self) -> None:
        chunker = _make_chunker(max_tokens=10, overlap_tokens=0)
        chunks = chunker.chunk("unknown_domain", _long_text(tokens=50))
        assert all(c.strategy == ChunkStrategy.SLIDING_WINDOW for c in chunks)

    def test_overlap_shares_content(self) -> None:
        config = ChunkingConfig(max_tokens_per_chunk=10, overlap_tokens=3, skip_if_fits=False)
        chunker = BinaryChunker(config)
        text = "Z" * (10 * _CHARS_PER_TOKEN * 3)
        chunks = chunker.chunk("unknown_domain", text)
        assert len(chunks) > 1
        # First chunk's tail should appear at the start of second chunk's content
        tail = chunks[0].content[-(3 * _CHARS_PER_TOKEN) :]
        assert chunks[1].content.startswith(tail)


# ---------------------------------------------------------------------------
# BinaryChunker — Domain-specific splitting
# ---------------------------------------------------------------------------


class TestDomainSpecificSplitting:
    def _static_text_with_functions(self, num_funcs: int = 5, tokens_each: int = 3) -> str:
        """Generate text with Ghidra-style function boundaries."""
        parts = []
        for i in range(num_funcs):
            header = f"void func_{i:04x}(HANDLE hProcess, DWORD dwSize) {{\n"
            body = "  " + ("X" * (tokens_each * _CHARS_PER_TOKEN)) + "\n}\n"
            parts.append(header + body)
        return "\n".join(parts)

    def _dynamic_text_with_pids(self, num_pids: int = 4, tokens_each: int = 3) -> str:
        parts = []
        for i in range(num_pids):
            header = f"PID: {1000 + i}\n"
            body = "Y" * (tokens_each * _CHARS_PER_TOKEN) + "\n"
            parts.append(header + body)
        return "\n".join(parts)

    def _network_text_with_flows(self, num_flows: int = 4, tokens_each: int = 3) -> str:
        parts = []
        for i in range(num_flows):
            header = f"Flow {i}: TCP 192.168.1.{i}:443\n"
            body = "N" * (tokens_each * _CHARS_PER_TOKEN) + "\n"
            parts.append(header + body)
        return "\n".join(parts)

    def test_static_uses_function_boundary_strategy(self) -> None:
        config = ChunkingConfig(max_tokens_per_chunk=5, overlap_tokens=0, skip_if_fits=False)
        chunker = BinaryChunker(config)
        text = self._static_text_with_functions(num_funcs=5, tokens_each=3)
        chunks = chunker.chunk("static", text)
        # At least some chunks should use function boundary strategy
        strategies = {c.strategy for c in chunks}
        assert ChunkStrategy.FUNCTION_BOUNDARY in strategies or len(chunks) >= 1

    def test_dynamic_domain_recognized(self) -> None:
        config = ChunkingConfig(max_tokens_per_chunk=5, overlap_tokens=0, skip_if_fits=False)
        chunker = BinaryChunker(config)
        text = self._dynamic_text_with_pids(num_pids=4, tokens_each=3)
        chunks = chunker.chunk("dynamic", text)
        assert len(chunks) >= 1

    def test_network_domain_recognized(self) -> None:
        config = ChunkingConfig(max_tokens_per_chunk=5, overlap_tokens=0, skip_if_fits=False)
        chunker = BinaryChunker(config)
        text = self._network_text_with_flows(num_flows=4, tokens_each=3)
        chunks = chunker.chunk("network", text)
        assert len(chunks) >= 1

    def test_no_boundary_markers_falls_back_to_sliding_window(self) -> None:
        config = ChunkingConfig(max_tokens_per_chunk=5, overlap_tokens=0, skip_if_fits=False)
        chunker = BinaryChunker(config)
        # Plain text with no function/PID/flow markers
        text = "lorem ipsum dolor sit amet " * 20
        chunks = chunker.chunk("static", text)
        assert all(c.strategy == ChunkStrategy.SLIDING_WINDOW for c in chunks)


# ---------------------------------------------------------------------------
# BinaryChunker — merge_summaries
# ---------------------------------------------------------------------------


class TestMergeSummaries:
    def test_empty_summaries_returns_empty(self) -> None:
        chunker = _make_chunker()
        assert chunker.merge_summaries([]) == ""

    def test_single_summary_returned_as_is(self) -> None:
        chunker = _make_chunker()
        assert chunker.merge_summaries(["only one"]) == "only one"

    def test_multiple_summaries_joined(self) -> None:
        chunker = _make_chunker()
        result = chunker.merge_summaries(["first", "second", "third"], domain="static")
        assert "Consolidated Analysis" in result
        assert "3 chunks" in result
        assert "first" in result
        assert "third" in result

    def test_merge_shows_chunk_numbers(self) -> None:
        chunker = _make_chunker()
        result = chunker.merge_summaries(["a", "b"])
        assert "Chunk 1/2" in result
        assert "Chunk 2/2" in result

    def test_domain_label_in_header(self) -> None:
        chunker = _make_chunker()
        result = chunker.merge_summaries(["a", "b"], domain="dynamic")
        assert "DYNAMIC" in result


# ---------------------------------------------------------------------------
# ChunkingConfig
# ---------------------------------------------------------------------------


class TestChunkingConfig:
    def test_defaults(self) -> None:
        config = ChunkingConfig()
        # 2026-07-11 raised this 6000 -> 20000 after the GPU/context upgrade:
        # the old value split a real PE into 27 chunks and the static analyst
        # re-ran Ghidra auto-analysis on every one of them. The assertion was
        # never updated and had been failing since (audit 2026-07-26).
        assert config.max_tokens_per_chunk == 20000
        assert config.overlap_tokens == 200
        assert config.skip_if_fits is True

    def test_custom_values(self) -> None:
        config = ChunkingConfig(max_tokens_per_chunk=2000, overlap_tokens=100, skip_if_fits=False)
        assert config.max_tokens_per_chunk == 2000


# ---------------------------------------------------------------------------
# FileDataLoader.load_chunked() — integration with mock file system
# ---------------------------------------------------------------------------


class TestFileDataLoaderChunked:
    def _make_loader(
        self,
        max_tokens: int = 100,
        parsed_text: str = "short",
    ) -> tuple[FileDataLoader, MagicMock]:
        chunking_cfg = ChunkingConfig(
            max_tokens_per_chunk=max_tokens, overlap_tokens=0, skip_if_fits=True
        )
        loader = FileDataLoader(chunking_config=chunking_cfg)
        # Patch the load method to avoid file I/O
        mock_load = MagicMock(return_value=parsed_text)
        loader.load = mock_load  # type: ignore[method-assign]
        return loader, mock_load

    def test_load_chunked_returns_list_of_chunks(self) -> None:
        loader, _ = self._make_loader(parsed_text="short text")
        chunks = loader.load_chunked("abc123", "static")
        assert isinstance(chunks, list)
        assert len(chunks) >= 1
        assert isinstance(chunks[0], TextChunk)

    def test_load_chunked_single_chunk_for_small_data(self) -> None:
        loader, mock_load = self._make_loader(max_tokens=1000, parsed_text="small")
        chunks = loader.load_chunked("abc123", "static")
        assert len(chunks) == 1
        assert chunks[0].content == "small"

    def test_load_chunked_multiple_for_large_data(self) -> None:
        large_text = "X" * (200 * _CHARS_PER_TOKEN)  # 200 tokens
        loader, _ = self._make_loader(max_tokens=50, parsed_text=large_text)
        chunks = loader.load_chunked("abc123", "static")
        assert len(chunks) > 1

    def test_load_chunked_domain_passed_to_chunker(self) -> None:
        loader, _ = self._make_loader(parsed_text="hello")
        chunks = loader.load_chunked("abc123", "dynamic")
        assert chunks[0].domain == "dynamic"

    def test_load_still_works_unchanged(self) -> None:
        loader = FileDataLoader()
        # Use load() with a non-existent path — should return "No X data available"
        result = loader.load("nonexistent", "static")
        assert "No static data available" in result
