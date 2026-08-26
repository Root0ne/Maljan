"""Unit tests for the per-sample function-RAG index (findings-log §4 Item 2)."""

from __future__ import annotations

from maljan.loaders.binary_chunker import ChunkStrategy, TextChunk
from maljan.memory.function_index import (
    BEHAVIOR_QUERIES,
    FunctionIndex,
    select_relevant_chunks,
)


def _chunk(index: int, content: str, total: int = 4) -> TextChunk:
    return TextChunk(
        index=index,
        total=total,
        strategy=ChunkStrategy.FUNCTION_BOUNDARY,
        content=content,
        char_count=len(content),
        token_estimate=max(1, len(content) // 4),
        domain="static",
    )


_INJECT = "/// Function: inject\nWriteProcessMemory CreateRemoteThread VirtualAllocEx into explorer"
_PERSIST = "/// Function: persist\nRegSetValueEx CurrentVersion Run autostart registry key"
_CRYPTO = "/// Function: enc\nCryptEncrypt AES ransomware file encryption loop over directories"
_NET = "/// Function: beacon\nWinHttpConnect periodic callback to remote command and control server"


def _corpus() -> list[TextChunk]:
    return [_chunk(0, _INJECT), _chunk(1, _PERSIST), _chunk(2, _CRYPTO), _chunk(3, _NET)]


class TestFunctionIndex:
    def test_from_chunks_builds_one_entry_per_chunk(self) -> None:
        idx = FunctionIndex.from_chunks(_corpus())
        assert len(idx) == 4

    def test_empty_corpus(self) -> None:
        idx = FunctionIndex.from_chunks([])
        assert len(idx) == 0
        assert idx.search("anything") == []

    def test_search_returns_subset_sorted_desc(self) -> None:
        idx = FunctionIndex.from_chunks(_corpus())
        results = idx.search("process injection", top_k=2)
        assert len(results) <= 2
        assert all(isinstance(c, TextChunk) for c, _ in results)
        scores = [s for _, s in results]
        assert scores == sorted(scores, reverse=True)

    def test_query_equal_to_chunk_ranks_that_chunk_first(self) -> None:
        # A query identical to a chunk's content yields the highest similarity
        # for that chunk (holds for both fastembed and the BoW fallback).
        corpus = _corpus()
        idx = FunctionIndex.from_chunks(corpus)
        top = idx.search(_CRYPTO, top_k=1)
        assert top
        assert top[0][0].index == 2

    def test_empty_query_returns_nothing(self) -> None:
        idx = FunctionIndex.from_chunks(_corpus())
        assert idx.search("   ") == []


class TestSelectForQueries:
    def test_union_dedups_and_preserves_order(self) -> None:
        idx = FunctionIndex.from_chunks(_corpus())
        selected = idx.select_for_queries(BEHAVIOR_QUERIES, top_k_per_query=1)
        indices = [c.index for c in selected]
        assert indices == sorted(set(indices))  # ordered, unique

    def test_top_k_zero_returns_empty(self) -> None:
        idx = FunctionIndex.from_chunks(_corpus())
        assert idx.select_for_queries(BEHAVIOR_QUERIES, top_k_per_query=0) == []


class TestSelectRelevantChunks:
    def test_top_k_zero_returns_all_unchanged(self) -> None:
        corpus = _corpus()
        assert select_relevant_chunks(corpus, top_k_per_query=0) is corpus

    def test_empty_chunks_returns_empty(self) -> None:
        assert select_relevant_chunks([], top_k_per_query=3) == []

    def test_selects_subset_for_large_corpus(self) -> None:
        corpus = _corpus()
        selected = select_relevant_chunks(corpus, top_k_per_query=1)
        assert 0 < len(selected) <= len(corpus)
        assert all(c in corpus for c in selected)

    def test_no_match_falls_back_to_all(self) -> None:
        # A single empty-content chunk embeds to a zero vector -> cosine 0 ->
        # nothing selected -> fall back to the full set.
        only_empty = [_chunk(0, "", total=1)]
        assert select_relevant_chunks(only_empty, top_k_per_query=3) == only_empty
