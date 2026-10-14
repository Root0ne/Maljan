"""Whole sources next to each other that fit one chunk are joined, even beside a split source.

Each chunk is a full tool loop. Joining used to be all or nothing: one split
source anywhere kept every source apart. Whole sources are now joined in order
while the next still fits. The pieces of one split source are never joined:
the chunker cut them apart because together they do not fit, which this pins
over every domain's boundaries, with and without overlap.

Every value is synthetic.
"""

from __future__ import annotations

import time

import pytest

from maljan.core.config import ChunkingConfig
from maljan.loaders.binary_chunker import SOURCE_SEPARATOR, BinaryChunker, joined_when_it_fits
from tests.unit._chunking_doubles import _chunk, _room


class TestJoining:
    def test_whole_sources_beside_a_split_one_join_where_they_fit(self) -> None:
        head = _chunk("H" * 10)
        pieces = [_chunk("A" * 100, 0, 2), _chunk("A" * 40, 1, 2)]
        tail = [_chunk("B" * 30), _chunk("C" * 30)]

        joined = joined_when_it_fits([head, *pieces, *tail], ChunkingConfig(), _room(100))

        assert [c.content for c in joined] == [
            "H" * 10,
            "A" * 100,
            "A" * 40,
            "B" * 30 + SOURCE_SEPARATOR + "C" * 30,
        ]
        assert (joined[-1].index, joined[-1].total) == (0, 1)

    def test_whole_sources_join_while_the_next_still_fits(self) -> None:
        chunks = [_chunk("a" * 40), _chunk("b" * 40), _chunk("c" * 40)]
        joined = joined_when_it_fits(chunks, ChunkingConfig(), _room(90))
        assert [c.char_count for c in joined] == [82, 40]

    def test_the_head_is_joined_with_the_whole_source_after_it(self) -> None:
        chunks = [_chunk("H" * 10), _chunk("B" * 10), _chunk("A" * 100, 0, 2), _chunk("A", 1, 2)]
        joined = joined_when_it_fits(chunks, ChunkingConfig(), _room(100))
        head = "H" * 10 + SOURCE_SEPARATOR + "B" * 10
        assert [c.content for c in joined] == [head, "A" * 100, "A"]

    @pytest.mark.parametrize("domain", ["triage", "network", "static", "dynamic"])
    @pytest.mark.parametrize("room", [1_000, 7_919, 30_000])
    @pytest.mark.parametrize("overlap", [0, 200])
    def test_two_pieces_of_one_source_never_fit_one_chunk(
        self, domain: str, room: int, overlap: int
    ) -> None:
        text = "".join(f"PID: {i}\nFlow {i}:\nvoid f{i}(\n" + "z" * (i % 997) for i in range(400))
        chunks = BinaryChunker(ChunkingConfig(overlap_tokens=overlap)).chunk(
            domain, text, room=_room(room)
        )
        assert len(chunks) > 1
        for before, after in zip(chunks, chunks[1:], strict=False):
            assert before.char_count + len(SOURCE_SEPARATOR) + after.char_count > room
        assert joined_when_it_fits(chunks, ChunkingConfig(), _room(room)) is chunks

    def test_ten_times_the_sources_take_about_ten_times_as_long(self) -> None:
        def timed(count: int) -> float:
            chunks = [_chunk("s" * 50) for _ in range(count)]
            began = time.perf_counter()
            joined_when_it_fits(chunks, ChunkingConfig(), lambda text: len(text) // 7 + 60)
            return time.perf_counter() - began

        timed(2_000)
        small = min(timed(2_000) for _ in range(3))
        large = min(timed(20_000) for _ in range(3))
        assert large < small * 20
