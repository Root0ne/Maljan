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
from maljan.loaders.binary_chunker import (
    CHUNK_CHARS,
    SIZED_BY,
    SIZED_BY_ROOM,
    SOURCE_SEPARATOR,
    BinaryChunker,
    header_chars,
    joined_when_it_fits,
)
from tests.unit._chunking_doubles import _chunk, _room


class TestJoining:
    def test_whole_sources_beside_a_split_one_join_where_they_fit(self) -> None:
        head = _chunk("H" * 100)
        pieces = [_chunk("A" * 1_000, 0, 2), _chunk("A" * 400, 1, 2)]
        tail = [_chunk("B" * 300), _chunk("C" * 300)]

        joined = joined_when_it_fits([head, *pieces, *tail], ChunkingConfig(), _room(1_000))

        assert [c.content for c in joined] == [
            "H" * 100,
            "A" * 1_000,
            "A" * 400,
            "B" * 300 + SOURCE_SEPARATOR + "C" * 300,
        ]
        assert (joined[-1].index, joined[-1].total) == (0, 1)

    def test_whole_sources_join_while_the_next_still_fits(self) -> None:
        chunks = [_chunk("a" * 400), _chunk("b" * 400), _chunk("c" * 400)]
        joined = joined_when_it_fits(chunks, ChunkingConfig(), _room(900))
        assert [c.char_count for c in joined] == [802, 400]

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
            cut_at = room - header_chars(domain, 10 * len(text), room)
            assert before.char_count + len(SOURCE_SEPARATOR) + after.char_count > cut_at
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


def test_a_join_near_the_room_leaves_room_for_its_header_and_no_sliver() -> None:
    # 15,000 + 10,752 fit the 25,832 room together but not behind a header:
    # joined there, the last pass cut them into a full piece and a sliver loop.
    room = 25_832
    sources = []
    for size, letter in ((15_000, "a"), (10_752, "b"), (5_000, "c")):
        source = _chunk(letter * size)
        source.metadata.update({SIZED_BY: SIZED_BY_ROOM, CHUNK_CHARS: room})
        sources.append(source)

    joined = joined_when_it_fits(sources, ChunkingConfig(overlap_tokens=0), _room(room))

    assert [c.content for c in joined] == [
        "a" * 15_000,
        "b" * 10_752 + SOURCE_SEPARATOR + "c" * 5_000,
    ]
    assert all(c.char_count + len(c.to_prompt_header()) + 2 <= room for c in joined)
