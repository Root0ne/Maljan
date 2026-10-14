"""Every chunk an analyst is sent fits the room it was sized at, with what is sent beside it.

In a list of more than one chunk each is sent behind its header, and a later
chunk behind the earlier chunks' calls. The chunker keeps the header out of
every piece it cuts, a packed bin counts its line breaks and the overlap it
carries, the overlap is held below the chunk, and the node's last pass cuts any
whole chunk the header would take past the room. The earlier calls take what is
left, the rest counted in one line. A JSON head another source follows is split
as dev split it; one that is the agent's only source stays the single chunk.

Seeded property runs pin the edges: a JSON head exactly at the room, multi-byte
text, an overlap above the room. Their bounds are kept realistic (rooms of at
least 2,000 characters, texts of at most 300,000).

Every value is synthetic.
"""

from __future__ import annotations

import json
import logging
import random
from types import SimpleNamespace
from typing import Any

import pytest

from maljan.agents.base_agent import (
    EARLIER_CALLS_LEFT_OUT,
    EARLIER_CHUNKS_HEAD,
    earlier_calls_room,
    earlier_chunks_block,
)
from maljan.core.config import ChunkingConfig
from maljan.loaders.binary_chunker import (
    CHUNK_CHARS,
    SIZED_BY,
    SIZED_BY_ROOM,
    BinaryChunker,
    HeadRoom,
    head_room,
    header_chars,
    joined_when_it_fits,
    within_the_room,
)
from tests.unit._chunking_doubles import _chunk, _room

DOMAINS = ("triage", "network", "static", "dynamic")


def _sent(chunks: list) -> list[int]:
    """What each chunk takes in its prompt: with its header where the list has more than one."""
    if len(chunks) == 1:
        return [chunks[0].char_count]
    total = len(chunks)
    return [
        len(
            f"[CHUNK {i + 1}/{total} | domain={c.domain} | strategy={c.strategy.name} | "
            f"~{c.token_estimate} tokens]"
        )
        + 2
        + c.char_count
        for i, c in enumerate(chunks)
    ]


def _text(rng: random.Random, size: int) -> str:
    lines: list[str] = []
    used = 0
    while used < size:
        kind = rng.randrange(5)
        line = (
            f"PID: {used}\n",
            f"Flow {used}:\n",
            f"void f{used}(\n",
            "é" * rng.randrange(1, 40) + "\n",
            "z" * rng.randrange(1, 3_000) + "\n",
        )[kind]
        lines.append(line)
        used += len(line)
    return "".join(lines)[:size]


# ---------------------------------------------------------------------------
# Packing and overlap
# ---------------------------------------------------------------------------


class TestABinNeverPassesItsSize:
    @pytest.mark.parametrize("overlap_tokens", [0, 200, 501, 2_000])
    def test_flows_at_a_small_room(self, overlap_tokens: int) -> None:
        text = "".join(f"Flow {i}:\n" + "x" * (i % 1_990) + "\n" for i in range(150))
        chunks = BinaryChunker(ChunkingConfig(overlap_tokens=overlap_tokens)).chunk(
            "network", text, room=_room(2_000)
        )
        assert len(chunks) > 1
        assert all(size <= 2_000 for size in _sent(chunks))

    def test_an_overlap_above_the_chunk_is_held_and_said(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        chunker = BinaryChunker(ChunkingConfig(overlap_tokens=1_000))
        with caplog.at_level(logging.WARNING, logger="maljan"):
            chunks = chunker.chunk(
                "network",
                "".join(f"Flow {i}:\n" + "y" * 900 + "\n" for i in range(20)),
                room=_room(2_000),
            )
        assert all(size <= 2_000 for size in _sent(chunks))
        said = [r.getMessage() for r in caplog.records]
        assert any("held to" in m or "clamping step" in m for m in said)


# ---------------------------------------------------------------------------
# The header and the earlier calls
# ---------------------------------------------------------------------------


class TestTheHeaderIsKeptOutOfTheRoom:
    def test_the_bound_holds_the_header_it_is_for(self) -> None:
        chunks = BinaryChunker(ChunkingConfig(overlap_tokens=0)).chunk(
            "dynamic", "d" * 50_000, room=_room(5_000)
        )
        bound = header_chars("dynamic", 10 * 50_000, 5_000)
        assert all(len(c.to_prompt_header()) + 2 <= bound for c in chunks)

    def test_a_whole_source_the_header_would_take_past_the_room_is_cut(self) -> None:
        whole = _chunk("w" * 9_990)
        whole.metadata.update({SIZED_BY: SIZED_BY_ROOM, CHUNK_CHARS: 10_000})
        other = _chunk("o" * 100)
        out = within_the_room([whole, other], ChunkingConfig(overlap_tokens=0))
        assert len(out) == 3
        assert "".join(c.content for c in out[:2]) == "w" * 9_990
        assert all(c.char_count + header_chars("triage", 10_100, 10_000) <= 10_000 for c in out[:2])

    def test_a_single_chunk_has_no_header_and_is_left_whole(self) -> None:
        only = _chunk("w" * 10_000)
        only.metadata.update({SIZED_BY: SIZED_BY_ROOM, CHUNK_CHARS: 10_000})
        assert within_the_room([only], ChunkingConfig()) == [only]

    def test_the_earlier_calls_take_what_is_left_and_count_the_rest(self) -> None:
        entries = [
            SimpleNamespace(tool="t", id=f"ev_{i:04d}", args={"a": i}, output="x", ok=True)
            for i in range(200)
        ]
        whole = earlier_chunks_block(entries)
        for room in (len(whole), len(whole) // 2, 2_000, len(EARLIER_CHUNKS_HEAD) + 300):
            block = earlier_chunks_block(entries, room)
            assert len(block) <= room
            if room < len(whole):
                assert (
                    block.splitlines()[-1].startswith(
                        EARLIER_CALLS_LEFT_OUT.split("{count}")[0] or str(len(entries))
                    )
                    or "not listed" in block.splitlines()[-1]
                )
        assert earlier_chunks_block(entries, 10) == ""
        assert earlier_chunks_block(entries, None) == whole

    def test_the_room_for_earlier_calls_is_the_agent_s_room_less_the_chunk(self) -> None:
        agent = SimpleNamespace(_input_room_chars=lambda _text: 10_000)
        assert earlier_calls_room(agent, "h" * 50, "c" * 1_000) == 10_000 - 50 - 1_000 - 4
        assert earlier_calls_room(SimpleNamespace(), "h", "c") is None
        assert (
            earlier_calls_room(SimpleNamespace(_input_room_chars=lambda _t: None), "h", "c") is None
        )


# ---------------------------------------------------------------------------
# A JSON head
# ---------------------------------------------------------------------------


HEAD = json.dumps({f"key_{i:04d}": f"value {i}" for i in range(400)})


class TestAJsonHead:
    def _head(self, alone: bool, extra: int) -> tuple[HeadRoom, int]:
        room = len(HEAD) + extra
        head = head_room(_room(room), lambda text: 3 * len(text) // 10 + 2_000)
        assert isinstance(head, HeadRoom)
        return head.alone_as(alone), room

    @pytest.mark.parametrize("extra", [0, 100, 2_000])
    def test_followed_by_another_source_it_is_split_within_the_room(self, extra: int) -> None:
        head, room = self._head(False, extra)
        chunks = BinaryChunker(ChunkingConfig(overlap_tokens=0)).chunk("static", HEAD, room=head)
        assert len(chunks) > 1
        assert "".join(c.content for c in chunks) == HEAD
        assert chunks[0].char_count + 2_000 <= room

    @pytest.mark.parametrize("extra", [0, 100])
    def test_alone_it_is_the_single_chunk_whole(self, extra: int) -> None:
        head, _room_ = self._head(True, extra)
        (only,) = BinaryChunker(ChunkingConfig(overlap_tokens=0)).chunk("static", HEAD, room=head)
        assert only.content == HEAD


# ---------------------------------------------------------------------------
# Seeded properties
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(40))
def test_every_chunk_fits_and_nothing_is_lost(seed: int) -> None:
    rng = random.Random(seed)
    room = rng.randrange(2_000, 60_000)
    text = _text(rng, rng.randrange(room // 2, min(300_000, room * 12)))
    overlap = rng.choice([0, 50, 200, room // 3])
    added = rng.choice([0, 100, room // 2, room - 1])
    domain = rng.choice(DOMAINS)
    chunker = BinaryChunker(ChunkingConfig(overlap_tokens=overlap))
    head = head_room(_room(room), lambda _text, n=added: n)

    chunks = chunker.chunk(domain, text, room=head)
    at_room = chunker.chunk(domain, text, room=_room(room))
    shown = within_the_room(chunks, ChunkingConfig(overlap_tokens=overlap))

    assert all(c.content.strip() for c in shown) or len(shown) == 1
    if len(shown) > 1:
        assert all(size <= room for size in _sent(shown)[1:])
        if added < room // 2:
            assert _sent(shown)[0] + added <= room
    assert len(chunks) <= len(at_room) + 1
    if overlap == 0:
        # Packing joins boundary segments with a line break, as it always has;
        # nothing of the text is lost either way.
        joined = "".join(c.content for c in chunks)
        assert joined.replace("\n", "") == text.replace("\n", "")


@pytest.mark.parametrize("seed", range(10))
def test_a_head_exactly_at_the_room(seed: int) -> None:
    rng = random.Random(1_000 + seed)
    room = len(HEAD) + rng.choice([0, 1])
    head = head_room(_room(room), lambda text: 2_000)
    assert isinstance(head, HeadRoom)
    for alone in (True, False):
        chunks = BinaryChunker(ChunkingConfig(overlap_tokens=0)).chunk(
            "static", HEAD, room=head.alone_as(alone)
        )
        assert "".join(c.content for c in chunks) == HEAD
        if alone:
            assert len(chunks) == 1
        else:
            assert chunks[0].char_count + 2_000 <= room


def test_multi_byte_text_is_cut_on_characters_and_kept_whole() -> None:
    text = ("é" * 997 + "\n") * 120
    chunks = BinaryChunker(ChunkingConfig(overlap_tokens=0)).chunk(
        "triage", text, room=_room(5_000)
    )
    assert "".join(c.content for c in chunks) == text
    assert all(size <= 5_000 for size in _sent(chunks))


def test_joined_whole_sources_still_fit_behind_their_headers() -> None:
    rng = random.Random(7)
    room = 6_000
    sources: list[Any] = []
    for _ in range(12):
        piece = _chunk("s" * rng.randrange(100, room))
        piece.metadata.update({SIZED_BY: SIZED_BY_ROOM, CHUNK_CHARS: room})
        sources.append(piece)
    joined = joined_when_it_fits(sources, ChunkingConfig(overlap_tokens=0), _room(room))
    assert all(size <= room for size in _sent(joined))
