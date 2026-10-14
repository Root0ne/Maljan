"""No chunk an analyst loops over holds nothing.

A source of nothing but whitespace adds no chunk beside another source, and the
source after it is the head the node adds to; an input of nothing at all is
still the one chunk it always was. A window of the overlap and trailing
whitespace is not made.

Every value is synthetic.
"""

from __future__ import annotations

import json
import logging
import time

import pytest

from maljan.core.config import ChunkingConfig
from maljan.loaders.binary_chunker import BinaryChunker, head_room, header_chars
from tests.unit._chunking_doubles import _container, _room


class TestNoChunkHoldsNothing:
    def test_a_source_of_nothing_beside_another_adds_no_chunk(self) -> None:
        container = _container(network="", sources=["sandbox.network", "sandbox.full"])
        report = {"rows": ["r" * 40] * 5_000}

        chunks = container.load_data_for_agent(
            "agent", file_hash="abc", sandbox_report=report, room=_room(100_000)
        )

        assert len(chunks) > 1
        assert all(c.content.strip() for c in chunks)

    def test_the_source_after_one_of_nothing_is_the_head(self) -> None:
        container = _container(network="   \n", sources=["sandbox.network", "sandbox.full"])
        report = {"rows": ["r" * 40] * 5_000}
        room = _room(100_000)

        chunks = container.load_data_for_agent(
            "agent",
            file_hash="abc",
            sandbox_report=report,
            room=room,
            head_room=head_room(room, lambda _text: 30_000),
        )

        text = json.dumps(report, separators=(",", ":"))
        reserve = header_chars("agent", 10 * len(text), 100_000)
        assert chunks[0].char_count == 70_000 - reserve
        assert all(c.char_count <= 100_000 - reserve for c in chunks[1:])

    def test_an_input_of_nothing_at_all_is_still_one_chunk(self) -> None:
        container = _container(network="", sources=["sandbox.network", "sandbox.network"])
        chunks = container.load_data_for_agent(
            "agent", file_hash="abc", sandbox_report={"network": {}}, room=_room(100_000)
        )
        assert [c.content for c in chunks] == [""]

    def test_a_context_of_nothing_leaves_the_sandbox_report_as_the_head(self) -> None:
        container = _container(role="generic", sample="")
        report = {"rows": ["r" * 40] * 100}
        chunks = container.load_data_for_agent(
            "agent", file_hash="abc", sandbox_report=report, room=_room(100_000)
        )
        assert [c.content for c in chunks] == [json.dumps(report, separators=(",", ":"))]

    @pytest.mark.parametrize("overlap", [0, 200])
    def test_a_tail_of_whitespace_is_no_window(self, overlap: int) -> None:
        chunker = BinaryChunker(ChunkingConfig(overlap_tokens=overlap))
        text = "w" * 300_000 + "\n" * 50
        chunks = chunker.chunk("triage", text, room=_room(100_000))
        held = 0
        for chunk in chunks:
            start = text.find(chunk.content, max(0, held - overlap * 4))
            assert text[max(held, start) : start + chunk.char_count].strip()
            held = start + chunk.char_count
        assert held >= len(text.rstrip())

    def test_ten_times_the_text_takes_about_ten_times_as_long(self) -> None:
        chunker = BinaryChunker(ChunkingConfig())

        def timed(size: int) -> float:
            text = "w" * size + " " * size
            began = time.perf_counter()
            chunker.chunk("triage", text, room=_room(1_000))
            return time.perf_counter() - began

        timed(200_000)
        small = min(timed(200_000) for _ in range(3))
        large = min(timed(2_000_000) for _ in range(3))
        assert large < small * 20


def test_a_source_of_nothing_left_out_is_said(caplog: pytest.LogCaptureFixture) -> None:
    container = _container(network="  \n", sources=["sandbox.network", "sandbox.full"])
    with caplog.at_level(logging.DEBUG, logger="maljan"):
        container.load_data_for_agent(
            "agent", file_hash="abc", sandbox_report={"rows": [1]}, room=_room(100_000)
        )
    assert any("whitespace left out" in r.getMessage() for r in caplog.records)
