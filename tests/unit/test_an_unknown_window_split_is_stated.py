"""With no context window learned an analyst's input is still split, and the run says so.

The split is at the size the platform shipped with, as before. Every chunk says
what sized it; an input that size split is a row in the run summary
(``truncation.input_split_unknown_window``), a sentence under Bounds Hit and a
log line, each with the remedy. A window or an operator's figure that sized it,
or an input that was not split, says nothing.

Every value is synthetic.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import pytest

from maljan.analysis.run_summary import RunSummaryBuilder, unknown_window_split_sentence
from maljan.core.config import ChunkingConfig
from maljan.core.container import unknown_window_split_line
from maljan.core.truncation_ledger import TruncationLedger
from maljan.llm.context_window import unknown_window_remedy
from maljan.loaders.binary_chunker import (
    CHUNK_CHARS,
    SHIPPED_CHUNK_CHARS,
    SIZED_BY,
    SIZED_BY_OPERATOR,
    SIZED_BY_ROOM,
    SIZED_BY_UNKNOWN_WINDOW,
    BinaryChunker,
    head_room,
)
from tests.unit._chunking_doubles import _container, _room, _rows


class TestEveryChunkSaysWhatSizedIt:
    @pytest.mark.parametrize(
        ("config", "room", "sized_by", "chars"),
        [
            (ChunkingConfig(max_tokens_per_chunk=100), _room(10), SIZED_BY_OPERATOR, 400),
            (ChunkingConfig(), _room(300), SIZED_BY_ROOM, 300),
            (ChunkingConfig(), _room(None), SIZED_BY_UNKNOWN_WINDOW, SHIPPED_CHUNK_CHARS),
            (ChunkingConfig(), None, SIZED_BY_UNKNOWN_WINDOW, SHIPPED_CHUNK_CHARS),
        ],
    )
    def test_the_size_and_its_source(
        self, config: ChunkingConfig, room: Any, sized_by: str, chars: int
    ) -> None:
        for chunk in BinaryChunker(config).chunk("triage", "x" * 1_000, room=room):
            assert chunk.metadata[SIZED_BY] == sized_by
            assert chunk.metadata[CHUNK_CHARS] == chars


REMEDY = unknown_window_remedy()


class TestAnUnknownWindowSplitIsStated:
    def test_a_split_at_the_shipped_size_is_a_row_with_the_remedy(self) -> None:
        container = _container(network="n" * 200_000)

        chunks = container.load_data_for_agent(
            "network", file_hash="abc", sandbox_report={"network": {}}, room=_room(None)
        )

        assert [c.char_count for c in chunks] == [80_000, 80_000, 40_000]
        assert _rows(container) == [
            {"agent": "network", "chunks": 3, "chunk_chars": 80_000, "remedy": REMEDY}
        ]

    def test_the_log_line_names_the_agent_the_split_and_the_remedy(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        container = _container(network="n" * 200_000)
        with caplog.at_level(logging.WARNING, logger="maljan"):
            container.load_data_for_agent(
                "network", file_hash="abc", sandbox_report={"network": {}}, room=_room(None)
            )
            container.load_data_for_agent(
                "network", file_hash="abc", sandbox_report={"network": {}}, room=_room(None)
            )
        line = unknown_window_split_line("network", 3, SHIPPED_CHUNK_CHARS, REMEDY)
        assert [r.getMessage() for r in caplog.records if "shipped" in r.getMessage()] == [line]
        assert "no context window was learned" in line and REMEDY in line

    def test_two_whole_sources_the_shipped_size_does_not_hold_together_are_a_row(self) -> None:
        container = _container(role="generic", sample="s" * 50_000)

        chunks = container.load_data_for_agent(
            "agent", file_hash="abc", sandbox_report={"rows": ["r" * 50_000]}, room=_room(None)
        )

        assert len(chunks) == 2
        assert [row["chunks"] for row in _rows(container)] == [2]

    @pytest.mark.parametrize(
        ("config", "room", "text"),
        [
            (ChunkingConfig(overlap_tokens=0), _room(100_000), "n" * 200_000),
            (ChunkingConfig(overlap_tokens=0, max_tokens_per_chunk=20_000), None, "n" * 200_000),
            (ChunkingConfig(overlap_tokens=0), _room(None), "n" * 70_000),
        ],
    )
    def test_no_row_where_a_window_or_a_figure_sized_it_or_nothing_was_split(
        self, config: ChunkingConfig, room: Any, text: str
    ) -> None:
        container = _container(network=text, config=config)
        container.load_data_for_agent(
            "network", file_hash="abc", sandbox_report={"network": {}}, room=room
        )
        assert _rows(container) == []

    def test_a_later_split_into_more_chunks_replaces_the_row(self) -> None:
        ledger = TruncationLedger()
        row = {"agent": "a", "chunk_chars": 1, "remedy": "r"}
        assert ledger.record_unknown_window_split(chunks=2, **row)
        assert not ledger.record_unknown_window_split(chunks=2, **row)
        assert ledger.record_unknown_window_split(chunks=3, **row)
        assert [row["chunks"] for row in ledger.snapshot()["input_split_unknown_window"]] == [3]


class TestTheRunSummaryRow:
    def _summary(self, rows: list[dict[str, Any]]) -> Any:
        snapshot = TruncationLedger().snapshot()
        snapshot.update(tool_output_calls=1, input_split_unknown_window=rows)
        return RunSummaryBuilder(time.time()).set_truncation(snapshot).build()

    def test_the_row_is_in_the_summary_and_its_sentence(self) -> None:
        rows = [
            {"agent": "triage", "chunks": 2, "chunk_chars": 80_000, "remedy": REMEDY},
            {"agent": "network", "chunks": 3, "chunk_chars": 80_000, "remedy": REMEDY},
        ]
        summary = self._summary(rows)

        assert summary.to_dict()["truncation"]["input_split_unknown_window"] == rows
        sentence = (
            "No context window was learned, so the input of triage (2 chunks) and network "
            "(3 chunks) was split at the shipped 80,000 characters rather than at the room "
            f"a window leaves. To size chunks from the window, {REMEDY}."
        )
        assert unknown_window_split_sentence(summary.truncation) == sentence
        assert sentence in summary.to_markdown()

    def test_no_row_no_sentence(self) -> None:
        summary = self._summary([])
        assert summary.to_dict()["truncation"]["input_split_unknown_window"] == []
        assert unknown_window_split_sentence(summary.truncation) == ""
        assert "No context window was learned" not in summary.to_markdown()


class TestTheSplitIsStatedOnceAndCountedAsTheNodeSendsIt:
    def test_one_line_per_agent_where_an_inner_load_split_first(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # The generic role's static context is a load of its own inside the
        # agent's load: only the outermost states the split, with the whole count.
        container = _container(role="generic", sample="s" * 200_000)
        with caplog.at_level(logging.WARNING, logger="maljan"):
            chunks = container.load_data_for_agent(
                "agent", file_hash="abc", sandbox_report={"rows": ["r" * 150_000]}, room=_room(None)
            )
        lines = [r.getMessage() for r in caplog.records if "shipped" in r.getMessage()]
        assert len(lines) == 1
        assert [row["chunks"] for row in _rows(container)] == [len(chunks)]
        assert f"into {len(chunks)} chunks" in lines[0]

    def test_the_head_addition_is_counted_before_the_join(self) -> None:
        # Together the two sources fit the shipped size; with the block the node
        # puts in front of the first they do not, and the node runs two loops.
        container = _container(network="n" * 29_000, sources=["sandbox.target", "sandbox.network"])
        report = {"target": {"x": "a" * 50_000}, "network": {}}
        container.load_data_for_agent(
            "agent",
            file_hash="abc",
            sandbox_report=report,
            room=_room(None),
            head_room=head_room(_room(None), lambda _text: 5_000),
        )
        assert [row["chunks"] for row in _rows(container)] == [2]

    def test_without_the_addition_the_same_sources_are_one_loop_and_no_row(self) -> None:
        container = _container(network="n" * 29_000, sources=["sandbox.target", "sandbox.network"])
        report = {"target": {"x": "a" * 50_000}, "network": {}}
        container.load_data_for_agent(
            "agent", file_hash="abc", sandbox_report=report, room=_room(None)
        )
        assert _rows(container) == []
