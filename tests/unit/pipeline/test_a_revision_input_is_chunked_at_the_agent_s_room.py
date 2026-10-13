"""A revision's input is chunked at the revising agent's own input room.

The revision paths (``_revision_input_is_absent`` and
``_build_revision_context``) load the agent's data with
``room=agent_input_room(container, agent_name)``, the room its first analysis
was chunked at: an input that fits it is one chunk and is revised whole, one
that does not is split at the room, and with no window learned the split is the
shipped size, never above it.

Every value is synthetic.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.core.config import ChunkingConfig
from maljan.llm.context_window import UNKNOWN_WINDOW_CHUNK_TOKENS
from maljan.loaders.binary_chunker import _CHARS_PER_TOKEN, BinaryChunker
from maljan.pipeline.nodes import _build_revision_context, _revision_input_is_absent

SHIPPED = UNKNOWN_WINDOW_CHUNK_TOKENS * _CHARS_PER_TOKEN


def _container(text: str, room: int | None, *, buildable: bool = True) -> tuple[Any, list]:
    """A container whose loads chunk ``text`` with a real chunker, recording each chunk list."""
    chunker = BinaryChunker(ChunkingConfig(overlap_tokens=0))
    made: list = []

    def chunked(_hash: str, name: str, room: Any = None) -> list:
        chunks = chunker.chunk(name, text, room=room)
        made.append(chunks)
        return chunks

    def for_agent(name: str, *, room: Any = None, **_kw: Any) -> list:
        return chunked("", name, room=room)

    agent = MagicMock()
    agent._input_room_chars.side_effect = lambda _text: room
    container = MagicMock()
    if buildable:
        container.get_agent.return_value = agent
    else:
        container.get_agent.side_effect = RuntimeError("no model")
    container.agent_role.return_value = "triage"
    container.load_chunked.side_effect = chunked
    container.load_data_for_agent.side_effect = for_agent
    return container, made


def _state(**over: Any) -> dict[str, Any]:
    return {"file_hash": "abc123", "reports": {"triage": "the first answer"}, **over}


class TestTheRevisionContext:
    def test_an_input_that_fits_the_room_is_not_split(self) -> None:
        text = "B" * 150_000
        container, made = _container(text, 200_000)

        context = _build_revision_context(_state(), container, "triage")

        assert context == text
        assert [len(chunks) for chunks in made] == [1]

    def test_an_input_over_the_room_is_split_at_the_room(self) -> None:
        container, made = _container("C" * 250_000, 100_000)

        context = _build_revision_context(_state(), container, "triage")

        assert [c.char_count for c in made[0]] == [100_000, 100_000, 50_000]
        assert "chunks=3" in context and "the first answer" in context

    @pytest.mark.parametrize("buildable", [True, False])
    def test_with_no_window_learned_the_split_is_the_shipped_size(self, buildable: bool) -> None:
        container, made = _container("E" * 200_000, None, buildable=buildable)

        _build_revision_context(_state(), container, "triage")

        assert [c.char_count for c in made[0]] == [SHIPPED, SHIPPED, 200_000 - 2 * SHIPPED]

    def test_a_room_above_the_shipped_size_keeps_an_input_it_holds_whole(self) -> None:
        container, made = _container("G" * 200_000, 3 * SHIPPED)

        _build_revision_context(_state(), container, "triage")

        assert len(made[0]) == 1


class TestTheDataCheck:
    def test_both_loads_are_given_the_agent_s_room(self) -> None:
        container, made = _container("D" * 250_000, 100_000)

        absent = _revision_input_is_absent(
            _state(sandbox_report={"triage": {"x": 1}}), container, "triage"
        )

        assert absent is False
        assert container.load_data_for_agent.call_args.kwargs["room"]("x") == 100_000
        assert [c.char_count for c in made[0]] == [100_000, 100_000, 50_000]

    def test_the_loader_path_is_given_the_agent_s_room(self) -> None:
        container, made = _container("D" * 150_000, 200_000)

        assert _revision_input_is_absent(_state(), container, "triage") is False
        assert container.load_chunked.call_args.kwargs["room"]("x") == 200_000
        assert [len(chunks) for chunks in made] == [1]
