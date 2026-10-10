"""An analyst's input is cut into chunks at the room its own window leaves, not at a fixed figure.

``chunking.max_tokens_per_chunk`` was 20,000 tokens for every model, a size
written for a 128K local server. A chunk now takes what the analyst's prompt
has room for — the window's room before the reply, less the system prompt, the
pack, the run state, the tool definitions and the share one tool answer is
sized from (``BaseAnalyst._input_room_chars``, the bound an input is already
shortened at). An operator's number still wins. An input whose sources fit that
room together is one chunk, so the analyst runs one loop over all of it; one
that does not is chunked as before, at the larger size.

A sandbox slice is model input only, so it is sent as compact JSON: the same
document, without the indentation.
"""

from __future__ import annotations

import json
from types import MethodType
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from maljan.agents.base_agent import BaseAnalyst
from maljan.core.config import ChunkingConfig, Settings
from maljan.core.container import ServiceContainer
from maljan.llm import context_window as cw
from maljan.llm.context_window import UNKNOWN_WINDOW_CHUNK_TOKENS, _load_table
from maljan.loaders.binary_chunker import (
    _CHARS_PER_TOKEN,
    BinaryChunker,
    ChunkStrategy,
    TextChunk,
    joined_when_it_fits,
)
from maljan.pipeline.nodes import make_stage_agent_node
from tests.stages import ANALYSIS_STAGE, paper_profile


def _derived(**over: Any) -> BinaryChunker:
    """A chunker with no operator figure: the size comes from the room it is handed."""
    return BinaryChunker(ChunkingConfig(**over))


def _room(chars: int | None) -> Any:
    return lambda _text: chars


def _chunk(content: str, index: int = 0, total: int = 1) -> TextChunk:
    return TextChunk(
        index=index,
        total=total,
        strategy=ChunkStrategy.SLIDING_WINDOW,
        content=content,
        char_count=len(content),
        token_estimate=len(content) // _CHARS_PER_TOKEN,
        domain="triage",
    )


class TestTheSettingIsAnOverride:
    def test_unset_is_the_default(self) -> None:
        assert ChunkingConfig().max_tokens_per_chunk is None
        assert Settings(_env_file=None).chunking.max_tokens_per_chunk is None

    def test_an_operator_figure_wins_over_the_room(self) -> None:
        chunker = BinaryChunker(ChunkingConfig(max_tokens_per_chunk=100, overlap_tokens=0))
        chunks = chunker.chunk("triage", "A" * 1000, room=_room(1_000_000))
        assert len(chunks) == 3
        assert all(c.char_count <= 100 * _CHARS_PER_TOKEN for c in chunks)


class TestTheChunkIsTheRoom:
    def test_an_input_inside_the_room_is_one_chunk_and_whole(self) -> None:
        text = "B" * 150_000
        (only,) = _derived().chunk("triage", text, room=_room(150_000))
        assert only.content == text

    def test_an_input_over_the_room_is_cut_at_the_room(self) -> None:
        text = "C" * 250_000
        chunks = _derived(overlap_tokens=0).chunk("triage", text, room=_room(100_000))
        assert [c.char_count for c in chunks] == [100_000, 100_000, 50_000]
        assert "".join(c.content for c in chunks) == text

    def test_the_room_is_asked_about_the_text_it_sizes(self) -> None:
        seen: list[str] = []
        _derived().chunk("triage", "D" * 10, room=lambda text: seen.append(text) or 100)
        assert seen == ["D" * 10]

    def test_with_no_window_learned_the_shipped_size_splits(self) -> None:
        text = "E" * 200_000
        shipped = UNKNOWN_WINDOW_CHUNK_TOKENS * _CHARS_PER_TOKEN
        for room in (_room(None), None):
            chunks = _derived(overlap_tokens=0).chunk("triage", text, room=room)
            assert [c.char_count for c in chunks] == [shipped, shipped, 200_000 - 2 * shipped]

    def test_with_no_room_at_all_the_input_is_one_chunk(self) -> None:
        text = "F" * 5_000
        (only,) = _derived().chunk("triage", text, room=_room(0))
        assert only.content == text


class TestSourcesThatFitTogetherAreOneChunk:
    def test_two_sources_inside_the_room_join_in_order(self) -> None:
        head, sandbox = _chunk('{"sha256": "ab"}'), _chunk('{"processes":[]}')
        (only,) = joined_when_it_fits([head, sandbox], ChunkingConfig(), _room(1_000))
        assert only.content == '{"sha256": "ab"}\n\n{"processes":[]}'
        assert (only.index, only.total, only.char_count) == (0, 1, len(only.content))

    def test_sources_over_the_room_stay_as_they_were(self) -> None:
        chunks = [_chunk("G" * 60), _chunk("H" * 60)]
        assert joined_when_it_fits(chunks, ChunkingConfig(), _room(100)) is chunks

    def test_the_room_is_asked_about_the_joined_text(self) -> None:
        seen: list[str] = []
        joined_when_it_fits(
            [_chunk("a"), _chunk("b")], ChunkingConfig(), lambda t: seen.append(t) or 10
        )
        assert seen == ["a\n\nb"]

    def test_an_operator_figure_is_the_bound(self) -> None:
        chunks = [_chunk("I" * 60), _chunk("J" * 60)]
        config = ChunkingConfig(max_tokens_per_chunk=25)
        assert joined_when_it_fits(chunks, config, _room(10_000)) is chunks
        config = ChunkingConfig(max_tokens_per_chunk=40)
        assert len(joined_when_it_fits(chunks, config, _room(10))) == 1

    def test_forced_chunking_never_joins(self) -> None:
        chunks = [_chunk("a"), _chunk("b")]
        config = ChunkingConfig(skip_if_fits=False)
        assert joined_when_it_fits(chunks, config, _room(1_000)) is chunks

    def test_one_chunk_is_returned_untouched(self) -> None:
        chunks = [_chunk("only")]
        assert joined_when_it_fits(chunks, ChunkingConfig(), _room(1)) is chunks

    def test_with_no_window_learned_sources_join_only_within_the_shipped_size(self) -> None:
        shipped = UNKNOWN_WINDOW_CHUNK_TOKENS * _CHARS_PER_TOKEN
        small = [_chunk("K" * 100), _chunk("L" * 100)]
        assert len(joined_when_it_fits(small, ChunkingConfig(), _room(None))) == 1
        large = [_chunk("K" * (shipped // 2)), _chunk("L" * (shipped // 2))]
        assert joined_when_it_fits(large, ChunkingConfig(), _room(None)) is large


# ---------------------------------------------------------------------------
# The node: one loop when the whole input fits, chunks of the room when not
# ---------------------------------------------------------------------------


def _isr() -> MagicMock:
    return MagicMock(claims=[], dissent_items=[], unparsed_answer="", to_text_summary=lambda: "")


def _agent(room: int | None) -> MagicMock:
    agent = MagicMock()
    agent._resolved.static_provider_id = "ghidra"
    agent._input_room_chars.side_effect = lambda _text: room
    agent.safe_analyze_isr.return_value = _isr()
    agent.safe_analyze_isr_chunked.return_value = _isr()
    agent.get_last_tool_evidence.return_value = []
    agent.ended_out_of_room = False
    return agent


def _container(agent: MagicMock, *, role: str, settings: Settings | None = None) -> MagicMock:
    """A double whose data loading is the container's own code over a real chunker."""
    config = settings or Settings(_env_file=None)
    chunker = BinaryChunker(config.chunking)
    container = MagicMock()
    container.is_mock = False
    container.event_sink = lambda *_a, **_k: None
    container.get_agent.return_value = agent
    container.agent_role.return_value = role
    container.config.chunking = config.chunking
    container.config.agents.definitions = {}
    container.config.llm.view_decomposition_views = 0
    container.loader.chunk_text.side_effect = lambda name, text, room=None: chunker.chunk(
        name, text, room=room
    )
    container.load_chunked.side_effect = lambda _h, name, room=None: chunker.chunk(
        name, f"No {name} data available for sample abc123.", room=room
    )
    container.parser_registry.create.side_effect = KeyError("no parser in this double")
    for name in (
        "load_data_for_agent",
        "_data_source_chunks",
        "_sandbox_slice",
        "_legacy_role_data",
    ):
        setattr(container, name, MethodType(getattr(ServiceContainer, name), container))
    container.active_profile.return_value = paper_profile([role])
    return container


def _state(**over: Any) -> dict[str, Any]:
    state: dict[str, Any] = {"file_hash": "abc123", "static_sample_path": "/work/abc123.exe"}
    state.update(over)
    return state


REPORT = {"target": {"sha256": "abc123"}, "signatures": [{"name": "loader_signature", "score": 10}]}


class TestTheNode:
    def test_a_generic_agent_whose_sources_fit_runs_one_loop_over_both(self) -> None:
        agent = _agent(room=1_000_000)
        node = make_stage_agent_node(ANALYSIS_STAGE, "triage", _container(agent, role="generic"))

        node(_state(sandbox_report=REPORT))

        agent.safe_analyze_isr_chunked.assert_not_called()
        (shown,) = agent.safe_analyze_isr.call_args[0]
        head, sandbox = shown.split("\n\n", 1)
        assert json.loads(head)["analysis_file_path"] == "/work/abc123.exe"
        assert sandbox == json.dumps(REPORT, separators=(",", ":"), default=str)

    def test_a_single_source_prompt_is_the_text_the_loader_made(self) -> None:
        agent = _agent(room=1_000_000)
        container = _container(agent, role="network")
        parsed = "## Network\n- 203.0.113.9:443 (TLS)\n" * 4_000
        container.parser_registry.create.side_effect = None
        container.parser_registry.create.return_value.parse.return_value = parsed
        node = make_stage_agent_node(ANALYSIS_STAGE, "network", container)

        node(_state(sandbox_report={"network": {"hosts": ["203.0.113.9"]}}))

        agent.safe_analyze_isr_chunked.assert_not_called()
        (shown,) = agent.safe_analyze_isr.call_args[0]
        assert shown == parsed

    def test_sources_over_the_room_run_as_chunks_of_the_room(self) -> None:
        room = 2_000
        agent = _agent(room=room)
        report = {"target": {"sha256": "abc123"}, "rows": ["x" * 40] * 200}
        settings = Settings(_env_file=None, chunking={"overlap_tokens": 0})
        node = make_stage_agent_node(
            ANALYSIS_STAGE, "triage", _container(agent, role="generic", settings=settings)
        )

        node(_state(sandbox_report=report))

        agent.safe_analyze_isr.assert_not_called()
        (chunks,) = agent.safe_analyze_isr_chunked.call_args[0]
        assert len(chunks) > 2
        assert all(c.char_count <= room for c in chunks[1:])
        assert "".join(c.content for c in chunks[1:]) == json.dumps(
            report, separators=(",", ":"), default=str
        )

    def test_with_no_window_learned_the_node_splits_at_the_shipped_size(self) -> None:
        agent = _agent(room=None)
        container = _container(agent, role="network")
        parsed = "## Network\n- 203.0.113.9:443 (TLS)\n" * 6_000
        container.parser_registry.create.side_effect = None
        container.parser_registry.create.return_value.parse.return_value = parsed
        node = make_stage_agent_node(ANALYSIS_STAGE, "network", container)

        node(_state(sandbox_report={"network": {"hosts": ["203.0.113.9"]}}))

        agent.safe_analyze_isr.assert_not_called()
        (chunks,) = agent.safe_analyze_isr_chunked.call_args[0]
        assert len(chunks) == 3
        assert all(c.char_count <= UNKNOWN_WINDOW_CHUNK_TOKENS * _CHARS_PER_TOKEN for c in chunks)

    def test_an_operator_figure_decides_the_split(self) -> None:
        agent = _agent(room=1_000_000)
        settings = Settings(_env_file=None, chunking={"max_tokens_per_chunk": 50})
        node = make_stage_agent_node(
            ANALYSIS_STAGE, "triage", _container(agent, role="generic", settings=settings)
        )

        node(_state(sandbox_report=REPORT))

        agent.safe_analyze_isr.assert_not_called()
        agent.safe_analyze_isr_chunked.assert_called_once()


# ---------------------------------------------------------------------------
# A small window: the room never exceeds what the model can hold
# ---------------------------------------------------------------------------


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - not exercised
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        return ""


# The windows the repository knows: every row of the vendored table, and the
# local llama-server deployments (64K and 128K) the benchmark runs used.
WINDOWS = sorted({*_load_table().values(), 65_536, 131_072})


@pytest.mark.parametrize("window", WINDOWS)
def test_on_every_known_window_a_chunk_fits_beside_its_prompt(window: int) -> None:
    agent = _Analyst(llm=None, name="triage")  # type: ignore[arg-type]
    budget = cw.ContextBudget(cw.WindowFact(window, cw.DECLARED, "test"))
    agent._context_budget = lambda: budget  # type: ignore[method-assign]
    agent._system_prompt = lambda *a, **k: "s" * 6_000  # type: ignore[method-assign]
    agent.facts_block = "p" * 4_000
    cfg = Settings(_env_file=None)

    with patch("maljan.agents.base_agent.get_settings", lambda: cfg):
        text = "x" * (budget.tool_budget_chars() * 2)
        room = agent._input_room_chars(text)
        chunks = BinaryChunker(cfg.chunking).chunk("triage", text, room=agent._input_room_chars)

    framing = 6_000 + 4_000
    assert room is not None
    if room == 0:
        # Nothing fits beside the prompt: one chunk, which the prompt shortens and says so.
        assert len(chunks) == 1
        return
    assert all(c.char_count <= room for c in chunks)
    assert room + framing + int(budget.tool_budget_chars() * cw.ANSWER_SHARE) <= (
        budget.tool_budget_chars()
    )


# ---------------------------------------------------------------------------
# Compact sandbox JSON
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source", ["sandbox.full", "sandbox.target", "sandbox.network", "sandbox.behavior"]
)
def test_a_sandbox_slice_is_compact_json_of_the_same_document(source: str) -> None:
    container = _container(_agent(room=None), role="generic")
    report = {"target": {"sha256": "abc123", "name": "s.exe"}, "network": {"hosts": ["a"]}}

    (chunk,) = ServiceContainer._sandbox_slice(container, "triage", source, report)

    expected = {"sandbox.target": report["target"], "sandbox.network": report["network"]}.get(
        source, report
    )
    assert json.loads(chunk.content) == expected
    assert chunk.content == json.dumps(expected, separators=(",", ":"), default=str)
