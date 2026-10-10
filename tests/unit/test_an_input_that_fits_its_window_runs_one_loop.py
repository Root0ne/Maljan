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
import time
from pathlib import Path
from types import MethodType
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.utils.function_calling import convert_to_openai_tool

from maljan.agents.base_agent import INPUT_NOTICE_ROOM, BaseAnalyst
from maljan.core.config import ChunkingConfig, ProfileDefinition, Settings, StageDefinition
from maljan.core.container import ServiceContainer
from maljan.llm import context_window as cw
from maljan.llm.context_window import UNKNOWN_WINDOW_CHUNK_TOKENS, _load_table
from maljan.loaders.binary_chunker import (
    _CHARS_PER_TOKEN,
    SHIPPED_CHUNK_CHARS,
    BinaryChunker,
    ChunkStrategy,
    TextChunk,
    head_room,
    joined_when_it_fits,
)
from maljan.pipeline.nodes import agent_input_room, make_stage_agent_node
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

    def test_pieces_of_a_split_source_are_never_joined(self) -> None:
        chunks = [_chunk('{"a": 1,', 0, 2), _chunk(' "b": 2}', 1, 2)]
        assert joined_when_it_fits(chunks, ChunkingConfig(), _room(1_000)) is chunks

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
    # Real numbers: a mock that ints to 1 turns the static retrieval narrowing on.
    container.config.preprocessing.static_function_rag_top_k = 0
    container.config.preprocessing.static_function_rag_min_chunks = 6
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


def _no_overlap() -> Settings:
    return Settings(_env_file=None, chunking={"overlap_tokens": 0})


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

    def test_an_upstream_block_that_takes_a_full_room_chunk_past_the_room_is_split_whole(
        self,
    ) -> None:
        # The old 80,000-character split cut this input in two, losslessly. Sized
        # at the room alone it is one chunk, and the block added after sizing
        # would have taken it past the room, where the prompt shortens it.
        room = 100_000
        agent = _agent(room=room)
        container = _container(agent, role="network", settings=_no_overlap())
        parsed = "n" * 99_000
        block = "Upstream findings: " + "u" * 10_000
        container.parser_registry.create.side_effect = None
        container.parser_registry.create.return_value.parse.return_value = parsed
        node = make_stage_agent_node(ANALYSIS_STAGE, "network", container)

        with patch("maljan.pipeline.nodes.upstream_findings", lambda *_a: block):
            node(_state(sandbox_report={"network": {"hosts": ["203.0.113.9"]}}))

        agent.safe_analyze_isr.assert_not_called()
        (chunks,) = agent.safe_analyze_isr_chunked.call_args[0]
        assert all(c.char_count <= room for c in chunks)
        head = chunks[0].content
        assert head.startswith(block + "\n\n")
        assert head[len(block) + 2 :] + "".join(c.content for c in chunks[1:]) == parsed

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
# The head source's room: less what the node adds, never below the shipped size
# ---------------------------------------------------------------------------


class TestTheHeadSourceRoom:
    def test_the_head_source_is_given_the_room_less_what_is_added(self) -> None:
        room = head_room(_room(300_000), lambda _text: 20_000)
        assert room is not None and room("x") == 280_000

    def test_the_head_source_is_never_given_less_than_the_shipped_size(self) -> None:
        for added in (0, 18_800, 29_500, 29_800, 1_000_000):
            room = head_room(_room(29_800), lambda _text, n=added: n)
            assert room is not None and room("x") == SHIPPED_CHUNK_CHARS

    def test_a_room_not_measured_is_passed_on(self) -> None:
        assert head_room(None, lambda _text: 10) is None
        for chars in (None, 0):
            room = head_room(_room(chars), lambda _text: 10)
            assert room is not None and room("x") == chars

    def test_other_sources_keep_the_whole_room(self) -> None:
        room = 100_000
        agent = _agent(room=room)
        settings = _no_overlap()
        container = _container(agent, role="generic", settings=settings)
        report = {"target": {"sha256": "abc123"}, "rows": ["x" * 40] * 6_000}
        block = "Upstream findings: " + "u" * 30_000
        node = make_stage_agent_node(ANALYSIS_STAGE, "triage", container)

        with patch("maljan.pipeline.nodes.upstream_findings", lambda *_a: block):
            node(_state(sandbox_report=report))

        (chunks,) = agent.safe_analyze_isr_chunked.call_args[0]
        sandbox = json.dumps(report, separators=(",", ":"), default=str)
        assert [c.char_count for c in chunks[1:]] == [
            min(room, len(sandbox) - i) for i in range(0, len(sandbox), room)
        ]
        assert json.loads(chunks[0].content)["upstream_findings"] == block


HOSTILE_ROOM = 29_800
HOSTILE_INPUT = "".join(f"- 203.0.{i % 250}.{i % 199}:443 flow {i:07d}\n" for i in range(20_000))[
    :595_000
]


def _hostile_node(
    parsed: str, block: str | None
) -> tuple[MagicMock, Any, dict[str, Any], MagicMock]:
    """A network analyst at a 29,800-character room whose upstream block is ``block``.

    ``None`` builds the block the real way: a stage handed the whole prose of
    the stage before it, under an operator cap above the room.
    """
    agent = _agent(room=HOSTILE_ROOM)
    container = _container(agent, role="network")
    container.parser_registry.create.side_effect = None
    container.parser_registry.create.return_value.parse.return_value = parsed
    stage = ANALYSIS_STAGE
    state = _state(sandbox_report={"network": {"hosts": ["203.0.113.9"]}})
    if block is None:
        stage = StageDefinition(
            key="deep",
            kind="analysis",
            agents=["network"],
            depends_on=["triage"],
            inject_upstream="full",
        )
        container.active_profile.return_value = ProfileDefinition(
            label="test",
            stages=[
                StageDefinition(key="triage", kind="analysis", agents=["triage"]),
                stage,
                StageDefinition(
                    key="verdict", kind="verdict", agents=["judge"], depends_on=["deep"]
                ),
            ],
        )
        container.config.reporting.upstream_findings_max_chars = 2 * HOSTILE_ROOM
        state["reports"] = {"triage": "prose of the stage before " * 10_000}
    return agent, make_stage_agent_node(stage, "network", container), state, container


def _chunks_shown(agent: MagicMock) -> list[str]:
    if agent.safe_analyze_isr_chunked.call_args is not None:
        (chunks,) = agent.safe_analyze_isr_chunked.call_args[0]
        return [c.content for c in chunks]
    return [agent.safe_analyze_isr.call_args[0][0]]


class TestAnUpstreamBlockNearTheRoomNeverMultipliesTheChunks:
    """However much is added to the head, the count stays within the shipped split's."""

    DEV = len(
        BinaryChunker(ChunkingConfig(max_tokens_per_chunk=UNKNOWN_WINDOW_CHUNK_TOKENS)).chunk(
            "network", HOSTILE_INPUT
        )
    )

    @pytest.mark.parametrize("added", [0, 18_800, 29_500, 29_799, 29_800, 29_801, 60_000])
    def test_a_block_of_any_size_up_to_past_the_room(self, added: int) -> None:
        block = "U" * (added - 2) if added >= 2 else ""
        agent, node, state, _container_ = _hostile_node(HOSTILE_INPUT, block)
        with patch("maljan.pipeline.nodes.upstream_findings", lambda *_a: block):
            node(state)
        shown = _chunks_shown(agent)
        assert 1 < len(shown) <= self.DEV
        assert all(len(c) <= SHIPPED_CHUNK_CHARS for c in shown[1:])
        assert shown[0].startswith(block)

    def test_a_real_block_under_an_operator_cap_above_the_room(self) -> None:
        agent, node, state, _container_ = _hostile_node(HOSTILE_INPUT, None)
        node(state)
        shown = _chunks_shown(agent)
        assert shown[0].startswith("## Upstream findings")
        assert "[upstream findings truncated]" in shown[0]
        assert len(shown[0].split("\n\n[upstream findings truncated]")[0]) >= HOSTILE_ROOM
        assert 1 < len(shown) <= self.DEV

    def test_ten_times_the_input_takes_about_ten_times_as_long(self) -> None:
        block = "U" * HOSTILE_ROOM

        def timed(parsed: str) -> float:
            agent, node, state, _container_ = _hostile_node(parsed, block)
            with patch("maljan.pipeline.nodes.upstream_findings", lambda *_a: block):
                began = time.perf_counter()
                node(state)
                return time.perf_counter() - began

        timed(HOSTILE_INPUT)
        small = min(timed(HOSTILE_INPUT) for _ in range(2))
        large = min(timed(HOSTILE_INPUT * 10) for _ in range(2))
        # Ten times the input in at most about ten times the time (twenty, for noise).
        assert large < small * 20


# ---------------------------------------------------------------------------
# A revision path asks for the room by the agent's name
# ---------------------------------------------------------------------------


class TestARevisionChunksWhereTheFirstAnalysisDid:
    def _container(self, room: int | None) -> MagicMock:
        agent = _agent(room=room)
        container = _container(agent, role="network", settings=_no_overlap())
        container.parser_registry.create.side_effect = None
        container.parser_registry.create.return_value.parse.return_value = "r" * 250_000
        return container

    def test_the_room_by_name_is_the_agent_s_own(self) -> None:
        container = self._container(room=100_000)
        container.get_agent.reset_mock()
        room = agent_input_room(container, "network")
        assert room("anything") == 100_000
        container.get_agent.assert_called_once_with("network")

    def test_the_input_splits_as_the_first_analysis_split_it(self) -> None:
        container = self._container(room=100_000)
        report = {"network": {"hosts": ["203.0.113.9"]}}
        first = container.load_data_for_agent(
            "network", file_hash="abc123", sandbox_report=report, room=_room(100_000)
        )
        again = container.load_data_for_agent(
            "network",
            file_hash="abc123",
            sandbox_report=report,
            room=agent_input_room(container, "network"),
        )
        assert [c.content for c in again] == [c.content for c in first]
        assert [c.char_count for c in again] == [100_000, 100_000, 50_000]

    def test_an_agent_that_cannot_be_built_gives_the_unknown_window_size(self) -> None:
        container = self._container(room=100_000)
        container.get_agent.side_effect = RuntimeError("no model")
        chunks = container.loader.chunk_text(
            "network", "r" * 200_000, room=agent_input_room(container, "network")
        )
        assert all(c.char_count <= UNKNOWN_WINDOW_CHUNK_TOKENS * _CHARS_PER_TOKEN for c in chunks)
        assert len(chunks) == 3


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

# The reverser's tool definitions as its first chunk request sent them: 179
# tools of the Ghidra, analysis, knowledge and VirusTotal servers.
REVERSER_TOOLS = json.loads(
    (
        Path(__file__).parents[1] / "fixtures" / "tools" / "reverser_ghidra_tool_definitions.json"
    ).read_text(encoding="utf-8")
)
REVERSER_SYSTEM = 7_786


def _reverser(window: int) -> tuple[_Analyst, cw.ContextBudget]:
    """The reverser's framing on ``window``: its system prompt, its tools, a pack at its bound."""
    agent = _Analyst(llm=None, name="all_tools_reverser_ghidra")  # type: ignore[arg-type]
    budget = cw.ContextBudget(cw.WindowFact(window, cw.DECLARED, "test"))
    agent._context_budget = lambda: budget  # type: ignore[method-assign]
    agent._system_prompt = lambda *a, **k: "s" * REVERSER_SYSTEM  # type: ignore[method-assign]
    agent.tools = list(REVERSER_TOOLS)
    agent.facts_block = "p" * int(budget.tool_budget_chars() * cw.ANSWER_SHARE)
    return agent, budget


@pytest.mark.parametrize("window", WINDOWS)
def test_on_every_known_window_a_chunk_fits_beside_the_reverser_s_prompt(window: int) -> None:
    agent, budget = _reverser(window)
    cfg = Settings(_env_file=None, chunking={"overlap_tokens": 0})
    text = "x" * 300_000

    with patch("maljan.agents.base_agent.get_settings", lambda: cfg):
        room = agent._input_room_chars(text)
        chunks = BinaryChunker(cfg.chunking).chunk("triage", text, room=agent._input_room_chars)

    # Measured here on its own: the definitions as the provider is sent them.
    tools = sum(
        len(json.dumps(convert_to_openai_tool(t), ensure_ascii=False)) for t in REVERSER_TOOLS
    )
    assert tools > 70_000
    budget_chars = budget.tool_budget_chars()
    expected = budget_chars - REVERSER_SYSTEM - len(agent.facts_block) - tools
    expected -= int(budget_chars * cw.ANSWER_SHARE) + INPUT_NOTICE_ROOM
    assert room == max(0, expected)
    if room == 0:
        # The framing alone fills the window: one chunk, which the prompt shortens and says so.
        assert len(chunks) == 1
        return
    assert all(c.char_count <= room for c in chunks)
    assert len(chunks) == -(-len(text) // room)
    assert "".join(c.content for c in chunks) == text


def test_on_64k_the_reverser_s_room_is_below_the_old_split_and_its_input_splits_more() -> None:
    agent, _budget = _reverser(65_536)
    cfg = Settings(_env_file=None, chunking={"overlap_tokens": 0})
    text = "x" * 160_000
    with patch("maljan.agents.base_agent.get_settings", lambda: cfg):
        room = agent._input_room_chars(text)
        derived = BinaryChunker(cfg.chunking).chunk("triage", text, room=agent._input_room_chars)
    old = BinaryChunker(ChunkingConfig(max_tokens_per_chunk=20_000, overlap_tokens=0))
    assert room is not None and 0 < room < 80_000
    assert len(derived) > len(old.chunk("triage", text))


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
