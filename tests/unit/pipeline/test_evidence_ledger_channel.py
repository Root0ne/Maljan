"""One tool call, one ledger row, on the channel exactly once.

``evidence_ledger`` is append-only, and every node that touches it drains the
agent it read from rather than reading it. Both halves of the alternative are
wrong and both were shipped: a node that reads without clearing re-emits the
previous round's calls (a built-in analyst revises without tools, so its buffer
still held the analysis round), and a loop that clears on entry throws away
every chunk but the last while the earlier ones have already consumed ids.

What these tests pin is the outcome a reader of ``/jobs/{id}/evidence`` sees:
the ids the run issued, each once, in order, with no holes.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
from maljan.pipeline.nodes import make_analyst_node, make_judge_node, make_revision_node
from maljan.schemas.evidence import EvidenceCounter
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


@dataclass
class _Chunk:
    content: str
    index: int = 0
    total: int = 1

    def to_prompt_header(self) -> str:
        return f"[chunk {self.index + 1}/{self.total}]"


def _tool(name: str = "probe"):
    from langchain_core.tools import StructuredTool

    def probe() -> str:
        """Probe."""
        return "ok"

    return StructuredTool.from_function(func=probe, name=name)


class _Analyst(BaseAnalyst):
    """An analyst whose analysis makes one tool call per chunk and revises tool-free.

    That is the built-in analysts' shape exactly: ``analyze_isr`` runs the tool
    loop, ``revise_isr`` is a single LLM call with no tools.
    """

    def __init__(self, name: str, counter: EvidenceCounter) -> None:
        super().__init__(llm=MagicMock(), name=name)
        self.evidence_counter = counter
        self.calls_made = 0
        # What the container's resolution would have attached; the analyst
        # node reads the provider id off it before it pins the sample path.
        self._resolved = MagicMock(static_provider_id="none", prompt="system")

    def _run_one_loop(self) -> None:
        recorder = EvidenceRecorder(self.name, counter=self.evidence_counter)
        record_tools([_tool()], recorder)[0].invoke({})
        self.calls_made += 1
        self._finish_evidence(recorder)

    def _isr(self) -> AgentISR:
        return AgentISR(
            agent_id=self.name,
            domain=self.name,
            claims=[ClaimEvidence(claim="c", evidence_ref="ev", confidence=0.6)],
        )

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(  # pragma: no cover - unused
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        return ""

    def safe_analyze_isr(self, data: str) -> AgentISR:
        self._run_one_loop()
        return self._isr()

    def safe_analyze_isr_chunked(self, chunks: list) -> AgentISR:
        for _ in chunks:
            self._run_one_loop()
        return self._isr()

    def safe_revise_isr(self, *args: Any, **kwargs: Any) -> tuple[str, AgentISR]:
        # Tool-free, like every built-in analyst's revision.
        return f"{self.name} revised", self._isr()


def _container(agents: dict[str, _Analyst], chunks: dict[str, list[_Chunk]]) -> MagicMock:
    container = MagicMock()
    container.is_mock = False
    container.event_sink = None
    container.agent_registry.list_agents.return_value = list(agents)
    container.analyst_keys.return_value = list(agents)
    container.agent_role.side_effect = lambda n: n
    container.config.llm.parallel_analysts = False
    # Real numbers, not MagicMocks: the static branch reads these to decide
    # whether to narrow the chunk list with the function-level retrieval, and
    # a mock that ints to 1 turns it on for every test in this file.
    container.config.preprocessing.static_function_rag_top_k = 0
    container.config.preprocessing.static_function_rag_min_chunks = 6
    container.get_agent.side_effect = lambda n: agents[n]
    container.load_chunked.side_effect = lambda _h, n: chunks[n]
    container.load_data.side_effect = lambda _h, n: chunks[n][0].content
    return container


def _analysis_state() -> dict[str, Any]:
    return {"file_hash": "a" * 64, "iteration_count": 0, "reports": {}, "isr_reports": {}}


def _revision_state() -> dict[str, Any]:
    return {
        "file_hash": "a" * 64,
        "iteration_count": 1,
        "discussion_history": [],
        "reports": {"static": "PE32 with VirtualAllocEx and CreateRemoteThread."},
        "isr_reports": {},
    }


def _ids(update: dict[str, Any]) -> list[str]:
    return [row["id"] for row in update.get("evidence_ledger") or []]


class TestTheAnalystNode:
    def test_one_chunk_returns_its_call(self) -> None:
        counter = EvidenceCounter()
        agents = {"static": _Analyst("static", counter)}
        container = _container(agents, {"static": [_Chunk("PE32 executable, 9 sections.")]})

        update = make_analyst_node("static", container)(_analysis_state())

        assert _ids(update) == ["ev_0001"]
        assert [row["tool_name"] for row in update["tool_evidence"]["static"]] == ["probe"]

    def test_a_multi_chunk_analysis_returns_every_chunk_s_calls(self) -> None:
        # The loop runs once per chunk and the node reads once at the end, so
        # anything the earlier chunks recorded has to survive until then.
        counter = EvidenceCounter()
        agents = {"static": _Analyst("static", counter)}
        chunks = [_Chunk(f"chunk {i}", index=i, total=3) for i in range(3)]
        container = _container(agents, {"static": chunks})

        update = make_analyst_node("static", container)(_analysis_state())

        assert agents["static"].calls_made == 3
        assert _ids(update) == ["ev_0001", "ev_0002", "ev_0003"]

    def test_the_node_leaves_the_agent_empty(self) -> None:
        counter = EvidenceCounter()
        agents = {"static": _Analyst("static", counter)}
        container = _container(agents, {"static": [_Chunk("PE32 executable.")]})

        make_analyst_node("static", container)(_analysis_state())

        assert agents["static"].drain_evidence_entries() == []


class TestTheRevisionNode:
    def test_a_tool_free_revision_appends_nothing(self) -> None:
        # The regression this file exists for: the agent is cached, its buffer
        # still held the analysis round, and reading it re-emitted every entry
        # onto an append-only channel.
        counter = EvidenceCounter()
        agents = {"static": _Analyst("static", counter)}
        chunks = {"static": [_Chunk("PE32 executable, 9 sections.")]}
        container = _container(agents, chunks)

        analysis = make_analyst_node("static", container)(_analysis_state())
        revision = asyncio.run(make_revision_node(container)(_revision_state()))

        assert _ids(analysis) == ["ev_0001"]
        assert "evidence_ledger" not in revision

    def test_a_revision_that_did_call_a_tool_returns_only_its_own_calls(self) -> None:
        counter = EvidenceCounter()
        agent = _Analyst("static", counter)
        agents = {"static": agent}
        chunks = {"static": [_Chunk("PE32 executable, 9 sections.")]}
        container = _container(agents, chunks)

        make_analyst_node("static", container)(_analysis_state())
        # A composed agent's revision does run the loop.
        agent.safe_revise_isr = lambda *a, **k: (  # type: ignore[method-assign]
            agent._run_one_loop() or ("revised", agent._isr())
        )
        revision = asyncio.run(make_revision_node(container)(_revision_state()))

        assert _ids(revision) == ["ev_0002"]


class TestTheJudgeNode:
    def _judge_with_two_rounds(self, counter: EvidenceCounter) -> Any:
        from maljan.agents.judge_agent import JudgeAgent

        judge = JudgeAgent(llm=MagicMock())
        judge.evidence_counter = counter
        for _ in range(2):
            recorder = EvidenceRecorder("judge", counter=counter)
            record_tools([_tool("reputation")], recorder)[0].invoke({})
            judge._evidence_entries.extend(recorder.entries)
        return judge

    def test_both_mediation_rounds_reach_the_channel(self) -> None:
        # ``mediate`` runs the loop once per negotiation round; a buffer the
        # node replaced each time would persist only the last round's calls
        # while the earlier ones had already consumed ids.
        counter = EvidenceCounter()
        judge = self._judge_with_two_rounds(counter)
        # The verdict itself is not under test. Losing it takes the node's own
        # error path, which must still hand over what the judge already spent.
        judge.give_verdict = AsyncMock(side_effect=RuntimeError("verdict lost"))

        container = MagicMock()
        container.is_mock = False
        container.event_sink = None
        container.analyst_keys.return_value = ["static"]
        container.get_judge_agent.return_value = judge

        update = asyncio.run(make_judge_node(container)({"iteration_count": 1}))

        assert update["degraded_mode"] is True
        assert _ids(update) == ["ev_0001", "ev_0002"]
        assert judge.drain_evidence_entries() == []

    def test_a_judge_that_called_nothing_returns_an_empty_list(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        judge = JudgeAgent(llm=MagicMock())
        judge.give_verdict = AsyncMock(side_effect=RuntimeError("verdict lost"))

        container = MagicMock()
        container.is_mock = False
        container.event_sink = None
        container.analyst_keys.return_value = ["static"]
        container.get_judge_agent.return_value = judge

        update = asyncio.run(make_judge_node(container)({"iteration_count": 1}))

        assert update["evidence_ledger"] == []


class TestOneSequenceAcrossTheRun:
    def test_analysis_then_revision_leaves_no_gaps_and_no_duplicates(self) -> None:
        # The default profile: three analysts, each analysing then revising
        # tool-free. What the worker persists is the concatenation of every
        # node's update, and it has to read as one sequence.
        counter = EvidenceCounter()
        names = ["static", "dynamic", "network"]
        agents = {name: _Analyst(name, counter) for name in names}
        chunks = {name: [_Chunk(f"{name} data for the sample.")] for name in names}
        container = _container(agents, chunks)

        persisted: list[str] = []
        for name in names:
            persisted += _ids(make_analyst_node(name, container)(_analysis_state()))
        persisted += _ids(asyncio.run(make_revision_node(container)(_revision_state())))

        assert persisted == ["ev_0001", "ev_0002", "ev_0003"]
        assert len(persisted) == len(set(persisted))
        assert counter.issued == len(persisted)
