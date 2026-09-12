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
import threading
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
from maljan.core.container import ServiceContainer
from maljan.pipeline.nodes import (
    make_analyst_node,
    make_judge_node,
    make_negotiation_node,
    make_revision_node,
)
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

    def test_a_failed_analyst_still_hands_over_the_calls_it_made(self) -> None:
        # Twenty Ghidra calls and then a timeout is twenty calls made. Nothing
        # else would ever drain them either: a run that reaches consensus in
        # round one never revises.
        from maljan.core.exceptions import AnalystError

        counter = EvidenceCounter()
        agent = _Analyst("static", counter)
        agents = {"static": agent}
        container = _container(agents, {"static": [_Chunk("PE32 executable.")]})

        def _die(_data: str) -> AgentISR:
            agent._run_one_loop()
            raise AnalystError("ghidra died")

        agent.safe_analyze_isr = _die  # type: ignore[method-assign]

        update = make_analyst_node("static", container)(_analysis_state())

        assert update["reports"]["static"].startswith("[ERROR]")
        assert _ids(update) == ["ev_0001"]
        assert agent.drain_evidence_entries() == []

    def test_a_crashed_analyst_hands_them_over_too(self) -> None:
        counter = EvidenceCounter()
        agent = _Analyst("static", counter)
        agents = {"static": agent}
        container = _container(agents, {"static": [_Chunk("PE32 executable.")]})

        def _crash(_data: str) -> AgentISR:
            agent._run_one_loop()
            raise RuntimeError("segfault in the loader")

        agent.safe_analyze_isr = _crash  # type: ignore[method-assign]

        update = make_analyst_node("static", container)(_analysis_state())

        assert "crashed" in update["reports"]["static"]
        assert _ids(update) == ["ev_0001"]

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


class _JudgeContainer:
    """A container that caches a distinct judge per role, as the real one does.

    The two roles are the whole point: the negotiation node mediates on
    ``expert`` and the verdict runs on ``judge``, and only mediation reaches a
    tool loop. A test whose container hands the same object to both cannot see
    a node draining the wrong one, which is how the defect survived a round.
    """

    is_mock = False
    event_sink = None

    def __init__(self, counter: EvidenceCounter) -> None:
        self._lock = threading.Lock()
        self._judge_agent_cache: dict[str, Any] = {}
        self._counter = counter
        self.config = MagicMock()

    def analyst_keys(self) -> list[str]:
        return ["static"]

    def get_judge_agent(self, role: str = "judge") -> Any:
        from maljan.agents.judge_agent import JudgeAgent

        cached = self._judge_agent_cache.get(role)
        if cached is None:
            cached = JudgeAgent(llm=MagicMock())
            cached.evidence_counter = self._counter
            self._judge_agent_cache[role] = cached
        return cached

    # The real drain, borrowed rather than reimplemented, so this test fails
    # if it stops looking at every cached role.
    drain_all_judge_evidence = ServiceContainer.drain_all_judge_evidence


def _mediates_with_a_tool_call(judge: Any) -> None:
    """Make this judge's ``mediate`` record one call through the real loop.

    The recording path is ``execute_tool_loop`` itself — the same code the
    mediator runs in production — with only the executor faked, so what lands
    in the buffer is what a real mediation would leave there.
    """
    from langchain_core.messages import AIMessage

    async def _mediate(**_kwargs: Any) -> tuple[Any, bool]:
        async def _ainvoke(payload, config=None):
            for wrapped in captured[0]:
                wrapped.invoke({})
            return {"messages": [AIMessage(content="Agents agree.")]}

        captured: list = []

        def _create(llm, tools):
            captured.append(tools)
            executor = MagicMock()
            executor.ainvoke = _ainvoke
            return executor

        judge.tools = [_tool("reputation")]
        with patch("langgraph.prebuilt.create_react_agent", _create):
            await judge.execute_tool_loop([("system", "mediate"), ("human", "reports")])
        return MagicMock(agent_name="Mediator", finding="Agents agree.", confidence_score=0.8), True

    judge.mediate = _mediate


class TestTheNegotiationNode:
    def test_the_mediator_s_calls_reach_the_channel(self) -> None:
        counter = EvidenceCounter()
        container = _JudgeContainer(counter)
        mediator = container.get_judge_agent(role="expert")
        _mediates_with_a_tool_call(mediator)

        update = asyncio.run(
            make_negotiation_node(container)(
                {"iteration_count": 0, "reports": {"static": "f"}, "isr_reports": {}}
            )
        )

        assert _ids(update) == ["ev_0001"]
        # The verdict instance is a different object and has nothing to give.
        assert container.get_judge_agent(role="judge") is not mediator
        assert container.get_judge_agent(role="judge").drain_evidence_entries() == []

    def test_two_rounds_each_return_their_own_round(self) -> None:
        counter = EvidenceCounter()
        container = _JudgeContainer(counter)
        _mediates_with_a_tool_call(container.get_judge_agent(role="expert"))
        node = make_negotiation_node(container)
        state = {"iteration_count": 0, "reports": {"static": "f"}, "isr_reports": {}}

        first = asyncio.run(node(state))
        second = asyncio.run(node({**state, "iteration_count": 1}))

        assert _ids(first) == ["ev_0001"]
        assert _ids(second) == ["ev_0002"]

    def test_a_mediation_that_failed_still_hands_over_what_it_spent(self) -> None:
        counter = EvidenceCounter()
        container = _JudgeContainer(counter)
        mediator = container.get_judge_agent(role="expert")
        _mediates_with_a_tool_call(mediator)
        recorded = mediator.mediate

        async def _fail(**kwargs: Any) -> tuple[Any, bool]:
            await recorded(**kwargs)
            raise TimeoutError("mediation timed out")

        mediator.mediate = _fail

        update = asyncio.run(
            make_negotiation_node(container)(
                {"iteration_count": 0, "reports": {"static": "f"}, "isr_reports": {}}
            )
        )

        assert update["is_consensus"] is False
        assert _ids(update) == ["ev_0001"]


class TestTheJudgeNode:
    def _run(self, container: _JudgeContainer) -> dict[str, Any]:
        judge = container.get_judge_agent(role="judge")
        # The verdict itself is not under test. Losing it takes the node's own
        # error path, which must still hand over anything still buffered.
        judge.give_verdict = AsyncMock(side_effect=RuntimeError("verdict lost"))
        return asyncio.run(make_judge_node(container)({"iteration_count": 1}))

    def test_it_picks_up_a_mediation_nothing_else_drained(self) -> None:
        # Mediation is where the calls happen; if no negotiation node ran (or a
        # future verdict path grows tools), the judge node is the backstop.
        counter = EvidenceCounter()
        container = _JudgeContainer(counter)
        mediator = container.get_judge_agent(role="expert")
        for _ in range(2):
            recorder = EvidenceRecorder("judge", counter=counter)
            record_tools([_tool("reputation")], recorder)[0].invoke({})
            mediator._evidence_entries.extend(recorder.entries)

        update = self._run(container)

        assert update["degraded_mode"] is True
        assert _ids(update) == ["ev_0001", "ev_0002"]

    def test_it_re_emits_nothing_the_negotiation_node_already_returned(self) -> None:
        counter = EvidenceCounter()
        container = _JudgeContainer(counter)
        _mediates_with_a_tool_call(container.get_judge_agent(role="expert"))

        negotiation = asyncio.run(
            make_negotiation_node(container)(
                {"iteration_count": 0, "reports": {"static": "f"}, "isr_reports": {}}
            )
        )
        judged = self._run(container)

        assert _ids(negotiation) == ["ev_0001"]
        assert judged["evidence_ledger"] == []


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
