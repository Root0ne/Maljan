"""Once a conversation has no room left, that agent's tool phase ends there.

Driven through the real loop: langgraph's own ReAct executor, the analyst's
stream over it, the evidence recorder's wrapper and the MCP toolkit's
guardrail, over a context budget that runs out part-way through. The model is
a stand-in that asks for another tool on every turn it is given, which is what
a live model did after it was told the tool phase had ended: it asked ten more
times, every call was refused without running a tool, and nothing stopped the
graph until its step limit — whose text then reached the console as the
agent's own words, and whose cap, ``steps``, was what the record kept.

The second half is that text on its own. langgraph writes "Sorry, need more
steps to process this request." into the conversation as an assistant turn
when a loop reaches its limit while still asking for tools. It is the graph's
sentence, not the agent's, and no path may hand it on as the agent's. Nor does
the platform write a sentence of its own in the agent's place: where nothing
was salvaged the agent says nothing, and the budget record and the stage event
say why.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.mcp_client import MCPLangChainToolkit
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.core.truncation_ledger import TruncationLedger
from maljan.llm import context_window as cw

# The graph's own sentence for a loop that reached its limit asking for tools.
GRAPH_STOP = "need more steps"

TASK = "look at it"

# What the framing weighs: enough that the fourth answer meets a conversation
# with no room for an answer and still room for the sentence saying so.
FRAMING = 11_300

CLAIM = (
    "CLAIM: the sample reads its own strings\nEVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: NONE"
)


class _AlwaysAsksForATool(BaseChatModel):
    """A model that asks for one more ``strings`` call on every loop turn.

    Told to stop — the salvage's directive or the final-answer nudge, both a
    human turn at the end of what it is sent — it answers with ``salvage``,
    which may be empty to stand for a salvage that produced nothing. Every call
    is kept, so a test can count the turns the loop took after the refusal.
    """

    salvage: str = CLAIM
    calls: list[list[BaseMessage]] = []

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        sent = list(messages)
        self.calls.append(sent)
        if _told_to_stop(sent):
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content=self.salvage))])
        turn = sum(1 for message in sent if isinstance(message, AIMessage))
        asked = AIMessage(
            content="Let me check the original binary's strings for any suspicious patterns.",
            tool_calls=[{"name": "strings", "args": {"offset": turn}, "id": f"call_{turn}"}],
        )
        return ChatResult(generations=[ChatGeneration(message=asked)])

    @property
    def _llm_type(self) -> str:
        return "always-asks"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


def _told_to_stop(sent: list[BaseMessage]) -> bool:
    """Whether this is the salvage or the nudge: a human turn that is not the task."""
    return isinstance(sent[-1], HumanMessage) and TASK not in str(sent[-1].content)


class _Container:
    """The two things the loop asks a job for: its budget and its event sink."""

    def __init__(self, budget: Any) -> None:
        self.budget = budget
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.config = None

    def event_sink(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append((event_type, dict(data)))

    def get_context_budget(self) -> Any:
        return self.budget

    def get_server_registry(self) -> Any:
        return None


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - not exercised
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        return ""


class _Offset(BaseModel):
    offset: int = 0


def _strings_tool(toolkit: MCPLangChainToolkit, ran: list[int]) -> Any:
    """A tool whose answer goes through the toolkit's own guardrail, off the loop."""

    async def _strings(offset: int = 0) -> str:
        ran.append(offset)
        answer = "a string the sample holds\n" * 160
        return await asyncio.to_thread(toolkit._apply_output_guardrail, answer)

    return StructuredTool.from_function(
        coroutine=_strings,
        name="strings",
        description="strings",
        args_schema=_Offset,
        infer_schema=False,
    )


@contextlib.contextmanager
def _settings(max_steps: int) -> Iterator[None]:
    with patch("maljan.agents.base_agent.get_settings") as settings:
        cfg = settings.return_value
        cfg.react_agent_timeout = 600
        cfg.react_agent_timeout_overrides = {}
        cfg.react_agent_max_steps = max_steps
        cfg.react_agent_max_steps_overrides = {}
        cfg.react_agent_tool_call_budget = 20
        cfg.llm.provider = "openai"
        cfg.llm.agents = {}
        cfg.llm.openai.context_size = 0
        cfg.reporting.evidence_budget_bytes = 0
        yield


def _run(
    budget: Any, *, max_steps: int, salvage: str = CLAIM, framing: int = FRAMING
) -> tuple[_Analyst, _AlwaysAsksForATool, _Container, list[int], TruncationLedger, str]:
    model = _AlwaysAsksForATool(salvage=salvage, calls=[])
    agent = _Analyst(llm=model, name="static")
    agent.logger = logging.getLogger("test.no_room")
    container = _Container(budget)
    agent._container = container
    ledger = TruncationLedger()
    toolkit = MCPLangChainToolkit(context_budget=budget, truncation_ledger=ledger)
    ran: list[int] = []
    agent.tools = [_strings_tool(toolkit, ran)]
    with _settings(max_steps):
        answer = agent.execute_tool_loop([("system", "s" * framing), ("human", TASK)])
    return agent, model, container, ran, ledger, answer


def _a_budget_that_runs_out() -> cw.ContextBudget:
    """An 8,192-token window with a quarter kept back for the reply.

    The tool budget is 18,432 characters; the framing and the tool's definition
    take about 11,500 of it, so the answers the guardrail hands over — 2,000
    characters each, the floor — leave no room for a fourth one, and room for
    the sentence that says so.
    """
    return cw.ContextBudget(cw.WindowFact(8192, cw.DECLARED, "test"), reply_tokens=2048)


def _loop_turns(model: _AlwaysAsksForATool) -> list[list[BaseMessage]]:
    """The model turns the loop itself took, without the salvage or the nudge."""
    return [sent for sent in model.calls if not _told_to_stop(sent)]


def _said_no_room(sent: list[BaseMessage]) -> bool:
    return any(
        isinstance(message, ToolMessage) and "no room left" in str(message.content)
        for message in sent
    )


def _agent_words(container: _Container) -> list[str]:
    return [
        str(data.get("text_delta", ""))
        for event_type, data in container.events
        if event_type == "agent_message_delta"
    ]


class TestTheToolPhaseEndsWhereTheRoomDoes:
    def test_the_loop_ends_at_the_refusal_rather_than_at_the_step_limit(self) -> None:
        agent, model, _container, ran, ledger, _answer = _run(
            _a_budget_that_runs_out(), max_steps=40
        )

        assert ledger.snapshot()["tool_output_no_room"] == 1, "the budget ran out mid-loop"
        assert len(ran) == 4, "the call that met no room ran; nothing after it did"
        told = [sent for sent in _loop_turns(model) if _said_no_room(sent)]
        assert _said_no_room(model.calls[-1]), "the model was told once, in the sentence"
        assert len(told) <= 1, f"the loop took {len(told)} more model turns after no room"
        assert len(_loop_turns(model)) <= len(ran) + 1

    def test_the_record_the_event_and_the_summary_say_no_room(self) -> None:
        agent, _model, container, _ran, _ledger, _answer = _run(
            _a_budget_that_runs_out(), max_steps=40
        )

        records = agent.drain_budget_records()
        assert [row["cap"] for row in records] == ["no_room"]
        caps = [data["cap"] for kind, data in container.events if kind == "stage_ended_at_cap"]
        assert caps == ["no_room"]
        summary = RunSummaryBuilder(0.0).set_budget({"static": records}).build()
        assert summary.budget is not None
        assert summary.budget["static"]["caps"] == ["no_room"]

    def test_the_salvage_is_written_from_what_was_gathered(self) -> None:
        _agent, model, _container, _ran, _ledger, answer = _run(
            _a_budget_that_runs_out(), max_steps=40
        )

        salvage = [sent for sent in model.calls if _told_to_stop(sent)]
        assert salvage, "the forced synthesis ran"
        gathered = [m for m in salvage[0] if isinstance(m, ToolMessage)]
        assert any("[ev_" in str(m.content) for m in gathered), "it saw what was gathered"
        assert "the sample reads its own strings" in answer

    def test_no_graph_text_is_attributed_to_the_agent(self) -> None:
        _agent, _model, container, _ran, _ledger, answer = _run(
            _a_budget_that_runs_out(), max_steps=40
        )

        assert not any(GRAPH_STOP in words for words in _agent_words(container))
        assert GRAPH_STOP not in answer


class TestTheStepLimitIsThePlatformsToSay:
    """A roomy window and a small step limit: the graph's own stop is reached."""

    @staticmethod
    def _roomy() -> cw.ContextBudget:
        return cw.ContextBudget(cw.WindowFact(1_000_000, cw.PROBED, "test"), reply_tokens=8192)

    def test_the_cap_is_steps_and_the_console_is_not_handed_the_graph_s_sentence(self) -> None:
        agent, _model, container, _ran, _ledger, _answer = _run(
            self._roomy(), max_steps=8, framing=100
        )

        assert [row["cap"] for row in agent.drain_budget_records()] == ["steps"]
        assert not any(GRAPH_STOP in words for words in _agent_words(container))

    def test_the_salvage_is_not_shown_the_graph_s_sentence_as_its_own_turn(self) -> None:
        _agent, model, _container, _ran, _ledger, _answer = _run(
            self._roomy(), max_steps=8, framing=100
        )

        salvage = [sent for sent in model.calls if _told_to_stop(sent)]
        assert salvage
        for sent in salvage:
            assert not any(
                isinstance(message, AIMessage) and GRAPH_STOP in str(message.content)
                for message in sent
            )

    @pytest.mark.parametrize("budget", ["roomy", "runs_out"])
    def test_a_salvage_that_produced_nothing_leaves_the_agent_saying_nothing(
        self, budget: str
    ) -> None:
        chosen = self._roomy() if budget == "roomy" else _a_budget_that_runs_out()
        agent, _model, _container, _ran, _ledger, answer = _run(
            chosen, max_steps=8 if budget == "roomy" else 40, salvage=""
        )

        assert answer == "", "neither the graph's sentence nor a tool's notice is an answer"
        isr = agent._text_to_isr(answer, revision_round=0)
        assert isr.claims == []
        assert isr.status == "no_claims"
        cap = "steps" if budget == "roomy" else "no_room"
        assert [row["cap"] for row in agent.drain_budget_records()] == [cap], "the reason"


class TestTheJudgeLoopToo:
    """The judge's loop is awaited whole, and its last message is its reasoning."""

    def test_the_graph_s_sentence_is_not_handed_on_as_the_judge_s_reasoning(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        judge = JudgeAgent(llm=_AlwaysAsksForATool(calls=[]))
        judge.tools = [_strings_tool(MCPLangChainToolkit(), [])]
        with (
            patch("maljan.agents.judge_agent.get_settings") as settings,
            patch("maljan.agents.base_agent.get_settings", settings),
        ):
            settings.return_value.react_agent_timeout = 60
            settings.return_value.react_agent_max_steps = 6
            reasoning = asyncio.run(judge.execute_tool_loop([("system", "s"), ("human", TASK)]))

        assert GRAPH_STOP not in reasoning
        assert reasoning == "", "the judge wrote no reasoning; the record says why"
        assert [row["cap"] for row in judge.drain_budget_records()] == ["steps"]


class TestTheNodeDoesNotRunItAgain:
    def test_an_analyst_that_ended_out_of_room_is_not_asked_a_second_time(self) -> None:
        agent, _model, _container, _ran, _ledger, _answer = _run(
            _a_budget_that_runs_out(), max_steps=40, salvage=""
        )
        assert agent.ended_out_of_room is True

        _agent, _model, _container, _ran, _ledger, _answer = _run(
            TestTheStepLimitIsThePlatformsToSay._roomy(), max_steps=8, framing=100
        )
        assert _agent.ended_out_of_room is False

    def test_the_node_reads_it_before_its_fallback_analysis(self) -> None:
        import inspect

        from maljan.pipeline import nodes

        source = inspect.getsource(nodes)
        guard = source.index('getattr(agent, "ended_out_of_room", False)')
        fallback = source.index("again = agent.safe_analyze_isr_within(")
        assert guard < fallback


class TestAJudgeWithNoReasoning:
    def test_no_model_is_asked_to_extract_a_verdict_from_nothing(self) -> None:
        from unittest.mock import AsyncMock

        from maljan.agents.judge_agent import JudgeAgent

        judge = JudgeAgent(llm=_AlwaysAsksForATool(calls=[]))
        extract = AsyncMock()
        with (
            patch.object(judge, "_initialize_mcp_client", AsyncMock()),
            patch.object(judge, "execute_tool_loop", AsyncMock(return_value="")),
            patch.object(judge, "_extract_mediator_verdict", extract),
        ):
            _argument, consensus = asyncio.run(judge.mediate({"static": "r"}, []))

        extract.assert_not_called()
        assert consensus is False


class TestTheNudgeAfterTheBudgetEndedThePhase:
    def test_is_still_sent_because_the_reply_reserve_is_whole(self) -> None:
        _agent, model, _container, _ran, _ledger, _answer = _run(
            _a_budget_that_runs_out(), max_steps=40, salvage=""
        )

        asked_to_stop = [sent for sent in model.calls if _told_to_stop(sent)]
        assert len(asked_to_stop) >= 2, "the salvage, then the nudge"
