"""Every model call a run makes is one call on the token ledger, under the model that answered.

A smoke run counted 20 calls while the model server served 22: the mediator's
fast path and the judge's verdict were never written down, and the report's
calls were written under no model at all. Each path is driven here against a
model that counts what it was asked, and the ledger has to agree with it —
path by path, and in one sum over all of them.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import RunnableLambda
from langchain_core.tools import StructuredTool
from tests.unit.agents.test_the_time_cap_salvages import TASK, _SlowModel, _strings_tool
from tests.unit.agents.test_the_time_cap_salvages import _Analyst as _SlowAnalyst
from tests.unit.agents.test_the_time_cap_salvages import _Container as _SlowContainer
from tests.unit.agents.test_the_time_cap_salvages import _settings as _time_cap_settings

from maljan.agents import base_agent
from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.dynamic_analyst import DynamicAnalyst
from maljan.agents.judge_agent import JudgeAgent
from maljan.agents.network_analyst import NetworkAnalyst
from maljan.agents.static_analyst import StaticAnalyst
from maljan.analysis.function_summarizer import FunctionSummarizer
from maljan.core.config import REPORTER_AGENT_KEY, Settings
from maljan.core.model_assignments import global_model_label, model_label_for
from maljan.core.token_ledger import TokenLedger
from maljan.llm.fallback import FallbackChatModel
from maljan.pipeline.mediation_models import MediatorVerdict
from maljan.reporting.composer import ReportComposer
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.narrative_agent import NarrativeAgent

USAGE = {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12}


class _Counting(BaseChatModel):
    """A chat model that answers ``content`` and counts every call, structured ones too."""

    content: str = "agreement_confidence: 0.95"
    asked: list[int] = []

    @property
    def _llm_type(self) -> str:
        return "counting"

    def _answer(self) -> AIMessage:
        self.asked.append(1)
        return AIMessage(content=self.content, usage_metadata=dict(USAGE))

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any):
        return ChatResult(generations=[ChatGeneration(message=self._answer())])

    def with_structured_output(self, schema: Any, *, include_raw: bool = False, **_: Any) -> Any:
        def _structured(_messages: Any) -> Any:
            raw = self._answer()
            try:
                parsed, error = _instance(schema), None
            except ValueError as exc:
                if not include_raw:
                    raise
                parsed, error = None, exc
            return {"raw": raw, "parsed": parsed, "parsing_error": error} if include_raw else parsed

        return RunnableLambda(_structured)


def _instance(schema: Any) -> Any:
    if schema is MediatorVerdict:
        return MediatorVerdict(contradictions=[], resolution_summary="aligned", confidence=0.95)
    return schema.model_validate({})


def _model(content: str = "agreement_confidence: 0.95") -> _Counting:
    return _Counting(content=content, asked=[])


SETTINGS = Settings(_env_file=None)


def _judge(llm: _Counting, ledger: TokenLedger, *, runs_on: str = "judge") -> JudgeAgent:
    judge = JudgeAgent(llm=llm, config=None)
    judge.token_ledger = ledger
    judge._container = SimpleNamespace(
        config=SETTINGS,
        event_sink=None,
        get_server_registry=lambda: None,
        get_context_budget=lambda: None,
    )
    judge._runs_on = runs_on
    return judge


def _report() -> MalwareReport:
    return MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)))


def _calls(ledger: TokenLedger, agent: str) -> int:
    return int(ledger.snapshot()["agents"].get(agent, {}).get("llm_calls", 0))


def _models(ledger: TokenLedger, agent: str) -> dict[str, int]:
    return dict(ledger.snapshot()["agents"].get(agent, {}).get("models", {}))


class TestTheJudge:
    def test_the_mediator_s_fast_path_is_counted_against_the_expert_model(self) -> None:
        llm, ledger = _model(), TokenLedger()
        judge = _judge(llm, ledger, runs_on="expert")

        asyncio.run(judge.mediate(reports={"static": "text"}, history=[]))

        assert len(llm.asked) == 1
        assert _calls(ledger, "judge") == 1
        assert _models(ledger, "judge") == {global_model_label(SETTINGS, "expert"): 1}

    def test_the_mediator_s_structured_extraction_is_counted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        llm, ledger = _model(), TokenLedger()
        judge = _judge(llm, ledger, runs_on="expert")
        monkeypatch.setattr(judge, "_supports_structured_output", lambda: True)

        asyncio.run(judge.mediate(reports={"static": "text"}, history=[]))

        assert len(llm.asked) == 2
        assert _calls(ledger, "judge") == 2

    def test_the_verdict_is_counted_against_the_judge_model(self) -> None:
        llm, ledger = _model("not a bundle"), TokenLedger()
        judge = _judge(llm, ledger)

        asyncio.run(judge.give_verdict(reports={"static": "text"}, history=[]))

        assert llm.asked, "the verdict asked the model"
        assert _calls(ledger, "judge") == len(llm.asked)
        assert _models(ledger, "judge") == {
            model_label_for(SETTINGS, "judge", role="judge"): len(llm.asked)
        }


class TestTheAnalystsRevisions:
    @pytest.mark.parametrize("cls", [StaticAnalyst, DynamicAnalyst, NetworkAnalyst])
    def test_both_revision_rounds_are_counted(self, cls: type) -> None:
        llm, ledger = _model("CLAIM: x\nEVIDENCE: ev_0001\nCONFIDENCE: 0.5\n---"), TokenLedger()
        agent = cls(llm=llm, name="static")
        agent.token_ledger = ledger
        agent._model_label = lambda: "openai/static-model"

        agent.revise("data", "own", {"dynamic": "peer"}, "feedback")
        agent.revise_isr("data", "own", {"dynamic": "peer"}, "feedback")

        assert len(llm.asked) == 2
        assert _calls(ledger, "static") == 2
        assert _models(ledger, "static") == {"openai/static-model": 2}


class TestTheReport:
    def test_the_narrative_s_structured_path_is_counted_against_the_reporter_s_model(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "maljan.reporting.narrative_agent.structured_output_supported_for_llm",
            lambda _llm: True,
        )
        llm, ledger = _model(), TokenLedger()
        label = model_label_for(SETTINGS, REPORTER_AGENT_KEY, role="judge")
        agent = NarrativeAgent(llm=llm, token_ledger=ledger, model_label=label)

        asyncio.run(agent.generate(_report()))

        assert len(llm.asked) >= 1
        assert _calls(ledger, REPORTER_AGENT_KEY) == len(llm.asked)
        assert _models(ledger, REPORTER_AGENT_KEY) == {label: len(llm.asked)}

    def test_the_narrative_s_manual_path_names_the_model(self) -> None:
        llm, ledger = _model("{}"), TokenLedger()
        agent = NarrativeAgent(llm=llm, token_ledger=ledger, model_label="openai/reporter")

        asyncio.run(agent.generate(_report()))

        assert _calls(ledger, REPORTER_AGENT_KEY) == len(llm.asked)
        assert _models(ledger, REPORTER_AGENT_KEY) == {"openai/reporter": len(llm.asked)}

    def test_every_composer_section_is_counted_on_either_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for supported in (True, False):
            monkeypatch.setattr(
                "maljan.reporting.composer.structured_output_supported_for_llm",
                lambda _llm, s=supported: s,
            )
            llm, ledger = _model("{}"), TokenLedger()
            composer = ReportComposer(
                llm=llm, per_section_timeout=5, token_ledger=ledger, model_label="openai/reporter"
            )

            asyncio.run(composer.compose(_report()))

            assert llm.asked, "a section asked the model"
            assert _calls(ledger, REPORTER_AGENT_KEY) == len(llm.asked)
            assert _models(ledger, REPORTER_AGENT_KEY) == {"openai/reporter": len(llm.asked)}


class TestTheSummariser:
    def test_a_summarised_tool_answer_is_counted(self) -> None:
        llm, ledger = _model("short"), TokenLedger()
        summarizer = FunctionSummarizer(llm=llm, token_ledger=ledger, model_label="openai/small")

        summarizer.summarize_chunk("int main() { return 0; }")
        summarizer.summarize_chunks(["a", "b", "c", "d"])  # four chunks and their merge

        assert _calls(ledger, "summarizer") == len(llm.asked) == 6
        assert _models(ledger, "summarizer") == {"openai/small": 6}


def test_the_ledger_is_the_sum_of_every_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """One ledger, every path above, and not one call more or less than was served."""
    monkeypatch.setattr(
        "maljan.reporting.narrative_agent.structured_output_supported_for_llm", lambda _llm: False
    )
    monkeypatch.setattr(
        "maljan.reporting.composer.structured_output_supported_for_llm", lambda _llm: False
    )
    ledger = TokenLedger()
    served: list[_Counting] = []

    def model(content: str = "agreement_confidence: 0.95") -> _Counting:
        served.append(_model(content))
        return served[-1]

    asyncio.run(
        _judge(model(), ledger, runs_on="expert").mediate(reports={"static": "t"}, history=[])
    )
    asyncio.run(_judge(model("x"), ledger).give_verdict(reports={"static": "t"}, history=[]))
    for cls, name in ((StaticAnalyst, "static"), (DynamicAnalyst, "dynamic")):
        agent = cls(llm=model("CLAIM: x\nEVIDENCE: e\nCONFIDENCE: 0.5\n---"), name=name)
        agent.token_ledger = ledger
        agent.revise("d", "o", {}, "f")
        agent.revise_isr("d", "o", {}, "f")
    asyncio.run(NarrativeAgent(llm=model("{}"), token_ledger=ledger).generate(_report()))
    asyncio.run(
        ReportComposer(llm=model("{}"), per_section_timeout=5, token_ledger=ledger).compose(
            _report()
        )
    )
    FunctionSummarizer(llm=model("s"), token_ledger=ledger).summarize_chunk("code")

    snapshot = ledger.snapshot()
    assert snapshot["llm_calls"] == sum(len(m.asked) for m in served)
    assert snapshot["input_tokens"] == 10 * snapshot["llm_calls"]
    assert snapshot["unreported_calls"] == 0
    assert set(snapshot["agents"]) == {"judge", "static", "dynamic", "reporter", "summarizer"}


class TestALoopThatDidNotComeBack:
    def test_the_turns_a_loop_took_before_its_hard_cap_are_counted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        llm, ledger = _Tooling(asked=[]), TokenLedger()
        agent = _Analyst(
            llm=llm,
            name="static",
            tools=[StructuredTool.from_function(func=_slow, name="slow", description="s")],
        )
        agent.token_ledger = ledger
        agent._container = MagicMock()
        agent._model_label = lambda: "openai/static-model"
        monkeypatch.setattr(base_agent, "_run_coro_blocking", _cut_off)

        with pytest.raises(TimeoutError):
            agent.execute_tool_loop([("system", "s"), ("human", "h")])

        assert llm.asked, "the loop took a turn before its clock ran out"
        assert _calls(ledger, "static") == len(llm.asked)
        assert _models(ledger, "static") == {"openai/static-model": len(llm.asked)}


class _Served(_SlowModel):
    """The time-cap stand-in, keeping how many of its calls it actually answered.

    A call a turn deadline or a cancelled loop cut off was asked and never
    answered; the ledger counts what the server answered, so this does too.
    """

    answered: list[int] = []

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **kw: Any):
        result = super()._generate(messages, stop, run_manager, **kw)
        self.answered.append(1)
        return result

    async def _agenerate(self, messages: Any, stop: Any = None, run_manager: Any = None, **kw: Any):
        result = await super()._agenerate(messages, stop, run_manager, **kw)
        self.answered.append(1)
        return result


def _slow_run(llm: Any, budget: int) -> tuple[TokenLedger, str]:
    ledger = TokenLedger()
    agent = _SlowAnalyst(llm=llm, name="static")
    agent._container = _SlowContainer()
    agent.tools = [_strings_tool()]
    agent.token_ledger = ledger
    with _time_cap_settings(budget):
        answer = agent.execute_tool_loop([("system", "read the sample"), ("human", TASK)])
    return ledger, answer


class TestTheSlowModelPaths:
    """Every call the time cap, its salvage, the nudge and a model list make, counted once."""

    def test_the_time_cap_s_turns_and_its_salvage(self) -> None:
        model = _Served(calls=[], answered=[])
        ledger, answer = _slow_run(model, budget=8)

        assert "only one copy runs" in answer, "the salvage wrote the answer"
        assert _calls(ledger, "static") == len(model.answered) == len(model.calls)

    def test_the_salvage_and_the_nudge_after_it(self) -> None:
        model = _Served(calls=[], answered=[], salvage="The sample seems to check something.")
        ledger, _answer = _slow_run(model, budget=8)

        assert _calls(ledger, "static") == len(model.answered)

    def test_a_model_list_s_switch_is_counted_under_the_model_that_answered(self) -> None:
        primary = _Served(calls=[], answered=[], stall_from=3)
        secondary = _Served(calls=[], answered=[])
        llm = FallbackChatModel(
            models=[primary, secondary], labels=["primary", "secondary"], agent="static"
        )
        ledger, answer = _slow_run(llm, budget=16)

        assert "only one copy runs" in answer
        assert len(primary.calls) > len(primary.answered), "the primary stalled"
        assert _models(ledger, "static") == {
            "primary": len(primary.answered),
            "secondary": len(secondary.answered),
        }
        assert _calls(ledger, "static") == len(primary.answered) + len(secondary.answered)

    def test_a_verdict_a_fallback_answered_is_counted_once_under_it(self) -> None:
        answering = _model("not a bundle")
        llm = FallbackChatModel(
            models=[_Refusing(), answering], labels=["openai/first", "openai/second"], agent="judge"
        )
        ledger = TokenLedger()
        judge = _judge(llm, ledger)  # type: ignore[arg-type]

        asyncio.run(judge.give_verdict(reports={"static": "text"}, history=[]))

        assert _models(ledger, "judge") == {"openai/second": len(answering.asked)}

    def test_every_composer_section_a_fallback_answered_is_counted_once_under_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "maljan.reporting.composer.structured_output_supported_for_llm", lambda _llm: False
        )
        answering = _model("{}")
        llm = FallbackChatModel(
            models=[_Refusing(), answering],
            labels=["openai/first", "openai/second"],
            agent=REPORTER_AGENT_KEY,
        )
        llm.restart()
        ledger = TokenLedger()
        composer = ReportComposer(
            llm=llm, per_section_timeout=5, token_ledger=ledger, model_label="openai/first"
        )

        asyncio.run(composer.compose(_report()))

        assert answering.asked
        assert _models(ledger, REPORTER_AGENT_KEY) == {"openai/second": len(answering.asked)}


class _Refusing(BaseChatModel):
    """A first model the provider refuses to connect to: nothing is served."""

    @property
    def _llm_type(self) -> str:
        return "refusing"

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any):
        raise ConnectionRefusedError(111, "refused")


class _Tooling(BaseChatModel):
    """Asks for the slow tool on every turn, with its usage reported."""

    asked: list[int] = []

    @property
    def _llm_type(self) -> str:
        return "tooling"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any):
        self.asked.append(1)
        call = {"name": "slow", "args": {"n": len(self.asked)}, "id": str(len(self.asked))}
        answer = AIMessage(content="", tool_calls=[call], usage_metadata=dict(USAGE))
        return ChatResult(generations=[ChatGeneration(message=answer)])


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *a: Any, **k: Any) -> str:  # pragma: no cover - unused
        return ""


_TOOL_STARTED = threading.Event()


def _slow(n: int) -> str:
    """Slow."""
    _TOOL_STARTED.set()
    time.sleep(0.5)
    return "ok"


def _cut_off(coro: Any, timeout: float, label: str = "") -> Any:
    """The hard cap, early: the loop is stopped while its first tool call runs.

    By then the model's turn is in the conversation the stream last handed
    over, which is what a loop the real cap stops leaves behind.
    """

    async def _within() -> Any:
        _TOOL_STARTED.clear()
        task = asyncio.ensure_future(coro)
        while not _TOOL_STARTED.is_set() and not task.done():
            await asyncio.sleep(0.01)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        raise TimeoutError("hard cap")

    return asyncio.run(_within())


class _Scripted(BaseChatModel):
    """Answers from a script of tool calls, final text and exceptions; keeps what it served.

    A string is a final answer, ``"tool"`` a call to ``peek``, an exception is
    raised. ``served`` counts the answers it returned, which is what a model
    server would bill.
    """

    script: list[Any] = []
    served: list[int] = []

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any):
        step = self.script.pop(0) if self.script else "tool"
        if isinstance(step, BaseException):
            raise step
        if step == "tool":
            n = len(self.served) + 1
            answer = AIMessage(
                content="",
                tool_calls=[{"name": "peek", "args": {"n": n}, "id": f"c{n}"}],
                usage_metadata=dict(USAGE),
            )
        else:
            answer = AIMessage(content=step, usage_metadata=dict(USAGE))
        self.served.append(1)
        return ChatResult(generations=[ChatGeneration(message=answer)])


def _peek(n: int) -> str:
    """Peek."""
    return f"bytes {n}"


def _peek_tool() -> Any:
    return StructuredTool.from_function(func=_peek, name="peek", description="p")


def _connection_error() -> Exception:
    import httpx
    from openai import APIConnectionError

    return APIConnectionError(request=httpx.Request("POST", "http://127.0.0.1:8080/v1"))


def _scripted_analyst(script: list[Any]) -> tuple[_Analyst, _Scripted, TokenLedger]:
    llm, ledger = _Scripted(script=list(script), served=[]), TokenLedger()
    agent = _Analyst(llm=llm, name="static", tools=[_peek_tool()])
    agent.token_ledger = ledger
    agent._container = MagicMock()
    agent._model_label = lambda: "openai/static-model"
    return agent, llm, ledger


class TestEveryLoopEndingCountsWhatWasServed:
    def test_a_step_cap_the_graph_ended_counts_each_served_turn_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The graph's own stop replaces a turn the model did answer: one call, usage unknown."""
        from maljan.core.config import get_settings

        monkeypatch.setitem(get_settings().react_agent_max_steps_overrides, "static", 3)
        agent, llm, ledger = _scripted_analyst(["tool"] * 10)

        agent.execute_tool_loop([("system", "s"), ("human", "h")])

        assert llm.served
        assert _calls(ledger, "static") == len(llm.served)

    def test_the_stop_this_code_appends_at_a_recursion_error_is_not_a_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from langgraph.errors import GraphRecursionError

        answered = AIMessage(
            content="",
            tool_calls=[{"name": "peek", "args": {"n": 1}, "id": "c1"}],
            usage_metadata=dict(USAGE),
        )

        class _Executor:
            def astream(self, state: Any, *_: Any, **__: Any) -> Any:
                async def _snapshots() -> Any:
                    yield {"messages": [*state["messages"], answered]}
                    raise GraphRecursionError("the step cap")

                return _snapshots()

        monkeypatch.setattr("langgraph.prebuilt.create_react_agent", lambda *a, **k: _Executor())
        agent, llm, ledger = _scripted_analyst(["CLAIM: x\nEVIDENCE: ev_0001"])

        agent.execute_tool_loop([("system", "s"), ("human", "h")])

        # The one turn the loop's model answered, and the salvage's own call.
        assert _calls(ledger, "static") == 1 + len(llm.served)
        assert ledger.snapshot()["unreported_calls"] == 0

    def test_an_attempt_abandoned_on_a_connection_error_counts_what_it_was_served(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(asyncio, "sleep", _no_wait)
        agent, llm, ledger = _scripted_analyst(
            ["tool", _connection_error(), "tool", "CLAIM: x\nEVIDENCE: ev_0001"]
        )

        agent.execute_tool_loop([("system", "s"), ("human", "h")])

        assert len(llm.served) == 3, "one turn before the drop, two in the replay"
        assert _calls(ledger, "static") == 3

    def test_a_loop_that_raised_an_analyst_error_counts_what_it_was_served(self) -> None:
        from maljan.core.exceptions import AnalystError

        agent, llm, ledger = _scripted_analyst(["tool", "tool", AnalystError("gave up")])

        with pytest.raises(AnalystError):
            agent.execute_tool_loop([("system", "s"), ("human", "h")])

        assert len(llm.served) == 2
        assert _calls(ledger, "static") == 2

    def test_a_judge_loop_that_failed_counts_what_it_was_served(self) -> None:
        llm = _Scripted(script=["tool", "tool", RuntimeError("the server broke")], served=[])
        ledger = TokenLedger()
        judge = _judge(llm, ledger)  # type: ignore[arg-type]
        judge.tools = [_peek_tool()]

        with pytest.raises(RuntimeError):
            asyncio.run(judge.execute_tool_loop([("system", "s"), ("human", "h")]))

        assert len(llm.served) == 2
        assert _calls(ledger, "judge") == 2


_REAL_SLEEP = asyncio.sleep


async def _no_wait(seconds: float, *args: Any, **kwargs: Any) -> Any:
    return await _REAL_SLEEP(0)
