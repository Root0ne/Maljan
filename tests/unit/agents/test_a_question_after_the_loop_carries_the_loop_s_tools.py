"""A question asked after an analyst's loop carries the loop's own tools.

On haiku7, 70 of 119 model calls were turns with no tools, and two defects
(a function never read, an absence stated of it) came from validation
retries in which the model could not check the value it was asked about. The
validation retry, the kept-retry drops question and the whole-answer question
now run the analyst's own tool loop over their conversation: the same tools
in the same order, the same guards, stall deadline and repeat guard, each
call filed on the ledger as a loop's is, every turn recorded under the
question's own call. The model decides whether to call one; the questions
say it may cite an entry or read it. A model that cannot bind the tools is
asked in the one tools-free call it was, and the log says so. A built-in
revision round carries the agent's tools the same way.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import BaseAnalyst, LoopBudget, _submit_to_agent_loop
from maljan.agents.delegation import tool_name
from maljan.agents.evidence_recorder import EARLIER_TURN, earlier_chunk_sentence
from maljan.agents.prompt_fragments import KEEP_REPLY
from maljan.core.exceptions import AnalystError
from maljan.core.spend import in_validation_retry, validation_retry
from maljan.core.token_ledger import (
    RETRY_DROPS_QUESTION_CALL,
    VALIDATION_RETRY_CALL,
    WHOLE_ANSWER_RETRY_CALL,
    TokenLedger,
)
from maljan.pipeline.validation import (
    ANALYST_TOOLS_ATTACHED,
    RETRY_DROP_TOOLS_ATTACHED,
    VALIDATION_ENTRIES_HEAD,
    Violation,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

from .test_a_validation_retry_is_shown_the_entries_its_answer_cites import FIRST as CITING
from .test_a_validation_retry_is_shown_the_entries_its_answer_cites import FIXED as NUMBERED
from .test_delegation import BOSS_REPORT, HELPER_REPORT, _run_boss, _team
from .test_delegation import _call as _turn
from .test_what_a_kept_retry_left_out_is_settled_by_the_analyst import FIRST as DROPPING
from .test_what_a_kept_retry_left_out_is_settled_by_the_analyst import RETRY as KEPT_RETRY

NAME = "static"
TOOLS_STATED = "SYSTEM: your tools are attached"
NO_TOOLS_STATED = "SYSTEM: no tools are attached"
REPORT = "CLAIM: it reads a file\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.6\nTECHNIQUE: T1005\n"
FIXED = "CLAIM: it reads a file\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.6\nTECHNIQUE: T1005\n"


class _Address(BaseModel):
    address: str = ""


def _tool(name: str, *, read_only: bool = False) -> StructuredTool:
    def _run(address: str = "") -> str:
        return f"{name} of {address}: body"

    return StructuredTool.from_function(
        func=_run,
        name=name,
        description=f"{name} a function.",
        args_schema=_Address,
        metadata={"maljan_read_only": True} if read_only else {},
    )


def _call(name: str, address: str, call_id: str) -> dict[str, Any]:
    return {"call": {"name": name, "args": {"address": address}, "id": call_id}}


class _Recording(BaseChatModel):
    """Answers from a script, a tool call or a text per turn; records each request and its tools."""

    script: list = []
    seen: list = []
    bound: list = []

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        names = [str(getattr(tool, "name", "")) for tool in tools]
        return self.model_copy(update={"bound": names})

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        self.seen.append({"tools": list(self.bound), "messages": list(messages)})
        step = self.script.pop(0) if self.script else REPORT
        if isinstance(step, dict):
            turn = AIMessage(content="", tool_calls=[step["call"]])
        else:
            turn = AIMessage(content=str(step))
        return ChatResult(generations=[ChatGeneration(message=turn)])

    @property
    def _llm_type(self) -> str:
        return "recording"


class _CannotBind(_Recording):
    """A model whose provider takes no tools."""

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        raise NotImplementedError("this provider takes no tools")


class _CallsWhileItMay(_Recording):
    """Calls a tool on every turn that carries tools; writes the fixed claim on one without."""

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        if self.bound:
            return super()._generate(messages, stop, run_manager)
        self.seen.append({"tools": [], "messages": list(messages)})
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=FIXED))])


class _BindsOnce(_Recording):
    """A model whose first bind (the turn's check) works and every later one is refused."""

    binds: list = []

    def bind_tools(self, tools: Any, **kw: Any) -> Any:
        self.binds.append(1)
        if len(self.binds) > 1:
            raise NotImplementedError("the provider refused the tool list")
        return super().bind_tools(tools, **kw)


class _Analyst(BaseAnalyst):
    def __init__(self, llm: Any, tools: list[Any]) -> None:
        super().__init__(llm=llm, name=NAME)
        self.tools = tools
        self.pack_ledger_ids = ["ev_0001"]
        self.token_ledger = TokenLedger()

    def _system_prompt(self, fallback: Any, tools: Any = None) -> str:
        return NO_TOOLS_STATED if tools is not None and not list(tools) else TOOLS_STATED

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


def _analyst(script: list[Any], model: type[_Recording] = _Recording) -> tuple[_Analyst, Any]:
    llm = model(script=list(script), seen=[])
    return _Analyst(llm, [_tool("decompile", read_only=True), _tool("rename")]), llm


def _isr() -> AgentISR:
    return AgentISR(
        agent_id=NAME,
        domain="static",
        claims=[
            ClaimEvidence(
                claim="it reads a file",
                evidence_ref="ev_0001",
                confidence=0.6,
                technique_id="T1005",
            )
        ],
    )


def _validate(analyst: _Analyst, isr: AgentISR, told: list[list[Violation]]) -> AgentISR:
    answers = iter(told)
    with patch("maljan.pipeline.validation.validate_isr", lambda *_a, **_k: next(answers, [])):
        return analyst._validate_isr(isr, "the raw data")


def _asked(seen: list[dict[str, Any]], marker: str) -> list[dict[str, Any]]:
    """The requests whose newest human turn carries ``marker``, in order."""
    out = []
    for request in seen:
        humans = [m for m in request["messages"] if isinstance(m, HumanMessage)]
        if humans and marker in str(humans[-1].content):
            out.append(request)
    return out


TOLD = [Violation(code="isr.ungrounded_technique", message="cite the entry that holds it")]


class TestTheValidationRetryCarriesTheLoopsTools:
    def test_the_retry_binds_the_tools_the_loop_bound_in_their_order(self) -> None:
        analyst, llm = _analyst([_call("decompile", "0x1000", "s1"), REPORT, FIXED])
        analyst.execute_tool_loop([("system", "s"), ("human", "Analyse.")])
        loop_tools = llm.seen[0]["tools"]

        _validate(analyst, _isr(), [TOLD, TOLD, []])

        retry = _asked(llm.seen, "cite the entry that holds it")[0]
        assert loop_tools == ["decompile", "rename"]
        assert retry["tools"] == loop_tools

    def test_a_tool_call_in_the_retry_reaches_the_ledger_and_its_answer_stands(self) -> None:
        analyst, llm = _analyst([_call("decompile", "0x309c", "c1"), FIXED])

        result = _validate(analyst, _isr(), [TOLD, TOLD, []])

        called = [e for e in analyst._evidence_entries if e.tool == "decompile"]
        assert [e.args for e in called] == [{"address": "0x309c"}]
        assert called[0].agent == NAME
        # The tool's answer was in the conversation the model wrote its fix from.
        last = llm.seen[-1]["messages"]
        assert any(isinstance(m, ToolMessage) and "0x309c" in str(m.content) for m in last)
        assert [c.evidence_ref for c in result.claims] == ["[ev_0003]"]

    def test_each_turn_of_the_retry_is_recorded_under_the_retry(self) -> None:
        analyst, _llm = _analyst([_call("decompile", "0x309c", "c1"), FIXED])

        _validate(analyst, _isr(), [TOLD, TOLD, []])

        calls = analyst.token_ledger.by_call()[NAME]
        assert calls[VALIDATION_RETRY_CALL]["calls"] == 2
        assert "tool loop turn" not in calls

    def test_the_question_s_loop_record_rides_on_the_loop_it_follows(self) -> None:
        analyst, _llm = _analyst(
            [_call("decompile", "0x1000", "s1"), REPORT, _call("decompile", "0x309c", "c1"), FIXED]
        )
        analyst.execute_tool_loop([("system", "s"), ("human", "Analyse.")])
        deadline = analyst._last_loop_deadline

        _validate(analyst, _isr(), [TOLD, TOLD, []])

        records = analyst.drain_budget_records()
        assert len(records) == 1
        assert len(records[0]["asked_after"]) == 1
        assert analyst._last_loop_deadline == deadline

    def test_a_retry_whose_loop_ends_at_a_cap_is_asked_in_its_tools_free_call(self) -> None:
        # The step cap ends the retry's loop while it is still calling: it is
        # asked once more without tools, as dev asked it, and that answer stands.
        calls = [_call("decompile", f"0x{n}", f"c{n}") for n in range(9)]
        analyst, llm = _analyst(calls, _CallsWhileItMay)

        with patch("maljan.agents.base_agent.loop_limits", return_value=(None, 3)):
            result = _validate(analyst, _isr(), [TOLD, TOLD, []])

        assert [c.evidence_ref for c in result.claims] == ["[ev_0003]"]
        last = llm.seen[-1]
        assert last["tools"] == []
        assert last["messages"][0].content == NO_TOOLS_STATED
        assert "attached" not in str(last["messages"][-1].content)
        rows = [
            r
            for rec in analyst.drain_budget_records()
            for r in rec.get("asked_without_tools") or []
        ]
        assert rows and rows[0]["call"] == VALIDATION_RETRY_CALL
        assert "ended at" in rows[0]["why"] and "without an answer" in rows[0]["why"]

    def test_with_no_time_left_after_the_loop_the_question_is_not_asked_again(self) -> None:
        calls = [_call("decompile", f"0x{n}", f"c{n}") for n in range(9)]
        analyst, llm = _analyst(calls, _CallsWhileItMay)
        analyst._last_loop_deadline = time.monotonic() + 100.0
        turns = [SystemMessage(content="s"), HumanMessage(content="Q?")]
        # Enough for the loop, too little once it has ended.
        needs = iter([0.0, 1_000.0])

        with (
            patch("maljan.agents.base_agent.loop_limits", return_value=(None, 3)),
            patch.object(BaseAnalyst, "seconds_an_answer_needs", lambda _s: next(needs)),
            pytest.raises(AnalystError, match="not asked"),
        ):
            analyst._answer_after_loop(turns, None, what=VALIDATION_RETRY_CALL, tools=True)
        assert llm.seen and all(request["tools"] for request in llm.seen)


class TestAnIdenticalCallIsAnsweredFromTheLoopsEntry:
    def test_a_read_only_call_the_loop_made_is_not_run_again(self) -> None:
        analyst, llm = _analyst(
            [_call("decompile", "0x309c", "c1"), REPORT, _call("decompile", "0x309c", "c2"), FIXED]
        )
        analyst.execute_tool_loop([("system", "s"), ("human", "Analyse.")])
        held = analyst._evidence_entries[0].id

        _validate(analyst, _isr(), [TOLD, TOLD, []])

        answers = [m for m in llm.seen[-1]["messages"][4:] if isinstance(m, ToolMessage)]
        assert earlier_chunk_sentence("decompile", held, origin=EARLIER_TURN) in str(
            answers[-1].content
        )
        ran = [e for e in analyst._evidence_entries if e.tool == "decompile" and not e.repeated_of]
        assert len(ran) == 1


def _validated_text(analyst: _Analyst, first: str) -> AgentISR:
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
    ):
        return analyst._validate_isr(isr, "evidence")


class TestTheDropsQuestionCarriesThemToo:
    def test_the_drops_question_binds_them_and_its_call_reaches_the_ledger(self) -> None:
        reply = "\n".join(f"KEEP C{n}: the routine decodes it" for n in range(1, 10))
        analyst, llm = _analyst([KEPT_RETRY, _call("decompile", "0x7b80", "d1"), reply])

        result = _validated_text(analyst, DROPPING)

        asked = _asked(llm.seen, RETRY_DROP_TOOLS_ATTACHED)
        assert len(asked) == 2
        assert all(request["tools"] == ["decompile", "rename"] for request in asked)
        assert [e.args for e in analyst._evidence_entries if e.tool == "decompile"] == [
            {"address": "0x7b80"}
        ]
        assert analyst.token_ledger.by_call()[NAME][RETRY_DROPS_QUESTION_CALL]["calls"] == 2
        # Its answer is read as the tools-free answer was: all nine kept.
        assert len(result.claims) == 32 + 9


class TestTheWholeAnswerQuestionCarriesThemToo:
    def test_the_whole_answer_question_binds_them_and_its_call_reaches_the_ledger(self) -> None:
        unnumbered = NUMBERED.replace("CLAIM 1:", "CLAIM:")
        analyst, llm = _analyst(
            [
                unnumbered + NUMBERED.replace("1:", "2:"),
                _call("decompile", "0x3868", "w1"),
                NUMBERED,
            ]
        )
        analyst._evidence_entries = [
            LedgerEntry(id="ev_0080", agent=NAME, tool="batch_decompile", output="body"),
            LedgerEntry(id="ev_0081", agent=NAME, tool="batch_decompile", output="body 2"),
        ]

        _validated_text(analyst, CITING)

        whole = _asked(llm.seen, "Your answer is now read whole")
        assert whole and all(r["tools"] == ["decompile", "rename"] for r in whole)
        assert ANALYST_TOOLS_ATTACHED in str(whole[0]["messages"][-1].content)
        assert {"address": "0x3868"} in [e.args for e in analyst._evidence_entries]
        assert analyst.token_ledger.by_call()[NAME][WHOLE_ANSWER_RETRY_CALL]["calls"] == 2


class TestTheWordingSaysTheTurnCarriesTools:
    def test_the_retry_says_it_may_read_and_its_prompt_states_the_tools(self) -> None:
        analyst, llm = _analyst([FIXED])

        _validate(analyst, _isr(), [TOLD, TOLD, []])

        retry = _asked(llm.seen, "cite the entry that holds it")[0]["messages"]
        assert isinstance(retry[0], SystemMessage) and retry[0].content == TOOLS_STATED
        question = str(retry[-1].content)
        assert ANALYST_TOOLS_ATTACHED in question and "or read it" in question
        assert "carries no tools" not in question

    def test_the_entries_head_says_nothing_of_tools(self) -> None:
        assert "no tools" not in VALIDATION_ENTRIES_HEAD
        assert "read the entries here" in VALIDATION_ENTRIES_HEAD


class TestAModelThatCannotBindThemAsksAsBefore:
    def test_the_retry_is_the_tools_free_call_and_the_log_says_so(self) -> None:
        analyst, llm = _analyst([FIXED], _CannotBind)
        analyst.logger = MagicMock()

        result = _validate(analyst, _isr(), [TOLD, TOLD, []])

        retry = _asked(llm.seen, "cite the entry that holds it")
        assert len(retry) == 1 and retry[0]["tools"] == []
        assert retry[0]["messages"][0].content == NO_TOOLS_STATED
        assert ANALYST_TOOLS_ATTACHED not in str(retry[0]["messages"][-1].content)
        said = [c.args for c in analyst.logger.warning.call_args_list]
        assert any("could not bind its tools" in a[0] and VALIDATION_RETRY_CALL in a for a in said)
        assert [c.evidence_ref for c in result.claims] == ["[ev_0003]"]
        assert analyst.token_ledger.by_call()[NAME][VALIDATION_RETRY_CALL]["calls"] == 1

    def test_an_agent_with_no_tools_asks_as_before_and_says_nothing(self) -> None:
        llm = _Recording(script=[FIXED], seen=[])
        analyst = _Analyst(llm, [])
        analyst.logger = MagicMock()

        _validate(analyst, _isr(), [TOLD, TOLD, []])

        assert llm.seen[-1]["tools"] == []
        analyst.logger.warning.assert_not_called()


class TestTheWindowCountsTheDefinitionsTheQuestionCarries:
    def test_the_definitions_are_counted_only_while_the_questions_carry_them(self) -> None:
        analyst, _llm = _analyst([])
        analyst._tool_definition_chars = 5_000

        assert BaseAnalyst._question_definition_chars(analyst) == 0
        analyst._questions_carry_tools = True
        assert BaseAnalyst._question_definition_chars(analyst) == 5_000
        analyst._questions_carry_tools = False
        assert BaseAnalyst._question_definition_chars(analyst) == 0

    def test_the_flag_is_cleared_when_the_turn_ends(self) -> None:
        analyst, _llm = _analyst([FIXED])

        _validate(analyst, _isr(), [TOLD, TOLD, []])

        assert analyst._questions_carry_tools is False


class TestTheInputMeterFilesTheQuestionUnderItsCall:
    def test_the_retry_s_loop_row_is_a_validation_retry(self) -> None:
        from maljan.core.input_meter import TOOL_LOOP, InputMeter

        analyst, _llm = _analyst([_call("decompile", "0x1000", "s1"), REPORT, FIXED])
        meter = InputMeter()
        analyst._container = MagicMock(input_meter=meter, event_sink=None)
        analyst.execute_tool_loop([("system", "s"), ("human", "Analyse.")])

        _validate(analyst, _isr(), [TOLD, TOLD, []])

        kinds = [row["kind"] for row in meter.rows()]
        assert kinds == [TOOL_LOOP, VALIDATION_RETRY_CALL]
        assert meter.rows()[1]["requests"] == 1


class TestARetryMayCiteTheEntryItsOwnCallFiled:
    """Checked against the ledger as it stands when its answer is checked, not before."""

    def test_no_ungrounded_finding_survives_a_retry_that_cites_its_new_entry(self) -> None:
        first = (
            "CLAIM: it reads a file from disk\nEVIDENCE: [ev_0777]\nCONFIDENCE: 0.6\n"
            "TECHNIQUE: T1005\n"
        )
        fixed = first.replace("ev_0777", "ev_0001")
        analyst, llm = _analyst([_call("decompile", "0x309c", "c1"), fixed])
        analyst.pack_ledger_ids = ["ev_0500"]

        result = _validated_text(analyst, first)

        assert len(llm.seen) == 2, "the retry was asked and called its tool"
        assert [e.id for e in analyst._evidence_entries] == ["ev_0001"]
        assert [c.evidence_ref for c in result.claims] == ["[ev_0001]"]
        codes = [v.code for v in analyst.validation_findings]
        assert "isr.ungrounded_technique" not in codes


class TestTheQuestionsShareWhatTheLoopLeft:
    def test_each_question_is_held_to_the_time_left_to_the_loop_s_deadline(self) -> None:
        analyst, _llm = _analyst([])
        held: list[float | None] = []

        def _loop(_m: Any, **kw: Any) -> str:
            held.append(kw["seconds"])
            return FIXED

        analyst.execute_tool_loop = _loop  # type: ignore[method-assign]
        analyst._last_loop_deadline = time.monotonic() + 100.0
        for what in (VALIDATION_RETRY_CALL, RETRY_DROPS_QUESTION_CALL, WHOLE_ANSWER_RETRY_CALL):
            analyst._answer_after_loop([], 1_000.0, what=what, tools=True)

        assert len(held) == 3
        assert all(seconds is not None and seconds <= 100.0 for seconds in held)
        assert held == sorted(held, reverse=True)

    def test_a_question_with_no_time_left_is_not_asked(self) -> None:
        analyst, llm = _analyst([FIXED])
        analyst._last_loop_deadline = time.monotonic() + 1.0

        with pytest.raises(AnalystError, match="not asked"):
            analyst._answer_after_loop([], 1_000.0, what=VALIDATION_RETRY_CALL, tools=True)
        assert llm.seen == []

    def test_the_questions_spend_the_loop_s_steps_and_then_ask_without_tools(self) -> None:
        analyst, llm = _analyst(
            [_call("decompile", "0x1000", "s1"), REPORT, _call("decompile", "0x309c", "c1"), FIXED]
        )
        turns = [SystemMessage(content="s"), HumanMessage(content="Q?")]
        with patch("maljan.agents.base_agent.loop_limits", return_value=(None, 9)):
            analyst.execute_tool_loop([("system", "s"), ("human", "Analyse.")])
            # The loop spent three steps of nine: its tool round and its answer.
            assert analyst._last_loop_steps_left == 6
            analyst._answer_after_loop(turns, None, what=VALIDATION_RETRY_CALL, tools=True)
            # The retry spent three more: the next question has three.
            assert analyst._last_loop_steps_left == 3
            analyst._answer_after_loop(turns, None, what=RETRY_DROPS_QUESTION_CALL, tools=True)
            assert analyst._last_loop_steps_left == 2
            analyst._answer_after_loop(turns, None, what=WHOLE_ANSWER_RETRY_CALL, tools=True)

        assert [bool(r["tools"]) for r in llm.seen] == [True, True, True, True, True, False]
        record = analyst.drain_budget_records()[0]
        assert record["asked_without_tools"][0]["call"] == WHOLE_ANSWER_RETRY_CALL
        assert "2 step(s)" in record["asked_without_tools"][0]["why"]
        # The questions' steps are the loop's, not added to what the agent spent.
        assert analyst.steps_spent == 3

    def test_a_delegated_callee_stays_inside_its_ask_s_steps(self) -> None:
        container = _team(
            boss_script=[
                _turn(tool_name("helper"), {"task": "t"}, "ask_1"),
                AIMessage(content=BOSS_REPORT),
            ],
            helper_script=[
                _turn("peek", {"path": "/samples/s.bin"}, "peek_1"),
                AIMessage(content=HELPER_REPORT),
            ],
        )
        container.config.agents.delegation_steps = 4
        noted: list[int] = []
        original = LoopBudget.note_delegated

        def _note(self: LoopBudget, steps: int) -> None:
            noted.append(int(steps))
            original(self, steps)

        with patch.object(LoopBudget, "note_delegated", _note):
            _run_boss(container)

        # Three of its four steps spent in its loop: its retry is asked without
        # tools, and the ask never spends past its ceiling.
        assert noted == [3]
        assert container.get_agent("helper")._last_loop_steps_left == 1


class TestALostBindIsADegradation:
    def test_the_reason_is_on_the_agent_and_the_registry_once(self) -> None:
        registry = MagicMock(degradation_reasons=[])
        analyst, _llm = _analyst([FIXED, FIXED], _CannotBind)
        analyst._container = MagicMock(get_server_registry=lambda: registry, event_sink=None)

        _validate(analyst, _isr(), [TOLD, TOLD, []])
        _validate(analyst, _isr(), [TOLD, TOLD, []])

        assert len(analyst.degradation_reasons) == 1
        assert "could not bind its tools" in analyst.degradation_reasons[0]
        assert registry.degradation_reasons == analyst.degradation_reasons

    def test_a_graph_that_cannot_bind_falls_back_to_the_tools_free_call(self) -> None:
        analyst, llm = _analyst([FIXED], _BindsOnce)

        result = _validate(analyst, _isr(), [TOLD, TOLD, []])

        retry = _asked(llm.seen, "cite the entry that holds it")
        assert len(retry) == 1 and retry[0]["tools"] == []
        assert [c.evidence_ref for c in result.claims] == ["[ev_0003]"]
        assert any("could not bind" in r for r in analyst.degradation_reasons)

    def test_a_failed_question_loop_falls_back_to_the_tools_free_call(self) -> None:
        # A provider refusing the request that carries the tools fails the
        # question's loop: the tools-free call is still asked, as dev asked it.
        analyst, llm = _analyst([_call("decompile", "0x1000", "s1"), REPORT, FIXED])
        analyst.execute_tool_loop([("system", "s"), ("human", "Analyse.")])
        real = BaseAnalyst.execute_tool_loop

        def _fails(self: Any, *a: Any, **k: Any) -> str:
            if k.get("asked"):
                raise AnalystError(f"{self.name} ReAct agent failed: provider answered 400")
            return real(self, *a, **k)

        with patch.object(BaseAnalyst, "execute_tool_loop", _fails):
            result = _validate(analyst, _isr(), [TOLD, TOLD, []])

        assert [c.evidence_ref for c in result.claims] == ["[ev_0003]"]
        assert llm.seen[-1]["tools"] == []
        assert llm.seen[-1]["messages"][0].content == NO_TOOLS_STATED
        rows = analyst.drain_budget_records()[0]["asked_without_tools"]
        assert rows[0]["call"] == VALIDATION_RETRY_CALL
        assert rows[0]["why"].startswith("its loop failed:") and "400" in rows[0]["why"]

    def test_a_question_whose_tools_could_not_bind_says_so_on_the_loop_s_record(self) -> None:
        analyst, _llm = _analyst([], _CannotBind)
        analyst._budget_records = [{"stage": "analysis"}]
        analyst._invoke_llm_with_timeout = lambda *_a, **_k: FIXED  # type: ignore[method-assign]

        analyst._answer_after_loop([], None, what=VALIDATION_RETRY_CALL, tools=False)

        rows = analyst._budget_records[0]["asked_without_tools"]
        assert rows == [
            {"call": VALIDATION_RETRY_CALL, "why": "its model could not bind its tools"}
        ]

    def test_an_agent_with_no_tools_records_nothing(self) -> None:
        llm = _Recording(script=[], seen=[])
        analyst = _Analyst(llm, [])
        analyst._budget_records = [{"stage": "analysis"}]
        analyst._invoke_llm_with_timeout = lambda *_a, **_k: FIXED  # type: ignore[method-assign]

        analyst._answer_after_loop([], None, what=VALIDATION_RETRY_CALL, tools=False)

        assert analyst._budget_records == [{"stage": "analysis"}]


class TestTheQuestionsRecordsAreFolded:
    def test_a_callee_s_handed_over_row_stays_a_record_of_its_own(self) -> None:
        analyst, _llm = _analyst([])
        stage = {"stage": "analysis", "steps_used": 3}
        own = {"stage": "analysis", "steps_used": 1}
        callee = {"stage": "analysis", "steps_used": 2, "agent": "helper"}
        analyst._budget_records = [stage, own, callee]

        analyst._fold_question_records(1)

        assert analyst._budget_records == [{**stage, "asked_after": [own]}, callee]

    def test_with_no_earlier_record_the_question_s_record_stays(self) -> None:
        analyst, _llm = _analyst([])
        analyst._budget_records = [{"stage": "analysis", "steps_used": 1}]

        analyst._fold_question_records(0)

        assert analyst._budget_records == [{"stage": "analysis", "steps_used": 1}]

    def test_a_question_a_cap_ended_does_not_say_the_stage_ended_at_a_cap(self) -> None:
        events: list[tuple[str, Any]] = []
        analyst, _llm = _analyst(
            [_call("decompile", "0x1000", "s1"), REPORT]
            + [_call("decompile", f"0x{n}", f"c{n}") for n in range(9)],
            _CallsWhileItMay,
        )
        analyst._container = MagicMock(
            event_sink=lambda kind, payload: events.append((kind, payload))
        )
        with patch("maljan.agents.base_agent.loop_limits", return_value=(None, 9)):
            analyst.execute_tool_loop([("system", "s"), ("human", "Analyse.")])
            result = _validate(analyst, _isr(), [TOLD, TOLD, []])

        # Its tools-free call answered after it.
        assert [c.evidence_ref for c in result.claims] == ["[ev_0003]"]
        assert not [kind for kind, _p in events if kind == "stage_ended_at_cap"]


class TestARetrysLoopTurnsAreCountedAsRetries:
    def test_the_flag_reaches_the_agent_loop(self) -> None:
        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=loop.run_forever, daemon=True)
        thread.start()

        async def _read() -> bool:
            return in_validation_retry()

        try:
            with validation_retry():
                inside, _ = _submit_to_agent_loop(_read(), loop)
                assert inside.result(timeout=5) is True
            outside, _ = _submit_to_agent_loop(_read(), loop)
            assert outside.result(timeout=5) is False
        finally:
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=5)
            loop.close()


class TestARevisionAsksTheNoToolCallQuestionOncePerAnalyst:
    def test_the_second_revision_is_not_asked_again(self) -> None:
        analyst, llm = _analyst([REPORT, KEEP_REPLY, REPORT])
        analyst._revision_tooled = True
        turns = [SystemMessage(content="s"), HumanMessage(content="Revise.")]

        first = analyst.revision_answer(turns)
        second = analyst.revision_answer(turns)

        assert "CLAIM" in first and "CLAIM" in second
        # The first answer called no tool: asked once (two requests), then never again.
        assert len(llm.seen) == 3
        assert all(r["tools"] == ["decompile", "rename"] for r in llm.seen)


class TestEveryFallbackIsWordedForNoTools:
    def test_too_few_steps_sends_the_no_tools_prompt_and_no_attached_sentence(self) -> None:
        from maljan.pipeline.validation import analyst_feedback_closing

        analyst, llm = _analyst([FIXED])
        analyst._last_loop_steps_known = True
        analyst._last_loop_steps_left = 2
        question = analyst_feedback_closing(whole=True, tools=True)
        turns = [SystemMessage(content=TOOLS_STATED), HumanMessage(content=question)]

        analyst._answer_after_loop(turns, None, what=VALIDATION_RETRY_CALL, tools=True)

        sent = llm.seen[-1]["messages"]
        assert llm.seen[-1]["tools"] == []
        assert sent[0].content == NO_TOOLS_STATED
        assert "attached" not in str(sent[-1].content)
        assert sent[-1].content == analyst_feedback_closing(whole=True)

    def test_the_drops_sentence_comes_off_too(self) -> None:
        analyst, _llm = _analyst([])
        text = f"items\n{RETRY_DROP_TOOLS_ATTACHED}\nFor each item, write one line."
        turns = [SystemMessage(content=TOOLS_STATED), HumanMessage(content=text)]

        out = analyst._tools_free_turns(turns)

        assert out[0].content == NO_TOOLS_STATED
        assert out[-1].content == "items\nFor each item, write one line."


class TestTheAskedBlocksAreThoseTheQuestionsNamed:
    def test_the_first_answer_is_read_at_the_ledger_the_feedback_saw(self) -> None:
        from maljan.pipeline.function_claims import FUNCTION_CLAIM_UNHELD_CODE

        first = "CLAIM: it reads a file\nEVIDENCE: [ev_0500]\nCONFIDENCE: 0.6\nTECHNIQUE: T1005\n"
        retry = "CLAIM 1: it reads a file\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.6\nTECHNIQUE: T1005\n"
        analyst, _llm = _analyst([_call("decompile", "0x309c", "c1"), retry])
        isr = analyst._text_to_isr(first, 0)
        unheld = Violation(code=FUNCTION_CLAIM_UNHELD_CODE, message="its facts hold none of it")
        read: list[tuple[bool, int]] = []

        def _check(candidate: Any, *_a: Any) -> Any:
            read.append((candidate is isr, len(analyst._evidence_entries)))
            return MagicMock(flagged=[0], violations=[], checked=1, not_checked=[])

        answers = iter([[unheld], [unheld], []])
        with (
            patch("maljan.pipeline.validation.validate_isr", lambda *_a, **_k: next(answers, [])),
            patch("maljan.agents.base_agent.listed_functions", return_value={"0x1": object()}),
            patch("maljan.agents.base_agent.function_facts", return_value=object()),
            patch("maljan.agents.base_agent.check_function_claims", side_effect=_check),
        ):
            analyst._validate_isr(isr, "evidence")

        # The retry's own call grew the ledger to one entry; the first answer's
        # asked blocks were still read at the length the feedback saw.
        assert len(analyst._evidence_entries) == 1
        assert (True, 1) not in read
        assert (True, 0) in read


class TestTheRecordsGoOnTheAgentsOwnRow:
    def test_two_questions_after_a_callee_row_fold_into_the_stage_row(self) -> None:
        analyst, _llm = _analyst([])
        stage = {"stage": "analysis", "steps_used": 3}
        q1 = {"stage": "analysis", "steps_used": 1}
        callee = {"stage": "analysis", "steps_used": 2, "agent": "helper"}
        analyst._budget_records = [stage, q1, callee]
        analyst._fold_question_records(1)
        q2 = {"stage": "analysis", "steps_used": 1}
        analyst._budget_records = [*analyst._budget_records, q2]

        analyst._fold_question_records(2)

        assert analyst._budget_records == [{**stage, "asked_after": [q1, q2]}, callee]

    def test_a_note_goes_on_the_agent_s_row_not_a_callee_s(self) -> None:
        analyst, _llm = _analyst([])
        stage = {"stage": "analysis"}
        callee = {"stage": "analysis", "agent": "helper"}
        analyst._budget_records = [stage, callee]

        analyst._note_question_without_tools(VALIDATION_RETRY_CALL, "why")

        noted = {**stage, "asked_without_tools": [{"call": VALIDATION_RETRY_CALL, "why": "why"}]}
        assert analyst._budget_records == [noted, callee]


class TestTheRunSummaryShowsTheQuestions:
    def test_the_agent_s_budget_carries_its_questions_and_fallbacks(self) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder

        rows = [
            {
                "stage": "analysis",
                "steps_used": 5,
                "asked_after": [
                    {"steps_used": 3, "elapsed_s": 2.5, "cap": None},
                    {"steps_used": 2, "elapsed_s": 1.0, "cap": "steps"},
                ],
                "asked_without_tools": [{"call": WHOLE_ANSWER_RETRY_CALL, "why": "w"}],
            }
        ]

        budget = RunSummaryBuilder(0.0).set_budget({NAME: rows})._budget

        assert budget[NAME]["questions"] == {
            "asked": 2,
            "steps_used": 5,
            "elapsed_s": 3.5,
            "caps": ["steps"],
            "asked_without_tools": [{"call": WHOLE_ANSWER_RETRY_CALL, "why": "w"}],
        }


class TestTheStepsLeftAreThoseOfTheLatestLoop:
    def test_a_new_loop_and_a_revision_clear_a_stale_count(self) -> None:
        analyst, _llm = _analyst([REPORT])
        analyst._asked_about_tools = True
        analyst._last_loop_steps_known = True
        analyst._last_loop_steps_left = 1

        with patch("maljan.agents.base_agent.loop_limits", return_value=(None, 9)):
            analyst.execute_tool_loop([("system", "s"), ("human", "Analyse.")])
        assert analyst._last_loop_steps_left == 8

        analyst.revise_isr = MagicMock(side_effect=RuntimeError("stop"))  # type: ignore[method-assign]
        analyst._truncate_input = lambda data, *a, **k: data  # type: ignore[method-assign]
        with pytest.raises(Exception, match="stop"):
            analyst.safe_revise_isr("d", "r", {}, "f", 1)
        assert analyst._last_loop_steps_known is False

    def test_a_loop_with_no_step_limit_gives_the_question_none(self) -> None:
        analyst, _llm = _analyst([REPORT])
        analyst._asked_about_tools = True
        held: list[Any] = []

        def _loop(_m: Any, **kw: Any) -> str:
            held.append(kw["steps"])
            return FIXED

        with patch("maljan.agents.base_agent.loop_limits", return_value=(None, None)):
            analyst.execute_tool_loop([("system", "s"), ("human", "Analyse.")])
        assert analyst._last_loop_steps_known and analyst._last_loop_steps_left is None
        analyst.execute_tool_loop = _loop  # type: ignore[method-assign]
        analyst._answer_after_loop([], None, what=VALIDATION_RETRY_CALL, tools=True)
        assert held == [None]
