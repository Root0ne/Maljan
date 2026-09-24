"""Each request is the previous one without its run-state block, plus new turns and the block.

A provider's prefix cache (and a local server's reuse of what it has already
read) holds only while the front of a request is byte-identical to the front of
the one before it. The run-state block counts its budget down on every turn of
a tool loop, so it rides at the end of the request's last message — the task,
the latest tool answer, the question a nudge, a salvage or a retry asks — and
comes off that message again once it is no longer last, leaving the message's
bytes as they were. Take the block off one request's last message and what is
left is, byte for byte, the front of the next request.

And the shape every chat format accepts: no request has two user turns in a
row, and none has a message that holds only the block.

Checked on the serialized form a provider receives (OpenAI chat messages), for
every request that carries the run state: an analyst's tool loop, its nudge,
its forced synthesis, its validation retry and its revision, the judge's tool
loop, and the composer's retry.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
    convert_to_openai_messages,
)
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import (
    FINAL_ANSWER_NUDGE,
    BaseAnalyst,
    frame_messages,
    prompt_to_messages,
    without_run_state,
)
from maljan.agents.judge_agent import JudgeAgent
from maljan.pipeline.run_state import (
    RUN_STATE_BEGIN,
    RUN_STATE_END,
    is_run_state_block,
    without_run_state_tail,
)
from maljan.pipeline.triage_pack import PACK_HEADING
from maljan.pipeline.validation import Violation, retry_with_feedback

FACTS = f"{PACK_HEADING}\n[ev_0001] identity: pe windows"
RUN_STATE = "sample: c\nledger: 1 entries (ev_0001), 1 from the triage pack"
REPORT = "CLAIM: it reads a file\nEVIDENCE: ev_0002\nCONFIDENCE: 0.6\nTECHNIQUE: T1005\n"
SYSTEM = "You are a static analyst."


def _asks_for_the_answer(message: Any) -> bool:
    text = str(getattr(message, "content", ""))
    return "Return your final ISR now" in text or "Do NOT request" in text


class _Scripted(BaseChatModel):
    """Calls ``lookup`` for its first ``calls`` turns, then says ``answer``; records requests.

    Asked by a nudge or a salvage, it writes the report.
    """

    calls: int = 3
    answer: str = REPORT
    seen: list = []

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        sent = list(messages)
        self.seen.append(sent)
        made = sum(1 for m in sent if isinstance(m, AIMessage) and m.tool_calls)
        if _asks_for_the_answer(sent[-1]):
            turn = AIMessage(content=REPORT)
        elif made < self.calls:
            turn = AIMessage(
                content="",
                tool_calls=[{"name": "lookup", "args": {"what": f"w{made}"}, "id": f"c{made}"}],
            )
        else:
            turn = AIMessage(content=self.answer)
        return ChatResult(generations=[ChatGeneration(message=turn)])

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


class _What(BaseModel):
    what: str = ""


def _lookup_tool() -> StructuredTool:
    def _lookup(what: str = "") -> str:
        return f"answer for {what}"

    return StructuredTool.from_function(
        func=_lookup, name="lookup", description="Look it up.", args_schema=_What
    )


def _wire(messages: list[Any]) -> list[dict[str, Any]]:
    """The request as a provider receives it."""
    return list(convert_to_openai_messages(messages))


def _text_of(entry: dict[str, Any]) -> str:
    content = entry.get("content")
    if isinstance(content, list):
        return "".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
    return str(content or "")


def _without_the_block_on_the_last(wire: list[dict[str, Any]]) -> list[str]:
    """The serialized request with the block taken off its last message."""
    out = [dict(entry) for entry in wire]
    last = out[-1]
    content = last.get("content")
    if isinstance(content, str):
        last["content"] = without_run_state_tail(content)
    elif isinstance(content, list) and content:
        tail = content[-1]
        if isinstance(tail, dict) and is_run_state_block(tail.get("text")):
            last["content"] = content[:-1]
    return [json.dumps(entry, sort_keys=True) for entry in out]


def _assert_each_request_extends_the_last(requests: list[list[Any]]) -> None:
    assert len(requests) >= 2, "one request proves nothing about the next"
    for earlier, later in zip(requests, requests[1:], strict=False):
        head = _without_the_block_on_the_last(_wire(earlier))
        whole = [json.dumps(entry, sort_keys=True) for entry in _wire(later)]
        assert whole[: len(head)] == head
        assert len(whole) > len(head)


def _assert_the_shape_every_template_takes(request: list[Any]) -> None:
    wire = _wire(request)
    roles = [entry["role"] for entry in wire]
    for first, second in zip(roles, roles[1:], strict=False):
        assert not (first == "user" and second == "user"), roles
    for entry in wire:
        assert not is_run_state_block(_text_of(entry)), "a message holds only the block"
    # The block is on the last message, once, and nowhere else.
    carriers = [i for i, entry in enumerate(wire) if RUN_STATE_BEGIN in _text_of(entry)]
    if carriers:
        assert carriers == [len(wire) - 1]
        assert _text_of(wire[-1]).endswith(RUN_STATE_END)


class _Analyst(BaseAnalyst):
    def __init__(self, llm: Any) -> None:
        super().__init__(llm=llm, name="static")

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


def _analyst(model: _Scripted) -> _Analyst:
    agent = _Analyst(model)
    agent.facts_block = FACTS
    agent.run_state_block = RUN_STATE
    agent.tools = [_lookup_tool()]
    return agent


def _loop(answer: str = REPORT) -> list[list[Any]]:
    model = _Scripted(seen=[], answer=answer)
    _analyst(model).execute_tool_loop([("system", SYSTEM), ("human", "Analyse.")])
    return model.seen


class TestAnAnalystsToolLoop:
    def test_every_request_ends_on_the_current_block(self) -> None:
        requests = _loop()
        assert len(requests) == 4
        budgets = []
        for request in requests:
            last = str(request[-1].content)
            assert last.endswith(RUN_STATE_END)
            budgets.append(last.split("budget remaining: ")[1].split(",")[0])
        # The line the block exists for still counts down, turn by turn.
        assert len(set(budgets)) == len(budgets)

    def test_the_first_request_carries_it_on_the_task(self) -> None:
        first = _loop()[0]
        assert len(first) == 2
        assert str(first[1].content).startswith(f"{FACTS}\n\nAnalyse.\n\n{RUN_STATE_BEGIN}")

    def test_a_later_request_carries_it_on_the_latest_tool_answer(self) -> None:
        later = _loop()[1]
        assert isinstance(later[-1], ToolMessage)
        assert "answer for w0\n\n" + RUN_STATE_BEGIN in str(later[-1].content)
        # The task it rode on before is sent as it was written.
        assert str(later[1].content) == f"{FACTS}\n\nAnalyse."

    def test_each_request_is_the_last_one_plus_new_turns(self) -> None:
        _assert_each_request_extends_the_last(_loop())

    def test_the_system_turn_is_the_one_its_author_wrote(self) -> None:
        for request in _loop():
            assert request[0].content == SYSTEM


class TestAfterTheLoop:
    def test_the_nudge_carries_it_on_its_own_question(self) -> None:
        requests = _loop(answer="Let me look at one more thing.")
        nudge = requests[-1]
        assert str(nudge[-1].content).startswith(FINAL_ANSWER_NUDGE + "\n\n" + RUN_STATE_BEGIN)
        _assert_each_request_extends_the_last(requests)

    def test_the_synthesis_carries_it_on_its_directive(self) -> None:
        requests = _loop(answer="")
        salvage = requests[-1]
        assert "Do NOT request" in str(salvage[-1].content)
        assert str(salvage[-1].content).endswith(RUN_STATE_END)
        _assert_each_request_extends_the_last(requests)


class TestTheShapeEveryTemplateTakes:
    @pytest.mark.parametrize("answer", [REPORT, "Let me look at one more thing.", ""])
    def test_no_loop_request_has_two_user_turns_or_a_lone_block(self, answer: str) -> None:
        for request in _loop(answer):
            _assert_the_shape_every_template_takes(request)

    def test_nor_does_a_revision_or_a_validation_retry(self) -> None:
        agent = _analyst(_Scripted(seen=[]))
        revision = agent.frame_messages(
            prompt_to_messages([("system", SYSTEM), ("human", "YOUR ORIGINAL REPORT: ...")])
        )
        _assert_the_shape_every_template_takes(revision)
        _assert_the_shape_every_template_takes(self._validation_requests()[-1])

    def test_a_tool_answer_in_parts_gets_a_text_part_and_loses_it_again(self) -> None:
        parts = [{"type": "text", "text": "answer"}]
        tool = ToolMessage(content=list(parts), tool_call_id="c0")
        framed = frame_messages([SystemMessage(content=SYSTEM), tool], run_state=RUN_STATE)
        content = framed[-1].content
        assert isinstance(content, list) and content[:-1] == parts
        assert is_run_state_block(content[-1]["text"])
        assert without_run_state(framed)[-1].content == parts

    def test_a_text_the_block_came_off_is_the_text_it_was(self) -> None:
        for text in ("", "task", "task\n\n", "  a\nb  "):
            framed = frame_messages([HumanMessage(content=text)], run_state=RUN_STATE)
            assert without_run_state(framed)[0].content == text

    def test_a_conversation_ending_on_the_model_s_turn_gets_no_block(self) -> None:
        said = AIMessage(content="my answer")
        framed = frame_messages([HumanMessage(content="t"), said], run_state=RUN_STATE)
        assert framed[-1].content == "my answer"
        assert RUN_STATE_BEGIN not in str(framed[0].content)

    def _validation_requests(self) -> list[list[Any]]:
        framed = frame_messages(
            prompt_to_messages([("system", SYSTEM), ("human", "evidence")]),
            facts_block=FACTS,
            run_state=RUN_STATE,
        )
        requests: list[list[Any]] = []

        async def _run(turns: list[Any]) -> Any:
            sent = frame_messages(turns, run_state=RUN_STATE)
            requests.append(sent)
            return AIMessage(content=REPORT)

        told = iter([[Violation(code="isr.ungrounded_technique", message="cite")], []])
        asyncio.run(
            retry_with_feedback(
                _run, framed, [lambda _p: next(told, [])], parse=lambda a: a.content
            )
        )
        return requests


@contextlib.contextmanager
def _judge_settings() -> Iterator[None]:
    with patch("maljan.agents.judge_agent.get_settings") as settings:
        cfg = settings.return_value
        cfg.react_agent_timeout = 600
        cfg.react_agent_max_steps = 40
        cfg.llm.provider = "openai"
        cfg.llm.agents = {}
        cfg.llm.openai.context_size = 0
        yield


class TestTheJudgesToolLoop:
    def test_each_request_is_the_last_one_plus_new_turns(self) -> None:
        from maljan.agents.judge_agent import _standing_blocks

        model = _Scripted(seen=[], answer="agreement_confidence: 0.8")
        judge = JudgeAgent(llm=model)
        judge.tools = [_lookup_tool()]
        human = f"{_standing_blocks(RUN_STATE, FACTS)}Expert Reports:\nstatic: text"
        with _judge_settings():
            asyncio.run(judge.execute_tool_loop([("system", "You mediate."), ("human", human)]))
        assert len(model.seen) == 4
        _assert_each_request_extends_the_last(model.seen)


class TestTheRetries:
    def test_a_composer_retry_extends_the_first_request(self) -> None:
        """The composer's retry is ``retry_with_feedback`` over its first request."""
        from maljan.pipeline.run_state import with_run_state

        first = [
            SystemMessage(content="You write one report section."),
            HumanMessage(content=f"{with_run_state('', RUN_STATE)}\n\n{FACTS}\n\nWrite it."),
        ]
        requests: list[list[Any]] = []

        async def _run(turns: list[Any]) -> Any:
            requests.append(list(turns))
            return AIMessage(content='{"text": "x"}')

        told = iter([[Violation(code="composer.schema", message="fix it")], []])
        asyncio.run(
            retry_with_feedback(_run, first, [lambda _p: next(told, [])], parse=lambda a: a.content)
        )
        assert len(requests) == 2
        _assert_each_request_extends_the_last(requests)

    def test_an_analysts_validation_retry_moves_the_block_to_its_question(self) -> None:
        """Through the analyst's own retry, which frames each request it sends."""
        from maljan.agents import base_agent
        from maljan.schemas.isr_models import AgentISR, ClaimEvidence

        told = [Violation(code="isr.ungrounded_technique", message="cite ev_0001")]
        answers = iter([told, told, []])
        agent = _analyst(_Scripted(seen=[]))
        agent._system_prompt = lambda _default, tools=None: SYSTEM  # type: ignore[method-assign]
        sent: list[list[Any]] = []

        def _capture(turns: list[Any], timeout: int) -> AIMessage:
            sent.append(list(turns))
            return AIMessage(content=REPORT)

        agent._invoke_llm_with_timeout = _capture  # type: ignore[method-assign]
        isr = AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(claim="c", evidence_ref="x", confidence=0.5, technique_id="T1055")
            ],
        )
        with patch.object(base_agent, "validate_isr", lambda *_a, **_k: next(answers, [])):
            agent._validate_isr(isr, "the raw data")
        assert sent
        retry = sent[0]
        _assert_the_shape_every_template_takes(retry)
        assert str(retry[-1].content).endswith(RUN_STATE_END)
        # The evidence turn the block rode on at first is sent as it was written.
        assert RUN_STATE_BEGIN not in str(retry[1].content)


class TestAQuestionAfterAUserTurn:
    """Where a retry or a salvage asks right after a user turn, it asks at its end."""

    def test_the_question_ends_the_user_turn_with_its_own_text(self) -> None:
        from maljan.pipeline.turns import with_question

        turns = with_question([SystemMessage(content=SYSTEM), HumanMessage(content="task")], "Q?")
        assert [t.type for t in turns] == ["system", "human"]
        assert turns[-1].content == "task\n\nQ?"

    def test_after_a_model_turn_or_a_tool_answer_it_is_a_turn_of_its_own(self) -> None:
        from maljan.pipeline.turns import with_question

        for last in (AIMessage(content="said"), ToolMessage(content="r", tool_call_id="c")):
            turns = with_question([HumanMessage(content="task"), last], "Q?")
            assert turns[-1].type == "human" and turns[-1].content == "Q?"
            assert turns[-2] is last

    def test_a_block_on_that_turn_comes_off_and_one_block_ends_the_framed_request(self) -> None:
        from maljan.pipeline.turns import with_question

        framed = frame_messages([HumanMessage(content="task")], run_state=RUN_STATE)
        asked = frame_messages(with_question(framed, "Q?"), run_state=RUN_STATE)
        text = str(asked[-1].content)
        assert text.startswith("task\n\nQ?\n\n" + RUN_STATE_BEGIN)
        assert text.count(RUN_STATE_BEGIN) == 1

    def test_the_analyst_s_retry_after_an_answer_cut_at_its_cap(self) -> None:
        from maljan.agents import base_agent

        cap = 64
        cut = "CLAIM: one\nEVIDENCE: [ev_0001] x\nCONFIDENCE: 0.5\nTECHNIQUE: NONE\n---\nCLAIM: tw"
        agent = _analyst(_Scripted(seen=[]))
        agent.pack_ledger_ids = ["ev_0001"]
        sent: list[list[Any]] = []

        def _capture(turns: list[Any], timeout: float, **_: Any) -> str:
            sent.append(list(turns))
            return REPORT

        agent._invoke_llm_with_timeout = _capture  # type: ignore[method-assign]
        isr = agent._text_to_isr(cut, 0)
        with (
            patch.object(base_agent, "analyst_output_cap", return_value=cap),
            patch.object(base_agent, "validity_check_available", return_value=True),
            patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
        ):
            agent._record_usage(
                AIMessage(
                    content=cut,
                    usage_metadata={
                        "input_tokens": 10,
                        "output_tokens": cap,
                        "total_tokens": 10 + cap,
                    },
                )
            )
            agent._validate_isr(isr, "evidence")
        assert sent, "the cut answer was asked about"
        retry = sent[0]
        _assert_the_shape_every_template_takes(retry)
        assert "cut_at_output_cap" in str(retry[-1].content)
        assert all("CLAIM: tw" not in str(t.content) for t in retry), "the cut answer stays out"

    def test_the_synthesis_when_the_trim_kept_only_the_task(self) -> None:
        from maljan.agents import base_agent

        with patch.object(base_agent, "_trim_for_synthesis", lambda msgs, _budget: msgs[:2]):
            requests = _loop(answer="")
        salvage = requests[-1]
        _assert_the_shape_every_template_takes(salvage)
        assert [m.type for m in salvage] == ["system", "human"]
        assert "Do NOT request" in str(salvage[-1].content)
        assert str(salvage[-1].content).startswith(f"{FACTS}\n\nAnalyse.\n\n")

    def test_the_judge_s_salvage_when_the_trim_kept_only_the_task(self) -> None:
        from maljan.agents import judge_agent

        model = _Scripted(seen=[], calls=0, answer="agreement_confidence: 0.8")
        judge = JudgeAgent(llm=model)
        gathered = [
            SystemMessage(content="You mediate."),
            HumanMessage(content="Expert Reports: x"),
            AIMessage(content="", tool_calls=[{"name": "lookup", "args": {}, "id": "c0"}]),
            ToolMessage(content="r", tool_call_id="c0"),
        ]
        with (
            patch.object(judge_agent, "_trim_for_synthesis", lambda msgs, _budget: msgs[:2]),
            patch.object(judge_agent, "synthesis_budget_chars", return_value=1),
        ):
            asyncio.run(judge._reasoning_from_what_was_gathered(gathered, 10.0, None))
        (request,) = model.seen
        _assert_the_shape_every_template_takes(request)
        assert [m.type for m in request] == ["system", "human"]
        assert str(request[-1].content).startswith(
            "Expert Reports: x\n\nDo NOT call any more tools."
        )
