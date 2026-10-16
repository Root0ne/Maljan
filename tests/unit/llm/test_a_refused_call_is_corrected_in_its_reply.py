"""An answer that is nothing but a call the schema refuses is corrected in the call's reply.

The structured path offers the schema's tool. A model that calls it with
arguments the schema does not take, and writes no text, has answered with the
call: its arguments are what is read and what every finding is about. The
retry of such a kept answer offers the same tool again, so it sends that
answer back as it came, thinking first, and the correction is the call's
reply, marked as an error. The request only appends to the one answered, so
every thinking block it carries stays valid, and the model reads the arguments
the correction names. The reply is the conversation's last request, so it
writes no cache entry nothing would read.

A request that offers no tool is sent no call: a retry held under an output
bound says the call as text, and every retry that never offered the tool (the
judge's verdict loop, the reporters' manual path) keeps the shape it had, the
answer left out and the correction asked at the end of the user turn.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage

from maljan.llm.anthropic_history import LAST_REQUEST
from maljan.llm.tool_replies import NO_REPLY_RECORDED
from maljan.pipeline.validation import (
    FEEDBACK_PREAMBLE,
    SECTION_CUT_CODE,
    Violation,
    _with_feedback,
    with_calls_said,
)
from maljan.reporting.composer import ReportComposer, _message_text
from tests.unit.reporting.test_the_composer_writes_its_sections_at_once import (
    _answer,
    _isr,
    _report,
    _section_of,
)

from .anthropic_wire import Wire, _unmarked, install, message
from .test_a_structured_answer_in_text_is_kept import (
    _LEAD,
    FACTS,
    USAGE,
    _by_section,
    _in_text,
    _model,
    _section,
    _text_of,
    _thinking,
)


def _result_text(block: dict[str, Any]) -> str:
    content = block.get("content")
    if isinstance(content, str):
        return content
    return "".join(part.get("text", "") for part in content or [] if isinstance(part, dict))


def _markers(body: dict[str, Any]) -> list[tuple[int, int]]:
    """Where a request carries a cache breakpoint: (message, block) positions."""
    return [
        (m, b)
        for m, turn in enumerate(body["messages"])
        if isinstance(turn["content"], list)
        for b, block in enumerate(turn["content"])
        if isinstance(block, dict) and "cache_control" in block
    ]


class _RefusedCalls:
    """Each section's first answer calls its tool with an argument its schema refuses."""

    def __init__(self, *, calls: int = 1) -> None:
        self.calls: dict[str, list[dict[str, Any]]] = {}
        self.ids = iter(range(1, 10_000))
        self.per_answer = calls

    @staticmethod
    def refused(section: str) -> dict[str, Any]:
        if section == "introduction":
            return {"text": ["The schema takes a string here."]}
        return {**_answer(section), "evidence_refs": "ev_0001"}

    def __call__(self, body: dict[str, Any]) -> dict[str, Any]:
        section = _section(body) if _LEAD in _text_of(body) else ""
        if not body.get("tools") or section in self.calls:
            return _in_text(body)
        made = [
            {
                "type": "tool_use",
                "id": f"toolu_{next(self.ids):04d}",
                "name": body["tools"][0]["name"],
                "input": self.refused(section),
            }
            for _ in range(self.per_answer)
        ]
        self.calls[section] = made
        return message([_thinking(), *made], stop="tool_use", usage=USAGE)


def _compose(monkeypatch: pytest.MonkeyPatch, answer: Any, **patches: Any) -> tuple[Wire, Any]:
    wire = Wire(answer)
    install(monkeypatch, wire)
    report = _report()
    composer = ReportComposer(llm=_model(), per_section_timeout=60)
    for name, value in patches.items():
        monkeypatch.setattr(composer, name, value.__get__(composer))
    with patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=True):
        asyncio.run(composer.compose(report, _isr(), facts_block=FACTS, concurrent=True))
    return wire, report


def _retried(wire: Wire) -> dict[str, list[dict[str, Any]]]:
    return {s: b for s, b in _by_section(wire).items() if len(b) == 2}


class TestTheRetryOfAnAnswerThatIsACall:
    def test_the_answer_goes_back_whole_and_the_correction_is_its_reply(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        answers = _RefusedCalls()
        wire, report = _compose(monkeypatch, answers)
        retried = _retried(wire)
        assert {"introduction", "packing_obfuscation"} <= set(retried)
        for section, (first, retry) in retried.items():
            (call,) = answers.calls[section]
            assert retry["tools"] == first["tools"], section
            assert retry["system"] == first["system"], section
            assert _unmarked(retry["messages"][0]["content"]) == _unmarked(
                first["messages"][0]["content"]
            ), "the first turn is sent as it was"
            assert [m["role"] for m in retry["messages"]] == ["user", "assistant", "user"]
            sent = _unmarked(retry["messages"][1]["content"])
            assert [b["type"] for b in sent] == ["thinking", "tool_use"]
            assert (sent[1]["id"], sent[1]["input"]) == (call["id"], call["input"]), (
                "the arguments the findings are about are in front of the model"
            )
            (reply,) = retry["messages"][2]["content"]
            assert reply["type"] == "tool_result" and reply["tool_use_id"] == call["id"]
            assert reply["is_error"] is True
            said = _result_text(reply)
            assert said.startswith(FEEDBACK_PREAMBLE)
            assert "[composer.schema]" in said
        assert wire.refused == []
        assert wire.dropped == [], "every thinking block sent back stays valid"
        assert report.technical_analysis is not None
        assert report.technical_analysis.packing_obfuscation is not None

    def test_the_reply_writes_no_cache_entry_nothing_reads(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        wire, _report_ = _compose(monkeypatch, _RefusedCalls())
        retried = _retried(wire)
        # A section alone with its schema carries no breakpoint at all, as its
        # one request did before; a prose section reads the group's head only.
        assert _markers(retried["introduction"][1]) == []
        prose = retried["packing_obfuscation"][1]
        assert _markers(prose) == [(0, 0)], "only the shared head, which the group wrote"
        assert _markers(retried["packing_obfuscation"][0]) == [(0, 0)]

    def test_every_call_of_the_answer_is_answered_in_call_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        answers = _RefusedCalls(calls=2)
        wire, report = _compose(monkeypatch, answers)
        retried = _retried(wire)
        assert retried
        for section, (_first, retry) in retried.items():
            made = answers.calls[section]
            sent = _unmarked(retry["messages"][1]["content"])
            assert [b.get("id") for b in sent if b["type"] == "tool_use"] == [
                c["id"] for c in made
            ], "the turn goes back with both calls"
            replies = retry["messages"][2]["content"]
            assert [r["tool_use_id"] for r in replies] == [c["id"] for c in made]
            assert replies[0]["is_error"] is True
            assert _result_text(replies[0]).startswith(FEEDBACK_PREAMBLE), "the call read"
            assert _result_text(replies[1]) == NO_REPLY_RECORDED, "the provider's completion"
        assert wire.refused == [] and wire.dropped == []
        assert report.technical_analysis is not None

    def test_the_narrative_round_answers_its_call_the_same_way(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.reporting import narrative_agent
        from tests.unit.reporting.test_narrative_agent import _make_report, _valid_narrative

        thin = _valid_narrative().model_dump()
        thin["key_findings"] = thin["key_findings"][:1]
        call = {"type": "tool_use", "id": "toolu_narrative", "name": "", "input": thin}

        def reply(body: dict[str, Any]) -> dict[str, Any]:
            if len(body["messages"]) == 1:
                named = {**call, "name": body["tools"][0]["name"]}
                return message([_thinking(), named], stop="tool_use", usage=USAGE)
            text = {"type": "text", "text": _valid_narrative().model_dump_json()}
            return message([_thinking(), text], stop="end_turn", usage=USAGE)

        wire = Wire(reply)
        install(monkeypatch, wire)
        monkeypatch.setattr(narrative_agent, "structured_output_supported_for_llm", lambda _l: True)
        out = asyncio.run(narrative_agent.NarrativeAgent(llm=_model()).generate(_make_report()))
        assert out is not None and len(out.key_findings) >= 2
        first, retry = wire.bodies
        assert retry["tools"] == first["tools"]
        assert [m["role"] for m in retry["messages"]] == ["user", "assistant", "user"]
        sent = _unmarked(retry["messages"][1]["content"])
        assert [b["type"] for b in sent] == ["thinking", "tool_use"]
        assert sent[1]["input"] == thin
        (result,) = retry["messages"][2]["content"]
        assert result["tool_use_id"] == "toolu_narrative" and result["is_error"] is True
        assert "[narrative.schema] (key_findings)" in _result_text(result)
        assert _markers(retry) == []
        assert wire.refused == [] and wire.dropped == []


class TestARetryHeldUnderAnOutputBound:
    def test_no_call_reaches_a_request_offered_no_tool(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def bounded(self: ReportComposer, turns: Any, **kwargs: Any) -> tuple[int | None, str]:
            # The first call is unbounded; a retry is held under a bound.
            return (2048, "a test bound") if len(turns) > 2 else (None, "its output budget")

        answers = _RefusedCalls()
        wire, report = _compose(monkeypatch, answers, _call_limit=bounded)
        retried = _retried(wire)
        assert retried
        for section, (_first, retry) in retried.items():
            assert not retry.get("tools"), section
            kinds = [
                block.get("type")
                for turn in retry["messages"]
                if isinstance(turn["content"], list)
                for block in turn["content"]
            ]
            assert "tool_use" not in kinds and "tool_result" not in kinds, section
            assert [m["role"] for m in retry["messages"]] == ["user", "assistant", "user"]
            said = retry["messages"][1]["content"]
            said = said if isinstance(said, str) else "".join(b["text"] for b in said)
            assert json.loads(said) == answers.calls[section][0]["input"]
            assert retry["max_tokens"] == 2048
        assert wire.refused == []
        assert report.technical_analysis is not None


def _a_call(section: str = "", call_id: str = "call_1") -> AIMessage:
    """A plain model's answer that is nothing but a call: a real message, never a stand-in."""
    args = {**_answer(section), "evidence_refs": "ev_0001"} if section else {"path": "x"}
    return AIMessage(content="", tool_calls=[{"name": "write_it", "args": args, "id": call_id}])


def _shapes(sent: list[list[BaseMessage]]) -> list[list[type]]:
    return [[type(m) for m in turns] for turns in sent]


class TestARetryThatNeverOfferedTheToolKeepsItsShape:
    @pytest.mark.asyncio
    async def test_the_judge_verdict_loop(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent
        from tests.unit.agents.test_judge_verdict_validation import REPORTS, _bundle_json

        sent: list[list[BaseMessage]] = []

        class _Llm:
            async def ainvoke(self, messages: list[BaseMessage], **_: Any) -> AIMessage:
                sent.append(list(messages))
                return _a_call() if len(sent) == 1 else AIMessage(content=_bundle_json())

        verdict = await JudgeAgent(llm=_Llm()).give_verdict(reports=REPORTS, history=[])  # type: ignore[arg-type]
        assert verdict.retries == 1 and verdict.violations == []
        assert _shapes(sent) == [[SystemMessage, HumanMessage], [SystemMessage, HumanMessage]]
        assert FEEDBACK_PREAMBLE in str(sent[1][-1].content)

    def test_the_composer_manual_path(self) -> None:
        sent: dict[str, list[list[BaseMessage]]] = {}

        class _Plain:
            async def ainvoke(self, messages: list[BaseMessage], **_: Any) -> AIMessage:
                section = _section_of(messages)
                first = section not in sent
                sent.setdefault(section, []).append(list(messages))
                if first and section == "packing_obfuscation":
                    return _a_call(section)
                return AIMessage(content=json.dumps(_answer(section)))

        composer = ReportComposer(llm=_Plain(), per_section_timeout=30)  # type: ignore[arg-type]
        with patch(
            "maljan.reporting.composer.structured_output_supported_for_llm", return_value=False
        ):
            asyncio.run(composer.compose(_report(), _isr(), concurrent=False))
        asked = sent["packing_obfuscation"]
        assert _shapes(asked) == [[SystemMessage, HumanMessage], [SystemMessage, HumanMessage]]
        assert "[composer.schema] (evidence_refs)" in str(asked[1][-1].content)

    def test_the_narrative_manual_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from maljan.reporting import narrative_agent
        from tests.unit.reporting.test_narrative_agent import _make_report, _valid_narrative

        thin = _valid_narrative().model_dump()
        thin["key_findings"] = thin["key_findings"][:1]
        sent: list[list[BaseMessage]] = []

        class _Plain:
            async def ainvoke(self, messages: list[BaseMessage], **_: Any) -> AIMessage:
                sent.append(list(messages))
                if len(sent) == 1:
                    call = {"name": "write_it", "args": thin, "id": "call_1"}
                    return AIMessage(content="", tool_calls=[call])
                return AIMessage(content=_valid_narrative().model_dump_json())

        monkeypatch.setattr(
            narrative_agent, "structured_output_supported_for_llm", lambda _l: False
        )
        out = asyncio.run(narrative_agent.NarrativeAgent(llm=_Plain()).generate(_make_report()))  # type: ignore[arg-type]
        assert out is not None
        assert _shapes(sent) == [[SystemMessage, HumanMessage], [SystemMessage, HumanMessage]]
        assert "[narrative.schema] (key_findings)" in str(sent[1][-1].content)


def _call_answer(call_id: str = "toolu_1", calls: int = 1) -> AIMessage:
    args = {"body": "x", "evidence_refs": "ev_0001"}
    made = [
        {"name": "_ProseOut", "args": {**args, "n": n}, "id": f"{call_id}{'' if n == 0 else n}"}
        for n in range(calls)
    ]
    if calls == 1:
        made[0]["args"] = args
    return AIMessage(
        content=[
            {"type": "thinking", "thinking": "", "signature": "sig"},
            *(
                {"type": "tool_use", "id": c["id"], "name": c["name"], "input": c["args"]}
                for c in made
            ),
        ],
        tool_calls=[{**c, "type": "tool_call"} for c in made],
    )


_FOUND = [Violation(code="composer.schema", message="is not a list", path="evidence_refs")]
_ASKED = [SystemMessage(content="rules"), HumanMessage(content="Write the section.")]


class TestTheCorrectionTurn:
    def test_the_conversation_only_grows(self) -> None:
        answer = _call_answer()
        turns = _with_feedback(list(_ASKED), answer, _FOUND, reply_to_calls=True)
        assert turns[:2] == _ASKED
        assert turns[2] is answer, "the answer goes back as it came"
        reply = turns[3]
        assert isinstance(reply, ToolMessage) and len(turns) == 4
        assert (reply.tool_call_id, reply.status) == ("toolu_1", "error")
        assert reply.content.startswith(FEEDBACK_PREAMBLE)
        assert "[composer.schema] (evidence_refs) is not a list" in reply.content
        assert reply.response_metadata == {LAST_REQUEST: True}, "nothing sends it again"

    def test_a_reply_a_later_retry_sends_again_is_not_the_last_request(self) -> None:
        turns = _with_feedback(
            list(_ASKED), _call_answer(), _FOUND, reply_to_calls=True, sent_again=True
        )
        assert turns[3].response_metadata == {}

    def test_a_retry_that_offers_no_tool_is_sent_no_call(self) -> None:
        turns = _with_feedback(list(_ASKED), _call_answer(), _FOUND)
        assert [type(t) for t in turns] == [SystemMessage, HumanMessage]
        assert str(turns[-1].content).startswith("Write the section.\n\n" + FEEDBACK_PREAMBLE)

    def test_a_described_answer_is_still_left_out(self) -> None:
        cut = [Violation(code=SECTION_CUT_CODE, message="cut at the cap")]
        turns = _with_feedback(
            list(_ASKED), _call_answer(), cut, keep_answer=False, reply_to_calls=True
        )
        assert len(turns) == 2 and isinstance(turns[-1], HumanMessage)
        assert "cut at the cap" in str(turns[-1].content)

    def test_a_call_with_no_id_is_left_out_as_before(self) -> None:
        answer = AIMessage(
            content="", tool_calls=[{"name": "_ProseOut", "args": {"body": "x"}, "id": ""}]
        )
        turns = _with_feedback(list(_ASKED), answer, _FOUND, reply_to_calls=True)
        assert len(turns) == 2 and not any(isinstance(t, ToolMessage) for t in turns)
        assert FEEDBACK_PREAMBLE in str(turns[-1].content)

    def test_said_as_text_the_call_keeps_its_arguments(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.pipeline import validation

        said: list[str] = []
        monkeypatch.setattr(validation.logger, "info", lambda msg, *a: said.append(msg % a))
        asked = _with_feedback(list(_ASKED), _call_answer(), _FOUND, reply_to_calls=True)
        turns = with_calls_said(asked)
        assert [type(t) for t in turns] == [SystemMessage, HumanMessage, AIMessage, HumanMessage]
        assert json.loads(str(turns[2].content)) == {"body": "x", "evidence_refs": "ev_0001"}
        assert not turns[2].tool_calls
        assert str(turns[3].content).startswith(FEEDBACK_PREAMBLE)
        assert [line for line in said if "tool call(s) _ProseOut (toolu_1) are said" in line]

    def test_every_call_is_said_and_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from maljan.pipeline import validation

        said: list[str] = []
        monkeypatch.setattr(validation.logger, "info", lambda msg, *a: said.append(msg % a))
        answer = _call_answer(calls=2)
        turns = with_calls_said(_with_feedback(list(_ASKED), answer, _FOUND, reply_to_calls=True))
        text = str(turns[2].content)
        assert [json.loads(part) for part in text.split("\n\n")] == [
            call["args"] for call in answer.tool_calls
        ]
        assert [line for line in said if "_ProseOut (toolu_1), _ProseOut (toolu_11)" in line]

    def test_a_history_with_no_call_is_sent_as_it_is(self) -> None:
        turns = [*_ASKED, AIMessage(content="{}"), HumanMessage(content="Fix it.")]
        assert with_calls_said(turns) is turns

    def test_the_arguments_count_toward_the_retry_size(self) -> None:
        answer = _call_answer()
        assert _message_text(answer) == json.dumps(answer.tool_calls[0]["args"])
        assert _message_text(HumanMessage(content="abc")) == "abc"
