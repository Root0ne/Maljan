"""An answer that is nothing but a call the schema refuses is corrected in the call's reply.

The structured path offers the schema's tool. A model that calls it with
arguments the schema does not take, and writes no text, has answered with the
call: its arguments are what is read and what every finding is about. The
retry sends that answer back as it came, thinking first, and the correction is
the call's reply, marked as an error. The request only appends to the one
answered, so every thinking block it carries stays valid, and the model reads
the arguments the correction names. A retry held under an output bound goes by
the plain model, which is offered no tool: there the call is said as text.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

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


class _RefusedCalls:
    """Each section's first answer calls its tool with an argument its schema refuses."""

    def __init__(self) -> None:
        self.calls: dict[str, dict[str, Any]] = {}
        self.ids = iter(range(1, 10_000))

    def __call__(self, body: dict[str, Any]) -> dict[str, Any]:
        section = _section(body) if _LEAD in _text_of(body) else ""
        if not body.get("tools") or section in self.calls:
            return _in_text(body)
        call = {
            "type": "tool_use",
            "id": f"toolu_{next(self.ids):04d}",
            "name": body["tools"][0]["name"],
            "input": {**_answer(section), "evidence_refs": "ev_0001"},
        }
        self.calls[section] = call
        return message([_thinking(), call], stop="tool_use", usage=USAGE)


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


class TestTheRetryOfAnAnswerThatIsACall:
    def test_the_answer_goes_back_whole_and_the_correction_is_its_reply(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        answers = _RefusedCalls()
        wire, report = _compose(monkeypatch, answers)
        retried = {s: b for s, b in _by_section(wire).items() if len(b) == 2}
        assert retried, "the refused arguments leave a schema finding to ask about"
        for section, (first, retry) in retried.items():
            call = answers.calls[section]
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
            assert "[composer.schema] (evidence_refs)" in said
        assert wire.refused == []
        assert wire.dropped == [], "every thinking block sent back stays valid"
        assert report.technical_analysis is not None
        assert report.technical_analysis.packing_obfuscation is not None

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
        retried = {s: b for s, b in _by_section(wire).items() if len(b) == 2}
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
            assert json.loads(said) == answers.calls[section]["input"]
            assert retry["max_tokens"] == 2048
        assert wire.refused == []
        assert report.technical_analysis is not None


def _call_answer(call_id: str = "toolu_1") -> AIMessage:
    args = {"body": "x", "evidence_refs": "ev_0001"}
    return AIMessage(
        content=[
            {"type": "thinking", "thinking": "", "signature": "sig"},
            {"type": "tool_use", "id": call_id, "name": "_ProseOut", "input": args},
        ],
        tool_calls=[{"name": "_ProseOut", "args": args, "id": call_id, "type": "tool_call"}],
    )


_FOUND = [Violation(code="composer.schema", message="is not a list", path="evidence_refs")]
_ASKED = [SystemMessage(content="rules"), HumanMessage(content="Write the section.")]


class TestTheCorrectionTurn:
    def test_the_conversation_only_grows(self) -> None:
        answer = _call_answer()
        turns = _with_feedback(list(_ASKED), answer, _FOUND)
        assert turns[:2] == _ASKED
        assert turns[2] is answer, "the answer goes back as it came"
        reply = turns[3]
        assert isinstance(reply, ToolMessage) and len(turns) == 4
        assert (reply.tool_call_id, reply.status) == ("toolu_1", "error")
        assert reply.content.startswith(FEEDBACK_PREAMBLE)
        assert "[composer.schema] (evidence_refs) is not a list" in reply.content

    def test_a_described_answer_is_still_left_out(self) -> None:
        cut = [Violation(code=SECTION_CUT_CODE, message="cut at the cap")]
        turns = _with_feedback(list(_ASKED), _call_answer(), cut, keep_answer=False)
        assert len(turns) == 2 and isinstance(turns[-1], HumanMessage)
        assert "cut at the cap" in str(turns[-1].content)

    def test_a_call_with_no_id_is_left_out_as_before(self) -> None:
        answer = _call_answer(call_id="")
        turns = _with_feedback(list(_ASKED), answer, _FOUND)
        assert len(turns) == 2 and not any(isinstance(t, ToolMessage) for t in turns)
        assert FEEDBACK_PREAMBLE in str(turns[-1].content)

    def test_said_as_text_the_call_keeps_its_arguments(self) -> None:
        turns = with_calls_said(_with_feedback(list(_ASKED), _call_answer(), _FOUND))
        assert [type(t) for t in turns] == [SystemMessage, HumanMessage, AIMessage, HumanMessage]
        assert json.loads(str(turns[2].content)) == {"body": "x", "evidence_refs": "ev_0001"}
        assert not turns[2].tool_calls
        assert str(turns[3].content).startswith(FEEDBACK_PREAMBLE)

    def test_a_history_with_no_call_is_sent_as_it_is(self) -> None:
        turns = [*_ASKED, AIMessage(content="{}"), HumanMessage(content="Fix it.")]
        assert with_calls_said(turns) is turns

    def test_the_arguments_count_toward_the_retry_size(self) -> None:
        answer = _call_answer()
        assert _message_text(answer) == json.dumps(answer.tool_calls[0]["args"])
        assert _message_text(HumanMessage(content="abc")) == "abc"
