"""The judge, and every reader beside it, reads the text an answer says, thinking aside.

``ChatAnthropic`` keeps an answer whose first block is ``thinking`` (or
``redacted_thinking``) as the list of blocks the API returned. Read with
``str()``, that list is its own repr, signature and all: the judge never found
the bundle in it, asked once more at its output cap and ended in the text
fallback on every verdict. Every reader now goes through
``maljan.llm.answer_text.answer_text``; a string answer (OpenAI-compatible
providers, which keep reasoning apart) is read exactly as before.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import MagicMock

from langchain_core.messages import AIMessage, HumanMessage

from maljan.agents.judge_agent import JudgeAgent, _answer_text, _is_not_json

_BUNDLE = json.dumps(
    {
        "type": "bundle",
        "objects": [{"type": "malware", "id": "malware--1", "name": "x", "is_family": False}],
        "x_maljan_assessment": {"verdict": "Malware", "confidence": 0.85},
    }
)
_THINKING = {"type": "thinking", "thinking": "", "signature": "c2lnbmF0dXJl"}
_REDACTED = {"type": "redacted_thinking", "data": "b3BhcXVl"}


def _blocks(*parts: Any) -> AIMessage:
    return AIMessage(content=list(parts))


def _text(text: str) -> dict[str, str]:
    return {"type": "text", "text": text}


def _shapes(text: str) -> dict[str, AIMessage]:
    """One answer text in each shape a client hands it back in."""
    half = len(text) // 2
    return {
        "thinking first": _blocks(_THINKING, _text(text)),
        "redacted thinking first": _blocks(_REDACTED, _text(text)),
        "two text blocks": _blocks(_THINKING, _text(text[:half]), _text(text[half:])),
        "a tool block beside": _blocks(
            _THINKING, _text(text), {"type": "tool_use", "id": "t1", "name": "x", "input": {}}
        ),
    }


# What the platform mints on every parse, whatever the answer said.
_MINTED = frozenset({"id", "created", "modified"})


def _stable(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _stable(v) for k, v in value.items() if k not in _MINTED}
    if isinstance(value, list):
        return [_stable(v) for v in value]
    return value


def _dump(bundle: Any) -> dict[str, Any]:
    return _stable(bundle.model_dump(mode="json"))


class TestTheVerdictIsReadFromItsText:
    def test_every_block_shape_parses_to_the_bundle_a_plain_answer_does(self) -> None:
        judge = JudgeAgent(llm=MagicMock())
        plain = _dump(judge._bundle_from_response(AIMessage(content=_BUNDLE), {}, None))
        assert plain.get("x_maljan_fallback_verdict") is None
        assert plain["x_maljan_assessment"]["confidence"] == 0.85

        for name, answer in _shapes(_BUNDLE).items():
            parsed = _dump(JudgeAgent(llm=MagicMock())._bundle_from_response(answer, {}, None))
            assert parsed == plain, name

    def test_a_block_answer_holding_a_bundle_is_json(self) -> None:
        for name, answer in _shapes(_BUNDLE).items():
            assert _is_not_json(answer) is False, name
            assert _answer_text(answer) == _BUNDLE, name

    def test_a_string_answer_is_read_exactly_as_before(self) -> None:
        for text in (_BUNDLE, "  not json  ", ""):
            assert _answer_text(AIMessage(content=text)) == text
            assert _answer_text(text) == text
        assert _is_not_json(AIMessage(content="")) is True
        assert _is_not_json(AIMessage(content="prose")) is True

    def test_an_answer_of_thinking_alone_is_not_json(self) -> None:
        assert _answer_text(_blocks(_THINKING)) == ""
        assert _is_not_json(_blocks(_THINKING)) is True


class _Says:
    """A chat model whose every call answers with ``reply``."""

    def __init__(self, reply: AIMessage) -> None:
        self.reply = reply
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: Any, **_kwargs: Any) -> AIMessage:
        self.calls.append(list(messages))
        return self.reply

    def bind_tools(self, *_args: Any, **_kwargs: Any) -> _Says:
        return self


class TestTheMediatorsQuestionsAreReadFromTheirText:
    def test_the_block_question_s_answer_is_its_text(self) -> None:
        reply = _blocks(_THINKING, _text("CONTRADICTIONS: NONE\nagreement_confidence: 0.9"))
        judge = JudgeAgent(llm=_Says(reply))

        said = asyncio.run(
            judge._ask_for_contradictions_block([("human", "reports")], "The reasoning.")
        )

        assert said == "The reasoning.\n\nCONTRADICTIONS: NONE\nagreement_confidence: 0.9"
        assert "signature" not in said

    def test_a_question_the_judge_asks_in_its_loop_is_published_as_its_text(
        self, monkeypatch: Any
    ) -> None:
        import maljan.agents.judge_agent as judge_module

        judge = JudgeAgent(llm=MagicMock())
        published: list[str] = []
        monkeypatch.setattr(
            judge_module, "emit_judge_question", lambda _sink, **kw: published.append(kw["text"])
        )

        judge._publish_questions(
            [
                HumanMessage(content="reports"),
                _blocks(_THINKING, _text("Which analyst holds ev_0001?")),
            ],
            set(),
        )

        assert published == ["Which analyst holds ev_0001?"]


class TestTheOtherReadersReadTheText:
    def test_the_narrative_reads_the_answer_s_text(self) -> None:
        from maljan.reporting.narrative_agent import _message_text

        for name, answer in _shapes('{"summary": "s"}').items():
            assert _message_text(answer) == '{"summary": "s"}', name
        assert _message_text(AIMessage(content="plain")) == "plain"
        assert _message_text(None) == ""

    def test_a_correction_turn_sends_the_answer_back_as_it_came(self) -> None:
        from maljan.pipeline.validation import _with_feedback

        answer = _blocks(_THINKING, _text(_BUNDLE))
        turns = _with_feedback([HumanMessage(content="ask")], answer, [])

        assert turns[1].content == answer.content

    def test_a_correction_turn_leaves_a_tool_call_out_of_the_answer(self) -> None:
        from maljan.pipeline.validation import _with_feedback

        call = {"type": "tool_use", "id": "t1", "name": "x", "input": {}}
        answer = _blocks(_THINKING, _text(_BUNDLE), call)
        turns = _with_feedback([HumanMessage(content="ask")], answer, [])

        assert turns[1].content == [_THINKING, _text(_BUNDLE)]

    def test_a_correction_turn_after_a_string_answer_is_unchanged(self) -> None:
        from maljan.pipeline.validation import _with_feedback

        turns = _with_feedback([HumanMessage(content="ask")], AIMessage(content=_BUNDLE), [])

        assert turns[1].content == _BUNDLE
