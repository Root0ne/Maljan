"""A tool call the clock left unrun reaches no provider's wire.

When the time cap ends a tool phase right after a model turn, that turn's calls
never ran, and a hosted provider refuses a transcript that carries a call with
no result. Taking the call off ``tool_calls`` is not enough: each provider's
own formatter reads the call from where its client put it — OpenAI's (and
llama.cpp's) from ``additional_kwargs["tool_calls"]``, Anthropic's from the
``tool_use`` block in the content, Gemini's from
``additional_kwargs["function_call"]``. Each case here is a message shaped the
way that client returns it, run through that provider's real formatter.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from maljan.agents.base_agent import without_unanswered_calls

TEXT = "Let me read a few more strings."


def _conversation(unrun: AIMessage, *, ran_id: str, ran_shape: dict[str, Any]) -> list[Any]:
    ran = AIMessage(**ran_shape)
    return [
        HumanMessage(content="look at it"),
        ran,
        ToolMessage(content="CreateMutexW", tool_call_id=ran_id, name="strings"),
        unrun,
    ]


def _call(call_id: str) -> dict[str, Any]:
    return {"name": "strings", "args": {"offset": 4}, "id": call_id, "type": "tool_call"}


class TestOpenAI:
    """``ChatOpenAI`` fills ``additional_kwargs["tool_calls"]`` on every tool-calling answer."""

    @staticmethod
    def _raw(call_id: str) -> dict[str, Any]:
        return {
            "id": call_id,
            "type": "function",
            "function": {"name": "strings", "arguments": json.dumps({"offset": 4})},
        }

    def _messages(self) -> list[Any]:
        unrun = AIMessage(
            content=TEXT,
            tool_calls=[_call("call_4")],
            additional_kwargs={"tool_calls": [self._raw("call_4")]},
        )
        return _conversation(
            unrun,
            ran_id="call_3",
            ran_shape={
                "content": "",
                "tool_calls": [_call("call_3")],
                "additional_kwargs": {"tool_calls": [self._raw("call_3")]},
            },
        )

    def test_the_unrun_call_leaves_the_request(self) -> None:
        from langchain_openai.chat_models.base import _convert_message_to_dict

        cleaned, dropped = without_unanswered_calls(self._messages())
        wire = [_convert_message_to_dict(message) for message in cleaned]

        assert dropped == 1
        sent_ids = {c["id"] for m in wire for c in (m.get("tool_calls") or [])}
        assert sent_ids == {"call_3"}, "only the call that ran is sent"
        assert wire[-1]["content"] == TEXT


class TestAnthropic:
    """``ChatAnthropic`` returns the call as a ``tool_use`` block beside the text."""

    def _messages(self) -> list[Any]:
        unrun = AIMessage(
            content=[
                {"type": "text", "text": TEXT},
                {"type": "tool_use", "id": "toolu_4", "name": "strings", "input": {"offset": 4}},
            ],
            tool_calls=[_call("toolu_4")],
        )
        return _conversation(
            unrun,
            ran_id="toolu_3",
            ran_shape={
                "content": [
                    {"type": "tool_use", "id": "toolu_3", "name": "strings", "input": {}},
                ],
                "tool_calls": [_call("toolu_3")],
            },
        )

    def test_the_unrun_call_leaves_the_request(self) -> None:
        from langchain_anthropic.chat_models import _format_messages

        cleaned, dropped = without_unanswered_calls(self._messages())
        _system, wire = _format_messages(cleaned)

        assert dropped == 1
        blocks = [
            block
            for message in wire
            for block in (message["content"] if isinstance(message["content"], list) else [])
            if isinstance(block, dict)
        ]
        used = {b["id"] for b in blocks if b.get("type") == "tool_use"}
        results = {b["tool_use_id"] for b in blocks if b.get("type") == "tool_result"}
        assert used == {"toolu_3"}, "only the call that ran is sent"
        assert used <= results, "every call sent has its result"
        assert any(b.get("type") == "text" and b.get("text") == TEXT for b in blocks)


class TestGemini:
    """``ChatGoogleGenerativeAI`` keeps the call in ``additional_kwargs["function_call"]``."""

    def _messages(self) -> list[Any]:
        unrun = AIMessage(
            content=TEXT,
            tool_calls=[_call("gemini_4")],
            additional_kwargs={
                "function_call": {"name": "strings", "arguments": json.dumps({"offset": 4})}
            },
        )
        return _conversation(
            unrun,
            ran_id="gemini_3",
            ran_shape={
                "content": "",
                "tool_calls": [_call("gemini_3")],
                "additional_kwargs": {
                    "function_call": {"name": "strings", "arguments": json.dumps({})}
                },
            },
        )

    def test_the_unrun_call_leaves_the_request(self) -> None:
        from langchain_google_genai.chat_models import _parse_chat_history

        cleaned, dropped = without_unanswered_calls(self._messages())
        _system, wire = _parse_chat_history(cleaned)

        assert dropped == 1
        last = wire[-1]
        assert last.role == "model"
        assert not any(getattr(part, "function_call", None) for part in last.parts), (
            "the unrun call is not sent"
        )
        assert any((getattr(part, "text", "") or "") == TEXT for part in last.parts)
        calls = [
            part.function_call
            for content in wire
            for part in content.parts
            if getattr(part, "function_call", None)
        ]
        assert len(calls) == 1, "the call that ran is still sent, with its result"
