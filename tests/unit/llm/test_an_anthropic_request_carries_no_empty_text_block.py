"""No Anthropic request carries a text block that is empty or only whitespace.

The Messages API refuses one with a 400 ("messages: text content blocks must
be non-empty"). A paid run's report composer met it: a section's answer was
streamed, and LangChain joins a stream's chunks into a list that starts with
the empty string the opening chunk carried. The validation retry sent that
list back as the answer it corrects, ``ChatAnthropic`` turned the empty string
into an empty text block, and the section was skipped. The request hook every
Anthropic request goes through (``anthropic_history.prepared``) now leaves out
every such block, from every turn and from the system prompt, and a turn left
with nothing at all; every other block keeps its place.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage

from maljan.core.config import Settings
from maljan.llm.anthropic_history import Memory, prepared
from maljan.llm.anthropic_provider import AnthropicProvider
from maljan.pipeline.validation import Violation, _with_feedback

from .anthropic_wire import Wire, install, message

MARK = {"type": "ephemeral"}


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        llm={"provider": "anthropic", "anthropic": {"api_key": "test-anthropic-key"}},
    )


def _empty_text_blocks(body: dict[str, Any]) -> list[Any]:
    found = []
    system = body.get("system")
    for block in system if isinstance(system, list) else []:
        if block.get("type") == "text" and not str(block.get("text") or "").strip():
            found.append(("system", block))
    for index, turn in enumerate(body.get("messages") or []):
        content = turn.get("content")
        if isinstance(content, str) and not content.strip():
            found.append((index, content))
        for block in content if isinstance(content, list) else []:
            if block.get("type") == "text" and not str(block.get("text") or "").strip():
                found.append((index, block))
    return found


def _prepared(messages: list[Any], **payload: Any) -> dict[str, Any]:
    return prepared(
        {"model": "claude-haiku-5-5", "messages": messages, **payload},
        Memory(),
        bound=True,
        cache_marker=MARK,
    )


class TestAStreamedAnswerSentBack:
    """The paid run's shape, end to end through the provider and a stand-in API."""

    def test_the_validation_retry_reaches_the_api(self, monkeypatch: pytest.MonkeyPatch) -> None:
        answers = iter(
            [
                message(
                    [
                        {"type": "thinking", "thinking": "", "signature": "sig-1"},
                        {"type": "text", "text": '{"body": "first"}'},
                    ],
                    stop="end_turn",
                    usage={"input_tokens": 10, "output_tokens": 5},
                ),
                message(
                    [{"type": "text", "text": '{"body": "second"}'}],
                    stop="end_turn",
                    usage={"input_tokens": 12, "output_tokens": 5},
                ),
            ]
        )
        wire = Wire(lambda _body: next(answers))
        install(monkeypatch, wire)
        # The output cap a composer section had: past the SDK's unstreamed
        # bound, so the answer is streamed and joined by LangChain.
        llm = AnthropicProvider(_settings()).build_model(
            "claude-haiku-5-5", 0.0, max_tokens=128_000
        )
        first = [HumanMessage(content="write the section")]

        answer = asyncio.run(llm.ainvoke(first))
        assert wire.bodies[0].get("stream") is True
        assert isinstance(answer.content, list) and answer.content[0] == ""

        retry = _with_feedback(first, answer, [Violation(code="report.flow_voice", message="m")])
        asyncio.run(llm.ainvoke(retry))

        assert wire.refused == []
        assert _empty_text_blocks(wire.bodies[1]) == []
        sent = wire.bodies[1]["messages"][1]["content"]
        assert [block["type"] for block in sent] == ["thinking", "text"]
        assert sent[0]["signature"] == "sig-1"


class TestTheRequestHook:
    def test_an_empty_block_is_left_out_and_every_other_keeps_its_place(self) -> None:
        thinking = {"type": "thinking", "thinking": "", "signature": "s"}
        body = _prepared(
            [
                {"role": "user", "content": [{"type": "text", "text": "q"}]},
                {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": ""},
                        thinking,
                        {"type": "text", "text": " \n"},
                        {"type": "text", "text": "answer"},
                    ],
                },
                {"role": "user", "content": [{"type": "text", "text": "fix"}]},
            ]
        )

        assert body["messages"][1]["content"] == [thinking, {"type": "text", "text": "answer"}]
        assert _empty_text_blocks(body) == []

    def test_a_turn_left_with_nothing_is_left_out(self) -> None:
        body = _prepared(
            [
                {"role": "user", "content": "q"},
                {"role": "assistant", "content": "\n\n"},
                {"role": "user", "content": "fix"},
            ]
        )

        assert [turn["content"] for turn in body["messages"]] == ["q", "fix"]

    def test_a_turn_of_empty_blocks_is_left_out(self) -> None:
        body = _prepared(
            [
                {"role": "user", "content": "q"},
                {"role": "assistant", "content": [{"type": "text", "text": ""}]},
                {"role": "user", "content": "fix"},
            ]
        )

        assert [turn["role"] for turn in body["messages"]] == ["user", "user"]

    def test_an_empty_system_block_is_left_out(self) -> None:
        body = _prepared(
            [{"role": "user", "content": "q"}],
            system=[{"type": "text", "text": ""}, {"type": "text", "text": "rules"}],
        )

        assert body["system"] == [{"type": "text", "text": "rules"}]

    def test_a_model_that_binds_no_thinking_is_held_to_it_too(self) -> None:
        body = prepared(
            {
                "model": "claude-sonnet-4-20250514",
                "messages": [
                    {"role": "user", "content": "q"},
                    {
                        "role": "assistant",
                        "content": [{"type": "text", "text": ""}, {"type": "text", "text": "a"}],
                    },
                    {"role": "user", "content": "fix"},
                ],
            },
            Memory(),
            bound=False,
            cache_marker=MARK,
        )

        assert body["messages"][1]["content"] == [{"type": "text", "text": "a"}]

    def test_a_request_with_no_empty_block_is_sent_as_it_was_built(self) -> None:
        messages = [
            {"role": "user", "content": "q"},
            {"role": "assistant", "content": [{"type": "text", "text": "a"}]},
            {"role": "user", "content": "more"},
        ]
        before = json.dumps(messages, sort_keys=True)

        body = _prepared(messages)

        assert json.dumps(messages, sort_keys=True) == before
        assert [turn["role"] for turn in body["messages"]] == ["user", "assistant", "user"]
        assert body["messages"][1]["content"][0]["text"] == "a"

    def test_the_conversation_the_caller_keeps_is_never_touched(self) -> None:
        turn = AIMessage(content=["", {"type": "text", "text": "a"}])
        content = list(turn.content)
        kept = [{"role": "assistant", "content": [{"type": "text", "text": ""}, *content[1:]]}]

        _prepared([{"role": "user", "content": "q"}, *kept, {"role": "user", "content": "x"}])

        assert kept[0]["content"][0] == {"type": "text", "text": ""}
        assert turn.content == content

    def test_an_empty_text_block_in_a_tool_result_is_left_out(self) -> None:
        body = _prepared(
            [
                {"role": "user", "content": "q"},
                {
                    "role": "assistant",
                    "content": [{"type": "tool_use", "id": "t1", "name": "pe_info", "input": {}}],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "t1",
                            "content": [
                                {"type": "text", "text": ""},
                                {"type": "text", "text": "r"},
                            ],
                        },
                        {
                            "type": "tool_result",
                            "tool_use_id": "t2",
                            "content": [{"type": "text", "text": " "}],
                        },
                    ],
                },
            ]
        )

        first, second = body["messages"][2]["content"]
        assert first["content"] == [{"type": "text", "text": "r"}]
        assert "content" not in second and second["tool_use_id"] == "t2"


class TestNoLaterStepMakesOne:
    """``_shared_heads`` runs after the filter and splits a turn only where both parts hold text."""

    @staticmethod
    def _split(text: str, size: int) -> Any:
        body = prepared(
            {"model": "claude-haiku-5-5", "messages": [{"role": "user", "content": text}]},
            Memory(),
            bound=True,
            cache_marker=MARK,
            heads={text: size},
        )
        return body["messages"][0]["content"]

    def test_a_head_and_a_rest_that_hold_text_are_split(self) -> None:
        assert self._split("head\n\nrest", 6) == [
            {"type": "text", "text": "head\n\n", "cache_control": MARK},
            {"type": "text", "text": "rest"},
        ]

    def test_a_rest_of_whitespace_alone_leaves_the_turn_whole(self) -> None:
        assert self._split("head\n\n", 4) == "head\n\n"

    def test_a_head_of_whitespace_alone_leaves_the_turn_whole(self) -> None:
        assert self._split("\n\nrest", 2) == "\n\nrest"
