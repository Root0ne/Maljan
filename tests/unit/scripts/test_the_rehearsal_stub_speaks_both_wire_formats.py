"""The rehearsal's stub model answers the vendors' own clients as their APIs would.

Each test drives the stub with the official SDK — ``anthropic`` and ``openai``
— on a loopback port, so a wire shape the stub gets wrong is a client that
fails here rather than a rehearsal that passes for the wrong reason: text and
thinking, tool calls, usage with its cache fields, every stop reason, a
streamed answer joined the same as a whole one, a server error the client
retries, and the simulated pace.
"""

from __future__ import annotations

import copy
import time
from typing import Any

import pytest
from scripts.rehearsal import wire
from scripts.rehearsal.stub_model import Pace, StubServer, StubState


class _Fixed:
    """A script answering every request with one reply, and a 500 first when asked."""

    model_name = "stub-model"

    def __init__(self, reply: wire.Reply, fail_first: bool = False) -> None:
        self.reply = reply
        self.fail_first = fail_first
        self.seen: list[wire.Request] = []

    def reset(self) -> None:
        self.seen.clear()

    def answer(self, request: wire.Request) -> tuple[str, wire.Reply, str]:
        self.seen.append(request)
        if self.fail_first and len(self.seen) == 1:
            return "analyst", wire.Reply(status=500, error="once"), "server_error_once"
        return "analyst", copy.deepcopy(self.reply), ""


def _stub(reply: wire.Reply, **kwargs: Any) -> tuple[StubServer, _Fixed]:
    script = _Fixed(reply, fail_first=kwargs.pop("fail_first", False))
    state = StubState(brain=script, **kwargs)  # type: ignore[arg-type]
    return StubServer(state).start(), script


TOOL = {
    "name": "pe_info",
    "description": "Read a PE header.",
    "input_schema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
}


class TestTheAnthropicMessagesApi:
    def _client(self, server: StubServer) -> Any:
        import anthropic

        return anthropic.Anthropic(base_url=server.root, api_key="not-a-key", max_retries=2)

    def test_text_thinking_and_usage(self) -> None:
        server, _ = _stub(wire.Reply(text="CLAIM: one", thinking="weighing", cached_tokens=5))
        try:
            message = self._client(server).messages.create(
                model="m",
                max_tokens=100,
                messages=[{"role": "user", "content": "the facts the run established " * 4}],
            )
        finally:
            server.stop()
        kinds = [block.type for block in message.content]
        assert kinds == ["thinking", "text"]
        assert message.content[1].text == "CLAIM: one"
        assert message.stop_reason == "end_turn"
        assert message.usage.cache_read_input_tokens == 5
        assert message.usage.cache_creation_input_tokens == 0
        assert message.usage.output_tokens > 0

    def test_a_streamed_answer_joins_to_the_same_message(self) -> None:
        call = wire.ToolCall("pe_info", {"path": "/x/sample_1.exe"})
        server, _ = _stub(wire.Reply(text="reading", thinking="plan", tool_calls=[call]))
        try:
            with self._client(server).messages.stream(
                model="m",
                max_tokens=100,
                tools=[TOOL],
                messages=[{"role": "user", "content": "go"}],
            ) as stream:
                message = stream.get_final_message()
        finally:
            server.stop()
        assert [block.type for block in message.content] == ["thinking", "text", "tool_use"]
        assert message.content[2].input == {"path": "/x/sample_1.exe"}
        assert message.stop_reason == "tool_use"
        assert message.usage.input_tokens > 0

    def test_a_cut_answer_stops_at_max_tokens_with_only_thinking(self) -> None:
        server, _ = _stub(wire.Reply(thinking="still thinking", stop="max_tokens"))
        try:
            message = self._client(server).messages.create(
                model="m", max_tokens=10, messages=[{"role": "user", "content": "go"}]
            )
        finally:
            server.stop()
        assert message.stop_reason == "max_tokens"
        assert [block.type for block in message.content] == ["thinking"]

    def test_tool_results_reach_the_script(self) -> None:
        server, script = _stub(wire.Reply(text="done"))
        try:
            self._client(server).messages.create(
                model="m",
                max_tokens=10,
                system="You are the static analyst.",
                tools=[TOOL],
                messages=[
                    {"role": "user", "content": "go"},
                    {
                        "role": "assistant",
                        "content": [
                            {"type": "tool_use", "id": "t1", "name": "pe_info", "input": {}}
                        ],
                    },
                    {
                        "role": "user",
                        "content": [
                            {"type": "tool_result", "tool_use_id": "t1", "content": "[ev_0026]"}
                        ],
                    },
                ],
            )
        finally:
            server.stop()
        (request,) = script.seen
        assert request.system == "You are the static analyst."
        assert request.tool_names == ["pe_info"]
        assert [r.text for r in request.tool_results] == ["[ev_0026]"]
        assert [c.name for c in request.tool_calls_made] == ["pe_info"]

    def test_one_server_error_is_retried_by_the_client(self) -> None:
        server, script = _stub(wire.Reply(text="answered"), fail_first=True)
        try:
            message = self._client(server).messages.create(
                model="m", max_tokens=10, messages=[{"role": "user", "content": "go"}]
            )
            statuses = [entry["status"] for entry in server.state.log]
        finally:
            server.stop()
        assert message.content[0].text == "answered"
        assert statuses == [500, 200]

    def test_the_models_api_describes_the_model(self) -> None:
        import httpx

        server, _ = _stub(wire.Reply(text="x"))
        try:
            answer = httpx.get(f"{server.root}/v1/models/claude-haiku-5-5").json()
        finally:
            server.stop()
        assert answer["type"] == "model"
        assert answer["max_input_tokens"] > 0
        assert answer["capabilities"]["effort"]["high"]["supported"] is True


class TestTheOpenAiChatCompletionsApi:
    def _client(self, server: StubServer) -> Any:
        import openai

        return openai.OpenAI(base_url=f"{server.root}/v1", api_key="not-a-key", max_retries=2)

    def test_text_reasoning_and_usage(self) -> None:
        server, _ = _stub(wire.Reply(text="CLAIM: one", thinking="weighing", cached_tokens=3))
        try:
            completion = self._client(server).chat.completions.create(
                model="m", messages=[{"role": "user", "content": "hello"}]
            )
        finally:
            server.stop()
        choice = completion.choices[0]
        assert choice.message.content == "CLAIM: one"
        assert choice.message.model_extra["reasoning_content"] == "weighing"
        assert choice.finish_reason == "stop"
        assert completion.usage.prompt_tokens_details.cached_tokens == 3
        assert completion.usage.completion_tokens_details.reasoning_tokens > 0

    def test_a_streamed_tool_call_with_usage(self) -> None:
        call = wire.ToolCall("pe_info", {"path": "/x/sample_1.exe"})
        server, _ = _stub(wire.Reply(thinking="plan", tool_calls=[call]))
        try:
            stream = self._client(server).chat.completions.create(
                model="m",
                messages=[{"role": "user", "content": "go"}],
                tools=[
                    {
                        "type": "function",
                        "function": {
                            "name": "pe_info",
                            "parameters": TOOL["input_schema"],
                        },
                    }
                ],
                stream=True,
                stream_options={"include_usage": True},
            )
            chunks = list(stream)
        finally:
            server.stop()
        arguments = "".join(
            part.function.arguments or ""
            for chunk in chunks
            for choice in chunk.choices
            for part in choice.delta.tool_calls or []
        )
        names = [
            part.function.name
            for chunk in chunks
            for choice in chunk.choices
            for part in choice.delta.tool_calls or []
            if part.function.name
        ]
        finishes = [c.finish_reason for chunk in chunks for c in chunk.choices if c.finish_reason]
        assert names == ["pe_info"]
        assert arguments == '{"path": "/x/sample_1.exe"}'
        assert finishes == ["tool_calls"]
        assert chunks[-1].usage is not None and chunks[-1].usage.completion_tokens > 0

    def test_a_cut_answer_finishes_on_length(self) -> None:
        server, _ = _stub(wire.Reply(thinking="still thinking", stop="max_tokens"))
        try:
            completion = self._client(server).chat.completions.create(
                model="m", messages=[{"role": "user", "content": "go"}], max_tokens=10
            )
        finally:
            server.stop()
        assert completion.choices[0].finish_reason == "length"
        assert completion.choices[0].message.content is None

    def test_one_server_error_is_retried_by_the_client(self) -> None:
        server, _ = _stub(wire.Reply(text="answered"), fail_first=True)
        try:
            completion = self._client(server).chat.completions.create(
                model="m", messages=[{"role": "user", "content": "go"}]
            )
            statuses = [entry["status"] for entry in server.state.log]
        finally:
            server.stop()
        assert completion.choices[0].message.content == "answered"
        assert statuses == [500, 200]


class TestThePace:
    def test_an_answer_takes_its_first_token_time_and_its_tokens_at_the_rate(self) -> None:
        import openai

        text = "x" * 400  # 100 tokens at four characters a token
        server, _ = _stub(wire.Reply(text=text), pace=Pace(0.2, 500.0))
        try:
            client = openai.OpenAI(base_url=f"{server.root}/v1", api_key="k", max_retries=0)
            started = time.monotonic()
            client.chat.completions.create(model="m", messages=[{"role": "user", "content": "a"}])
            elapsed = time.monotonic() - started
        finally:
            server.stop()
        assert elapsed >= 0.2 + 100 / 500.0

    @pytest.mark.parametrize("stream", [False, True])
    def test_no_pace_answers_at_once(self, stream: bool) -> None:
        import openai

        server, _ = _stub(wire.Reply(text="y" * 400))
        try:
            client = openai.OpenAI(base_url=f"{server.root}/v1", api_key="k", max_retries=0)
            started = time.monotonic()
            answer = client.chat.completions.create(
                model="m", messages=[{"role": "user", "content": "a"}], stream=stream
            )
            if stream:
                list(answer)
            elapsed = time.monotonic() - started
        finally:
            server.stop()
        assert elapsed < 2.0
