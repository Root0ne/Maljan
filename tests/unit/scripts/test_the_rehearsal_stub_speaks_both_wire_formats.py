"""The rehearsal's stub model answers the vendors' own clients as their APIs do, refusals too.

Each test drives the stub with the official SDK — ``anthropic`` and ``openai``
— on a loopback port, so a wire shape the stub gets wrong is a client that
fails here rather than a rehearsal that passes for the wrong reason: text and
thinking (plain and redacted), tool calls, usage with its cache reads and
writes, every stop reason, a streamed answer joined the same as a whole one,
pings, errors typed by status with a request id, a 429 or 529 the client
retries, an error mid-stream, the cut at the request's own cap, the simulated
pace — and every request the real API refuses refused here the same way.
"""

from __future__ import annotations

import copy
import time
from typing import Any

import httpx
import pytest
from scripts.rehearsal import wire
from scripts.rehearsal.stub_model import Pace, StubServer, StubState

HAIKU = "claude-haiku-5-5"


class _Fixed:
    """A script answering every request with one reply, after any replies queued first."""

    def __init__(self, reply: wire.Reply, first: list[wire.Reply] | None = None) -> None:
        self.reply = reply
        self.first = list(first or [])
        self.seen: list[wire.Request] = []

    def reset(self) -> None:
        self.seen.clear()

    def answer(self, request: wire.Request) -> tuple[str, wire.Reply, str]:
        self.seen.append(request)
        if self.first:
            return "analyst", self.first.pop(0), "queued"
        return "analyst", copy.deepcopy(self.reply), ""


def _stub(reply: wire.Reply, **kwargs: Any) -> tuple[StubServer, _Fixed]:
    script = _Fixed(reply, kwargs.pop("first", None))
    state = StubState(brain=script, **kwargs)  # type: ignore[arg-type]
    return StubServer(state).start(), script


def _anthropic(server: StubServer, retries: int = 2) -> Any:
    import anthropic

    return anthropic.Anthropic(base_url=server.root, api_key="not-a-key", max_retries=retries)


def _openai(server: StubServer, retries: int = 2) -> Any:
    import openai

    return openai.OpenAI(base_url=f"{server.root}/v1", api_key="not-a-key", max_retries=retries)


TOOL = {
    "name": "pe_info",
    "description": "Read a PE header.",
    "input_schema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
}
USER = [{"role": "user", "content": "the facts the run established " * 4}]


class TestTheAnthropicMessagesApi:
    def test_text_thinking_and_usage(self) -> None:
        server, _ = _stub(wire.Reply(text="CLAIM: one", thinking="weighing"))
        try:
            message = _anthropic(server).messages.create(model=HAIKU, max_tokens=100, messages=USER)
        finally:
            server.stop()
        assert [block.type for block in message.content] == ["thinking", "text"]
        assert message.content[0].signature.startswith("stubsig-")
        assert message.content[1].text == "CLAIM: one"
        assert message.stop_reason == "end_turn"
        assert message.usage.output_tokens > 0
        assert message.usage.cache_creation is not None

    def test_a_streamed_answer_joins_to_the_same_message(self) -> None:
        call = wire.ToolCall("pe_info", {"path": "/x/sample_1.exe"})
        server, _ = _stub(wire.Reply(text="reading", thinking="plan", tool_calls=[call]))
        try:
            with _anthropic(server).messages.stream(
                model=HAIKU, max_tokens=100, tools=[TOOL], messages=USER
            ) as stream:
                message = stream.get_final_message()
        finally:
            server.stop()
        assert [block.type for block in message.content] == ["thinking", "text", "tool_use"]
        assert message.content[2].input == {"path": "/x/sample_1.exe"}
        assert message.stop_reason == "tool_use"
        assert message.usage.input_tokens > 0

    def test_a_stream_carries_pings(self) -> None:
        server, _ = _stub(wire.Reply(text="x" * 400))
        try:
            answer = httpx.post(
                f"{server.root}/v1/messages",
                headers={"x-api-key": "k", "anthropic-version": "2023-06-01"},
                json={"model": HAIKU, "max_tokens": 500, "messages": USER, "stream": True},
            )
        finally:
            server.stop()
        assert "event: ping" in answer.text
        assert answer.headers["request-id"].startswith("req_")

    @pytest.mark.parametrize("stop", ["refusal", "pause_turn", "context_window"])
    def test_every_stop_reason(self, stop: str) -> None:
        server, _ = _stub(wire.Reply(thinking="still thinking", stop=stop))
        try:
            message = _anthropic(server).messages.create(model=HAIKU, max_tokens=50, messages=USER)
        finally:
            server.stop()
        wanted = {"context_window": "model_context_window_exceeded"}.get(stop, stop)
        assert message.stop_reason == wanted

    def test_an_answer_longer_than_its_cap_is_cut_there(self) -> None:
        server, _ = _stub(wire.Reply(text="y" * 4000))
        try:
            message = _anthropic(server).messages.create(model=HAIKU, max_tokens=10, messages=USER)
        finally:
            server.stop()
        assert message.stop_reason == "max_tokens"
        assert message.usage.output_tokens <= 10

    def test_a_cached_prefix_is_written_then_read(self) -> None:
        system = [
            {
                "type": "text",
                "text": "The standing rules of the analysis. " * 600,
                "cache_control": {"type": "ephemeral", "ttl": "1h"},
            }
        ]
        server, _ = _stub(wire.Reply(text="ok"))
        try:
            client = _anthropic(server)
            first = client.messages.create(model=HAIKU, max_tokens=10, system=system, messages=USER)
            second = client.messages.create(
                model=HAIKU, max_tokens=10, system=system, messages=USER
            )
        finally:
            server.stop()
        assert first.usage.cache_creation_input_tokens > 0
        assert first.usage.cache_creation.ephemeral_1h_input_tokens > 0
        assert first.usage.cache_read_input_tokens == 0
        assert second.usage.cache_read_input_tokens == first.usage.cache_creation_input_tokens
        assert second.usage.cache_creation_input_tokens == 0

    @pytest.mark.parametrize(("model", "cached"), [(HAIKU, False), ("claude-sonnet-4-5", True)])
    def test_a_prefix_shorter_than_the_model_s_minimum_is_not_cached(
        self, model: str, cached: bool
    ) -> None:
        system = [
            {
                "type": "text",
                "text": "Rules. " * 1200,  # about 2,100 tokens: past 1,024, short of 4,096
                "cache_control": {"type": "ephemeral"},
            }
        ]
        server, _ = _stub(wire.Reply(text="ok"))
        try:
            client = _anthropic(server)
            client.messages.create(model=model, max_tokens=10, system=system, messages=USER)
            second = client.messages.create(
                model=model, max_tokens=10, system=system, messages=USER
            )
        finally:
            server.stop()
        assert (second.usage.cache_read_input_tokens > 0) is cached

    def test_a_thinking_block_replayed_whole_is_taken_and_a_changed_one_refused(self) -> None:
        import anthropic

        server, _ = _stub(wire.Reply(text="answer", thinking="weighing"))
        try:
            client = _anthropic(server)
            first = client.messages.create(model=HAIKU, max_tokens=50, messages=USER)
            turn = [block.model_dump(exclude_none=True) for block in first.content]
            history = [*USER, {"role": "assistant", "content": turn}]
            client.messages.create(
                model=HAIKU, max_tokens=50, messages=[*history, {"role": "user", "content": "more"}]
            )
            edited = [{"role": "user", "content": "a different first turn"}, history[1]]
            with pytest.raises(anthropic.BadRequestError, match="Invalid `signature`"):
                client.messages.create(
                    model=HAIKU,
                    max_tokens=50,
                    messages=[*edited, {"role": "user", "content": "more"}],
                )
            dropped = client.beta.messages.create(
                model=HAIKU,
                max_tokens=50,
                messages=[*edited, {"role": "user", "content": "more"}],
                thinking={
                    "type": "adaptive",
                    "block_binding": {"prefix_mismatch_behavior": "drop_block"},
                },
                betas=["thinking-binding-controls-2026-08-01"],
            )
        finally:
            server.stop()
        assert dropped.content

    def test_a_tool_turn_sent_back_without_its_thinking_block_is_refused(self) -> None:
        import anthropic

        call = wire.ToolCall("pe_info", {"path": "/x/sample_1.exe"})
        server, _ = _stub(wire.Reply(thinking="plan", tool_calls=[call]))
        try:
            client = _anthropic(server)
            first = client.messages.create(model=HAIKU, max_tokens=100, tools=[TOOL], messages=USER)
            turn = [block.model_dump(exclude_none=True) for block in first.content]
            use = next(block for block in turn if block["type"] == "tool_use")
            answer = {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": use["id"], "content": "[ev_0026]"}
                ],
            }
            kept = [*USER, {"role": "assistant", "content": turn}, answer]
            client.messages.create(model=HAIKU, max_tokens=100, tools=[TOOL], messages=kept)
            stripped = [*USER, {"role": "assistant", "content": [use]}, answer]
            with pytest.raises(
                anthropic.BadRequestError, match="Expected `thinking` or `redacted_thinking`"
            ):
                client.messages.create(model=HAIKU, max_tokens=100, tools=[TOOL], messages=stripped)
            # With thinking off the API takes the turn without its thinking block.
            client.messages.create(
                model=HAIKU,
                max_tokens=100,
                tools=[TOOL],
                messages=stripped,
                thinking={"type": "disabled"},
            )
        finally:
            server.stop()

    def test_a_held_call_is_listed_while_held_and_let_go_when_the_stub_stops(self) -> None:
        import threading

        import anthropic

        server, _ = _stub(wire.Reply(text="late", delay=600.0))
        failures: list[BaseException] = []

        def ask() -> None:
            try:
                _anthropic(server, retries=0).messages.create(
                    model=HAIKU, max_tokens=50, messages=USER
                )
            except anthropic.APIError as exc:
                failures.append(exc)

        caller = threading.Thread(target=ask)
        caller.start()
        deadline = time.monotonic() + 10
        while not server.state.waiting and time.monotonic() < deadline:
            time.sleep(0.05)
        assert [c.get("waiting") for c in server.state.calls()] == [True]
        started = time.monotonic()
        server.stop()
        caller.join(timeout=15)
        assert time.monotonic() - started < 10
        assert not caller.is_alive() and failures
        assert server.state.log[-1]["stop"] == "stopped"

    def test_a_redacted_block_replays_as_received(self) -> None:
        server, _ = _stub(wire.Reply(text="answer", thinking="weighing", redacted=True))
        try:
            client = _anthropic(server)
            first = client.messages.create(model=HAIKU, max_tokens=500, messages=USER)
            assert first.content[0].type == "redacted_thinking"
            turn = [block.model_dump(exclude_none=True) for block in first.content]
            client.messages.create(
                model=HAIKU,
                max_tokens=50,
                messages=[
                    *USER,
                    {"role": "assistant", "content": turn},
                    {"role": "user", "content": "go on"},
                ],
            )
        finally:
            server.stop()

    def test_tool_results_reach_the_script(self) -> None:
        server, script = _stub(wire.Reply(text="done"))
        try:
            _anthropic(server).messages.create(
                model=HAIKU,
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
        assert [r.text for r in request.tool_results] == ["[ev_0026]"]
        assert [c.name for c in request.tool_calls_made] == ["pe_info"]

    @pytest.mark.parametrize(
        ("change", "said"),
        [
            (
                {
                    "messages": [
                        {"role": "user", "content": "go"},
                        {
                            "role": "assistant",
                            "content": [
                                {"type": "tool_use", "id": "t1", "name": "pe_info", "input": {}}
                            ],
                        },
                        {"role": "user", "content": "no result"},
                    ]
                },
                "without `tool_result`",
            ),
            (
                {
                    "messages": [
                        {
                            "role": "user",
                            "content": [
                                {"type": "tool_result", "tool_use_id": "t9", "content": "x"}
                            ],
                        }
                    ]
                },
                "unexpected `tool_use_id`",
            ),
            (
                {
                    "system": [
                        {
                            "type": "text",
                            "text": f"block {n}",
                            "cache_control": {"type": "ephemeral"},
                        }
                        for n in range(5)
                    ]
                },
                "A maximum of 4 blocks with cache_control",
            ),
            (
                {
                    "messages": [
                        {"role": "user", "content": "go"},
                        {
                            "role": "assistant",
                            "content": [
                                {"type": "text", "text": ""},
                                {"type": "text", "text": "the answer"},
                            ],
                        },
                        {"role": "user", "content": "fix it"},
                    ]
                },
                "messages: text content blocks must be non-empty",
            ),
            (
                {
                    "messages": [
                        {"role": "user", "content": "go"},
                        {"role": "assistant", "content": "\n\n"},
                        {"role": "user", "content": "fix it"},
                    ]
                },
                "messages: text content blocks must contain non-whitespace text",
            ),
            (
                {
                    "messages": [
                        {"role": "user", "content": "go"},
                        {"role": "assistant", "content": ""},
                        {"role": "user", "content": "fix it"},
                    ]
                },
                "messages.1: all messages must have non-empty content",
            ),
            (
                {"system": [{"type": "text", "text": ""}]},
                "system: text content blocks must be non-empty",
            ),
            ({"temperature": 0.1}, "sampling parameters are not supported"),
            ({"thinking": {"type": "enabled", "budget_tokens": 1024}}, "thinking.type"),
            ({"tool_choice": {"type": "any"}, "tools": [TOOL]}, "tool_choice forces tool use"),
            ({"max_tokens": 200_000}, "maximum allowed number of output tokens"),
        ],
    )
    def test_a_request_the_api_refuses_is_refused_the_same_way(
        self, change: dict[str, Any], said: str
    ) -> None:
        server, script = _stub(wire.Reply(text="never"))
        body = {"model": HAIKU, "max_tokens": 50, "messages": USER, **change}
        try:
            answer = httpx.post(
                f"{server.root}/v1/messages",
                headers={"x-api-key": "k", "anthropic-version": "2023-06-01"},
                json=body,
            )
            (entry,) = server.state.log
        finally:
            server.stop()
        assert answer.status_code == 400
        assert answer.json()["error"]["type"] == "invalid_request_error"
        assert said in answer.json()["error"]["message"]
        assert entry["status"] == 400 and said in entry["refused"]
        assert script.seen == []

    def test_a_prompt_past_the_window_is_refused(self) -> None:
        import anthropic

        server, _ = _stub(wire.Reply(text="never"), window=50)
        try:
            with pytest.raises(anthropic.BadRequestError, match="prompt is too long"):
                _anthropic(server).messages.create(model=HAIKU, max_tokens=10, messages=USER * 10)
        finally:
            server.stop()

    @pytest.mark.parametrize(
        ("headers", "status", "kind"),
        [
            ({"anthropic-version": "2023-06-01"}, 401, "authentication_error"),
            ({"x-api-key": "k"}, 400, "invalid_request_error"),
        ],
    )
    def test_missing_headers_are_refused_with_the_api_s_error(
        self, headers: dict[str, str], status: int, kind: str
    ) -> None:
        server, _ = _stub(wire.Reply(text="never"))
        try:
            answer = httpx.post(
                f"{server.root}/v1/messages",
                headers=headers,
                json={"model": HAIKU, "max_tokens": 5, "messages": USER},
            )
        finally:
            server.stop()
        assert answer.status_code == status
        assert answer.json() == {
            "type": "error",
            "error": {"type": kind, "message": answer.json()["error"]["message"]},
        }

    def test_a_wrong_key_is_refused_when_one_is_expected(self) -> None:
        import anthropic

        server, _ = _stub(wire.Reply(text="never"), api_key="the-right-key")
        try:
            with pytest.raises(anthropic.AuthenticationError):
                _anthropic(server).messages.create(model=HAIKU, max_tokens=5, messages=USER)
        finally:
            server.stop()

    @pytest.mark.parametrize(
        ("status", "kind", "headers"),
        [
            (500, "api_error", {}),
            (529, "overloaded_error", {}),
            (429, "rate_limit_error", {"retry-after": "0"}),
        ],
    )
    def test_a_transient_error_is_typed_and_retried_by_the_client(
        self, status: int, kind: str, headers: dict[str, str]
    ) -> None:
        failing = wire.Reply(status=status, error="transient", headers=headers)
        server, _ = _stub(wire.Reply(text="answered"), first=[failing])
        try:
            message = _anthropic(server).messages.create(model=HAIKU, max_tokens=10, messages=USER)
            statuses = [entry["status"] for entry in server.state.log]
        finally:
            server.stop()
        assert message.content[0].text == "answered"
        assert statuses == [status, 200]
        assert wire.anthropic_error(status, "x")["error"]["type"] == kind

    def test_an_error_mid_stream_reaches_the_client(self) -> None:
        import anthropic

        server, _ = _stub(wire.Reply(text="x" * 200, stream_error=True))
        try:
            with pytest.raises(anthropic.APIStatusError, match="Overloaded"):
                with _anthropic(server, retries=0).messages.stream(
                    model=HAIKU, max_tokens=100, messages=USER
                ) as stream:
                    stream.get_final_message()
        finally:
            server.stop()

    def test_the_models_api_answers_the_stored_description_and_404s_an_unknown_id(self) -> None:
        server, _ = _stub(wire.Reply(text="x"))
        try:
            known = httpx.get(f"{server.root}/v1/models/{HAIKU}")
            unknown = httpx.get(f"{server.root}/v1/models/no-such-model")
        finally:
            server.stop()
        assert known.json()["max_input_tokens"] == 1_000_000
        assert known.json()["max_tokens"] == 128_000
        assert known.json()["capabilities"]["thinking"]["types"]["enabled"]["supported"] is False
        assert unknown.status_code == 404
        assert unknown.json()["error"]["type"] == "not_found_error"


class TestTheStubStandsForAHostedApiOrALocalRuntime:
    def test_a_hosted_api_serves_no_runtime_metadata_and_lists_no_window(self) -> None:
        server, _ = _stub(wire.Reply(text="x"), served=["deepseek-v4-flash"])
        try:
            props = httpx.get(f"{server.root}/props")
            info = httpx.get(f"{server.root}/info")
            listed = httpx.get(f"{server.root}/v1/models").json()["data"]
        finally:
            server.stop()
        assert props.status_code == 404 and info.status_code == 404
        assert listed == [{"id": "deepseek-v4-flash", "object": "model", "owned_by": "rehearsal"}]

    def test_a_local_llama_server_reports_its_window_and_slots(self) -> None:
        server, _ = _stub(
            wire.Reply(text="x"),
            served=["deepseek-v4-flash"],
            runtime="llama",
            window=32_768,
            slots=2,
        )
        try:
            props = httpx.get(f"{server.root}/props").json()
            listed = httpx.get(f"{server.root}/v1/models").json()["data"]
        finally:
            server.stop()
        assert props == {"default_generation_settings": {"n_ctx": 32_768}, "total_slots": 2}
        assert listed[0]["context_length"] == 32_768

    def test_a_window_is_documented_only_by_a_description_a_table_row_or_the_run(self) -> None:
        from scripts.rehearsal.models import facts_for

        assert facts_for("claude-haiku-5-5").window_documented
        assert facts_for("deepseek-chat").window_documented
        assert facts_for("deepseek-v4-pro").window_documented
        assert not facts_for("acme-hosted-pro").window_documented
        assert facts_for("acme-hosted-pro", window=1_000_000).window_documented


class TestTheOpenAiChatCompletionsApi:
    def test_text_reasoning_and_usage(self) -> None:
        server, _ = _stub(wire.Reply(text="CLAIM: one", thinking="weighing"))
        try:
            completion = _openai(server).chat.completions.create(
                model="deepseek-v4-flash", messages=[{"role": "user", "content": "hello"}]
            )
        finally:
            server.stop()
        choice = completion.choices[0]
        assert choice.message.content == "CLAIM: one"
        assert choice.message.model_extra["reasoning_content"] == "weighing"
        assert choice.finish_reason == "stop"
        assert completion.usage.completion_tokens_details.reasoning_tokens > 0

    def test_a_repeated_prefix_is_read_from_the_cache(self) -> None:
        long = [{"role": "system", "content": "The standing rules. " * 600}]
        server, _ = _stub(wire.Reply(text="ok"))
        try:
            client = _openai(server)
            client.chat.completions.create(
                model="deepseek-v4-flash", messages=[*long, {"role": "user", "content": "a"}]
            )
            second = client.chat.completions.create(
                model="deepseek-v4-flash", messages=[*long, {"role": "user", "content": "b"}]
            )
        finally:
            server.stop()
        assert second.usage.prompt_tokens_details.cached_tokens > 0

    def test_a_streamed_tool_call_with_usage(self) -> None:
        call = wire.ToolCall("pe_info", {"path": "/x/sample_1.exe"})
        server, _ = _stub(wire.Reply(thinking="plan", tool_calls=[call]))
        try:
            stream = _openai(server).chat.completions.create(
                model="deepseek-v4-flash",
                messages=[{"role": "user", "content": "go"}],
                tools=[
                    {
                        "type": "function",
                        "function": {"name": "pe_info", "parameters": TOOL["input_schema"]},
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
        finishes = [c.finish_reason for chunk in chunks for c in chunk.choices if c.finish_reason]
        assert arguments == '{"path": "/x/sample_1.exe"}'
        assert finishes == ["tool_calls"]
        assert chunks[-1].usage is not None and chunks[-1].usage.completion_tokens > 0

    def test_a_cut_answer_finishes_on_length(self) -> None:
        server, _ = _stub(wire.Reply(text="z" * 400))
        try:
            completion = _openai(server).chat.completions.create(
                model="deepseek-v4-flash",
                messages=[{"role": "user", "content": "go"}],
                max_tokens=10,
            )
        finally:
            server.stop()
        assert completion.choices[0].finish_reason == "length"
        assert completion.usage.completion_tokens <= 10

    def test_a_tool_call_without_its_answer_is_refused(self) -> None:
        import openai

        server, _ = _stub(wire.Reply(text="never"))
        messages = [
            {"role": "user", "content": "go"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "c1",
                        "type": "function",
                        "function": {"name": "pe_info", "arguments": "{}"},
                    }
                ],
            },
            {"role": "user", "content": "no answer"},
        ]
        try:
            with pytest.raises(openai.BadRequestError, match="tool_call_ids did not have"):
                _openai(server).chat.completions.create(
                    model="deepseek-v4-flash", messages=messages
                )
        finally:
            server.stop()

    def test_a_missing_key_is_refused(self) -> None:
        server, _ = _stub(wire.Reply(text="never"))
        try:
            answer = httpx.post(
                f"{server.root}/v1/chat/completions",
                json={"model": "m", "messages": [{"role": "user", "content": "x"}]},
            )
        finally:
            server.stop()
        assert answer.status_code == 401
        assert answer.json()["error"]["code"] == "invalid_api_key"

    def test_one_server_error_is_typed_and_answered_on_retry(self) -> None:
        server, _ = _stub(wire.Reply(text="answered"), first=[wire.Reply(status=500, error="x")])
        try:
            completion = _openai(server).chat.completions.create(
                model="deepseek-v4-flash", messages=[{"role": "user", "content": "go"}]
            )
            statuses = [entry["status"] for entry in server.state.log]
        finally:
            server.stop()
        assert completion.choices[0].message.content == "answered"
        assert statuses == [500, 200]
        assert wire.openai_error(500, "x")["error"]["type"] == "server_error"

    def test_an_error_mid_stream_reaches_the_client(self) -> None:
        import openai

        server, _ = _stub(wire.Reply(text="x" * 200, stream_error=True))
        try:
            with pytest.raises(openai.APIError):
                list(
                    _openai(server, retries=0).chat.completions.create(
                        model="deepseek-v4-flash",
                        messages=[{"role": "user", "content": "go"}],
                        stream=True,
                    )
                )
        finally:
            server.stop()


class TestAnUnknownModel:
    def test_is_a_404_on_both_wires_and_a_served_one_is_answered(self) -> None:
        import anthropic
        import openai

        server, _ = _stub(wire.Reply(text="ok"), served=["operator-model"])
        try:
            with pytest.raises(anthropic.NotFoundError):
                _anthropic(server).messages.create(
                    model="no-such-model", max_tokens=5, messages=USER
                )
            with pytest.raises(openai.NotFoundError):
                _openai(server).chat.completions.create(
                    model="no-such-model", messages=[{"role": "user", "content": "x"}]
                )
            served = _openai(server).chat.completions.create(
                model="operator-model", messages=[{"role": "user", "content": "x"}]
            )
        finally:
            server.stop()
        assert served.choices[0].message.content == "ok"


class TestThePace:
    def test_an_answer_takes_its_first_token_time_and_its_tokens_at_the_rate(self) -> None:
        text = "x" * 400  # 100 tokens at four characters a token
        server, _ = _stub(wire.Reply(text=text), pace=Pace(0.2, 500.0))
        try:
            started = time.monotonic()
            _openai(server, retries=0).chat.completions.create(
                model="deepseek-v4-flash", messages=[{"role": "user", "content": "a"}]
            )
            elapsed = time.monotonic() - started
        finally:
            server.stop()
        assert elapsed >= 0.2 + 100 / 500.0

    @pytest.mark.parametrize("stream", [False, True])
    def test_no_pace_answers_at_once(self, stream: bool) -> None:
        server, _ = _stub(wire.Reply(text="y" * 400))
        try:
            started = time.monotonic()
            answer = _openai(server, retries=0).chat.completions.create(
                model="deepseek-v4-flash",
                messages=[{"role": "user", "content": "a"}],
                stream=stream,
            )
            if stream:
                list(answer)
            elapsed = time.monotonic() - started
        finally:
            server.stop()
        assert elapsed < 2.0

    def test_three_characters_a_token_counts_more_tokens(self) -> None:
        wire.set_chars_per_token(3)
        try:
            assert wire.tokens_of("x" * 30) == 10
        finally:
            wire.set_chars_per_token(4)
        assert wire.tokens_of("x" * 30) == 8
