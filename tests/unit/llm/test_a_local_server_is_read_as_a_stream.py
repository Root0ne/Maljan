"""A llama.cpp server's answer is read as a stream, so a slow call shows its pace.

A non-streamed answer from llama.cpp sends nothing until it has finished: the
headers too. A call on a slow local model was therefore silent for its whole
life, and nothing but the provider's request timeout could end it. Read as a
stream, each generated piece arrives as it is made, and the call's deadline
reads the call's pace from them (``generation_rate._CallDeadline``).

The answer the stream adds up to is the answer the server sent: its text, its
tool calls, its finish reason, the server's ``timings`` (on the last chunk)
and its usage. ik_llama.cpp puts a running total of the usage on every chunk
of the answer, and the chunks' usages are added together when the chunks are
joined; only the total the stream closes with is kept. A hosted API is read
as it was.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest
from langchain_core.messages import HumanMessage

from maljan.core.config import Settings
from maljan.llm.generation_rate import (
    IN_CALL_SOURCE,
    LLAMA_CPP_PROMPT_SOURCE,
    LLAMA_CPP_SOURCE,
    TIMEOUT_MARGIN,
    GenerationRates,
    ModelCallDeadline,
    attach_rate_meter,
)
from maljan.llm.openai_provider import OpenAIProvider, forget_standard_only

from .virtual_time import run, run_expecting

_TIMINGS = {"prompt_n": 120, "prompt_ms": 400.0, "predicted_n": 3, "predicted_ms": 1500.0}


@pytest.fixture(autouse=True)
def _forget() -> Any:
    forget_standard_only()
    yield
    forget_standard_only()


def _chunk(delta: dict[str, Any] | None, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": "chatcmpl-1",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "m",
        "choices": [] if delta is None else [{"index": 0, "delta": delta, "finish_reason": None}],
    }
    body.update(extra)
    return body


def _running(n: int) -> dict[str, Any]:
    return {"completion_tokens": n, "prompt_tokens": 120, "total_tokens": 120 + n}


def _stream(*, running_usage: bool, tool_call: bool = False) -> list[dict[str, Any]]:
    """An answer as llama.cpp streams it; ``running_usage`` is ik_llama.cpp's shape."""

    def usage(n: int) -> dict[str, Any]:
        return {"usage": _running(n)} if running_usage else {}

    if tool_call:
        pieces = [
            _chunk({"role": "assistant", "content": None}, **usage(1)),
            _chunk(
                {
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "call-1",
                            "type": "function",
                            "function": {"name": "lookup", "arguments": '{"q": '},
                        }
                    ]
                },
                **usage(2),
            ),
            _chunk(
                {"tool_calls": [{"index": 0, "function": {"arguments": '"x"}'}}]},
                **usage(3),
            ),
        ]
        finish = "tool_calls"
    else:
        pieces = [
            _chunk({"role": "assistant", "content": None}, **usage(1)),
            _chunk({"content": "do"}, **usage(1)),
            _chunk({"content": "n"}, **usage(2)),
            _chunk({"content": "e"}, **usage(3)),
        ]
        finish = "stop"
    closing = _chunk({})
    closing["choices"][0]["finish_reason"] = finish
    return [
        *pieces,
        closing,
        _chunk(None, usage=_running(3), timings=_TIMINGS),
    ]


def _transport(chunks: list[dict[str, Any]], seen: list[dict[str, Any]]) -> httpx.MockTransport:
    def _handle(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        body = "".join(f"data: {json.dumps(c)}\n\n" for c in chunks) + "data: [DONE]\n\n"
        return httpx.Response(
            200, content=body.encode(), headers={"content-type": "text/event-stream"}
        )

    return httpx.MockTransport(_handle)


def _settings(base_url: str, compat: str) -> Settings:
    return Settings(
        _env_file=None,
        llm={"openai": {"api_key": "not-a-key", "base_url": base_url, "compat": compat}},
    )


def _local(chunks: list[dict[str, Any]], seen: list[dict[str, Any]], **kwargs: Any) -> Any:
    transport = _transport(chunks, seen)
    return OpenAIProvider(_settings("http://127.0.0.1:8080/v1", "llama_cpp")).build_model(
        "m",
        0.0,
        max_tokens=512,
        http_client=httpx.Client(transport=transport),
        http_async_client=httpx.AsyncClient(transport=transport),
        **kwargs,
    )


_WHOLE = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "created": 0,
    "model": "m",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "done"}, "finish_reason": "stop"}
    ],
    "usage": {"prompt_tokens": 120, "completion_tokens": 3, "total_tokens": 123},
}


class TestWhichEndpointsStream:
    def test_a_llama_cpp_server_is_asked_for_a_stream_with_its_usage(self) -> None:
        seen: list[dict[str, Any]] = []
        _local(_stream(running_usage=False), seen).invoke([HumanMessage(content="hi")])

        assert seen[0]["stream"] is True
        assert seen[0]["stream_options"] == {"include_usage": True}

    def test_langchain_s_own_gap_limit_does_not_cut_a_long_prompt_read(self) -> None:
        # ``langchain-openai`` ends a stream after 120 s without a chunk; a slow
        # model reading a long prompt is silent longer than that before its
        # first piece, and the silence is the provider's timeout to bound.
        model = OpenAIProvider(_settings("http://127.0.0.1:8080/v1", "auto")).build_model(
            "m", 0.0, max_tokens=512
        )

        assert not model.stream_chunk_timeout

    @pytest.mark.parametrize(
        ("base_url", "compat"),
        [("https://api.deepseek.com", "deepseek"), ("https://api.example.org/v1", "auto")],
    )
    def test_a_hosted_api_is_read_whole_as_before(self, base_url: str, compat: str) -> None:
        seen: list[dict[str, Any]] = []

        def _handle(request: httpx.Request) -> httpx.Response:
            seen.append(json.loads(request.content))
            return httpx.Response(200, json=_WHOLE)

        model = OpenAIProvider(_settings(base_url, compat)).build_model(
            "m",
            0.0,
            max_tokens=512,
            http_client=httpx.Client(transport=httpx.MockTransport(_handle)),
        )

        assert model.invoke([HumanMessage(content="hi")]).content == "done"
        assert not seen[0].get("stream")


class TestTheStreamAddsUpToTheServersAnswer:
    @pytest.mark.parametrize("running_usage", [True, False], ids=["ik_llama", "llama.cpp"])
    def test_text_finish_reason_timings_and_usage(self, running_usage: bool) -> None:
        seen: list[dict[str, Any]] = []
        answer = _local(_stream(running_usage=running_usage), seen).invoke(
            [HumanMessage(content="hi")]
        )

        assert seen[0]["stream"] is True
        assert answer.content == "done"
        assert answer.response_metadata["finish_reason"] == "stop"
        assert answer.response_metadata["timings"] == _TIMINGS
        assert answer.usage_metadata["output_tokens"] == 3
        assert answer.usage_metadata["input_tokens"] == 120
        assert answer.response_metadata["token_usage"]["completion_tokens"] == 3

    @pytest.mark.asyncio
    async def test_the_async_path_adds_up_the_same(self) -> None:
        seen: list[dict[str, Any]] = []
        answer = await _local(_stream(running_usage=True), seen).ainvoke(
            [HumanMessage(content="hi")]
        )

        assert answer.content == "done"
        assert answer.usage_metadata["output_tokens"] == 3
        assert answer.response_metadata["timings"] == _TIMINGS

    @pytest.mark.asyncio
    async def test_a_streamed_tool_call_is_the_tool_call(self) -> None:
        seen: list[dict[str, Any]] = []
        answer = await _local(_stream(running_usage=True, tool_call=True), seen).ainvoke(
            [HumanMessage(content="hi")]
        )

        assert [(c["name"], c["args"]) for c in answer.tool_calls] == [("lookup", {"q": "x"})]
        assert answer.response_metadata["finish_reason"] == "tool_calls"

    @pytest.mark.asyncio
    async def test_the_server_s_timings_reach_the_meter(self) -> None:
        rates = GenerationRates()
        seen: list[dict[str, Any]] = []
        model = attach_rate_meter(_local(_stream(running_usage=True), seen), rates, "m")

        await model.ainvoke([HumanMessage(content="hi")])

        assert rates.rate("m") == pytest.approx(2.0)
        assert rates.rate_source("m") == [LLAMA_CPP_SOURCE]
        assert rates.prompt_rate("m") == pytest.approx(300.0)
        assert rates.snapshot()["models"]["m"]["prompt_sources"] == [LLAMA_CPP_PROMPT_SOURCE]

    @pytest.mark.parametrize(
        "where",
        ["the closing chunk", "the finish chunk", "every chunk"],
    )
    def test_the_usage_is_the_last_the_stream_sends(self, where: str) -> None:
        chunks = _stream(running_usage=where == "every chunk")
        final = chunks.pop()  # the closing chunk without choices
        if where == "the finish chunk":
            chunks[-1]["usage"] = final["usage"]
            chunks[-1]["timings"] = final["timings"]
        else:
            chunks.append(final)
        seen: list[dict[str, Any]] = []

        answer = _local(chunks, seen).invoke([HumanMessage(content="hi")])

        assert answer.usage_metadata["output_tokens"] == 3
        assert answer.response_metadata["token_usage"]["completion_tokens"] == 3
        assert answer.response_metadata["timings"] == _TIMINGS

    def test_timings_on_every_chunk_are_the_last(self) -> None:
        chunks = _stream(running_usage=False)
        for index, chunk in enumerate(chunks[:-1]):
            chunk["timings"] = {**_TIMINGS, "predicted_n": index, "predicted_ms": 10.5 * index}
        seen: list[dict[str, Any]] = []

        answer = _local(chunks, seen).invoke([HumanMessage(content="hi")])

        assert answer.response_metadata["timings"] == _TIMINGS

    @pytest.mark.parametrize(
        "calls",
        [
            [("call-1", "lookup", '{"q": "x"}'), ("call-2", "fetch", '{"url": "u"}')],
            [("call-1", "lookup", '{"q": "x"}'), ("call-2", "fetch", "{not json}")],
            [("call-1", "lookup", "")],
        ],
        ids=["parallel", "one-malformed", "no-arguments"],
    )
    def test_tool_calls_are_read_as_a_whole_answer_s_are(
        self, calls: list[tuple[str, str, str]]
    ) -> None:
        from .streamed_wire import streamed

        whole = {
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 0,
            "model": "m",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {"id": i, "type": "function", "function": {"name": n, "arguments": a}}
                            for i, n, a in calls
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": {"prompt_tokens": 120, "completion_tokens": 9, "total_tokens": 129},
        }

        def _as_stream(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=streamed(whole), headers={"content-type": "text/event-stream"}
            )

        def _as_whole(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=whole)

        local = OpenAIProvider(_settings("http://127.0.0.1:8080/v1", "llama_cpp")).build_model(
            "m",
            0.0,
            max_tokens=512,
            http_client=httpx.Client(transport=httpx.MockTransport(_as_stream)),
        )
        hosted = OpenAIProvider(_settings("https://api.example.org/v1", "auto")).build_model(
            "m", 0.0, http_client=httpx.Client(transport=httpx.MockTransport(_as_whole))
        )

        read_streamed = local.invoke([HumanMessage(content="hi")])
        read_whole = hosted.invoke([HumanMessage(content="hi")])

        assert read_streamed.tool_calls == read_whole.tool_calls
        assert read_streamed.invalid_tool_calls == read_whole.invalid_tool_calls

    @pytest.mark.asyncio
    async def test_a_cut_tool_call_stays_a_cut_call(self) -> None:
        # A call whose arguments end mid-string, as a call the output cap cut
        # does: read whole it is an invalid call, and read as a stream it is
        # the same, not a call closed where it was cut.
        chunks = _stream(running_usage=False, tool_call=True)
        chunks[2]["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"] = '"x'
        seen: list[dict[str, Any]] = []

        answer = await _local(chunks, seen).ainvoke([HumanMessage(content="hi")])

        assert answer.tool_calls == []
        assert [(c["name"], c["args"]) for c in answer.invalid_tool_calls] == [
            ("lookup", '{"q": "x')
        ]


def _sse(body: dict[str, Any]) -> bytes:
    return f"data: {json.dumps(body)}\n\n".encode()


class TestASlowLocalModelEndToEnd:
    """The real client over a server that makes 2.3 pieces a second, on a clock that jumps."""

    @staticmethod
    def _slow_server(
        pieces: int,
        stall_after: int | None = None,
        *,
        field: str = "content",
        read_timeout_after: float | None = None,
        error_after: int | None = None,
    ) -> httpx.MockTransport:
        """``read_timeout_after``: the stall ends in the connection's read timeout, that late.

        ``error_after``: after that many pieces the server reports a failure
        inside the stream, as llama.cpp does once a stream has begun.
        """

        async def body() -> Any:
            yield _sse(_chunk({"role": "assistant", "content": None}))
            for index in range(pieces):
                if error_after is not None and index >= error_after:
                    yield _sse({"error": {"code": 500, "message": "boom", "type": "server_error"}})
                    return
                if stall_after is not None and index >= stall_after:
                    if read_timeout_after is None:
                        await asyncio.Event().wait()
                    await asyncio.sleep(read_timeout_after or 0.0)
                    raise httpx.ReadTimeout("no data within the read timeout")
                await asyncio.sleep(1 / 2.3)
                yield _sse(_chunk({field: "x"}))
            closing = _chunk({})
            closing["choices"][0]["finish_reason"] = "stop"
            yield _sse(closing)
            yield _sse(_chunk(None, usage=_running(pieces)))
            yield b"data: [DONE]\n\n"

        async def _handle(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, content=body(), headers={"content-type": "text/event-stream"}
            )

        return httpx.MockTransport(_handle)

    @staticmethod
    def _model(transport: httpx.MockTransport) -> Any:
        return OpenAIProvider(_settings("http://127.0.0.1:8080/v1", "llama_cpp")).build_model(
            "m", 0.0, max_tokens=8192, http_async_client=httpx.AsyncClient(transport=transport)
        )

    def test_its_first_call_runs_past_1800_s_to_its_answer(self) -> None:
        model = self._model(self._slow_server(5000))

        answer, took = run(model.ainvoke([HumanMessage(content="hi")]))

        assert took > 1800
        assert answer.content == "x" * 5000
        assert answer.usage_metadata["output_tokens"] == 5000

    @pytest.mark.parametrize("field", ["content", "reasoning_content"])
    def test_when_it_stalls_it_is_cut_at_its_cap_at_the_pace_it_showed(self, field: str) -> None:
        # Reasoning pieces are generated pieces too: a thinking model's pace
        # is its reasoning's until it starts to answer.
        rates = GenerationRates()
        model = attach_rate_meter(
            self._model(self._slow_server(5000, 100, field=field)), rates, "m"
        )

        exc, took = run_expecting(ModelCallDeadline, model.ainvoke([HumanMessage(content="hi")]))

        # The opening chunk names only the role and is no piece; 100 pieces,
        # the first 1 / 2.3 s in, then the cap at 2.3 a second.
        assert took == pytest.approx((1 / 2.3 + 8192 / 2.3) * TIMEOUT_MARGIN, rel=1e-6)
        assert "pace measured in this call" in str(exc)
        assert rates.rate_source("m") == [IN_CALL_SOURCE]
        assert rates.rate("m") == pytest.approx(2.3)

    def test_a_reasoning_answer_is_joined_without_its_reasoning(self) -> None:
        # ``langchain-openai`` leaves a whole answer's reasoning out; so does the join.
        answer, _took = run(
            self._model(self._slow_server(5, field="reasoning_content")).ainvoke(
                [HumanMessage(content="hi")]
            )
        )

        assert "reasoning_content" not in answer.additional_kwargs

    def test_a_read_timeout_after_pieces_is_the_silence_after_the_last_one(self) -> None:
        model = self._model(self._slow_server(5000, 10, read_timeout_after=1800.0))

        exc, took = run_expecting(ModelCallDeadline, model.ainvoke([HumanMessage(content="hi")]))

        assert took == pytest.approx(10 / 2.3 + 1800.0)
        said = str(exc)
        assert "silence after its last generated piece" in said
        assert "no piece for 1800 s after piece 10" in said

    def test_a_read_timeout_before_any_piece_is_raised_as_it_came(self) -> None:
        model = self._model(self._slow_server(5000, 0, read_timeout_after=1700.0))

        exc, _took = run_expecting(Exception, model.ainvoke([HumanMessage(content="hi")]))

        assert not isinstance(exc, ModelCallDeadline)
        assert isinstance(exc, httpx.ReadTimeout)

    def test_a_server_error_inside_the_stream_is_the_error_a_whole_answer_raises(self) -> None:
        import openai

        streamed_error, _took = run_expecting(
            Exception,
            self._model(self._slow_server(5000, error_after=3)).ainvoke(
                [HumanMessage(content="hi")]
            ),
        )

        def _whole(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                500, json={"error": {"code": 500, "message": "boom", "type": "server_error"}}
            )

        hosted = OpenAIProvider(_settings("https://api.example.org/v1", "auto")).build_model(
            "m", 0.0, http_client=httpx.Client(transport=httpx.MockTransport(_whole))
        )
        with pytest.raises(Exception) as whole:
            hosted.invoke([HumanMessage(content="hi")])

        assert isinstance(streamed_error, openai.InternalServerError)
        assert type(streamed_error) is type(whole.value)


class TestWhatADirectStreamSees:
    def test_its_chunks_carry_no_reasoning(self) -> None:
        # Reasoning pieces count towards the call's pace, and a caller that
        # streams the model directly sees them as ``langchain-openai`` would:
        # without the reasoning, which a whole answer does not carry either.
        chunks = _stream(running_usage=False)
        chunks.insert(1, _chunk({"reasoning_content": "thinking"}))
        seen: list[dict[str, Any]] = []

        pieces = list(_local(chunks, seen).stream([HumanMessage(content="hi")]))

        assert pieces
        assert all("reasoning_content" not in p.additional_kwargs for p in pieces)


class TestAServerErrorAlwaysReachesTheCaller:
    def test_a_status_error_that_cannot_be_built_leaves_the_server_s_own(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import builtins

        import openai

        from maljan.llm.openai_provider import _as_status_error

        real_import = builtins.__import__

        def _no_httpx2(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "httpx2":
                raise ImportError("no httpx2 here")
            return real_import(name, *args, **kwargs)

        request = httpx.Request("POST", "http://127.0.0.1:8080/v1/chat/completions")
        error = openai.APIError("boom", request=request, body={"code": 500, "message": "boom"})
        monkeypatch.setattr(builtins, "__import__", _no_httpx2)

        assert _as_status_error(error) is error
