"""A provider saying "not now" never costs an analyst.

One HTTP 5xx on an analyst's first model call used to lose the whole analyst:
its tool loop asked again only after a dropped connection, the OpenAI
provider's client never retries (``max_retries=0``), and the Anthropic SDK's
own retries end where the stream begins, so an ``overloaded_error`` event after
the first byte ended the loop too. Only the judge, the mediator and the
reporting layer asked again.

Every model call is now asked again by the one policy those callers already
used (``maljan.llm.transient``): a 5xx, a 529, a 429 (after its
``Retry-After``), a dropped connection or an error event in the stream. A
refusal is answered once. A retry repeats one model request, so no tool runs
twice and no ledger entry is written twice, and each failed attempt is counted
in the run summary.

The providers are driven against a stub HTTP server on the loopback
interface; no request leaves the machine.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from unittest.mock import MagicMock

import anthropic
import httpx
import openai
import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool

from maljan.agents.base_agent import BaseAnalyst
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.core.config import Settings
from maljan.core.exceptions import AnalystError
from maljan.core.token_ledger import TokenLedger
from maljan.llm.fallback import FallbackChatModel
from maljan.llm.generation_rate import ModelCallDeadline
from maljan.llm.transient import (
    RETRIES_KEY,
    retry_on_connection_error,
    transient_failure,
    with_transient_retries,
)

from .anthropic_wire import message, streamed

USAGE = {"input_tokens": 3, "output_tokens": 1, "total_tokens": 4}
_REQUEST = httpx.Request("POST", "http://127.0.0.1:8080/v1")


def _response(status: int, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(status, headers=headers or {}, request=_REQUEST)


def _openai_status(status: int, headers: dict[str, str] | None = None) -> Exception:
    return openai.APIStatusError(
        f"Error code: {status}", response=_response(status, headers), body=None
    )


def _anthropic_status(status: int, body: Any = None) -> Exception:
    return anthropic.APIStatusError(f"Error code: {status}", response=_response(status), body=body)


def _overloaded_in_the_stream() -> Exception:
    """What the Anthropic SDK raises for an ``error`` event after the stream began: status 200."""
    return _anthropic_status(
        200, {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}
    )


def _openai_stream_error() -> Exception:
    """What the OpenAI SDK raises for an ``error`` chunk inside a stream."""
    return openai.APIError(
        "An error occurred during streaming",
        request=_REQUEST,
        body={"type": "server_error", "code": "server_error", "message": "try again"},
    )


def _connection_reset() -> Exception:
    return openai.APIConnectionError(request=_REQUEST)


@pytest.fixture(autouse=True)
def _no_real_backoff(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """The delays are read off the call, not waited for."""
    waits: list[float] = []

    async def _record(seconds: float) -> None:
        waits.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", _record)
    monkeypatch.setattr("maljan.llm.transient.time.sleep", waits.append)
    return waits


class TestWhatIsTransient:
    @pytest.mark.parametrize(
        "failure",
        [
            _openai_status(500),
            _openai_status(502),
            _openai_status(503),
            _openai_status(429, {"retry-after": "3"}),
            _anthropic_status(529),
            _anthropic_status(500),
            _overloaded_in_the_stream(),
            _openai_stream_error(),
            _connection_reset(),
            httpx.RemoteProtocolError("peer closed connection"),
            ConnectionResetError(104, "reset by peer"),
        ],
    )
    def test_a_provider_saying_not_now(self, failure: Exception) -> None:
        assert transient_failure(failure) is not None

    @pytest.mark.parametrize(
        "failure",
        [
            _openai_status(400),
            _openai_status(401),
            _openai_status(403),
            _openai_status(404),
            _openai_status(422),
            _anthropic_status(400, {"type": "error", "error": {"type": "invalid_request_error"}}),
            _anthropic_status(401, {"type": "error", "error": {"type": "authentication_error"}}),
            TimeoutError("hard cap"),
            ModelCallDeadline("the model request timed out"),
            httpx.ReadTimeout("silence"),
            ValueError("malformed structured output"),
        ],
    )
    def test_a_refusal_a_stall_or_a_schema_error_is_not(self, failure: Exception) -> None:
        assert transient_failure(failure) is None


# ---------------------------------------------------------------------------
# The analyst's tool loop


class _Scripted(BaseChatModel):
    """Answers from a script: ``"tool"`` calls ``peek``, a string answers, an exception raises."""

    script: list[Any] = []
    served: list[int] = []
    asked: list[int] = []

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any):
        self.asked.append(1)
        step = self.script.pop(0) if self.script else "CLAIM: x\nEVIDENCE: ev_0001"
        if isinstance(step, BaseException):
            raise step
        if step == "tool":
            n = len(self.served) + 1
            answer = AIMessage(
                content="",
                tool_calls=[{"name": "peek", "args": {"n": n}, "id": f"c{n}"}],
                usage_metadata=dict(USAGE),
            )
        else:
            answer = AIMessage(content=step, usage_metadata=dict(USAGE))
        self.served.append(1)
        return ChatResult(generations=[ChatGeneration(message=answer)])


_Retrying = with_transient_retries(_Scripted)

_PEEKS: list[int] = []


def _peek(n: int) -> str:
    """Peek."""
    _PEEKS.append(n)
    return f"bytes {n}"


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *a: Any, **k: Any) -> str:  # pragma: no cover - unused
        return ""


def _analyst(script: list[Any]) -> tuple[_Analyst, Any, TokenLedger]:
    _PEEKS.clear()
    llm = _Retrying(script=list(script), served=[], asked=[])
    ledger = TokenLedger()
    tool = StructuredTool.from_function(func=_peek, name="peek", description="p")
    agent = _Analyst(llm=llm, name="static", tools=[tool])
    agent.token_ledger = ledger
    agent._container = MagicMock()
    agent._model_label = lambda: "openai/static-model"
    return agent, llm, ledger


class TestTheAnalystCompletes:
    @pytest.mark.parametrize(
        "failure",
        [
            _openai_status(500),
            _openai_status(503),
            _anthropic_status(529),
            _openai_status(429, {"retry-after": "2"}),
            _overloaded_in_the_stream(),
            _openai_stream_error(),
            _connection_reset(),
        ],
    )
    def test_a_transient_failure_on_the_first_call(self, failure: Exception) -> None:
        agent, llm, ledger = _analyst([failure, "tool", "CLAIM: it reads\nEVIDENCE: ev_0001"])

        text = agent.execute_tool_loop([("system", "s"), ("human", "h")])

        assert "it reads" in text
        assert len(llm.asked) == 3, "the failed call, the same turn asked again, the answer"
        assert _PEEKS == [1]
        rows = ledger.snapshot().get("retries") or []
        assert [row["agent"] for row in rows] == ["static"]

    def test_a_retry_mid_loop_makes_no_tool_call_twice(self) -> None:
        agent, llm, _ledger = _analyst(
            ["tool", "tool", _openai_status(503), "CLAIM: it reads\nEVIDENCE: ev_0002"]
        )

        agent.execute_tool_loop([("system", "s"), ("human", "h")])

        assert _PEEKS == [1, 2], "each tool ran once; only the failed model request was made again"
        entries = agent.drain_evidence_entries()
        assert len(entries) == 2
        assert len({entry.id for entry in entries}) == 2

    def test_the_retry_after_the_provider_asked_for_is_waited(
        self, _no_real_backoff: list[float]
    ) -> None:
        agent, _llm, _ledger = _analyst([_openai_status(429, {"retry-after": "7"}), "CLAIM: x"])

        agent.execute_tool_loop([("system", "s"), ("human", "h")])

        assert _no_real_backoff == [7]

    def test_the_backoff_is_jittered(self, _no_real_backoff: list[float]) -> None:
        agent, _llm, _ledger = _analyst([_openai_status(500), _openai_status(500), "CLAIM: x"])

        agent.execute_tool_loop([("system", "s"), ("human", "h")])

        first, second = _no_real_backoff
        assert 0.5 <= first <= 1.5
        assert 1.0 <= second <= 3.0

    def test_a_400_is_asked_once_and_fails_the_analyst(self) -> None:
        agent, llm, _ledger = _analyst([_openai_status(400)])

        with pytest.raises(AnalystError):
            agent.execute_tool_loop([("system", "s"), ("human", "h")])

        assert len(llm.asked) == 1

    def test_an_exhausted_retry_fails_the_analyst_as_any_provider_failure_does(self) -> None:
        agent, llm, _ledger = _analyst([_openai_status(503)] * 3)

        with pytest.raises(AnalystError):
            agent.execute_tool_loop([("system", "s"), ("human", "h")])

        assert len(llm.asked) == 3, "the attempts the mediator's retry has always made"


class TestOnePolicyNotTwo:
    @pytest.mark.asyncio
    async def test_a_call_already_retried_by_its_caller_is_made_once_by_the_model(self) -> None:
        llm = _Retrying(script=[_openai_status(503)] * 9, served=[], asked=[])

        with pytest.raises(openai.APIStatusError):
            await retry_on_connection_error(lambda: llm.ainvoke("hi"), what="Mediator fast path")

        assert len(llm.asked) == 3, "three attempts, not three times three"

    @pytest.mark.asyncio
    async def test_the_answer_after_a_retry_says_so(self) -> None:
        llm = _Retrying(script=[_anthropic_status(529), "fine"], served=[], asked=[])

        answer = await llm.ainvoke("hi")

        assert answer.content == "fine"
        assert len(answer.response_metadata[RETRIES_KEY]) == 1

    @pytest.mark.asyncio
    async def test_a_model_list_moves_on_after_the_retries_without_waiting_again(
        self, _no_real_backoff: list[float]
    ) -> None:
        first = _Retrying(
            script=[_openai_status(429, {"retry-after": "4"})] * 3, served=[], asked=[]
        )
        second = _Retrying(script=["from the second"], served=[], asked=[])
        models = FallbackChatModel(models=[first, second], labels=["a/one", "b/two"], agent="x")

        answer = await models.ainvoke("hi")

        assert answer.content == "from the second"
        assert len(first.asked) == 3
        assert _no_real_backoff == [4, 4], "the first model's own two waits, and no third"

    @pytest.mark.asyncio
    async def test_a_model_list_moves_on_after_an_error_in_the_stream(self) -> None:
        first = _Retrying(script=[_overloaded_in_the_stream()] * 3, served=[], asked=[])
        second = _Retrying(script=["from the second"], served=[], asked=[])
        models = FallbackChatModel(models=[first, second], labels=["a/one", "b/two"], agent="x")

        answer = await models.ainvoke("hi")

        assert answer.content == "from the second"


class TestTheRunSummaryCountsThem:
    def test_each_failed_attempt_is_a_row(self) -> None:
        ledger = TokenLedger()
        answer = AIMessage(
            content="ok",
            usage_metadata=dict(USAGE),
            response_metadata={RETRIES_KEY: ["model call (m): HTTP 503 (attempt 1 of 3)"]},
        )
        from maljan.core.token_ledger import record_response_usage

        record_response_usage(ledger, answer, agent="static", model="openai/m")
        builder = RunSummaryBuilder(0.0)
        builder.set_token_usage(ledger.snapshot())
        summary = builder.build()

        assert summary.models["static"]["retries"] == [
            {"model": "openai/m", "reason": "model call (m): HTTP 503 (attempt 1 of 3)"}
        ]
        text = summary.to_markdown()
        assert "## Provider Retries" in text
        assert "1 model request failed at the provider for a moment and was made again" in text

    def test_a_run_without_one_reads_as_it_always_did(self) -> None:
        ledger = TokenLedger()
        from maljan.core.token_ledger import record_response_usage

        record_response_usage(
            ledger, AIMessage(content="ok", usage_metadata=dict(USAGE)), agent="static"
        )
        assert "retries" not in ledger.snapshot()
        builder = RunSummaryBuilder(0.0)
        builder.set_token_usage(ledger.snapshot())
        summary = builder.build()
        assert all("retries" not in block for block in (summary.models or {}).values())
        assert "Provider Retries" not in summary.to_markdown()


# ---------------------------------------------------------------------------
# The two providers, on the wire


class _Scripts(BaseHTTPRequestHandler):
    """Answers each request from the server's script: a status and body, or a stream."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # noqa: D102 — quiet
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length") or 0)
        if length:
            self.rfile.read(length)
        self.server.requests += 1  # type: ignore[attr-defined]
        script: list[tuple[int, str, bytes]] = self.server.script  # type: ignore[attr-defined]
        status, kind, data = script.pop(0)
        self.send_response(status)
        self.send_header("content-type", kind)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def server() -> Iterator[ThreadingHTTPServer]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Scripts)
    httpd.daemon_threads = True
    httpd.requests = 0  # type: ignore[attr-defined]
    httpd.script = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield httpd
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(10)


def _url(httpd: ThreadingHTTPServer) -> str:
    host, port = httpd.server_address[:2]
    return f"http://{host}:{port}"


def _anthropic(httpd: ThreadingHTTPServer, **kwargs: Any) -> Any:
    from maljan.llm.anthropic_provider import AnthropicProvider

    settings = Settings(_env_file=None, llm={"anthropic": {"api_key": "test-value"}})
    return AnthropicProvider(settings).build_model(
        "claude-haiku-5-5", 0.0, base_url=_url(httpd), max_tokens=64, **kwargs
    )


def _openai(httpd: ThreadingHTTPServer) -> Any:
    from maljan.llm.openai_provider import OpenAIProvider

    settings = Settings(
        _env_file=None,
        llm={"openai": {"api_key": "test-value", "base_url": f"{_url(httpd)}/v1"}},
    )
    settings.llm.openai.compat = "standard"
    return OpenAIProvider(settings).build_model("m", 0.0, max_tokens=64)


def _anthropic_answer(text: str) -> dict[str, Any]:
    return message(
        [{"type": "text", "text": text}],
        stop="end_turn",
        usage={"input_tokens": 3, "output_tokens": 1},
    )


def _stream_then_overloaded() -> bytes:
    opening = {**_anthropic_answer(""), "content": [], "stop_reason": None}
    started = json.dumps({"type": "message_start", "message": opening})
    start = f"event: message_start\ndata: {started}\n\n"
    error = {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}
    return (start + f"event: error\ndata: {json.dumps(error)}\n\n").encode()


def _openai_answer(text: str) -> bytes:
    return json.dumps(
        {
            "id": "c1",
            "object": "chat.completion",
            "created": 1,
            "model": "m",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
        }
    ).encode()


_JSON = "application/json"
_SSE = "text/event-stream"


class TestTheProvidersBehaveTheSame:
    def test_neither_sdk_retries_underneath_the_policy(self, server: ThreadingHTTPServer) -> None:
        assert _anthropic(server).max_retries == 0
        assert _openai(server).max_retries == 0

    def test_an_anthropic_overload_after_the_stream_began_is_asked_again(
        self, server: ThreadingHTTPServer
    ) -> None:
        server.script = [  # type: ignore[attr-defined]
            (200, _SSE, _stream_then_overloaded()),
            (200, _SSE, streamed(_anthropic_answer("answered"))),
        ]
        model = _anthropic(server, streaming=True)

        answer = asyncio.run(model.ainvoke("hello"))

        assert "answered" in str(answer.content)
        assert server.requests == 2  # type: ignore[attr-defined]

    def test_an_anthropic_529_is_asked_again(self, server: ThreadingHTTPServer) -> None:
        overloaded = {"type": "error", "error": {"type": "overloaded_error", "message": "x"}}
        server.script = [  # type: ignore[attr-defined]
            (529, _JSON, json.dumps(overloaded).encode()),
            (200, _JSON, json.dumps(_anthropic_answer("answered")).encode()),
        ]

        answer = asyncio.run(_anthropic(server).ainvoke("hello"))

        assert "answered" in str(answer.content)
        assert server.requests == 2  # type: ignore[attr-defined]

    def test_an_openai_503_is_asked_again(self, server: ThreadingHTTPServer) -> None:
        server.script = [  # type: ignore[attr-defined]
            (503, _JSON, b'{"error": {"message": "overloaded", "type": "server_error"}}'),
            (200, _JSON, _openai_answer("answered")),
        ]

        answer = asyncio.run(_openai(server).ainvoke("hello"))

        assert answer.content == "answered"
        assert server.requests == 2  # type: ignore[attr-defined]

    def test_a_400_is_sent_once_by_either(self, server: ThreadingHTTPServer) -> None:
        refused = {"type": "error", "error": {"type": "invalid_request_error", "message": "x"}}
        server.script = [  # type: ignore[attr-defined]
            (400, _JSON, json.dumps(refused).encode()),
            (400, _JSON, b'{"error": {"message": "bad", "type": "invalid_request_error"}}'),
        ]

        with pytest.raises(anthropic.BadRequestError):
            asyncio.run(_anthropic(server).ainvoke("hello"))
        with pytest.raises(openai.BadRequestError):
            asyncio.run(_openai(server).ainvoke("hello"))

        assert server.requests == 2  # type: ignore[attr-defined]
