"""A model's async HTTP client is only ever used on the event loop it was built on.

A pooled connection belongs to the loop that opened it. This process makes
model calls on more than one: the shared agent loop the analysts run on, and
the worker's own, where the report node and the composer await theirs. The
Anthropic provider's client came from ``langchain_anthropic``'s process-wide
``lru_cache``, so a connection the analysts opened on the agent loop was
reused by the reporter on the worker loop, and the first request there failed
inside httpcore with "bound to a different event loop"; only the SDK's own
retry, on a new connection, hid it. A model held across two loops (the
narrative agent, the composer) has the same shape on every provider.

Each provider is driven here against a stub HTTP/1.1 server on the loopback
interface, with keep-alive on so a pooled connection is reused, from two loops
that are both running: one on a thread of its own (the agent loop) and the
test's own. No request leaves the machine, and the SDK retries are off so a
crossed loop is a failed call rather than a hidden one.
"""

from __future__ import annotations

import asyncio
import gc
import json
import os
import socket
import threading
from collections.abc import Callable, Coroutine, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from pydantic import BaseModel

from maljan.core.config import Settings

from .anthropic_wire import message, streamed

# ---------------------------------------------------------------------------
# The stub server


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # noqa: D102 — quiet
        return

    def setup(self) -> None:
        super().setup()
        self.server.opened += 1  # type: ignore[attr-defined]

    def _answer(self, body: dict[str, Any]) -> tuple[str, bytes]:
        """The content type and bytes the API this path belongs to answers with."""
        path = self.path.split("?", 1)[0]
        if path.endswith("/messages"):
            tools = body.get("tools") or []
            content: list[dict[str, Any]] = [{"type": "text", "text": "answered"}]
            if tools:
                content = [
                    {
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": tools[0]["name"],
                        "input": {"summary": "answered"},
                    }
                ]
            answer = message(
                content,
                stop="tool_use" if tools else "end_turn",
                usage={"input_tokens": 3, "output_tokens": 1},
            )
            if body.get("stream"):
                return "text/event-stream", streamed(answer)
            return "application/json", json.dumps(answer).encode()
        if path.endswith("/chat/completions"):
            answer = {
                "id": "c1",
                "object": "chat.completion",
                "created": 1,
                "model": "m",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "answered"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
            }
            return "application/json", json.dumps(answer).encode()
        if path.endswith("/api/chat"):
            line = {
                "model": "m",
                "created_at": "2026-01-01T00:00:00Z",
                "message": {"role": "assistant", "content": "answered"},
                "done": True,
                "done_reason": "stop",
                "prompt_eval_count": 3,
                "eval_count": 1,
            }
            return "application/x-ndjson", (json.dumps(line) + "\n").encode()
        if ":generateContent" in path:
            answer = {
                "candidates": [
                    {
                        "content": {"role": "model", "parts": [{"text": "answered"}]},
                        "finishReason": "STOP",
                    }
                ],
                "usageMetadata": {
                    "promptTokenCount": 3,
                    "candidatesTokenCount": 1,
                    "totalTokenCount": 4,
                },
            }
            return "application/json", json.dumps(answer).encode()
        return "application/json", json.dumps({"answered": True}).encode()

    def _reply(self) -> None:
        length = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = {}
        self.server.requests += 1  # type: ignore[attr-defined]
        self.server.cookies.append(self.headers.get("cookie"))  # type: ignore[attr-defined]
        self.server.targets.append(self.path)  # type: ignore[attr-defined]
        kind, data = self._answer(body if isinstance(body, dict) else {})
        self.send_response(200)
        # As a CDN in front of a hosted API sets one, to be sent back.
        self.send_header("set-cookie", "__cf_bm=abc; Path=/")
        self.send_header("content-type", kind)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_POST = _reply  # noqa: N815
    do_GET = _reply  # noqa: N815


@pytest.fixture
def server() -> Iterator[ThreadingHTTPServer]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    httpd.opened = 0  # type: ignore[attr-defined]
    httpd.requests = 0  # type: ignore[attr-defined]
    httpd.cookies = []  # type: ignore[attr-defined]
    httpd.targets = []  # type: ignore[attr-defined]
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


# ---------------------------------------------------------------------------
# Two running loops


class _LoopThread:
    """An event loop served on a thread of its own, as the agent loop is."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self._thread.start()

    def run(self, coro: Coroutine[Any, Any, Any]) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(30)

    def close(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(10)
        self.loop.close()


@pytest.fixture
def agent_loop() -> Iterator[_LoopThread]:
    loop = _LoopThread()
    try:
        yield loop
    finally:
        if not loop.loop.is_closed():
            loop.close()


def _on_both(agent_loop: _LoopThread, call: Callable[[], Coroutine[Any, Any, Any]]) -> list[Any]:
    """``call`` on the agent loop, on a second loop, and on the agent loop again."""
    results = [agent_loop.run(call())]
    results.append(asyncio.run(call()))
    results.append(agent_loop.run(call()))
    return results


def _socket_count() -> int:
    count = 0
    for name in os.listdir("/proc/self/fd"):
        try:
            if os.readlink(f"/proc/self/fd/{name}").startswith("socket:"):
                count += 1
        except OSError:
            continue
    return count


# ---------------------------------------------------------------------------
# The providers


class _Section(BaseModel):
    summary: str


def _anthropic(httpd: ThreadingHTTPServer) -> Any:
    from maljan.llm.anthropic_provider import AnthropicProvider

    settings = Settings(_env_file=None, llm={"anthropic": {"api_key": "test-value"}})
    return AnthropicProvider(settings).build_model(
        "claude-haiku-5-5", 0.0, base_url=_url(httpd), max_retries=0, max_tokens=64
    )


def _openai(httpd: ThreadingHTTPServer) -> Any:
    from maljan.llm.openai_provider import OpenAIProvider

    settings = Settings(
        _env_file=None,
        llm={"openai": {"api_key": "test-value", "base_url": f"{_url(httpd)}/v1"}},
    )
    settings.llm.openai.compat = "standard"
    return OpenAIProvider(settings).build_model("m", 0.0, max_tokens=64)


class TestTheAnthropicModel:
    def test_one_model_answers_on_two_running_loops(
        self, server: ThreadingHTTPServer, agent_loop: _LoopThread
    ) -> None:
        model = _anthropic(server)

        async def call() -> str:
            return str((await model.ainvoke("hello")).content)

        assert _on_both(agent_loop, call) == ["answered"] * 3

    def test_a_streamed_answer_is_read_on_two_running_loops(
        self, server: ThreadingHTTPServer, agent_loop: _LoopThread
    ) -> None:
        model = _anthropic(server)

        async def call() -> str:
            return "".join([str(chunk.content) async for chunk in model.astream("hello")])

        assert _on_both(agent_loop, call) == ["answered"] * 3

    def test_a_structured_answer_is_read_on_two_running_loops(
        self, server: ThreadingHTTPServer, agent_loop: _LoopThread
    ) -> None:
        structured = _anthropic(server).with_structured_output(_Section)

        async def call() -> str:
            return str((await structured.ainvoke("hello")).summary)

        assert _on_both(agent_loop, call) == ["answered"] * 3

    def test_two_models_for_one_endpoint_answer_on_two_running_loops(
        self, server: ThreadingHTTPServer, agent_loop: _LoopThread
    ) -> None:
        # Each stage builds its own model; the pool behind them was the shared one.
        async def call() -> str:
            return str((await _anthropic(server).ainvoke("hello")).content)

        assert _on_both(agent_loop, call) == ["answered"] * 3

    def test_many_loops_leave_no_socket_open(self, server: ThreadingHTTPServer) -> None:
        model = _anthropic(server)

        async def call() -> str:
            return str((await model.ainvoke("hello")).content)

        asyncio.run(call())
        gc.collect()
        before = _socket_count()
        for _ in range(25):
            assert asyncio.run(call()) == "answered"
        gc.collect()
        assert _socket_count() <= before
        assert server.requests == 26  # type: ignore[attr-defined]
        # Each loop's client was closed with its loop, and none is held for it.
        assert len(model._async_client._client._loop_bound_clients) == 0

    def test_a_loop_closed_without_its_shutdown_leaves_no_socket_open(
        self, server: ThreadingHTTPServer
    ) -> None:
        model = _anthropic(server)

        async def call() -> str:
            return str((await model.ainvoke("hello")).content)

        asyncio.run(call())
        gc.collect()
        before = _socket_count()
        for _ in range(10):
            # A retired agent loop: stopped and closed, its generators never shut down.
            retired = _LoopThread()
            assert retired.run(call()) == "answered"
            retired.close()
            assert asyncio.run(call()) == "answered"
        gc.collect()
        assert _socket_count() <= before + 1
        # Only the last retired loop can still be held: the next send forgets it.
        assert len(model._async_client._client._loop_bound_clients) <= 1

    def test_loops_on_many_threads_at_once_each_get_their_own_connections(
        self, server: ThreadingHTTPServer
    ) -> None:
        model = _anthropic(server)
        answers: list[str] = []
        errors: list[BaseException] = []
        start = threading.Barrier(8)

        def worker() -> None:
            async def calls() -> None:
                for _ in range(3):
                    answers.append(str((await model.ainvoke("hello")).content))

            try:
                start.wait(10)
                asyncio.run(calls())
            except BaseException as exc:  # noqa: BLE001 — reported below
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(30)
        assert errors == []
        assert answers == ["answered"] * 24
        assert len(model._async_client._client._loop_bound_clients) == 0

    def test_a_cookie_the_server_sets_is_sent_back_on_every_loop(
        self, server: ThreadingHTTPServer, agent_loop: _LoopThread
    ) -> None:
        # The jar is the one every request is built from, whichever loop sent
        # the answer that set the cookie.
        model = _anthropic(server)

        async def call() -> str:
            return str((await model.ainvoke("hello")).content)

        _on_both(agent_loop, call)
        asyncio.run(call())
        assert server.cookies == [None, "__cf_bm=abc", "__cf_bm=abc", "__cf_bm=abc"]  # type: ignore[attr-defined]


class TestTheOpenAIModel:
    def test_one_model_answers_on_two_running_loops(
        self, server: ThreadingHTTPServer, agent_loop: _LoopThread
    ) -> None:
        model = _openai(server)

        async def call() -> str:
            return str((await model.ainvoke("hello")).content)

        assert _on_both(agent_loop, call) == ["answered"] * 3

    def test_many_loops_leave_no_socket_open(self, server: ThreadingHTTPServer) -> None:
        model = _openai(server)

        async def call() -> str:
            return str((await model.ainvoke("hello")).content)

        asyncio.run(call())
        gc.collect()
        before = _socket_count()
        for _ in range(25):
            assert asyncio.run(call()) == "answered"
        gc.collect()
        assert _socket_count() <= before


def _ollama(base_url: str) -> Any:
    from maljan.llm.ollama_provider import OllamaProvider

    settings = Settings(_env_file=None, llm={"ollama": {"base_url": base_url}})
    return OllamaProvider(settings).build_model("m", 0.0)


class TestTheOllamaModel:
    def test_one_model_answers_on_two_running_loops(
        self, server: ThreadingHTTPServer, agent_loop: _LoopThread
    ) -> None:
        model = _ollama(_url(server))

        async def call() -> str:
            return str((await model.ainvoke("hello")).content)

        assert _on_both(agent_loop, call) == ["answered"] * 3

    def test_a_proxy_named_in_the_environment_is_still_used(
        self,
        server: ThreadingHTTPServer,
        agent_loop: _LoopThread,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The stub stands as the proxy; the Ollama host itself does not resolve.
        for name in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy", "HTTPS_PROXY"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("HTTP_PROXY", _url(server))
        model = _ollama("http://ollama.invalid:11434")

        async def call() -> str:
            return str((await model.ainvoke("hello")).content)

        assert _on_both(agent_loop, call) == ["answered"] * 3
        assert server.targets == ["http://ollama.invalid:11434/api/chat"] * 3  # type: ignore[attr-defined]


class TestTheGeminiModel:
    def test_one_model_answers_on_two_running_loops(
        self, server: ThreadingHTTPServer, agent_loop: _LoopThread
    ) -> None:
        from maljan.llm.gemini_provider import GeminiProvider

        settings = Settings(_env_file=None, llm={"gemini": {"api_key": "test-value"}})
        model = GeminiProvider(settings).build_model("gemini-test", 0.0, base_url=_url(server))

        async def call() -> str:
            return str((await model.ainvoke("hello")).content)

        assert _on_both(agent_loop, call) == ["answered"] * 3
        # The provider retries; a crossed loop would show as a request sent twice.
        assert server.requests == 3  # type: ignore[attr-defined]


def test_a_gemini_client_laid_out_otherwise_is_named_in_one_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from types import SimpleNamespace

    from maljan.llm import gemini_provider, loop_clients

    monkeypatch.setattr(loop_clients, "_UNRECOGNISED", set())
    moved = SimpleNamespace(client=SimpleNamespace(_api_client=SimpleNamespace()))
    with caplog.at_level("WARNING"):
        gemini_provider._bind_async_client_per_loop(moved)
        gemini_provider._bind_async_client_per_loop(moved)
    lines = [r.getMessage() for r in caplog.records if "gemini provider" in r.getMessage()]
    assert len(lines) == 1
    assert "left one per model" in lines[0]
    assert "test-value" not in lines[0]


def test_the_stub_server_keeps_its_connections_alive(server: ThreadingHTTPServer) -> None:
    """The reuse the tests above depend on: two requests, one connection."""
    with socket.create_connection(server.server_address[:2]) as conn:
        for _ in range(2):
            conn.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            data = b""
            while b"}" not in data:
                data += conn.recv(4096)
    assert server.opened == 1  # type: ignore[attr-defined]
    assert server.requests == 2  # type: ignore[attr-defined]
