"""A loopback model server for rehearsing a whole analysis at zero cost.

It speaks the Anthropic Messages API (``POST /v1/messages``, the Models API's
``GET /v1/models/{id}``) and the OpenAI-compatible chat completions API
(``POST /v1/chat/completions``, ``GET /v1/models``, llama.cpp's ``/props``),
streamed or whole, and answers every request from a script
(``scripts.rehearsal.roles``) that reads the request's own role markers and
tool list. Maljan reaches it only through its own settings: the OpenAI base URL,
or the Anthropic base URL.

Before a request is answered it is held to the rules the real API holds it to
(``scripts.rehearsal.validate``): a request the paid API would refuse is
refused here with the same status and error body, and the stub's log says so.
Every answer is cut at the request's own output cap, every thinking block is
signed to what it was written after, and usage reports the prompt cache's
reads and writes as the provider would.

A simulated pace — time to first token and tokens per second — makes every
answer take the time a real model would. ``GET /_stub/log`` answers every
request seen: the role it was read as, its usage, the fault the scenario
applied and any refusal.

Run on its own::

    python scripts/rehearsal/stub_model.py --port 8765 --scenario normal \\
        --tokens-per-second 400 --first-token-seconds 0.2

It binds 127.0.0.1 only and never makes a request of its own.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import threading
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.rehearsal import validate, wire  # noqa: E402
from scripts.rehearsal.models import ModelFacts, facts_for  # noqa: E402
from scripts.rehearsal.roles import Brain, composer_section, role_of  # noqa: E402

LOOPBACK = "127.0.0.1"


@dataclass
class Pace:
    """How fast the simulated model answers."""

    first_token_seconds: float = 0.0
    tokens_per_second: float = 0.0

    def seconds_for(self, tokens: int) -> float:
        if self.tokens_per_second <= 0:
            return 0.0
        return tokens / self.tokens_per_second


@dataclass
class StubState:
    brain: Brain
    pace: Pace = field(default_factory=Pace)
    # A window every model is served with instead of its documented one.
    window: int | None = None
    slots: int = 1
    # The key every request must carry; ``None`` checks only that one is sent.
    api_key: str | None = None
    # The model names ``GET /v1/models`` lists, beside any model a request named.
    served: list[str] = field(default_factory=list)
    log: list[dict[str, Any]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    signer: validate.Signer = field(default_factory=validate.Signer)
    cache: validate.PromptCache = field(default_factory=validate.PromptCache)
    # Where each request body is written, one file per request; ``None`` keeps none.
    dump_dir: Path | None = None

    def facts(self, model: str) -> ModelFacts:
        return facts_for(model, window=self.window, slots=self.slots)

    def record(self, entry: dict[str, Any]) -> None:
        with self.lock:
            entry["n"] = len(self.log) + 1
            self.log.append(entry)
            model = str(entry.get("model") or "")
            if model and entry.get("status") == 200 and model not in self.served:
                self.served.append(model)


def _effort_of(body: dict[str, Any]) -> str:
    config = body.get("output_config")
    if isinstance(config, dict) and config.get("effort"):
        return str(config["effort"])
    return str(body.get("reasoning_effort") or "")


def _entry(request: wire.Request, role: str) -> dict[str, Any]:
    return {
        "at": time.time(),
        "api": request.api,
        "model": request.model,
        "role": role,
        "stream": request.stream,
        "max_tokens": request.max_tokens,
        "tools": len(request.tools),
        "turns": len(request.turns),
        "effort": _effort_of(request.raw),
        "fault": "",
        "refused": "",
    }


def build_app(state: StubState) -> Any:
    """The Starlette application serving both dialects from ``state``."""
    from starlette.applications import Starlette
    from starlette.requests import Request as HttpRequest
    from starlette.responses import JSONResponse, StreamingResponse
    from starlette.routing import Route

    async def _paced(events: Iterator[tuple[str, int]]) -> AsyncIterator[bytes]:
        if state.pace.first_token_seconds > 0:
            await asyncio.sleep(state.pace.first_token_seconds)
        for chunk, tokens in events:
            delay = state.pace.seconds_for(tokens)
            if delay > 0:
                await asyncio.sleep(delay)
            yield chunk.encode("utf-8")

    def _headers(api: str, extra: dict[str, str] | None = None) -> dict[str, str]:
        key = "request-id" if api == "anthropic" else "x-request-id"
        return {key: wire.new_id("req_"), **(extra or {})}

    def _error(api: str, status: int, message: str, extra: dict[str, str] | None = None) -> Any:
        return JSONResponse(
            wire.error_body(api, status, message), status_code=status, headers=_headers(api, extra)
        )

    async def _answer(http: HttpRequest, api: str) -> Any:
        body = await http.json()
        headers = dict(http.headers)
        request = (
            wire.read_anthropic(body, headers)
            if api == "anthropic"
            else wire.read_openai(body, headers)
        )
        facts = state.facts(request.model)
        entry = _entry(request, role_of(request))
        try:
            validate.check_credentials(api, request, state.api_key)
        except validate.ApiError as refusal:
            entry.update(status=refusal.status, refused=refusal.message, stop="error")
            entry.update(input_tokens=0, output_tokens=0)
            state.record(entry)
            return _error(api, refusal.status, refusal.message)
        if not facts.known and request.model not in state.served:
            # An id the API does not serve is a 404, before anything is read.
            entry.update(status=404, refused=f"model: {request.model}", stop="error")
            entry.update(input_tokens=0, output_tokens=0)
            state.record(entry)
            return _error(api, 404, f"model: {request.model}")
        if state.dump_dir is not None:
            state.dump_dir.mkdir(parents=True, exist_ok=True)
            (state.dump_dir / f"{len(state.log) + 1:04d}-{entry['role']}.json").write_text(
                json.dumps(body, indent=1), encoding="utf-8"
            )
        try:
            if api == "anthropic":
                validate.check_anthropic(body, request, facts, state.signer, api_key=state.api_key)
            else:
                validate.check_openai(body, request, facts, api_key=state.api_key)
        except validate.ApiError as refusal:
            entry.update(status=refusal.status, refused=refusal.message, stop="error")
            entry.update(input_tokens=request.input_tokens, output_tokens=0)
            state.record(entry)
            return _error(api, refusal.status, refusal.message)
        role, reply, fault = state.brain.answer(request)
        entry["role"], entry["fault"], entry["delay"] = role, fault, reply.delay
        if role == "composer":
            entry["section"] = composer_section(request)
        reply = wire.cut_to(reply, request.max_tokens)
        entry.update(reply.note)
        if reply.delay > 0:
            await asyncio.sleep(reply.delay)
        if reply.status != 200:
            entry.update(status=reply.status, stop="error", input_tokens=0, output_tokens=0)
            state.record(entry)
            if state.pace.first_token_seconds > 0:
                await asyncio.sleep(state.pace.first_token_seconds)
            return _error(api, reply.status, reply.error, reply.headers)
        if api == "anthropic":
            prefix = validate.anthropic_prefix(body, len(body.get("messages") or []), facts)
            reply.signature = state.signer.sign(prefix, reply.thinking)
            reply.redacted_data = state.signer.redacted(prefix) if reply.redacted else ""
            if reply.thinking or reply.redacted:
                state.signer.thought_tool_ids.update(c.id for c in wire.calls_with_ids(reply))
            usage = state.cache.anthropic(
                body, reply.output_tokens, reply.thinking_tokens, facts.min_cacheable
            )
        else:
            usage = state.cache.openai(
                body, reply.output_tokens, reply.thinking_tokens, facts.min_cacheable
            )
        entry.update(
            status=200,
            stop=reply.stop_reason(),
            tool_calls=[call.name for call in reply.tool_calls],
            text_chars=len(reply.text),
            stream_error=reply.stream_error,
            **usage.as_log(),
        )
        state.record(entry)
        if request.stream:
            events = (
                wire.anthropic_events(request, reply, usage)
                if api == "anthropic"
                else wire.openai_events(request, reply, usage)
            )
            return StreamingResponse(
                _paced(events), media_type="text/event-stream", headers=_headers(api)
            )
        delay = state.pace.first_token_seconds + state.pace.seconds_for(reply.output_tokens)
        if delay > 0:
            await asyncio.sleep(delay)
        if reply.stream_error:
            # A whole answer cannot break off; the overload is the answer.
            status = 529 if api == "anthropic" else 503
            return _error(api, status, "Overloaded")
        whole = (
            wire.anthropic_message(request, reply, usage)
            if api == "anthropic"
            else wire.openai_completion(request, reply, usage)
        )
        return JSONResponse(whole, headers=_headers(api))

    async def messages(http: HttpRequest) -> Any:
        return await _answer(http, "anthropic")

    async def chat(http: HttpRequest) -> Any:
        return await _answer(http, "openai")

    async def anthropic_model(http: HttpRequest) -> Any:
        model = http.path_params["model"]
        answer = state.facts(model).models_api_answer()
        if answer is None:
            return _error("anthropic", 404, f"model: {model}")
        return JSONResponse(answer, headers=_headers("anthropic"))

    async def model_list(http: HttpRequest) -> Any:
        with state.lock:
            names = list(state.served)
        return JSONResponse(
            {
                "object": "list",
                "data": [
                    {
                        "id": name,
                        "object": "model",
                        "owned_by": "rehearsal",
                        "context_length": state.facts(name).window,
                    }
                    for name in names
                ],
            }
        )

    async def props(http: HttpRequest) -> Any:
        with state.lock:
            names = list(state.served)
        window = state.facts(names[0]).window if names else (state.window or 200_000)
        return JSONResponse(
            {"default_generation_settings": {"n_ctx": window}, "total_slots": state.slots}
        )

    async def log(http: HttpRequest) -> Any:
        with state.lock:
            return JSONResponse(list(state.log))

    async def reset(http: HttpRequest) -> Any:
        with state.lock:
            state.log.clear()
        state.brain.reset()
        state.cache = validate.PromptCache()
        return JSONResponse({"ok": True})

    return Starlette(
        routes=[
            Route("/v1/messages", messages, methods=["POST"]),
            Route("/v1/chat/completions", chat, methods=["POST"]),
            Route("/chat/completions", chat, methods=["POST"]),
            Route("/v1/models/{model:path}", anthropic_model, methods=["GET"]),
            Route("/v1/models", model_list, methods=["GET"]),
            Route("/props", props, methods=["GET"]),
            Route("/_stub/log", log, methods=["GET"]),
            Route("/_stub/reset", reset, methods=["POST"]),
        ]
    )


class StubServer:
    """The stub on a loopback port, in a thread of this process; ``stop`` ends it.

    Port 0, the default, takes a free port; ``root`` says which.
    """

    def __init__(self, state: StubState, port: int = 0, host: str = LOOPBACK) -> None:
        import socket

        import uvicorn

        self.state = state
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        self.host = host
        self._socket = sock
        self.port = int(sock.getsockname()[1])
        config = uvicorn.Config(
            build_app(state), log_level="warning", access_log=False, lifespan="off"
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(
            target=self._server.run, kwargs={"sockets": [sock]}, daemon=True
        )

    @property
    def root(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> StubServer:
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("the stub model server did not start")
            time.sleep(0.02)
        return self

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)
        try:
            self._socket.close()
        except OSError:
            pass

    def __enter__(self) -> StubServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()


def main(argv: list[str] | None = None) -> int:
    from scripts.rehearsal.roles import SCENARIOS

    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--port", type=int, default=0, help="0 takes a free port")
    parser.add_argument("--scenario", default="normal", choices=sorted(SCENARIOS))
    parser.add_argument("--model", action="append", default=[], help="a model GET /v1/models lists")
    parser.add_argument("--tokens-per-second", type=float, default=0.0)
    parser.add_argument("--first-token-seconds", type=float, default=0.0)
    parser.add_argument("--window", type=int, default=None, help="serve every model this window")
    parser.add_argument("--slots", type=int, default=1)
    parser.add_argument("--chars-per-token", type=int, default=4)
    parser.add_argument("--loop-steps", type=int, default=0, help="tool calls per analyst loop")
    parser.add_argument("--slow-seconds", type=float, default=0.0, help="slow-model delay")
    parser.add_argument("--dump-dir", default="", help="write every request body here")
    args = parser.parse_args(argv)
    wire.set_chars_per_token(args.chars_per_token)
    brain = Brain(
        scenario=args.scenario,
        loop_steps=args.loop_steps or None,
        slow_seconds=args.slow_seconds or None,
    )
    state = StubState(
        brain=brain,
        pace=Pace(args.first_token_seconds, args.tokens_per_second),
        window=args.window,
        slots=args.slots,
        served=list(args.model),
        dump_dir=Path(args.dump_dir) if args.dump_dir else None,
    )
    server = StubServer(state, args.port).start()
    print(json.dumps({"root": server.root, "scenario": args.scenario}), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
