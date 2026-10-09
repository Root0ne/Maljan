"""A loopback model server for rehearsing a whole analysis at zero cost.

It speaks the Anthropic Messages API (``POST /v1/messages``, the Models API's
``GET /v1/models/{id}``) and the OpenAI-compatible chat completions API
(``POST /v1/chat/completions``, ``GET /v1/models``, llama.cpp's ``/props``),
streamed or whole, and answers every request from a script
(``scripts.rehearsal.roles``) that reads the request's own role markers and
tool list. Maljan reaches it only through its own settings: the OpenAI base URL,
or the Anthropic base URL.

A simulated pace — time to first token and tokens per second — makes every
answer take the time a real model would, so a wall-clock effect is measurable
without paying for one. ``GET /_stub/log`` answers every request seen, with the
role it was read as and the fault (if any) the scenario applied.

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

from scripts.rehearsal import wire  # noqa: E402
from scripts.rehearsal.roles import Brain, composer_section  # noqa: E402

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
class ModelFacts:
    """What the metadata endpoints say about the served model."""

    window: int = 200_000
    max_output: int = 64_000
    slots: int = 1
    effort_levels: tuple[str, ...] = ("low", "medium", "high", "xhigh", "max")


@dataclass
class StubState:
    brain: Brain
    pace: Pace = field(default_factory=Pace)
    facts: ModelFacts = field(default_factory=ModelFacts)
    log: list[dict[str, Any]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)
    # Where each request body is written, one file per request; ``None`` keeps none.
    dump_dir: Path | None = None

    def record(self, entry: dict[str, Any]) -> None:
        with self.lock:
            entry["n"] = len(self.log) + 1
            self.log.append(entry)


def _summary(request: wire.Request, reply: wire.Reply, role: str, fault: str) -> dict[str, Any]:
    return {
        "at": time.time(),
        "api": request.api,
        "model": request.model,
        "role": role,
        "stream": request.stream,
        "max_tokens": request.max_tokens,
        "tools": len(request.tools),
        "turns": len(request.turns),
        "input_tokens": request.input_tokens,
        "output_tokens": reply.output_tokens,
        "status": reply.status,
        "stop": reply.stop_reason() if reply.status == 200 else "error",
        "tool_calls": [call.name for call in reply.tool_calls],
        "text_chars": len(reply.text),
        "fault": fault,
        "effort": _effort_of(request),
    }


def _effort_of(request: wire.Request) -> str:
    raw = request.raw
    config = raw.get("output_config")
    if isinstance(config, dict) and config.get("effort"):
        return str(config["effort"])
    return str(raw.get("reasoning_effort") or "")


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

    async def _whole_delay(reply: wire.Reply) -> None:
        delay = state.pace.first_token_seconds + state.pace.seconds_for(reply.output_tokens)
        if delay > 0:
            await asyncio.sleep(delay)

    async def _answer(http: HttpRequest, api: str) -> Any:
        body = await http.json()
        request = wire.read_anthropic(body) if api == "anthropic" else wire.read_openai(body)
        role, reply, fault = state.brain.answer(request)
        entry = _summary(request, reply, role, fault)
        entry.update(reply.note)
        if role == "composer":
            entry.setdefault("section", composer_section(request))
        state.record(entry)
        if state.dump_dir is not None:
            state.dump_dir.mkdir(parents=True, exist_ok=True)
            (state.dump_dir / f"{entry['n']:04d}-{role}.json").write_text(
                json.dumps(body, indent=1), encoding="utf-8"
            )
        if reply.delay > 0:
            await asyncio.sleep(reply.delay)
        if reply.status != 200:
            await _whole_delay(wire.Reply())
            error = wire.anthropic_error(reply) if api == "anthropic" else wire.openai_error(reply)
            return JSONResponse(error, status_code=reply.status)
        if request.stream:
            events = (
                wire.anthropic_events(request, reply)
                if api == "anthropic"
                else wire.openai_events(request, reply)
            )
            return StreamingResponse(_paced(events), media_type="text/event-stream")
        await _whole_delay(reply)
        whole = (
            wire.anthropic_message(request, reply)
            if api == "anthropic"
            else wire.openai_completion(request, reply)
        )
        return JSONResponse(whole)

    async def messages(http: HttpRequest) -> Any:
        return await _answer(http, "anthropic")

    async def chat(http: HttpRequest) -> Any:
        return await _answer(http, "openai")

    async def anthropic_model(http: HttpRequest) -> Any:
        model = http.path_params["model"]
        levels = {level: {"supported": True} for level in state.facts.effort_levels}
        return JSONResponse(
            {
                "type": "model",
                "id": model,
                "display_name": model,
                "created_at": "2026-01-01T00:00:00Z",
                "max_input_tokens": state.facts.window,
                "max_tokens": state.facts.max_output,
                "capabilities": {"effort": {"supported": True, **levels}},
            }
        )

    async def model_list(http: HttpRequest) -> Any:
        return JSONResponse(
            {
                "object": "list",
                "data": [
                    {
                        "id": state.brain.model_name,
                        "object": "model",
                        "owned_by": "rehearsal",
                        "context_length": state.facts.window,
                    }
                ],
            }
        )

    async def props(http: HttpRequest) -> Any:
        return JSONResponse(
            {
                "default_generation_settings": {"n_ctx": state.facts.window},
                "total_slots": state.facts.slots,
            }
        )

    async def log(http: HttpRequest) -> Any:
        with state.lock:
            return JSONResponse(list(state.log))

    async def reset(http: HttpRequest) -> Any:
        with state.lock:
            state.log.clear()
        state.brain.reset()
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
    """The stub on a loopback port, in a thread of this process; ``stop`` ends it."""

    def __init__(self, state: StubState, port: int = 0) -> None:
        import socket

        import uvicorn

        self.state = state
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LOOPBACK, port))
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
        return f"http://{LOOPBACK}:{self.port}"

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
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--scenario", default="normal", choices=sorted(SCENARIOS))
    parser.add_argument("--model", default="rehearsal-model")
    parser.add_argument("--tokens-per-second", type=float, default=0.0)
    parser.add_argument("--first-token-seconds", type=float, default=0.0)
    parser.add_argument("--window", type=int, default=200_000)
    parser.add_argument("--slots", type=int, default=1)
    parser.add_argument("--loop-steps", type=int, default=0, help="tool calls per analyst loop")
    parser.add_argument("--slow-seconds", type=float, default=0.0, help="slow-model delay")
    parser.add_argument("--dump-dir", default="", help="write every request body here")
    args = parser.parse_args(argv)
    brain = Brain(
        scenario=args.scenario,
        model_name=args.model,
        loop_steps=args.loop_steps or None,
        slow_seconds=args.slow_seconds or None,
    )
    state = StubState(
        brain=brain,
        pace=Pace(args.first_token_seconds, args.tokens_per_second),
        facts=ModelFacts(window=args.window, slots=args.slots),
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
