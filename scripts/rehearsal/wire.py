"""The two wire formats the stub model speaks, read into one request shape and written back.

A request in either dialect is read into :class:`Request` — the system text,
the turns with their tool calls and tool results, the tools offered, the
output cap, whether to stream — so a script that picks an answer never needs
to know which API asked. A :class:`Reply` — thinking (plain or redacted),
text, tool calls, how it stopped — is written back with its :class:`Usage` as
the Anthropic Messages API or the OpenAI-compatible chat completions API
writes it, streamed as server-sent events (with ``ping`` events, and an
``error`` event mid-stream when the reply asks for one) or whole. Error
bodies are typed by status as each API types them.

Nothing here decides what to answer (``scripts.rehearsal.roles``) or whether
a request is one the API would take (``scripts.rehearsal.validate``).
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

# Characters per token. A stub has no tokenizer; four is the product's own
# figure, and ``set_chars_per_token(3)`` counts a JSON-heavy prompt the way a
# real tokenizer does, so an estimator that undercounts shows up.
_CHARS_PER_TOKEN = [4]


def set_chars_per_token(chars: int) -> None:
    """Count tokens at ``chars`` characters each from now on (at least one)."""
    _CHARS_PER_TOKEN[0] = max(1, int(chars))


def tokens_of(text: str) -> int:
    """A token count that grows with ``text``, zero for none."""
    per = _CHARS_PER_TOKEN[0]
    return (len(text) + per - 1) // per if text else 0


@dataclass
class ToolCall:
    """One call to a tool, as an assistant turn carries it."""

    name: str
    args: dict[str, Any]
    id: str = ""


@dataclass
class ToolResult:
    """One tool's answer, as the next user (or tool) turn carries it."""

    id: str
    text: str


@dataclass
class Turn:
    """One message of the conversation, in either dialect."""

    role: str
    text: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)


@dataclass
class Request:
    """What a request asked for, whichever API it was sent to."""

    api: str
    model: str
    system: str
    turns: list[Turn]
    tools: list[dict[str, Any]]
    max_tokens: int | None
    stream: bool
    raw: dict[str, Any]
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def tool_names(self) -> list[str]:
        return [str(tool.get("name") or "") for tool in self.tools]

    @property
    def last_user_text(self) -> str:
        for turn in reversed(self.turns):
            if turn.role == "user" and turn.text:
                return turn.text
        return ""

    @property
    def all_text(self) -> str:
        """Every word the request carries, system first."""
        parts = [self.system]
        for turn in self.turns:
            parts.append(turn.text)
            parts.extend(result.text for result in turn.tool_results)
        return "\n".join(part for part in parts if part)

    @property
    def tool_results(self) -> list[ToolResult]:
        return [result for turn in self.turns for result in turn.tool_results]

    @property
    def tool_calls_made(self) -> list[ToolCall]:
        return [call for turn in self.turns for call in turn.tool_calls]

    @property
    def input_tokens(self) -> int:
        """The whole prompt, counted over the request body as it was sent."""
        body = {k: v for k, v in self.raw.items() if k in ("system", "messages", "tools")}
        return tokens_of(json.dumps(body, ensure_ascii=False, sort_keys=True))


# How a reply stops, in the stub's own words; each API spells them its way.
STOPS = ("end", "tool", "max_tokens", "refusal", "pause_turn", "context_window")


@dataclass
class Reply:
    """One answer: what the model thought, wrote and called, and how it stopped.

    ``stop`` is one of :data:`STOPS`, or empty for "end" or "tool" as the
    reply's calls say. ``status`` other than 200 answers with an error body
    instead. ``stream_error`` breaks a streamed answer off with an
    ``overloaded_error`` event after its first content. ``redacted`` adds a
    ``redacted_thinking`` block before the answer.
    """

    text: str = ""
    thinking: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop: str = ""
    status: int = 200
    error: str = ""
    redacted: bool = False
    stream_error: bool = False
    # Extra response headers (``retry-after``).
    headers: dict[str, str] = field(default_factory=dict)
    # Set by the server before the reply is written: the thinking block's
    # signature and the redacted block's data, both bound to the request.
    signature: str = ""
    redacted_data: str = ""
    # Seconds the server waits before it starts answering, on top of its pace.
    delay: float = 0.0
    # What the script wants the stub's log to say about this reply.
    note: dict[str, Any] = field(default_factory=dict)

    def stop_reason(self) -> str:
        if self.stop:
            return self.stop
        return "tool" if self.tool_calls else "end"

    @property
    def thinking_tokens(self) -> int:
        return tokens_of(self.thinking) + (tokens_of(self.redacted_data) if self.redacted else 0)

    @property
    def output_tokens(self) -> int:
        calls = sum(tokens_of(json.dumps(call.args)) for call in self.tool_calls)
        return tokens_of(self.text) + self.thinking_tokens + calls


def cut_to(reply: Reply, cap: int | None) -> Reply:
    """``reply`` as the model would end it at an output cap of ``cap`` tokens.

    Thinking is written first, then text, then tool calls; whatever does not
    fit is cut, a tool call that does not fit whole is not written, and the
    reply stops at ``max_tokens``.
    """
    if not cap or cap <= 0 or reply.output_tokens <= cap or reply.status != 200:
        return reply
    per = _CHARS_PER_TOKEN[0]
    left = cap
    thinking_room = min(tokens_of(reply.thinking), left)
    reply.thinking = reply.thinking[: thinking_room * per]
    left -= tokens_of(reply.thinking)
    reply.text = reply.text[: max(0, left) * per]
    left -= tokens_of(reply.text)
    kept = []
    for call in reply.tool_calls:
        cost = tokens_of(json.dumps(call.args))
        if cost > left:
            break
        kept.append(call)
        left -= cost
    reply.tool_calls = kept
    reply.stop = "max_tokens"
    reply.note = {**reply.note, "cut_at_cap": cap}
    return reply


@dataclass
class Usage:
    """What one call consumed, as the provider reports it."""

    input_tokens: int
    output_tokens: int
    cache_read: int = 0
    cache_write_5m: int = 0
    cache_write_1h: int = 0
    reasoning_tokens: int = 0

    @property
    def cache_write(self) -> int:
        return self.cache_write_5m + self.cache_write_1h

    @property
    def total_input(self) -> int:
        return self.input_tokens + self.cache_read + self.cache_write

    def as_log(self) -> dict[str, int]:
        return {
            "input_tokens": self.total_input,
            "uncached_input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read,
            "cache_write_5m_tokens": self.cache_write_5m,
            "cache_write_1h_tokens": self.cache_write_1h,
            "reasoning_tokens": self.reasoning_tokens,
        }


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                out.append(str(block.get("text") or ""))
            elif isinstance(block, str):
                out.append(block)
        return "\n".join(out)
    return ""


def read_anthropic(body: dict[str, Any], headers: dict[str, str] | None = None) -> Request:
    """An Anthropic Messages API request body as a :class:`Request`."""
    system = _text_of(body.get("system"))
    turns: list[Turn] = []
    for message in body.get("messages") or []:
        role = str(message.get("role") or "")
        content = message.get("content")
        turn = Turn(role=role)
        if isinstance(content, str):
            turn.text = content
        else:
            texts = []
            for block in content or []:
                kind = block.get("type") if isinstance(block, dict) else None
                if kind == "text":
                    texts.append(str(block.get("text") or ""))
                elif kind == "tool_use":
                    turn.tool_calls.append(
                        ToolCall(
                            name=str(block.get("name") or ""),
                            args=dict(block.get("input") or {}),
                            id=str(block.get("id") or ""),
                        )
                    )
                elif kind == "tool_result":
                    turn.tool_results.append(
                        ToolResult(
                            id=str(block.get("tool_use_id") or ""),
                            text=_text_of(block.get("content")),
                        )
                    )
            turn.text = "\n".join(texts)
        turns.append(turn)
    tools = [
        {
            "name": tool.get("name"),
            "description": tool.get("description") or "",
            "schema": tool.get("input_schema") or {},
        }
        for tool in body.get("tools") or []
        if isinstance(tool, dict)
    ]
    cap = body.get("max_tokens")
    return Request(
        api="anthropic",
        model=str(body.get("model") or ""),
        system=system,
        turns=turns,
        tools=tools,
        max_tokens=int(cap) if isinstance(cap, int) else None,
        stream=bool(body.get("stream")),
        raw=body,
        headers={k.lower(): v for k, v in (headers or {}).items()},
    )


def read_openai(body: dict[str, Any], headers: dict[str, str] | None = None) -> Request:
    """An OpenAI-compatible chat completions request body as a :class:`Request`."""
    system_parts: list[str] = []
    turns: list[Turn] = []
    for message in body.get("messages") or []:
        role = str(message.get("role") or "")
        text = _text_of(message.get("content"))
        if role in ("system", "developer"):
            system_parts.append(text)
            continue
        if role == "tool":
            result = ToolResult(id=str(message.get("tool_call_id") or ""), text=text)
            if turns and turns[-1].role == "user" and not turns[-1].text:
                turns[-1].tool_results.append(result)
            else:
                turns.append(Turn(role="user", tool_results=[result]))
            continue
        turn = Turn(role=role, text=text)
        for call in message.get("tool_calls") or []:
            function = call.get("function") or {}
            try:
                args = json.loads(function.get("arguments") or "{}")
            except ValueError:
                args = {}
            turn.tool_calls.append(
                ToolCall(
                    name=str(function.get("name") or ""),
                    args=args if isinstance(args, dict) else {},
                    id=str(call.get("id") or ""),
                )
            )
        turns.append(turn)
    tools = []
    for tool in body.get("tools") or []:
        function = tool.get("function") if isinstance(tool, dict) else None
        if isinstance(function, dict):
            tools.append(
                {
                    "name": function.get("name"),
                    "description": function.get("description") or "",
                    "schema": function.get("parameters") or {},
                }
            )
    cap = body.get("max_completion_tokens", body.get("max_tokens"))
    return Request(
        api="openai",
        model=str(body.get("model") or ""),
        system="\n".join(system_parts),
        turns=turns,
        tools=tools,
        max_tokens=int(cap) if isinstance(cap, int) else None,
        stream=bool(body.get("stream")),
        raw=body,
        headers={k.lower(): v for k, v in (headers or {}).items()},
    )


def new_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:24]}"


def calls_with_ids(reply: Reply, prefix: str = "toolu_") -> list[ToolCall]:
    """The reply's tool calls, each given an id now if it has none."""
    return _calls_with_ids(reply, prefix)


def _calls_with_ids(reply: Reply, prefix: str) -> list[ToolCall]:
    for call in reply.tool_calls:
        if not call.id:
            call.id = new_id(prefix)
    return reply.tool_calls


# ------------------------------------------------------------------------ errors

# How each API types an error by its status.
_ANTHROPIC_ERROR_TYPES = {
    400: "invalid_request_error",
    401: "authentication_error",
    403: "permission_error",
    404: "not_found_error",
    413: "request_too_large",
    429: "rate_limit_error",
    500: "api_error",
    529: "overloaded_error",
}
_OPENAI_ERROR_TYPES = {
    400: "invalid_request_error",
    401: "invalid_request_error",
    403: "permission_error",
    404: "invalid_request_error",
    429: "rate_limit_exceeded",
    500: "server_error",
    503: "server_error",
}


def anthropic_error(status: int, message: str) -> dict[str, Any]:
    """The Messages API's error body for ``status``."""
    kind = _ANTHROPIC_ERROR_TYPES.get(
        status, "api_error" if status >= 500 else "invalid_request_error"
    )
    return {"type": "error", "error": {"type": kind, "message": message or kind}}


def openai_error(status: int, message: str) -> dict[str, Any]:
    """The chat completions API's error body for ``status``."""
    kind = _OPENAI_ERROR_TYPES.get(
        status, "server_error" if status >= 500 else "invalid_request_error"
    )
    code = "invalid_api_key" if status == 401 else None
    return {"error": {"message": message or kind, "type": kind, "param": None, "code": code}}


def error_body(api: str, status: int, message: str) -> dict[str, Any]:
    return anthropic_error(status, message) if api == "anthropic" else openai_error(status, message)


# --------------------------------------------------------------------- Anthropic

_ANTHROPIC_STOP = {
    "end": "end_turn",
    "tool": "tool_use",
    "max_tokens": "max_tokens",
    "refusal": "refusal",
    "pause_turn": "pause_turn",
    "context_window": "model_context_window_exceeded",
}


def anthropic_usage(usage: Usage) -> dict[str, Any]:
    return {
        "input_tokens": usage.input_tokens,
        "output_tokens": usage.output_tokens,
        "cache_creation_input_tokens": usage.cache_write,
        "cache_read_input_tokens": usage.cache_read,
        "cache_creation": {
            "ephemeral_5m_input_tokens": usage.cache_write_5m,
            "ephemeral_1h_input_tokens": usage.cache_write_1h,
        },
        "service_tier": "standard",
    }


def _anthropic_blocks(reply: Reply) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    if reply.redacted:
        blocks.append({"type": "redacted_thinking", "data": reply.redacted_data})
    if reply.thinking:
        blocks.append(
            {"type": "thinking", "thinking": reply.thinking, "signature": reply.signature}
        )
    if reply.text:
        blocks.append({"type": "text", "text": reply.text})
    for call in _calls_with_ids(reply, "toolu_"):
        blocks.append({"type": "tool_use", "id": call.id, "name": call.name, "input": call.args})
    return blocks


def anthropic_message(request: Request, reply: Reply, usage: Usage) -> dict[str, Any]:
    """The whole Messages API answer."""
    return {
        "id": new_id("msg_"),
        "type": "message",
        "role": "assistant",
        "model": request.model,
        "content": _anthropic_blocks(reply),
        "stop_reason": _ANTHROPIC_STOP[reply.stop_reason()],
        "stop_sequence": None,
        "usage": anthropic_usage(usage),
    }


def _sse(event: str, data: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _pieces(text: str, size: int = 24) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)] or []


_PING = _sse("ping", {"type": "ping"})
_OVERLOADED = _sse(
    "error", {"type": "error", "error": {"type": "overloaded_error", "message": "Overloaded"}}
)


def anthropic_events(request: Request, reply: Reply, usage: Usage) -> Iterator[tuple[str, int]]:
    """The streamed answer as server-sent events, each with the tokens it carries.

    A ``ping`` follows ``message_start`` and every eighth event, as the API
    sends them. A reply asking for a stream error breaks off with an
    ``overloaded_error`` event after its first content delta.
    """
    message = anthropic_message(request, reply, usage)
    message["content"] = []
    message["stop_reason"] = None
    message["usage"] = {**anthropic_usage(usage), "output_tokens": 1}
    yield _sse("message_start", {"type": "message_start", "message": message}), 0
    yield _PING, 0
    sent = 0
    for index, block in enumerate(_anthropic_blocks(reply)):
        for event, tokens in _anthropic_block_events(index, block):
            sent += 1
            if sent % 8 == 0:
                yield _PING, 0
            yield event, tokens
            if reply.stream_error and "content_block_delta" in event:
                yield _OVERLOADED, 0
                return
    final = anthropic_usage(usage)
    yield (
        _sse(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {
                    "stop_reason": _ANTHROPIC_STOP[reply.stop_reason()],
                    "stop_sequence": None,
                },
                # The whole usage, cumulative, as the API's message_delta carries it.
                "usage": final,
            },
        ),
        0,
    )
    yield _sse("message_stop", {"type": "message_stop"}), 0


def _anthropic_block_events(index: int, block: dict[str, Any]) -> Iterator[tuple[str, int]]:
    def delta(payload: dict[str, Any]) -> str:
        return _sse(
            "content_block_delta",
            {"type": "content_block_delta", "index": index, "delta": payload},
        )

    kind = block["type"]
    if kind == "redacted_thinking":
        start = {"type": "redacted_thinking", "data": block["data"]}
        yield (
            _sse(
                "content_block_start",
                {"type": "content_block_start", "index": index, "content_block": start},
            ),
            tokens_of(block["data"]),
        )
    elif kind == "thinking":
        start = {"type": "thinking", "thinking": "", "signature": ""}
        yield (
            _sse(
                "content_block_start",
                {"type": "content_block_start", "index": index, "content_block": start},
            ),
            0,
        )
        for piece in _pieces(block["thinking"]):
            yield delta({"type": "thinking_delta", "thinking": piece}), tokens_of(piece)
        yield delta({"type": "signature_delta", "signature": block["signature"]}), 0
    elif kind == "text":
        yield (
            _sse(
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": index,
                    "content_block": {"type": "text", "text": ""},
                },
            ),
            0,
        )
        for piece in _pieces(block["text"]):
            yield delta({"type": "text_delta", "text": piece}), tokens_of(piece)
    else:
        start = {"type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}
        yield (
            _sse(
                "content_block_start",
                {"type": "content_block_start", "index": index, "content_block": start},
            ),
            0,
        )
        for piece in _pieces(json.dumps(block["input"]), 64):
            yield delta({"type": "input_json_delta", "partial_json": piece}), tokens_of(piece)
    yield _sse("content_block_stop", {"type": "content_block_stop", "index": index}), 0


# ------------------------------------------------------------------------ OpenAI

_OPENAI_STOP = {
    "end": "stop",
    "tool": "tool_calls",
    "max_tokens": "length",
    "refusal": "content_filter",
    "pause_turn": "stop",
    "context_window": "length",
}


def openai_usage(usage: Usage) -> dict[str, Any]:
    total_in = usage.total_input
    return {
        "prompt_tokens": total_in,
        "completion_tokens": usage.output_tokens,
        "total_tokens": total_in + usage.output_tokens,
        "prompt_tokens_details": {"cached_tokens": usage.cache_read},
        "completion_tokens_details": {"reasoning_tokens": usage.reasoning_tokens},
        # DeepSeek's own spelling of the same split.
        "prompt_cache_hit_tokens": usage.cache_read,
        "prompt_cache_miss_tokens": total_in - usage.cache_read,
    }


def openai_completion(request: Request, reply: Reply, usage: Usage) -> dict[str, Any]:
    """The whole chat completions answer."""
    message: dict[str, Any] = {"role": "assistant", "content": reply.text or None}
    if reply.thinking:
        message["reasoning_content"] = reply.thinking
    calls = _calls_with_ids(reply, "call_")
    if calls:
        message["tool_calls"] = [
            {
                "id": call.id,
                "type": "function",
                "function": {"name": call.name, "arguments": json.dumps(call.args)},
            }
            for call in calls
        ]
    return {
        "id": new_id("chatcmpl-"),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": request.model,
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": _OPENAI_STOP[reply.stop_reason()],
            }
        ],
        "usage": openai_usage(usage),
    }


def openai_events(request: Request, reply: Reply, usage: Usage) -> Iterator[tuple[str, int]]:
    """The streamed answer as server-sent ``data:`` chunks, each with the tokens it carries."""
    ident = new_id("chatcmpl-")
    created = int(time.time())

    def chunk(delta: dict[str, Any], finish: str | None = None) -> str:
        body = {
            "id": ident,
            "object": "chat.completion.chunk",
            "created": created,
            "model": request.model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
        }
        return f"data: {json.dumps(body)}\n\n"

    yield chunk({"role": "assistant", "content": ""}), 0
    pieces: list[tuple[str, int]] = []
    for piece in _pieces(reply.thinking):
        pieces.append((chunk({"reasoning_content": piece}), tokens_of(piece)))
    for piece in _pieces(reply.text):
        pieces.append((chunk({"content": piece}), tokens_of(piece)))
    for index, call in enumerate(_calls_with_ids(reply, "call_")):
        head = {
            "index": index,
            "id": call.id,
            "type": "function",
            "function": {"name": call.name, "arguments": ""},
        }
        pieces.append((chunk({"tool_calls": [head]}), 0))
        for piece in _pieces(json.dumps(call.args), 64):
            part = {"index": index, "function": {"arguments": piece}}
            pieces.append((chunk({"tool_calls": [part]}), tokens_of(piece)))
    for number, (event, tokens) in enumerate(pieces):
        yield event, tokens
        if reply.stream_error and number == 0:
            error = openai_error(503, "The server is overloaded, please try again later.")
            yield f"data: {json.dumps(error)}\n\n", 0
            return
    yield chunk({}, _OPENAI_STOP[reply.stop_reason()]), 0
    options = request.raw.get("stream_options") or {}
    if isinstance(options, dict) and options.get("include_usage"):
        body = {
            "id": ident,
            "object": "chat.completion.chunk",
            "created": created,
            "model": request.model,
            "choices": [],
            "usage": openai_usage(usage),
        }
        yield f"data: {json.dumps(body)}\n\n", 0
    yield "data: [DONE]\n\n", 0
