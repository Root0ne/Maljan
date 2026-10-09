"""The two wire formats the stub model speaks, read into one request shape and written back.

A request in either dialect is read into :class:`Request` — the system text,
the turns with their tool calls and tool results, the tools offered, the
output cap, whether to stream — so a script that picks an answer never needs
to know which API asked. A :class:`Reply` — thinking, text, tool calls, how it
stopped, its usage — is written back as the Anthropic Messages API or the
OpenAI-compatible chat completions API writes it, streamed as server-sent
events or whole.

Nothing here decides what to answer; ``scripts.rehearsal.roles`` does.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

# Roughly four characters a token: a stub has no tokenizer, and a figure that
# moves with the text is what a usage check needs.
CHARS_PER_TOKEN = 4


def tokens_of(text: str) -> int:
    """A token count that grows with ``text``, zero for none."""
    return (len(text) + CHARS_PER_TOKEN - 1) // CHARS_PER_TOKEN if text else 0


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
        return tokens_of(self.all_text) + tokens_of(json.dumps(self.tools))


@dataclass
class Reply:
    """One answer: what the model thought, wrote and called, and how it stopped.

    ``stop`` is ``end``, ``tool`` or ``max_tokens``. ``status`` other than 200
    answers with an error body instead. ``cached_tokens`` is the part of the
    input the reply reports as read from a prompt cache.
    """

    text: str = ""
    thinking: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop: str = ""
    status: int = 200
    error: str = ""
    cached_tokens: int = 0
    # Seconds the server waits before it starts answering, on top of its pace.
    delay: float = 0.0
    # What the script wants the stub's log to say about this reply.
    note: dict[str, Any] = field(default_factory=dict)

    def stop_reason(self) -> str:
        if self.stop:
            return self.stop
        return "tool" if self.tool_calls else "end"

    @property
    def output_tokens(self) -> int:
        calls = sum(tokens_of(json.dumps(call.args)) for call in self.tool_calls)
        return tokens_of(self.text) + tokens_of(self.thinking) + calls


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


def read_anthropic(body: dict[str, Any]) -> Request:
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
    )


def read_openai(body: dict[str, Any]) -> Request:
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
    )


def _new_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:24]}"


def _calls_with_ids(reply: Reply, prefix: str) -> list[ToolCall]:
    for call in reply.tool_calls:
        if not call.id:
            call.id = _new_id(prefix)
    return reply.tool_calls


# --------------------------------------------------------------------- Anthropic

_ANTHROPIC_STOP = {"end": "end_turn", "tool": "tool_use", "max_tokens": "max_tokens"}


def _anthropic_usage(request: Request, reply: Reply) -> dict[str, int]:
    cached = min(reply.cached_tokens, request.input_tokens)
    return {
        "input_tokens": request.input_tokens - cached,
        "output_tokens": reply.output_tokens,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": cached,
    }


def _anthropic_blocks(reply: Reply) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    if reply.thinking:
        blocks.append(
            {"type": "thinking", "thinking": reply.thinking, "signature": "stub-signature"}
        )
    if reply.text:
        blocks.append({"type": "text", "text": reply.text})
    for call in _calls_with_ids(reply, "toolu_"):
        blocks.append({"type": "tool_use", "id": call.id, "name": call.name, "input": call.args})
    return blocks


def anthropic_message(request: Request, reply: Reply) -> dict[str, Any]:
    """The whole Messages API answer."""
    return {
        "id": _new_id("msg_"),
        "type": "message",
        "role": "assistant",
        "model": request.model,
        "content": _anthropic_blocks(reply),
        "stop_reason": _ANTHROPIC_STOP[reply.stop_reason()],
        "stop_sequence": None,
        "usage": _anthropic_usage(request, reply),
    }


def anthropic_error(reply: Reply) -> dict[str, Any]:
    kind = "overloaded_error" if reply.status >= 500 else "invalid_request_error"
    return {"type": "error", "error": {"type": kind, "message": reply.error or "stub error"}}


def _sse(event: str, data: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _pieces(text: str, size: int = 24) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)] or []


def anthropic_events(request: Request, reply: Reply) -> Iterator[tuple[str, int]]:
    """The streamed answer as server-sent events, each with the tokens it carries."""
    usage = _anthropic_usage(request, reply)
    start_usage = dict(usage, output_tokens=1)
    message = anthropic_message(request, reply)
    message["content"] = []
    message["stop_reason"] = None
    message["usage"] = start_usage
    yield _sse("message_start", {"type": "message_start", "message": message}), 0
    for index, block in enumerate(_anthropic_blocks(reply)):
        kind = block["type"]
        if kind == "thinking":
            yield (
                _sse(
                    "content_block_start",
                    {
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {"type": "thinking", "thinking": "", "signature": ""},
                    },
                ),
                0,
            )
            for piece in _pieces(block["thinking"]):
                delta = {"type": "thinking_delta", "thinking": piece}
                yield (
                    _sse(
                        "content_block_delta",
                        {"type": "content_block_delta", "index": index, "delta": delta},
                    ),
                    tokens_of(piece),
                )
            delta = {"type": "signature_delta", "signature": block["signature"]}
            yield (
                _sse(
                    "content_block_delta",
                    {"type": "content_block_delta", "index": index, "delta": delta},
                ),
                0,
            )
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
                delta = {"type": "text_delta", "text": piece}
                yield (
                    _sse(
                        "content_block_delta",
                        {"type": "content_block_delta", "index": index, "delta": delta},
                    ),
                    tokens_of(piece),
                )
        else:
            yield (
                _sse(
                    "content_block_start",
                    {
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {
                            "type": "tool_use",
                            "id": block["id"],
                            "name": block["name"],
                            "input": {},
                        },
                    },
                ),
                0,
            )
            arguments = json.dumps(block["input"])
            for piece in _pieces(arguments, 64):
                delta = {"type": "input_json_delta", "partial_json": piece}
                yield (
                    _sse(
                        "content_block_delta",
                        {"type": "content_block_delta", "index": index, "delta": delta},
                    ),
                    tokens_of(piece),
                )
        yield _sse("content_block_stop", {"type": "content_block_stop", "index": index}), 0
    yield (
        _sse(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": message_stop(reply), "stop_sequence": None},
                # The whole usage, cumulative, as the API's message_delta carries it.
                "usage": usage,
            },
        ),
        0,
    )
    yield _sse("message_stop", {"type": "message_stop"}), 0


def message_stop(reply: Reply) -> str:
    return _ANTHROPIC_STOP[reply.stop_reason()]


# ------------------------------------------------------------------------ OpenAI

_OPENAI_STOP = {"end": "stop", "tool": "tool_calls", "max_tokens": "length"}


def _openai_usage(request: Request, reply: Reply) -> dict[str, Any]:
    cached = min(reply.cached_tokens, request.input_tokens)
    return {
        "prompt_tokens": request.input_tokens,
        "completion_tokens": reply.output_tokens,
        "total_tokens": request.input_tokens + reply.output_tokens,
        "prompt_tokens_details": {"cached_tokens": cached},
        "completion_tokens_details": {"reasoning_tokens": tokens_of(reply.thinking)},
    }


def openai_completion(request: Request, reply: Reply) -> dict[str, Any]:
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
        "id": _new_id("chatcmpl-"),
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
        "usage": _openai_usage(request, reply),
    }


def openai_error(reply: Reply) -> dict[str, Any]:
    kind = "server_error" if reply.status >= 500 else "invalid_request_error"
    return {"error": {"message": reply.error or "stub error", "type": kind, "code": None}}


def openai_events(request: Request, reply: Reply) -> Iterator[tuple[str, int]]:
    """The streamed answer as server-sent ``data:`` chunks, each with the tokens it carries."""
    ident = _new_id("chatcmpl-")
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
    for piece in _pieces(reply.thinking):
        yield chunk({"reasoning_content": piece}), tokens_of(piece)
    for piece in _pieces(reply.text):
        yield chunk({"content": piece}), tokens_of(piece)
    for index, call in enumerate(_calls_with_ids(reply, "call_")):
        head = {
            "index": index,
            "id": call.id,
            "type": "function",
            "function": {"name": call.name, "arguments": ""},
        }
        yield chunk({"tool_calls": [head]}), 0
        arguments = json.dumps(call.args)
        for piece in _pieces(arguments, 64):
            part = {"index": index, "function": {"arguments": piece}}
            yield chunk({"tool_calls": [part]}), tokens_of(piece)
    yield chunk({}, _OPENAI_STOP[reply.stop_reason()]), 0
    options = request.raw.get("stream_options") or {}
    if isinstance(options, dict) and options.get("include_usage"):
        body = {
            "id": ident,
            "object": "chat.completion.chunk",
            "created": created,
            "model": request.model,
            "choices": [],
            "usage": _openai_usage(request, reply),
        }
        yield f"data: {json.dumps(body)}\n\n", 0
    yield "data: [DONE]\n\n", 0
