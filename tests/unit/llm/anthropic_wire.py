"""A stand-in for the Anthropic Messages API, whole or streamed as the request asks.

The bodies a test reads are the bodies the Anthropic SDK would have sent: the
real ``ChatAnthropic`` the provider builds sends them through an ``httpx2``
mock transport, and no request leaves the process. A streamed answer is sent
as the server sends one — ``message_start``, each block's start, deltas and
stop (a thinking block's text, then its ``signature_delta``), ``message_delta``
with the usage totals (no split of the cache writes by lifetime, as the API
streams them), ``message_stop``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx2
import pytest

MODEL = "claude-haiku-5-5"


def message(content: list[dict[str, Any]], *, stop: str, usage: dict[str, int]) -> dict[str, Any]:
    """One whole Messages API answer."""
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "model": MODEL,
        "content": content,
        "stop_reason": stop,
        "stop_sequence": None,
        "usage": usage,
    }


def _event(kind: str, data: dict[str, Any]) -> str:
    return f"event: {kind}\ndata: {json.dumps({'type': kind, **data})}\n\n"


def streamed(answer: dict[str, Any]) -> bytes:
    """``answer`` as the server streams it."""
    usage = dict(answer["usage"])
    opening = {**answer, "content": [], "stop_reason": None, "usage": {**usage, "output_tokens": 1}}
    parts = [_event("message_start", {"message": opening})]
    for index, block in enumerate(answer["content"]):
        kind = block["type"]
        if kind == "thinking":
            parts.append(
                _event(
                    "content_block_start",
                    {
                        "index": index,
                        "content_block": {"type": "thinking", "thinking": "", "signature": ""},
                    },
                )
            )
            parts.append(
                _event(
                    "content_block_delta",
                    {
                        "index": index,
                        "delta": {"type": "thinking_delta", "thinking": block["thinking"]},
                    },
                )
            )
            parts.append(
                _event(
                    "content_block_delta",
                    {
                        "index": index,
                        "delta": {"type": "signature_delta", "signature": block["signature"]},
                    },
                )
            )
        elif kind == "text":
            parts.append(
                _event(
                    "content_block_start",
                    {"index": index, "content_block": {"type": "text", "text": ""}},
                )
            )
            parts.append(
                _event(
                    "content_block_delta",
                    {"index": index, "delta": {"type": "text_delta", "text": block["text"]}},
                )
            )
        elif kind == "tool_use":
            parts.append(
                _event(
                    "content_block_start",
                    {
                        "index": index,
                        "content_block": {
                            "type": "tool_use",
                            "id": block["id"],
                            "name": block["name"],
                            "input": {},
                        },
                    },
                )
            )
            parts.append(
                _event(
                    "content_block_delta",
                    {
                        "index": index,
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": json.dumps(block["input"]),
                        },
                    },
                )
            )
        parts.append(_event("content_block_stop", {"index": index}))
    parts.append(
        _event(
            "message_delta",
            {
                "delta": {"stop_reason": answer["stop_reason"], "stop_sequence": None},
                # ``MessageDeltaUsage``: the totals, without the split of the
                # cache writes by lifetime that ``message_start`` carries.
                "usage": {k: v for k, v in usage.items() if k != "cache_creation"},
            },
        )
    )
    parts.append(_event("message_stop", {}))
    return "".join(parts).encode()


def _unmarked(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _unmarked(v) for k, v in value.items() if k != "cache_control"}
    if isinstance(value, list):
        return [_unmarked(v) for v in value]
    return value


def _prefix(body: dict[str, Any], messages: list[Any]) -> str:
    return json.dumps(
        _unmarked({"system": body.get("system"), "tools": body.get("tools"), "messages": messages}),
        sort_keys=True,
    )


CLEAR_AT_BETA = "mid-conversation-system-clear-at-2026-08-21"
BINDING_BETA = "thinking-binding-controls-2026-08-01"


def _system_placement(messages: list[Any], betas: set[str]) -> str:
    """The mid-conversation system message rules, as the page documents them."""
    for index, turn in enumerate(messages):
        if turn.get("role") != "system":
            continue
        if "clear_at" in turn and CLEAR_AT_BETA not in betas:
            return f"messages.{index}.clear_at: Extra inputs are not permitted"
        if index == 0:
            return "messages.0: a system message cannot be the first message"
        # Consecutive system messages are one section.
        start = index
        while start > 0 and messages[start - 1].get("role") == "system":
            start -= 1
        if start == 0 or messages[start - 1].get("role") != "user":
            return f"messages.{index}: a system message must follow a user message"
        after = index + 1
        while after < len(messages) and messages[after].get("role") == "system":
            after += 1
        if after < len(messages) and messages[after].get("role") != "assistant":
            return f"messages.{index}: a system message must be last or followed by an assistant"
    return ""


def refusal(body: dict[str, Any], betas: set[str] = frozenset()) -> str:  # type: ignore[assignment]
    """What the Messages API refuses in ``body`` on Claude Haiku 5.5, as documented, or ``""``.

    Sampling parameters at a non-default value, ``budget_tokens``, a request
    ending on an assistant turn (a prefill, refused while thinking is on), a
    message other than the last with empty content, a text block that is empty
    or only whitespace (in a turn or the system prompt), a mid-conversation system
    message out of place or turn-scoped without its beta, a ``tool_use``
    without its ``tool_result`` at the front of the next user turn. The
    preserved-thinking checks are :meth:`Wire.thinking_refusal`.
    """
    # The sampling rule is Claude Haiku 5.5's; an older model the tests name
    # still takes a temperature.
    for key, default in (("temperature", 1), ("top_p", 1), ("top_k", None)):
        if body.get("model") == MODEL and key in body and body[key] != default:
            return f"{key}: a non-default value is not supported on this model"
    thinking = body.get("thinking")
    if isinstance(thinking, dict) and "budget_tokens" in thinking:
        return "thinking.budget_tokens is not supported on this model"
    if isinstance(thinking, dict) and "block_binding" in thinking and BINDING_BETA not in betas:
        return "thinking.block_binding: Extra inputs are not permitted"
    messages = body.get("messages") or []
    if messages and messages[-1].get("role") == "assistant":
        return "assistant message prefill is not supported while thinking is on"
    for index, turn in enumerate(messages[:-1]):
        content = turn.get("content")
        if content in ([], "") and not turn.get("clear_at"):
            return f"messages.{index}: all messages must have non-empty content"
    system = body.get("system")
    for block in system if isinstance(system, list) else []:
        if isinstance(block, dict) and block.get("type") == "text":
            if not str(block.get("text") or "").strip():
                return "system: text content blocks must be non-empty"
    for turn in messages:
        content = turn.get("content")
        blocks = list(content) if isinstance(content, list) else []
        for block in list(blocks):
            inner = block.get("content") if isinstance(block, dict) else None
            if isinstance(inner, list) and block.get("type") == "tool_result":
                blocks.extend(inner)
        for block in blocks:
            if isinstance(block, dict) and block.get("type") == "text":
                if not str(block.get("text") or ""):
                    return "messages: text content blocks must be non-empty"
                if not str(block.get("text")).strip():
                    return "messages: text content blocks must contain non-whitespace text"
        if isinstance(content, str) and content and not content.strip():
            return "messages: text content blocks must contain non-whitespace text"
    placed = _system_placement(messages, betas)
    if placed:
        return placed
    for index, turn in enumerate(messages):
        if turn.get("role") != "assistant" or not isinstance(turn.get("content"), list):
            continue
        calls = [b["id"] for b in turn["content"] if b.get("type") == "tool_use"]
        if not calls:
            continue
        following = messages[index + 1] if index + 1 < len(messages) else {}
        content = following.get("content") if isinstance(following.get("content"), list) else []
        answered = [b.get("tool_use_id") for b in content if b.get("type") == "tool_result"]
        if answered[: len(calls)] != calls:
            return f"messages.{index}: tool_use ids were found without tool_result blocks"
    return ""


class Wire:
    """Answers every request with ``answer(body)`` and keeps each body it was sent.

    Refuses, with the API's 400, what the documentation says Claude Haiku 5.5
    refuses (:func:`refusal`, :meth:`thinking_refusal`). A request that asks
    for ``drop_block`` (with its beta) has the blocks that fail the prefix
    check dropped instead, and each is noted in ``dropped``.
    """

    def __init__(self, answer: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self.answer = answer
        self.bodies: list[dict[str, Any]] = []
        self.paths: list[str] = []
        self.betas: list[set[str]] = []
        self.refused: list[str] = []
        self.dropped: list[str] = []
        # signature -> the prefix of the request the block was written after.
        self.issued: dict[str, str] = {}
        # tool_use id -> the thinking blocks of the answer that called it.
        self.thinking_of_call: dict[str, list[dict[str, Any]]] = {}

    def thinking_refusal(self, body: dict[str, Any], betas: set[str]) -> str:
        """The preserved-thinking checks, said as the API says them, or ``""``.

        * The latest assistant turn, when tool results follow it, carries its
          thinking blocks exactly as they were returned (the API errors page,
          "Thinking blocks cannot be modified").
        * Every block sent back was written after exactly the history before
          it in this request (the prefix check). A block written while an
          earlier one was gone passes while that one stays gone; putting a
          removed block back fails the blocks written without it.
        """
        if body.get("model") != MODEL:
            # Models before the current generation run no prefix check.
            return ""
        messages = body.get("messages") or []
        assistants = [i for i, m in enumerate(messages) if m.get("role") == "assistant"]
        if assistants:
            latest = messages[assistants[-1]]
            content = latest.get("content") if isinstance(latest.get("content"), list) else []
            calls = [b.get("id") for b in content if b.get("type") == "tool_use"]
            if calls and calls[0] in self.thinking_of_call:
                sent = [b for b in content if b.get("type") in ("thinking", "redacted_thinking")]
                if _unmarked(sent) != self.thinking_of_call[calls[0]]:
                    return (
                        f"messages.{assistants[-1]}.content: thinking blocks in the latest "
                        "assistant message cannot be modified"
                    )
        binding = (body.get("thinking") or {}).get("block_binding") or {}
        dropping = binding.get("prefix_mismatch_behavior") == "drop_block"
        rendered = self.render(body)
        for index in assistants:
            for block in messages[index].get("content") or []:
                if not isinstance(block, dict) or block.get("type") != "thinking":
                    continue
                written = self.issued.get(str(block.get("signature")))
                if written is None or written == _prefix(body, rendered[:index]):
                    continue
                if dropping:
                    self.dropped.append(str(block.get("signature")))
                    continue
                return (
                    f"messages.{index}.content.0: Invalid `signature` in `thinking` block. "
                    "The block is bound to a different conversation."
                )
        return ""

    def render(self, body: dict[str, Any]) -> list[Any]:
        """The messages as the model reads them: with ``drop_block``, the failing blocks out.

        A block fails when the history rendered before it is not the one it was
        written after; one dropped changes what every later block is checked
        against, as the page says.
        """
        messages = list(body.get("messages") or [])
        binding = (body.get("thinking") or {}).get("block_binding") or {}
        if binding.get("prefix_mismatch_behavior") != "drop_block":
            return messages
        out: list[Any] = []
        for turn in messages:
            content = turn.get("content")
            if turn.get("role") != "assistant" or not isinstance(content, list):
                out.append(turn)
                continue
            kept = []
            for block in content:
                written = (
                    self.issued.get(str(block.get("signature")))
                    if isinstance(block, dict) and block.get("type") == "thinking"
                    else None
                )
                if written is not None and written != _prefix(body, out):
                    continue
                kept.append(block)
            out.append({**turn, "content": kept})
        return out

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content) if request.content else {}
        betas = {b.strip() for b in request.headers.get("anthropic-beta", "").split(",") if b}
        self.bodies.append(body)
        self.paths.append(request.url.path)
        self.betas.append(betas)
        refused = refusal(body, betas) or self.thinking_refusal(body, betas)
        if refused:
            self.refused.append(refused)
            return httpx2.Response(
                400,
                json={
                    "type": "error",
                    "error": {"type": "invalid_request_error", "message": refused},
                },
            )
        answer = self.answer(body)
        prefix = _prefix(body, self.render(body))
        thinking = [b for b in answer["content"] if b.get("type") == "thinking"]
        for block in thinking:
            self.issued[str(block["signature"])] = prefix
        for block in answer["content"]:
            if block.get("type") == "tool_use":
                self.thinking_of_call[str(block["id"])] = [dict(b) for b in thinking]
        if body.get("stream"):
            return httpx2.Response(
                200, headers={"content-type": "text/event-stream"}, content=streamed(answer)
            )
        return httpx2.Response(200, json=answer)


def install(monkeypatch: pytest.MonkeyPatch, wire: Wire) -> None:
    """Every ``ChatAnthropic`` built from now on sends through ``wire``."""
    from langchain_anthropic import chat_models

    transport = httpx2.MockTransport(wire)

    def sync_client(**kwargs: Any) -> httpx2.Client:
        return httpx2.Client(transport=transport, base_url=kwargs.get("base_url") or "")

    def async_client(**kwargs: Any) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=transport, base_url=kwargs.get("base_url") or "")

    monkeypatch.setattr(chat_models, "_get_default_httpx_client", sync_client)
    monkeypatch.setattr(chat_models, "_get_default_async_httpx_client", async_client)
