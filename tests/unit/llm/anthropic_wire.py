"""A stand-in for the Anthropic Messages API, whole or streamed as the request asks.

The bodies a test reads are the bodies the Anthropic SDK would have sent: the
real ``ChatAnthropic`` the provider builds sends them through an ``httpx2``
mock transport, and no request leaves the process. A streamed answer is sent
as the server sends one — ``message_start``, each block's start, deltas and
stop (a thinking block's text, then its ``signature_delta``), ``message_delta``
with the usage, ``message_stop``.
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
                "usage": usage,
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


def refusal(body: dict[str, Any]) -> str:
    """What the Messages API refuses in ``body`` on Claude Haiku 5.5, as documented, or ``""``.

    Sampling parameters at a non-default value, ``budget_tokens``, a request
    ending on an assistant turn (a prefill, refused while thinking is on), a
    ``tool_use`` without its ``tool_result`` at the front of the next user turn.
    The preserved-thinking prefix check is :meth:`Wire.stale_block`.
    """
    # The sampling rule is Claude Haiku 5.5's; an older model the tests name
    # still takes a temperature.
    for key, default in (("temperature", 1), ("top_p", 1), ("top_k", None)):
        if body.get("model") == MODEL and key in body and body[key] != default:
            return f"{key}: a non-default value is not supported on this model"
    thinking = body.get("thinking")
    if isinstance(thinking, dict) and "budget_tokens" in thinking:
        return "thinking.budget_tokens is not supported on this model"
    messages = body.get("messages") or []
    if messages and messages[-1].get("role") == "assistant":
        return "assistant message prefill is not supported while thinking is on"
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
    refuses (:func:`refusal`), and checks every thinking block sent back
    against the request it was written after, as the API's prefix check does
    on the accounts the API enforces it for by default.
    """

    def __init__(self, answer: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        self.answer = answer
        self.bodies: list[dict[str, Any]] = []
        self.paths: list[str] = []
        self.refused: list[str] = []
        # signature -> the prefix of the request the block was written after.
        self.issued: dict[str, str] = {}

    def stale_block(self, body: dict[str, Any]) -> str:
        """The first thinking block sent back whose prefix changed, said as the API says it."""
        messages = body.get("messages") or []
        for index, turn in enumerate(messages):
            if turn.get("role") != "assistant" or not isinstance(turn.get("content"), list):
                continue
            for block in turn["content"]:
                if block.get("type") != "thinking":
                    continue
                written = self.issued.get(str(block.get("signature")))
                if written is not None and written != _prefix(body, messages[:index]):
                    return (
                        f"messages.{index}.content.0: Invalid `signature` in `thinking` block. "
                        "The block is bound to a different conversation."
                    )
        return ""

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content) if request.content else {}
        self.bodies.append(body)
        self.paths.append(request.url.path)
        refused = refusal(body) or self.stale_block(body)
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
        prefix = _prefix(body, body.get("messages") or [])
        for block in answer["content"]:
            if block.get("type") == "thinking":
                self.issued[str(block["signature"])] = prefix
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
