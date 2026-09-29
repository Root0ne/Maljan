"""A fake OpenAI-compatible server's answer, whole or streamed as the request asks.

A llama.cpp server's answer is read as a stream, so a fake that stands for one
has to send its answer as chunks when the request says ``"stream": true``. The
chunks are the ones llama.cpp sends: the role, the text, each tool call whole
under its index, the finish reason, and the usage (with ``timings`` where the
answer has them) on a closing chunk without choices.
"""

from __future__ import annotations

import json
from typing import Any

import httpx


def _chunk(answer: dict[str, Any], choices: list[dict[str, Any]], **extra: Any) -> str:
    body = {
        "id": answer.get("id", "chatcmpl-1"),
        "object": "chat.completion.chunk",
        "created": answer.get("created", 0),
        "model": answer.get("model", "m"),
        "choices": choices,
        **extra,
    }
    return f"data: {json.dumps(body)}\n\n"


def _delta(delta: dict[str, Any], finish: str | None = None) -> list[dict[str, Any]]:
    return [{"index": 0, "delta": delta, "finish_reason": finish}]


def streamed(answer: dict[str, Any]) -> bytes:
    """``answer``, a whole ``chat.completion``, as the stream a llama.cpp server sends."""
    choice = answer["choices"][0]
    message = choice.get("message") or {}
    opening: dict[str, Any] = {"role": "assistant", "content": message.get("content")}
    if message.get("reasoning_content") is not None:
        opening["reasoning_content"] = message["reasoning_content"]
    parts = [_chunk(answer, _delta(opening))]
    for index, call in enumerate(message.get("tool_calls") or []):
        piece = {"index": index, **call}
        parts.append(_chunk(answer, _delta({"tool_calls": [piece]})))
    parts.append(_chunk(answer, _delta({}, choice.get("finish_reason") or "stop")))
    closing: dict[str, Any] = {}
    if answer.get("usage") is not None:
        closing["usage"] = answer["usage"]
    if answer.get("timings") is not None:
        closing["timings"] = answer["timings"]
    if closing:
        parts.append(_chunk(answer, [], **closing))
    parts.append("data: [DONE]\n\n")
    return "".join(parts).encode()


def reply(request: httpx.Request, answer: dict[str, Any], status: int = 200) -> httpx.Response:
    """``answer`` as the request asked for it: streamed, or whole."""
    body = json.loads(request.content) if request.content else {}
    if status == 200 and body.get("stream"):
        return httpx.Response(
            200, content=streamed(answer), headers={"content-type": "text/event-stream"}
        )
    return httpx.Response(status, json=answer)
