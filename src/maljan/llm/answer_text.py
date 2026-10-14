"""The text a model's answer says, whatever shape its client keeps the answer in.

Most clients hand back an answer's ``content`` as a string. ``ChatAnthropic``
keeps it as the list of blocks the API returned whenever the answer is more
than one text block — and an answer from a model that thinks by default is a
``thinking`` block (an empty text and a signature, on Claude Haiku 5.5) before
its ``text`` block. Read with ``str()``, such an answer is the repr of a list,
signature and all, and nothing downstream can read a claim out of it.

The list is kept as it came on the message, because the thinking block has to
go back to the API unchanged; only the reading is changed here: the text
blocks, joined in order, and nothing else. A string is returned as it is.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def answer_text(content: Any) -> str:
    """The text ``content`` says: a string as it is, a block list's text parts joined."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            part
            if isinstance(part, str)
            else str(part.get("text") or "")
            if isinstance(part, dict) and part.get("type") == "text"
            else ""
            for part in content
        )
    return "" if content is None else str(content)


def tool_call_arguments(message: Any) -> dict[str, Any] | None:
    """The arguments of the first tool call ``message`` made, or ``None``.

    A provider that answers a schema by function calling leaves ``content``
    empty and the answer in the call's arguments.
    """
    for call in list(getattr(message, "tool_calls", None) or []):
        args = call.get("args") if isinstance(call, dict) else getattr(call, "args", None)
        if isinstance(args, dict):
            return args
    return None


def structured_answer_text(message: Any, text_of: Callable[[Any], str] | None = None) -> str:
    """The text a structured request's answer is read from: its tool call's arguments, or its text.

    A request that offered a schema's tool may be answered by a call of it,
    with arguments the schema did not take, or by the object written as text;
    either is the model's answer. A call whose arguments did not parse is read
    as the text it sent. An answer that calls no tool is read as its text, as
    every answer to a request without the tool is: by ``text_of`` when the
    caller reads its answers its own way, else by :func:`answer_text`.
    """
    import json

    args = tool_call_arguments(message)
    if args:
        return json.dumps(args, ensure_ascii=False)
    for call in list(getattr(message, "invalid_tool_calls", None) or []):
        sent = call.get("args") if isinstance(call, dict) else None
        if isinstance(sent, str) and sent.strip():
            return sent
    if text_of is not None:
        return text_of(message)
    return answer_text(getattr(message, "content", message))
