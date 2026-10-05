"""The turn a question goes in: its own, or the end of the user turn before it.

A retry or a salvage asks its question after whatever the conversation ends
on. After a model's turn or a tool answer that is a user turn of its own;
after a user turn it is the end of that turn, because two user turns in a row
are refused by chat templates that require the roles to alternate, and by
some hosted APIs.
"""

from __future__ import annotations

from typing import Any

__all__ = ["with_question"]


def with_question(messages: list[Any], text: str) -> list[Any]:
    """``messages`` with ``text`` asked last, in a user turn of its own or at the end of one.

    A conversation that already ends on a user turn gets the question at the
    end of that turn, after a blank line, rather than a second user turn after
    it: two user turns in a row are refused by chat templates that require the
    roles to alternate, and by some hosted APIs. The question's own text is
    unchanged. A run-state block at the end of that turn is taken off first —
    it belongs at the end of the request, and the caller that frames the
    request puts it there again.
    """
    from langchain_core.messages import HumanMessage

    from maljan.pipeline.run_state import is_run_state_block, without_run_state_tail

    turns = list(messages)
    last = turns[-1] if turns else None
    if not isinstance(last, HumanMessage):
        turns.append(HumanMessage(content=text))
        return turns
    content = last.content
    if isinstance(content, list):
        parts = list(content)
        tail = parts[-1] if parts else None
        if isinstance(tail, dict) and is_run_state_block(tail.get("text")):
            parts = parts[:-1]
        turns[-1] = last.model_copy(update={"content": [*parts, {"type": "text", "text": text}]})
        return turns
    said = without_run_state_tail(str(content or ""))
    turns[-1] = last.model_copy(update={"content": f"{said}\n\n{text}" if said else text})
    return turns
