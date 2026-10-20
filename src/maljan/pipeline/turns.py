"""The turn a question goes in: its own, or the end of the user turn before it.

A retry or a salvage asks its question after whatever the conversation ends
on. After a model's turn or a tool answer that is a user turn of its own;
after a user turn it is the end of that turn, because two user turns in a row
are refused by chat templates that require the roles to alternate, and by
some hosted APIs.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

__all__ = ["with_question"]


def with_question(
    messages: list[Any], text: str, notes: Mapping[str, Any] | None = None
) -> list[Any]:
    """``messages`` with ``text`` asked last, in a user turn of its own or at the end of one.

    A conversation that already ends on a user turn gets the question at the
    end of that turn, after a blank line, rather than a second user turn after
    it: two user turns in a row are refused by chat templates that require the
    roles to alternate, and by some hosted APIs. The question's own text is
    unchanged. A run-state block at the end of that turn is taken off first —
    it belongs at the end of the request, and the caller that frames the
    request puts it there again.

    ``notes`` go on the turn the question ends up in (its ``response_metadata``,
    after any it carries): a question said for a turn the request was noted
    by keeps the note.
    """
    from langchain_core.messages import HumanMessage

    from maljan.llm.anthropic_history import RUN_STATE_ATTACHED
    from maljan.pipeline.run_state import is_run_state_block, without_run_state_tail

    turns = list(messages)
    last = turns[-1] if turns else None
    extra = dict(notes or {})
    if not isinstance(last, HumanMessage):
        turns.append(HumanMessage(content=text, response_metadata=extra))
        return turns
    # Only the block the platform noted it attached comes off: a turn that
    # ends on markers the sample or a tool wrote keeps them as written.
    noted_block = (last.response_metadata or {}).get(RUN_STATE_ATTACHED)
    attached = noted_block if isinstance(noted_block, str) else ""
    noted = {"response_metadata": {**(last.response_metadata or {}), **extra}} if extra else {}
    content = last.content
    if isinstance(content, list):
        parts = list(content)
        tail = parts[-1] if parts else None
        if isinstance(tail, dict) and is_run_state_block(tail.get("text"), attached):
            parts = parts[:-1]
        asked = [*parts, {"type": "text", "text": text}]
        turns[-1] = last.model_copy(update={"content": asked, **noted})
        return turns
    said = without_run_state_tail(str(content or ""), attached)
    turns[-1] = last.model_copy(update={"content": f"{said}\n\n{text}" if said else text, **noted})
    return turns
