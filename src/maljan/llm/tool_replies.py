"""No provider's request carries a tool call without its reply.

A turn can carry a call no tool ran: one whose arguments never parsed sits in
``invalid_tool_calls``, which langgraph's tool node does not run, and a history
can end on a turn whose calls were never answered at all. Every provider's API
pairs a call with its reply and refuses a history where one is missing:

* OpenAI-compatible servers want each assistant turn's ``tool_calls`` followed
  by one ``tool`` message per call id — DeepSeek answered a revision loop's
  turn with 400, "An assistant message with 'tool_calls' must be followed by
  tool messages responding to each 'tool_call_id'", and the analyst was lost
  for the round;
* Anthropic wants every ``tool_use`` block answered by a ``tool_result`` block
  at the front of the next user turn;
* Gemini wants a model turn's ``functionCall`` parts answered by as many
  ``functionResponse`` parts in the next user turn;
* Ollama takes the OpenAI shape and pairs a turn's calls with the ``tool``
  messages after it.

One rule for all of them, applied to the request each client builds, in that
client's own message shape: a call with no reply is sent with a reply that
states only what is known — that no reply was recorded, and, for a call whose
arguments did not parse, that it was not run. Nothing the model wrote is
changed or removed; the call stays in its turn as the model wrote it and only
the missing reply is added. The conversation the loop keeps is not touched, so
a turn sent twice is the same turn, and a history that is already well formed
is sent as it was.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from maljan.core.logger import logger

NO_REPLY_RECORDED = "No reply was recorded for this call."
NOT_RUN_REPLY = (
    "No reply was recorded for this call: its arguments did not parse, so it was not run."
)


def reply_text(call_id: str, not_run: frozenset[str] | set[str]) -> str:
    """The known-only reply for one unanswered call."""
    return NOT_RUN_REPLY if call_id and call_id in not_run else NO_REPLY_RECORDED


def unparsed_call_ids(messages: list[Any]) -> frozenset[str]:
    """The ids of the calls in ``messages``' turns whose arguments did not parse."""
    return frozenset(
        str(call.get("id") or "")
        for message in messages
        for call in getattr(message, "invalid_tool_calls", None) or []
        if isinstance(call, dict) and call.get("id")
    )


def _openai_reply(call_id: str, text: str) -> dict[str, Any]:
    return {"role": "tool", "tool_call_id": call_id, "content": text}


def _ollama_reply(call_id: str, text: str) -> dict[str, Any]:
    # The shape ``ChatOllama`` gives a tool message of its own.
    return {"role": "tool", "content": text, "images": [], "tool_call_id": call_id}


def answered_tool_calls(
    messages: list[Any],
    not_run: frozenset[str] | set[str] = frozenset(),
    make_reply: Callable[[str, str], dict[str, Any]] = _openai_reply,
) -> tuple[list[Any], int]:
    """OpenAI-shaped messages with every tool call answered, in its call order.

    The tool messages that follow an assistant turn are put in the order of
    its calls, and a call with none gets ``NO_REPLY_RECORDED``, or
    ``NOT_RUN_REPLY`` when its id is one of ``not_run`` (the turn's calls
    whose arguments did not parse). A tool message that answers none of the
    turn's calls stays where it was, after them: dropping it would remove
    something the conversation holds. Returns the messages and how many
    replies were written. A history that is already well formed comes back as
    it was. Ollama's messages take the same shape (``make_reply``).
    """
    out: list[Any] = []
    written = 0
    index = 0
    while index < len(messages):
        message = messages[index]
        out.append(message)
        index += 1
        calls = message.get("tool_calls") if isinstance(message, dict) else None
        if not (isinstance(message, dict) and message.get("role") == "assistant" and calls):
            continue
        replies: list[Any] = []
        while (
            index < len(messages)
            and isinstance(messages[index], dict)
            and messages[index].get("role") == "tool"
        ):
            replies.append(messages[index])
            index += 1
        for call in calls:
            call_id = str(call.get("id") or "") if isinstance(call, dict) else ""
            match = next((r for r in replies if str(r.get("tool_call_id") or "") == call_id), None)
            if match is not None:
                replies.remove(match)
                out.append(match)
                continue
            out.append(make_reply(call_id, reply_text(call_id, not_run)))
            written += 1
        out.extend(replies)
    return out, written


def _blocks(content: Any, kind: str) -> list[dict[str, Any]]:
    if not isinstance(content, list):
        return []
    return [b for b in content if isinstance(b, dict) and b.get("type") == kind]


def answered_anthropic_messages(
    messages: list[Any], not_run: frozenset[str] | set[str] = frozenset()
) -> tuple[list[Any], int]:
    """Anthropic-shaped messages with every ``tool_use`` block answered.

    Anthropic wants each ``tool_use`` id of an assistant turn answered by a
    ``tool_result`` block at the front of the next user turn. A missing one is
    written there, after the results the turn already has and before anything
    else the user turn says; a turn with no user turn after it gets one that
    holds only the replies. A user turn that is plain text keeps its text,
    after the replies. Returns the messages and how many replies were written.
    """
    out: list[Any] = []
    written = 0
    index = 0
    while index < len(messages):
        message = messages[index]
        out.append(message)
        index += 1
        if not (isinstance(message, dict) and message.get("role") == "assistant"):
            continue
        ids = [str(b.get("id") or "") for b in _blocks(message.get("content"), "tool_use")]
        if not ids:
            continue
        following = messages[index] if index < len(messages) else None
        has_user = isinstance(following, dict) and following.get("role") == "user"
        content: Any = following.get("content") if has_user else None  # type: ignore[union-attr]
        answered = {str(b.get("tool_use_id") or "") for b in _blocks(content, "tool_result")}
        missing = [
            {"type": "tool_result", "tool_use_id": call_id, "content": reply_text(call_id, not_run)}
            for call_id in ids
            if call_id not in answered
        ]
        if not missing:
            continue
        written += len(missing)
        if not has_user:
            out.append({"role": "user", "content": missing})
            continue
        if isinstance(content, list):
            lead = 0
            while (
                lead < len(content)
                and isinstance(content[lead], dict)
                and content[lead].get("type") == "tool_result"
            ):
                lead += 1
            new_content = [*content[:lead], *missing, *content[lead:]]
        elif isinstance(content, str) and content:
            new_content = [*missing, {"type": "text", "text": content}]
        else:
            new_content = missing
        out.append({**following, "content": new_content})  # type: ignore[dict-item]
        index += 1
    return out, written


def answered_messages(
    messages: list[Any], not_run: frozenset[str] | set[str] = frozenset()
) -> tuple[list[Any], int]:
    """LangChain messages with every parsed tool call answered, in its call order.

    For a client that pairs a call with its reply by something other than an
    id in the request it sends: Gemini's ``functionCall`` and
    ``functionResponse`` parts carry no id, so they pair by name and order,
    and ``ChatGoogleGenerativeAI`` writes a turn's responses in the order of
    its ``ToolMessage``s. Answering the conversation before the client
    serializes it lets the client's own serializer write the reply in its own
    shape, matched to the right call. The ``ToolMessage``s after a turn are put
    in the order of its calls; a call with none gets a ``ToolMessage`` with
    the known-only reply; a ``ToolMessage`` that answers none of the turn's
    calls stays after them. Only ``tool_calls`` are answered: a call whose
    arguments did not parse is not written into such a request at all.
    Returns the messages and how many replies were written.
    """
    from langchain_core.messages import AIMessage, ToolMessage  # noqa: PLC0415

    out: list[Any] = []
    written = 0
    index = 0
    while index < len(messages):
        message = messages[index]
        out.append(message)
        index += 1
        calls = message.tool_calls if isinstance(message, AIMessage) else None
        if not calls:
            continue
        replies: list[Any] = []
        while index < len(messages) and isinstance(messages[index], ToolMessage):
            replies.append(messages[index])
            index += 1
        for call in calls:
            call_id = str(call.get("id") or "")
            match = next((r for r in replies if str(r.tool_call_id or "") == call_id), None)
            if match is not None:
                replies.remove(match)
                out.append(match)
                continue
            out.append(
                ToolMessage(
                    content=reply_text(call_id, not_run),
                    tool_call_id=call_id,
                    name=call.get("name"),
                )
            )
            written += 1
        out.extend(replies)
    return out, written


def _not_run_in(value: Any) -> int:
    """How many replies in a history say the call was not run, whatever its shape."""
    if isinstance(value, str):
        return int(value == NOT_RUN_REPLY)
    if isinstance(value, dict):
        return sum(_not_run_in(v) for v in value.values())
    if isinstance(value, list):
        return sum(_not_run_in(v) for v in value)
    content = getattr(value, "content", None)
    return _not_run_in(content) if content is not None else 0


def _anthropic_ids(ids: frozenset[str]) -> frozenset[str]:
    """``ids`` together with the form langchain-anthropic writes them into a request in."""
    try:
        from langchain_anthropic.chat_models import _normalize_tool_call_id  # noqa: PLC0415
    except Exception:  # noqa: BLE001 — without it the ids are compared as they are
        return ids
    return ids | frozenset(str(_normalize_tool_call_id(i) or "") for i in ids)


Answer = Callable[[list[Any], frozenset[str]], tuple[list[Any], int]]


def _ollama_answer(sent: list[Any], not_run: frozenset[str]) -> tuple[list[Any], int]:
    return answered_tool_calls(sent, not_run, _ollama_reply)


def _anthropic_answer(sent: list[Any], not_run: frozenset[str]) -> tuple[list[Any], int]:
    return answered_anthropic_messages(sent, _anthropic_ids(not_run))


# Each provider's request hook — the method every request of that client
# passes through, invoke and stream alike — and how its history is answered:
# in the request the hook returns (``payload``, the history under the key
# named), or in the conversation handed to the hook (``input``).
DIALECTS: dict[str, tuple[str, str, str, Answer]] = {
    "openai": ("_get_request_payload", "payload", "messages", answered_tool_calls),
    "anthropic": ("_get_request_payload", "payload", "messages", _anthropic_answer),
    "gemini": ("_prepare_request", "input", "", answered_messages),
    "ollama": ("_chat_params", "payload", "messages", _ollama_answer),
}

# One subclass per (chat class, dialect) seen, so pydantic builds each schema once.
_ANSWERED_CLASSES: dict[tuple[type, str], type] = {}


def _conversation(model: Any, input_: Any) -> list[Any] | None:
    """The conversation a request is built from, or ``None`` when it cannot be read."""
    try:
        return list(model._convert_input(input_).to_messages())
    except Exception:  # noqa: BLE001 — without it every missing reply says only what is known
        return None


def with_answered_tool_calls(chat_class: Any, dialect: str = "openai") -> Any:
    """``chat_class`` never sending a tool call without its reply.

    Wraps the provider's request hook (``DIALECTS``): each request is
    completed as it is sent, in the provider's own message shape, and the
    operator is told how many replies were written. Applied last, over every
    other change a provider makes to its request — DeepSeek's reasoning
    passback matches the request's messages to the conversation's one for
    one, and the replies written here come after it. A class without the hook
    is returned as it is.
    """
    hook, where, key, answer = DIALECTS[dialect]
    if not isinstance(chat_class, type) or not hasattr(chat_class, hook):
        return chat_class
    cached = _ANSWERED_CLASSES.get((chat_class, dialect))
    if cached is not None:
        return cached
    base_hook: Any = getattr(chat_class, hook)

    def answered_hook(self: Any, input_: Any, *args: Any, **kwargs: Any) -> Any:
        conversation = _conversation(self, input_)
        not_run = unparsed_call_ids(conversation or [])
        written = not_run_written = 0
        if where == "input":
            if conversation is not None:
                answered, written = answer(conversation, not_run)
                if written:
                    not_run_written = _not_run_in(answered) - _not_run_in(conversation)
                    input_ = answered
            payload = base_hook(self, input_, *args, **kwargs)
        else:
            payload = base_hook(self, input_, *args, **kwargs)
            sent = payload.get(key) if isinstance(payload, dict) else None
            if isinstance(sent, list):
                answered, written = answer(sent, not_run)
                if written:
                    not_run_written = _not_run_in(answered) - _not_run_in(sent)
                    payload[key] = answered
        if written:
            logger.warning(
                "%s provider: %d tool call(s) in the history had no reply; each is sent "
                "with a reply saying so (%d of them with arguments that did not parse, said "
                "not run).",
                dialect,
                written,
                not_run_written,
            )
        return payload

    answered_class = type(chat_class.__name__, (chat_class,), {hook: answered_hook})
    answered_class.__module__ = __name__
    answered_class.__qualname__ = chat_class.__qualname__
    _ANSWERED_CLASSES[(chat_class, dialect)] = answered_class
    return answered_class
