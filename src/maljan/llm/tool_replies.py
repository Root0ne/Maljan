"""No provider's request carries a tool call without its reply.

A turn can carry a call no tool ran: one whose arguments never parsed sits in
``invalid_tool_calls``, which langgraph's tool node does not run, and a history
can end on a turn whose calls were never answered at all. Every provider's API
pairs a call with its reply and refuses a history where one is missing:

* OpenAI-compatible chat completions want each assistant turn's
  ``tool_calls`` followed by one ``tool`` message per call id — DeepSeek
  answered a revision loop's turn with 400, "An assistant message with
  'tool_calls' must be followed by tool messages responding to each
  'tool_call_id'", and the analyst was lost for the round;
* OpenAI's Responses API wants a ``function_call_output`` item for every
  ``function_call`` item's ``call_id``;
* Anthropic wants every ``tool_use`` block answered by a ``tool_result`` block
  at the front of the next user turn;
* Gemini wants a model turn's ``functionCall`` parts answered by as many
  ``functionResponse`` parts in the next user turn;
* Ollama takes the OpenAI chat shape and pairs a turn's calls with the
  ``tool`` messages after it.

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

# What a completer notes of each change it makes, one entry per change: a
# reply written (``WRITTEN``, or ``NOT_RUN`` when it says the call was not
# run) or a recorded reply moved to its call (``MOVED``). The operator's counts
# are taken from here, not from the text of the request.
Record = list[str]
WRITTEN = "written"
NOT_RUN = "not_run"
MOVED = "moved"


def _reply(call_id: str, not_run: frozenset[str] | set[str], record: Record | None) -> str:
    """The known-only reply for one unanswered call, noted in ``record``."""
    unparsed = bool(call_id) and call_id in not_run
    if record is not None:
        record.append(NOT_RUN if unparsed else WRITTEN)
    return NOT_RUN_REPLY if unparsed else NO_REPLY_RECORDED


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
    *,
    record: Record | None = None,
) -> tuple[list[Any], int]:
    """OpenAI chat-shaped messages with every tool call answered, in its call order.

    Chat completions pair a call with the ``tool`` messages right after its
    turn. Those are put in the order of the turn's calls. A call with none
    there takes the first ``tool`` message recorded for its id further on that
    answers no call of the turn it follows: the reply was recorded, only in
    the wrong place, and it is moved to its call rather than said missing. A
    call with no reply anywhere gets ``NO_REPLY_RECORDED``, or
    ``NOT_RUN_REPLY`` when its id is one of ``not_run`` (the calls whose
    arguments did not parse). A tool message that answers none of the turn's
    calls stays after them: dropping it would remove something the
    conversation holds. Returns the messages and how many replies were
    written; a history with nothing missing comes back as it was, the same
    list. Ollama's messages take the same shape (``make_reply``).
    """

    def is_turn(message: Any) -> bool:
        return (
            isinstance(message, dict)
            and message.get("role") == "assistant"
            and bool(message.get("tool_calls"))
        )

    def is_tool(message: Any) -> bool:
        return isinstance(message, dict) and message.get("role") == "tool"

    def ids_of(message: Any) -> list[str]:
        return [
            str(call.get("id") or "") if isinstance(call, dict) else ""
            for call in message.get("tool_calls") or []
        ]

    # Tool messages that answer no call of the turn they follow, by position.
    strays: list[int] = []
    owner: set[str] = set()
    for position, message in enumerate(messages):
        if is_turn(message):
            owner = set(ids_of(message))
        elif is_tool(message):
            if str(message.get("tool_call_id") or "") not in owner:
                strays.append(position)
        else:
            owner = set()

    out: list[Any] = []
    written = 0
    moved: set[int] = set()
    index = 0
    while index < len(messages):
        if index in moved:
            index += 1
            continue
        message = messages[index]
        out.append(message)
        turn = index
        index += 1
        if not is_turn(message):
            continue
        replies: list[Any] = []
        while index < len(messages) and is_tool(messages[index]):
            if index not in moved:
                replies.append(messages[index])
            index += 1
        for call_id in ids_of(message):
            match = next((r for r in replies if str(r.get("tool_call_id") or "") == call_id), None)
            if match is not None:
                replies.remove(match)
                out.append(match)
                continue
            later = next(
                (
                    p
                    for p in strays
                    if p > turn
                    and p not in moved
                    and str(messages[p].get("tool_call_id") or "") == call_id
                ),
                None,
            )
            if later is not None:
                moved.add(later)
                out.append(messages[later])
                if record is not None:
                    record.append(MOVED)
                continue
            out.append(make_reply(call_id, _reply(call_id, not_run, record)))
            written += 1
        out.extend(replies)
    if not written and not moved:
        return messages, 0
    return out, written


def answered_responses_input(
    items: list[Any],
    not_run: frozenset[str] | set[str] = frozenset(),
    *,
    record: Record | None = None,
) -> tuple[list[Any], int]:
    """OpenAI Responses API input items with every ``function_call`` answered.

    The Responses API pairs a ``function_call`` with the
    ``function_call_output`` of the same ``call_id``, wherever it stands in the
    input, so a call counts as answered when any output carries its id. A
    missing one is written right after the run of call and output items its
    call stands in, in call order. Returns the items and how many replies were
    written; an input that is already well formed comes back as it was.
    """
    answered = {
        str(item.get("call_id") or "")
        for item in items
        if isinstance(item, dict) and item.get("type") == "function_call_output"
    }
    out: list[Any] = []
    written = 0
    pending: list[str] = []
    for index, item in enumerate(items):
        out.append(item)
        kind = item.get("type") if isinstance(item, dict) else None
        if kind == "function_call":
            call_id = str(item.get("call_id") or "")
            if call_id not in answered:
                pending.append(call_id)
        following = items[index + 1] if index + 1 < len(items) else None
        run_goes_on = isinstance(following, dict) and following.get("type") in (
            "function_call",
            "function_call_output",
        )
        if pending and not run_goes_on:
            for call_id in pending:
                out.append(
                    {
                        "type": "function_call_output",
                        "call_id": call_id,
                        "output": _reply(call_id, not_run, record),
                    }
                )
                answered.add(call_id)
                written += 1
            pending = []
    return out, written


def _blocks(content: Any, kind: str) -> list[dict[str, Any]]:
    if not isinstance(content, list):
        return []
    return [b for b in content if isinstance(b, dict) and b.get("type") == kind]


def answered_anthropic_messages(
    messages: list[Any],
    not_run: frozenset[str] | set[str] = frozenset(),
    *,
    record: Record | None = None,
) -> tuple[list[Any], int]:
    """Anthropic-shaped messages with every ``tool_use`` block answered.

    Anthropic wants each ``tool_use`` id of an assistant turn answered by a
    ``tool_result`` block at the front of the next user turn. A call with no
    result there takes the first ``tool_result`` recorded for its id further
    on that answers no call of the turn before it: the reply was recorded,
    only in the wrong place, and it is moved to its call (a user turn it
    leaves empty is left out; the API joins the turns around it). A call with
    no result anywhere gets the known-only reply. Either goes after the
    results the user turn already has and before anything else it says; a
    turn with no user turn after it gets one that holds only the replies. A
    user turn that is plain text keeps its text, after the replies. Returns the
    messages and how many replies were written; a history with nothing
    missing comes back as it was, the same list.
    """

    def is_result(block: Any) -> bool:
        return isinstance(block, dict) and block.get("type") == "tool_result"

    # ``tool_result`` blocks that answer no call of the assistant turn right
    # before their user turn, as (message position, block position).
    strays: list[tuple[int, int]] = []
    owner: set[str] = set()
    for position, message in enumerate(messages):
        if not isinstance(message, dict):
            owner = set()
            continue
        content = message.get("content")
        if message.get("role") == "assistant":
            owner = {str(b.get("id") or "") for b in _blocks(content, "tool_use")}
            continue
        if message.get("role") == "user" and isinstance(content, list):
            strays += [
                (position, b)
                for b, block in enumerate(content)
                if is_result(block) and str(block.get("tool_use_id") or "") not in owner
            ]
        owner = set()

    taken: set[tuple[int, int]] = set()

    def content_at(position: int) -> Any:
        """The content of a message, without the blocks moved out of it."""
        content = messages[position].get("content")
        if not isinstance(content, list) or not any(p == position for p, _ in taken):
            return content
        return [b for i, b in enumerate(content) if (position, i) not in taken]

    def take(call_id: str, after: int) -> Any:
        """The first stray result for ``call_id`` after ``after``, moved out, or ``None``."""
        for position, b in strays:
            if position > after and (position, b) not in taken:
                block = messages[position]["content"][b]
                if str(block.get("tool_use_id") or "") == call_id:
                    taken.add((position, b))
                    if record is not None:
                        record.append(MOVED)
                    return block
        return None

    out: list[Any] = []
    written = 0
    index = 0
    while index < len(messages):
        message = messages[index]
        position = index
        index += 1
        if isinstance(message, dict) and message.get("role") == "user" and taken:
            content = content_at(position)
            if isinstance(content, list) and not content:
                continue
            if content is not message.get("content"):
                message = {**message, "content": content}
        out.append(message)
        if not (isinstance(message, dict) and message.get("role") == "assistant"):
            continue
        ids = [str(b.get("id") or "") for b in _blocks(message.get("content"), "tool_use")]
        if not ids:
            continue
        following = messages[index] if index < len(messages) else None
        has_user = isinstance(following, dict) and following.get("role") == "user"
        # Without the results already moved out of it to an earlier call.
        content = content_at(index) if has_user else None
        answered = {str(b.get("tool_use_id") or "") for b in _blocks(content, "tool_result")}
        missing: list[Any] = []
        for call_id in ids:
            if call_id in answered:
                continue
            block = take(call_id, index if has_user else position)
            if block is None:
                block = {
                    "type": "tool_result",
                    "tool_use_id": call_id,
                    "content": _reply(call_id, not_run, record),
                }
                written += 1
            missing.append(block)
        if not missing:
            continue
        if not has_user:
            out.append({"role": "user", "content": missing})
            continue
        if isinstance(content, list):
            lead = 0
            while lead < len(content) and is_result(content[lead]):
                lead += 1
            new_content = [*content[:lead], *missing, *content[lead:]]
        elif isinstance(content, str) and content:
            new_content = [*missing, {"type": "text", "text": content}]
        else:
            new_content = missing
        out.append({**following, "content": new_content})  # type: ignore[dict-item]
        index += 1
    if not written and not taken:
        return messages, 0
    return out, written


def answered_messages(
    messages: list[Any],
    not_run: frozenset[str] | set[str] = frozenset(),
    *,
    record: Record | None = None,
) -> tuple[list[Any], int]:
    """LangChain messages with every parsed tool call answered, for Gemini.

    Gemini's ``functionCall`` and ``functionResponse`` parts carry no id, so
    they pair by name and order. ``ChatGoogleGenerativeAI`` builds a turn's
    responses from every ``ToolMessage`` in the conversation whose
    ``tool_call_id`` is one of the turn's calls, the first one per id, in the
    order they stand. Answering the conversation before the client serializes
    it lets the client's own serializer write the reply in its own shape.

    The client's rule decides what is answered: a call is answered when any
    ``ToolMessage`` in the conversation carries its id, wherever it stands. A
    call no ``ToolMessage`` answers gets one with the known-only reply, placed
    so the turn's responses come out in call order: before the first reply to
    a later call of the turn, else after the last reply to an earlier one, else
    right after the turn. Nothing else moves. Only ``tool_calls`` are
    answered: a call whose arguments did not parse is not written into such a
    request at all. Returns the messages and how many replies were written.
    """
    from langchain_core.messages import AIMessage, ToolMessage  # noqa: PLC0415

    first_reply: dict[str, int] = {}
    for position, message in enumerate(messages):
        if isinstance(message, ToolMessage):
            first_reply.setdefault(str(message.tool_call_id or ""), position)

    # (position to insert before, turn position, call index, message)
    inserts: list[tuple[int, int, int, Any]] = []
    for turn_position, message in enumerate(messages):
        calls = message.tool_calls if isinstance(message, AIMessage) else None
        if not calls:
            continue
        ids = [str(call.get("id") or "") for call in calls]
        replied = [(first_reply[i], k) for k, i in enumerate(ids) if i in first_reply]
        for k, (call, call_id) in enumerate(zip(calls, ids, strict=True)):
            if call_id in first_reply:
                continue
            later = [p for p, j in replied if j > k]
            earlier = [p for p, j in replied if j < k]
            if later:
                position = min(later)
            elif earlier:
                position = max(earlier) + 1
            else:
                position = turn_position + 1
            reply = ToolMessage(
                content=_reply(call_id, not_run, record),
                tool_call_id=call_id,
                name=call.get("name"),
            )
            inserts.append((position, turn_position, k, reply))
    if not inserts:
        return messages, 0
    inserts.sort(key=lambda entry: entry[:3])
    out: list[Any] = []
    pending = iter(inserts)
    upcoming = next(pending, None)
    for position in range(len(messages) + 1):
        while upcoming is not None and upcoming[0] == position:
            out.append(upcoming[3])
            upcoming = next(pending, None)
        if position < len(messages):
            out.append(messages[position])
    return out, len(inserts)


def _anthropic_ids(ids: frozenset[str]) -> frozenset[str]:
    """``ids`` together with the form langchain-anthropic writes them into a request in."""
    try:
        from langchain_anthropic.chat_models import _normalize_tool_call_id  # noqa: PLC0415
    except Exception:  # noqa: BLE001 — without it the ids are compared as they are
        return ids
    return ids | frozenset(str(_normalize_tool_call_id(i) or "") for i in ids)


def _complete_openai(payload: Any, not_run: frozenset[str], record: Record) -> None:
    """Chat completions (``messages``) or the Responses API (``input``), as the client chose."""
    if not isinstance(payload, dict):
        return
    if isinstance(payload.get("messages"), list):
        answered, _ = answered_tool_calls(payload["messages"], not_run, record=record)
        payload["messages"] = answered
    elif isinstance(payload.get("input"), list):
        answered, _ = answered_responses_input(payload["input"], not_run, record=record)
        payload["input"] = answered


def _complete_anthropic(payload: Any, not_run: frozenset[str], record: Record) -> None:
    sent = payload.get("messages") if isinstance(payload, dict) else None
    if isinstance(sent, list):
        answered, _ = answered_anthropic_messages(sent, _anthropic_ids(not_run), record=record)
        payload["messages"] = answered


def _complete_ollama(payload: Any, not_run: frozenset[str], record: Record) -> None:
    sent = payload.get("messages") if isinstance(payload, dict) else None
    if isinstance(sent, list):
        answered, _ = answered_tool_calls(sent, not_run, _ollama_reply, record=record)
        payload["messages"] = answered


# Each provider's request hook — the method every request of that client
# passes through, invoke and stream alike — and where its history is answered:
# in the request the hook returns (``payload``), or in the conversation handed
# to the hook (``input``).
DIALECTS: dict[str, tuple[str, str, Callable[..., Any]]] = {
    "openai": ("_get_request_payload", "payload", _complete_openai),
    "anthropic": ("_get_request_payload", "payload", _complete_anthropic),
    "gemini": ("_prepare_request", "input", answered_messages),
    "ollama": ("_chat_params", "payload", _complete_ollama),
}

# One subclass per (chat class, dialect) seen, so pydantic builds each schema once.
_ANSWERED_CLASSES: dict[tuple[type, str], type] = {}


def _conversation(model: Any, input_: Any) -> list[Any] | None:
    """The conversation a request is built from, or ``None`` when it cannot be read."""
    try:
        return list(model._convert_input(input_).to_messages())
    except Exception:  # noqa: BLE001 — see the two outcomes in ``with_answered_tool_calls``
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

    Where the conversation cannot be read back from the hook's input, a
    payload dialect still completes the request, and every reply it writes
    says only that no reply was recorded; the ``input`` dialect (Gemini)
    sends the request as the client built it.
    """
    hook, where, complete = DIALECTS[dialect]
    if not isinstance(chat_class, type) or not hasattr(chat_class, hook):
        return chat_class
    cached = _ANSWERED_CLASSES.get((chat_class, dialect))
    if cached is not None:
        return cached
    base_hook: Any = getattr(chat_class, hook)

    def answered_hook(self: Any, input_: Any, *args: Any, **kwargs: Any) -> Any:
        conversation = _conversation(self, input_)
        not_run = unparsed_call_ids(conversation or [])
        record: Record = []
        if where == "input":
            if conversation is not None:
                answered, written = complete(conversation, not_run, record=record)
                if written:
                    input_ = answered
            payload = base_hook(self, input_, *args, **kwargs)
        else:
            payload = base_hook(self, input_, *args, **kwargs)
            complete(payload, not_run, record)
        written = sum(1 for entry in record if entry != MOVED)
        if written:
            logger.warning(
                "%s provider: %d tool call(s) in the history had no reply; each is sent "
                "with a reply saying so (%d of them with arguments that did not parse, said "
                "not run).",
                dialect,
                written,
                record.count(NOT_RUN),
            )
        if MOVED in record:
            logger.warning(
                "%s provider: %d recorded tool reply(ies) stood away from their call and "
                "are sent right after it.",
                dialect,
                record.count(MOVED),
            )
        return payload

    answered_class = type(chat_class.__name__, (chat_class,), {hook: answered_hook})
    answered_class.__module__ = __name__
    answered_class.__qualname__ = chat_class.__qualname__
    _ANSWERED_CLASSES[(chat_class, dialect)] = answered_class
    return answered_class
