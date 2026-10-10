"""Every Anthropic request keeps the thinking blocks it replays valid, and caches what it re-sends.

A model of the current generation (the vendored table's ``prefix_bound_thinking``
rows: Claude Haiku 5.5 among them) returns ``thinking`` blocks whose
``signature`` is bound to everything before them: the ``system`` prompt, the
``tools`` and every earlier message. A later request that sends a block back
after any of those changed is refused with a 400 on the accounts the API checks
it for by default (the Preserved thinking page:
https://platform.claude.com/docs/en/build-with-claude/preserved-thinking).
Appending is always valid. So, on such a model, every request is built to be
the one before it plus its new turns:

* **The run-state block** (``pipeline.run_state``) rides at the end of the
  request's newest user turn, where it stays data in the user's channel, as on
  every other provider; nothing of it is ever sent with a system role. The
  platform notes the exact block it attached on the message
  (:data:`RUN_STATE_ATTACHED`); only that block is recognised, never text that
  merely ends with the markers. The newest turn carries the whole current
  block, as on every other provider, and every earlier user turn is sent again
  exactly as it was sent, block and all, so the history only grows. The earlier
  copies are counted by the callers' window, room and spend measures
  (:func:`replays_earlier_blocks`), never hidden.

* **Assistant turns are sent as they were received.** The callers keep a
  ``[thinking, tool_use]`` turn whole on this provider, and a call that never
  ran is answered by the tool-reply completion (``tool_replies``) rather than
  taken off its turn.

* **A changed history** — a salvage cut to fit — is found rather than listed:
  each thinking block received is remembered with a running digest of the
  request it was written after, and each block sent back is compared with the
  history before it. On the request where a block is first found stale every
  block still goes back as received and the API is asked to drop the stale
  ones (``thinking.block_binding.prefix_mismatch_behavior: "drop_block"``, beta
  ``thinking-binding-controls-2026-08-01``), the recovery the Preserved
  thinking page documents. On every later request the dropped blocks are left
  out ("once you remove a block, leave it out"), so the blocks written after
  them, written while they were gone, stay valid and the model keeps that
  reasoning. A block is kept where leaving it out would empty its turn or
  touch the latest assistant turn, and the request then asks to drop again.

**No empty text block** reaches the API, on any model: one that is empty or
only whitespace, which the API refuses with a 400, is left out of every turn
and the system prompt, and a turn left with nothing is left out whole. A
streamed answer sent back again carries one (LangChain's join of a stream
starts with the empty string of its opening chunk).

**Prompt caching** is asked for only where a prefix is sent again: a request
of a tool loop (the loop's turns are noted, :data:`TOOL_LOOP_TURN`) or one that
carries an earlier assistant turn. It gets explicit breakpoints on the last
block of its newest user turn and on the user turn before its newest assistant
turn. A tool loop's first user turn is sent as a one-block list on every
request, so it can carry a breakpoint on the first request without changing
shape on the next. A single-shot call carries none and pays no write premium
(https://platform.claude.com/docs/en/build-with-claude/prompt-caching) — except
where its first user turn is noted with a head that other requests repeat
(:data:`SHARED_HEAD`, the report composer's sections): that turn is sent as two
text blocks, the head with a breakpoint and the rest after it, whose texts
joined are the turn's text, so every request sharing the head reads one cached
prefix.

What is remembered lives on the chat model that sent it (:func:`memory_of`),
which a job's service container builds for its own agents and drops when the
job ends; nothing is held at module level, so nothing of one job reaches
another's request. The conversation a caller keeps is never touched; only the
request is.
"""

from __future__ import annotations

import hashlib
import json
import threading
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from maljan.core.logger import logger

BINDING_BETA = "thinking-binding-controls-2026-08-01"

# Where a message carries the exact run-state block the platform attached to
# it, and where a tool loop's request says it is one, in ``response_metadata``
# (which no client sends).
RUN_STATE_ATTACHED = "maljan_run_state_attached"
TOOL_LOOP_TURN = "maljan_tool_loop_turn"
# Where a user turn says how many of its leading characters are a head other
# requests send too, in ``response_metadata``.
SHARED_HEAD = "maljan_shared_head"

_THINKING_KINDS = ("thinking", "redacted_thinking")

# Where a chat model keeps its memory, in its own ``__dict__``.
_MEMORY_ATTR = "_maljan_preserved_thinking"


class Memory:
    """What one chat model sent and received, for its own later requests only."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        # signature digest -> digest of the request the block was written after.
        self.produced_after: dict[str, str] = {}
        # digest of a user turn as it reads without its run-state block -> the
        # turn as it was sent.
        self.sent_turns: dict[str, dict[str, Any]] = {}
        # digests of the first user turns sent as a one-block list.
        self.listed_first: set[str] = set()
        # signature digests of blocks the API was asked to drop.
        self.stale: set[str] = set()

    def clear(self) -> None:
        with self.lock:
            self.produced_after.clear()
            self.sent_turns.clear()
            self.listed_first.clear()
            self.stale.clear()


_memory_lock = threading.Lock()


def memory_of(model: Any) -> Memory:
    """The memory ``model`` keeps for its own requests, made on first use."""
    held = getattr(model, "__dict__", {}).get(_MEMORY_ATTR)
    if isinstance(held, Memory):
        return held
    with _memory_lock:
        held = model.__dict__.get(_MEMORY_ATTR)
        if not isinstance(held, Memory):
            held = Memory()
            model.__dict__[_MEMORY_ATTR] = held
    return held


# ── Which models bind thinking to its prefix ──────────────────────────────

_table_lock = threading.Lock()
_bound_rows: dict[str, str] | None = None


def _prefix_bound_rows() -> dict[str, str]:
    """The vendored table's ``prefix_bound_thinking`` rows, read once: family key -> source."""
    global _bound_rows
    from maljan.core.paths import resolve_data
    from maljan.llm.context_window import TABLE_PATH

    with _table_lock:
        if _bound_rows is not None:
            return _bound_rows
        rows: dict[str, str] = {}
        try:
            raw = json.loads(Path(resolve_data(TABLE_PATH)).read_text(encoding="utf-8"))
            for key, row in (raw.get("prefix_bound_thinking") or {}).items():
                source = str(row.get("source") or "") if isinstance(row, dict) else ""
                if not str(key).startswith("_") and source:
                    rows[str(key).lower()] = source
        except Exception as exc:  # noqa: BLE001 — a table that cannot be read names no model
            logger.debug("the vendored prefix-bound rows could not be read: %s", exc)
        _bound_rows = rows
        return _bound_rows


def binds_thinking_to_prefix(model: object) -> bool:
    """Whether ``model`` is documented to bind its thinking blocks to their prefix."""
    from maljan.llm.context_window import model_family

    family = model_family(model)
    return bool(family) and any(family.startswith(key) for key in _prefix_bound_rows())


def _models_of(llm: Any) -> list[Any]:
    """``llm`` and every model it binds or falls back to."""
    found: list[Any] = []
    pending = [llm]
    while pending and len(found) < 16:
        current = pending.pop()
        if current is None:
            continue
        found.append(current)
        pending.append(getattr(current, "bound", None))
        inner = getattr(current, "models", None)
        if isinstance(inner, list):
            pending.extend(inner)
    return found


def replays_earlier_blocks(llm: Any) -> bool:
    """Whether a request to ``llm`` re-sends the run-state blocks of its earlier turns.

    True where any model it may send to keeps its history append-only (a model
    in ``prefix_bound_thinking`` on this provider): such a request weighs those
    copies too, and the callers' measures count them.
    """
    return any(
        getattr(type(model), "_maljan_keeps_turns", False)
        and binds_thinking_to_prefix(getattr(model, "model", ""))
        for model in _models_of(llm)
    )


def keeps_turns_as_received(llm: Any) -> bool:
    """Whether ``llm`` (or a model it binds or falls back to) sends assistant turns as received.

    The callers that would otherwise rebuild a turn — take an unrun call off
    it, drop a call whose arguments never parsed, change the system turn for a
    tool-free question — ask this first, and leave the turn whole.
    """
    seen = 0
    pending = [llm]
    while pending and seen < 16:
        seen += 1
        current = pending.pop()
        if current is None:
            continue
        if getattr(type(current), "_maljan_keeps_turns", False):
            return True
        pending.append(getattr(current, "bound", None))
        inner = getattr(current, "models", None)
        if isinstance(inner, list):
            pending.extend(inner)
    return False


# ── Digests ────────────────────────────────────────────────────────────────


def _without_markers(value: Any) -> Any:
    """``value`` without its ``cache_control`` markers, which the binding does not cover."""
    if isinstance(value, dict):
        return {k: _without_markers(v) for k, v in value.items() if k != "cache_control"}
    if isinstance(value, list):
        return [_without_markers(v) for v in value]
    return value


def _dump(value: Any) -> bytes:
    text = json.dumps(_without_markers(value), sort_keys=True, ensure_ascii=False, default=str)
    return text.encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_dump(value)).hexdigest()


def _signature_key(block: dict[str, Any]) -> str:
    signed = block.get("signature") if block.get("type") == "thinking" else block.get("data")
    return hashlib.sha256(str(signed or "").encode("utf-8")).hexdigest() if signed else ""


def _is_thinking(block: Any) -> bool:
    return isinstance(block, dict) and block.get("type") in _THINKING_KINDS


# ── The run-state block, in the user's turn ───────────────────────────────


def _replace_tail(text: Any, block: str, replacement: str) -> tuple[Any, bool]:
    """``text`` with ``block`` at its end replaced by ``replacement``, or unchanged."""
    if not isinstance(text, str) or not block or not text.endswith(block):
        return text, False
    return text[: len(text) - len(block)] + replacement, True


def _with_block_replaced(message: dict[str, Any], block: str, replacement: str) -> dict[str, Any]:
    """The user turn with the platform's exact ``block`` at its end replaced, or ``message``."""
    content = message.get("content")
    if isinstance(content, str):
        text, done = _replace_tail(content, block, replacement)
        return {**message, "content": text} if done else message
    if not isinstance(content, list) or not content or not isinstance(content[-1], dict):
        return message
    last = content[-1]
    if last.get("type") == "text" and last.get("text") == block and not replacement:
        # The block was a part of its own; without it the part goes.
        return {**message, "content": content[:-1]}
    if last.get("type") == "text":
        text, done = _replace_tail(last.get("text"), block, replacement)
        if done:
            return {**message, "content": [*content[:-1], {**last, "text": text}]}
        return message
    if last.get("type") == "tool_result":
        inner = last.get("content")
        if isinstance(inner, str):
            text, done = _replace_tail(inner, block, replacement)
            if done:
                return {**message, "content": [*content[:-1], {**last, "content": text}]}
        elif isinstance(inner, list) and inner and isinstance(inner[-1], dict):
            if inner[-1].get("text") == block and not replacement and len(inner) > 1:
                return {**message, "content": [*content[:-1], {**last, "content": inner[:-1]}]}
            text, done = _replace_tail(inner[-1].get("text"), block, replacement)
            if done:
                part = {**inner[-1], "text": text}
                return {
                    **message,
                    "content": [*content[:-1], {**last, "content": [*inner[:-1], part]}],
                }
    return message


def _user_indexes(messages: list[Any]) -> list[int]:
    return [i for i, m in enumerate(messages) if isinstance(m, dict) and m.get("role") == "user"]


def _keep_run_state_appended(memory: Memory, messages: list[Any], attached: str) -> list[Any]:
    """Earlier user turns as they were sent, the newest one as framed, noted for later requests.

    ``attached`` is the exact block the platform put on the newest turn; the
    turn is remembered as it reads without it, so the next request, which
    frames that turn without its block, sends it as it was sent here.
    """
    users = _user_indexes(messages)
    if not users:
        return messages
    out = list(messages)
    newest = users[-1]
    for index in users[:-1]:
        following = out[index + 1] if index + 1 < len(out) else None
        if isinstance(following, dict) and following.get("role") == "assistant":
            with memory.lock:
                sent = memory.sent_turns.get(_digest(out[index]))
            if sent is not None:
                out[index] = sent
    if attached and newest == len(out) - 1:
        bare = _with_block_replaced(out[newest], attached, "")
        if bare is not out[newest]:
            sent_turn = out[newest]
            # The turn as it reads once the platform takes its block off, the
            # separator in front of a block added to text included.
            stripped = _with_block_replaced(bare, "\n\n", "")
            for key in {_digest(bare), _digest(stripped)}:
                with memory.lock:
                    memory.sent_turns[key] = sent_turn
    return out


# ── A tool loop's first user turn ─────────────────────────────────────────


def _first_turn_listed(memory: Memory, messages: list[Any], loop: bool) -> list[Any]:
    """A tool loop's first user turn as a one-block list, on every request of the loop."""
    users = _user_indexes(messages)
    if not users:
        return messages
    first = messages[users[0]]
    content = first.get("content")
    if not isinstance(content, str):
        return messages
    from maljan.pipeline.run_state import without_run_state_tail

    # Keyed as the turn reads without a run-state block, which the platform
    # puts on it on the first request and takes off on the next.
    key = _digest({**first, "content": without_run_state_tail(content)})
    with memory.lock:
        listed = key in memory.listed_first
        if loop and not listed:
            memory.listed_first.add(key)
            listed = True
    if not listed:
        return messages
    out = list(messages)
    out[users[0]] = {**first, "content": [{"type": "text", "text": content}]}
    return out


# ── Thinking blocks ───────────────────────────────────────────────────────


def _settle_thinking(
    memory: Memory, payload: dict[str, Any], messages: list[Any]
) -> tuple[list[Any], bool, str]:
    """``(messages, whether to ask the API to drop, the whole request's digest)``.

    Blocks dropped on an earlier request are left out where that leaves
    their turn non-empty and the turn is not the latest assistant turn. Each
    remaining block is compared with the history before it, by one running
    digest over the request as the API renders it, dropped blocks left out.
    """
    assistants = [
        i for i, m in enumerate(messages) if isinstance(m, dict) and m.get("role") == "assistant"
    ]
    latest = assistants[-1] if assistants else -1
    running = hashlib.sha256(
        _dump({"system": payload.get("system"), "tools": payload.get("tools")})
    )
    out: list[Any] = []
    ask_to_drop = False
    newly: set[str] = set()
    for index, message in enumerate(messages):
        if index not in assistants or not isinstance(message.get("content"), list):
            out.append(message)
            running.update(b"\x00" + _dump(message))
            continue
        blocks = message["content"]
        with memory.lock:
            stale = set(memory.stale)
        kept = [b for b in blocks if not (_is_thinking(b) and _signature_key(b) in stale)]
        if len(kept) != len(blocks) and kept and index != latest:
            message = {**message, "content": kept}
            blocks = kept
        elif len(kept) != len(blocks):
            ask_to_drop = True
        here = running.copy().hexdigest()
        rendered: list[Any] = []
        for block in blocks:
            key = _signature_key(block) if _is_thinking(block) else ""
            if key:
                with memory.lock:
                    produced = memory.produced_after.get(key)
                if key in stale or key in newly:
                    continue
                if produced is not None and produced != here:
                    newly.add(key)
                    ask_to_drop = True
                    continue
            rendered.append(block)
        out.append(message)
        running.update(b"\x00" + _dump({**message, "content": rendered}))
    if newly:
        with memory.lock:
            memory.stale |= newly
        logger.warning(
            "anthropic provider: the history before %d thinking block(s) changed since they "
            "were written; they go back as received this once and the API is asked to drop "
            "them, and later requests leave them out.",
            len(newly),
        )
    return out, ask_to_drop, running.hexdigest()


def _with_beta(payload: dict[str, Any], beta: str) -> None:
    betas = list(payload.get("betas") or [])
    if beta not in betas:
        betas.append(beta)
    payload["betas"] = betas


def _drop_mismatched(payload: dict[str, Any]) -> None:
    thinking = dict(payload.get("thinking") or {"type": "adaptive"})
    thinking["block_binding"] = {"prefix_mismatch_behavior": "drop_block"}
    payload["thinking"] = thinking
    _with_beta(payload, BINDING_BETA)


# ── Prompt caching ────────────────────────────────────────────────────────


def _marked(message: dict[str, Any], marker: dict[str, str]) -> dict[str, Any]:
    """``message`` with ``marker`` on its last block.

    A turn whose content is a string is left as it is: turning it into a block
    list here would send a turn already sent in another shape, which is an
    edit of the history before every later thinking block.
    """
    content = message.get("content")
    if isinstance(content, list) and content and isinstance(content[-1], dict):
        if _is_thinking(content[-1]):
            return message
        return {**message, "content": [*content[:-1], {**content[-1], "cache_control": marker}]}
    return message


def _turn_text(content: Any) -> str | None:
    """A user turn's text when it is one string or one plain text block, else ``None``."""
    if isinstance(content, str):
        return content
    if (
        isinstance(content, list)
        and len(content) == 1
        and isinstance(content[0], dict)
        and content[0].get("type") == "text"
        and set(content[0]) <= {"type", "text"}
        and isinstance(content[0].get("text"), str)
    ):
        return str(content[0]["text"])
    return None


def _shared_heads(messages: list[Any], heads: dict[str, int], marker: dict[str, str]) -> list[Any]:
    """Each user turn noted with a shared head, as the head with a breakpoint and the rest.

    ``heads`` maps a noted turn's whole text to its head's length. The two
    blocks' texts joined are the turn's text, character for character; a
    head that is empty or the whole turn leaves the turn as it is.
    """
    if not heads:
        return messages
    out: list[Any] = []
    for message in messages:
        if isinstance(message, dict) and message.get("role") == "user":
            text = _turn_text(message.get("content"))
            size = heads.get(text, 0) if text is not None else 0
            # Split only where both parts hold text: a part of whitespace
            # alone is a block the API refuses.
            if (
                text is not None
                and 0 < size < len(text)
                and text[:size].strip()
                and text[size:].strip()
            ):
                message = {
                    **message,
                    "content": [
                        {"type": "text", "text": text[:size], "cache_control": marker},
                        {"type": "text", "text": text[size:]},
                    ],
                }
        out.append(message)
    return out


def _cache_breakpoints(messages: list[Any], marker: dict[str, str], loop: bool) -> list[Any]:
    """Explicit breakpoints on a conversation that re-sends its prefix, none otherwise."""
    roles = [m.get("role") if isinstance(m, dict) else None for m in messages]
    if "assistant" not in roles and not loop:
        return messages
    users = [i for i, role in enumerate(roles) if role == "user"]
    marks = {users[-1]} if users else set()
    if "assistant" in roles:
        last_assistant = max(i for i, role in enumerate(roles) if role == "assistant")
        before = [i for i in users if i < last_assistant]
        if before:
            marks.add(before[-1])
    return [_marked(m, marker) if i in marks else m for i, m in enumerate(messages)]


# ── Empty text ────────────────────────────────────────────────────────────


def _holds_text(block: Any) -> bool:
    """Whether ``block`` is anything but a text block with no character other than whitespace."""
    if not isinstance(block, dict) or block.get("type") != "text":
        return True
    return bool(str(block.get("text") or "").strip())


def _with_text_kept(block: Any) -> Any:
    """``block``, a ``tool_result`` without the empty text blocks of its list content.

    A result whose list held nothing else goes without content, which the API
    takes as a result with none.
    """
    if not isinstance(block, dict) or block.get("type") != "tool_result":
        return block
    inner = block.get("content")
    if not isinstance(inner, list) or all(_holds_text(part) for part in inner):
        return block
    kept = [part for part in inner if _holds_text(part)]
    if kept:
        return {**block, "content": kept}
    return {key: value for key, value in block.items() if key != "content"}


def _without_empty_text(payload: dict[str, Any], messages: list[Any]) -> list[Any]:
    """``messages`` and ``payload['system']`` without a text block the API refuses as empty.

    The Messages API refuses, with a 400, a text block that is empty or holds
    only whitespace, and a turn other than a final prefill with no content.
    LangChain joins a streamed answer's chunks into a list that starts with
    the empty string the opening chunk carried, and ``ChatAnthropic`` sends
    that string back as an empty text block when the answer is sent again (a
    validation retry, a tool loop's next step). Every such block is left out
    here, from every turn, from a ``tool_result``'s list content and from the
    system prompt; a turn left with nothing is left out whole, and the API
    takes the turns either side of it as one. ``_shared_heads``, which runs
    after this, splits a turn only where both parts hold text, so no step of
    this hook makes such a block again.
    Every other block keeps its place and its bytes, so a thinking block's
    signature still checks. One pass over the request.
    """
    system = payload.get("system")
    if isinstance(system, list) and not all(_holds_text(block) for block in system):
        kept_system = [block for block in system if _holds_text(block)]
        if kept_system:
            payload["system"] = kept_system
        else:
            payload.pop("system", None)
    out: list[Any] = []
    for message in messages:
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, str):
            if content.strip():
                out.append(message)
            continue
        if isinstance(content, list):
            kept = [_with_text_kept(block) for block in content if _holds_text(block)]
            if not kept:
                continue
            changed = len(kept) != len(content) or any(
                a is not b for a, b in zip(kept, content, strict=False)
            )
            out.append({**message, "content": kept} if changed else message)
            continue
        out.append(message)
    return out


# ── The request hook ──────────────────────────────────────────────────────

# The digest of the request a call is about to send, handed from the request
# hook to the code that reads the answer. A one-element list, so a hook running
# in a copied context (the deadline wrapper runs the call in a task of its own)
# still writes where the caller reads.
_PENDING: ContextVar[list[str] | None] = ContextVar("maljan_anthropic_pending", default=None)


def prepared(
    payload: dict[str, Any],
    memory: Memory,
    *,
    bound: bool,
    cache_marker: dict[str, str],
    attached: str = "",
    loop: bool = False,
    heads: dict[str, int] | None = None,
) -> dict[str, Any]:
    """The request ``payload`` built to keep its replayed thinking valid and cache what repeats.

    ``bound`` is whether the model binds thinking to its prefix
    (:func:`binds_thinking_to_prefix`); only such a model's history is kept
    append-only and its blocks checked. ``attached`` is the exact run-state
    block the platform put on the newest turn, ``loop`` whether the request is
    a tool loop's. ``heads`` maps the text of each user turn noted with a
    shared head to the head's length (:data:`SHARED_HEAD`). On every model, a
    text block that is empty or only whitespace is left out first
    (:func:`_without_empty_text`). Never raises: a request this cannot read is
    sent as built.
    """
    try:
        messages = payload.get("messages")
        if not isinstance(messages, list):
            return payload
        payload = dict(payload)
        # First, so every later step, and the digests the thinking check
        # keeps, read the request as it is sent.
        messages = _without_empty_text(payload, messages)
        payload["messages"] = messages
        messages = _shared_heads(messages, dict(heads or {}), cache_marker)
        messages = _first_turn_listed(memory, messages, loop)
        if bound:
            messages = _keep_run_state_appended(memory, messages, attached)
            messages, ask_to_drop, whole = _settle_thinking(memory, payload, messages)
            if ask_to_drop:
                _drop_mismatched(payload)
            pending = _PENDING.get()
            if pending is not None:
                pending[:] = [whole]
        payload["messages"] = _cache_breakpoints(messages, cache_marker, loop)
        last = messages[-1] if messages else None
        if isinstance(last, dict) and last.get("role") == "assistant":
            logger.warning(
                "anthropic provider: the request ends on an assistant turn, which a model that "
                "thinks by default refuses as a prefill."
            )
    except Exception as exc:  # noqa: BLE001 — the request is sent as it was built
        logger.debug("anthropic provider: history left as built (%s).", exc)
    return payload


def note_answer(result: Any, prefix: str, memory: Memory) -> None:
    """Remember each thinking block an answer carries with the request it was written after."""
    if not prefix:
        return
    try:
        for generation in getattr(result, "generations", None) or []:
            message = getattr(generation, "message", None)
            content = getattr(message, "content", None)
            if not isinstance(content, list):
                continue
            for block in content:
                if _is_thinking(block):
                    key = _signature_key(block)
                    if key:
                        with memory.lock:
                            memory.produced_after[key] = prefix
    except Exception as exc:  # noqa: BLE001 — an answer not remembered is one not checked
        logger.debug("anthropic provider: thinking blocks not noted (%s).", exc)


def _notes_of(model: Any, input_: Any) -> tuple[str, bool]:
    """``(the run-state block the platform attached to the newest turn, a tool loop's turn)``."""
    try:
        messages = model._convert_input(input_).to_messages()
    except Exception:  # noqa: BLE001 — a request whose turns cannot be read carries no note
        return "", False
    last = messages[-1] if messages else None
    noted = getattr(last, "response_metadata", None) or {}
    block = noted.get(RUN_STATE_ATTACHED)
    return (block if isinstance(block, str) else ""), bool(noted.get(TOOL_LOOP_TURN))


def _heads_of(model: Any, input_: Any) -> dict[str, int]:
    """Each user turn's text noted with a shared head, and the head's length."""
    try:
        messages = model._convert_input(input_).to_messages()
    except Exception:  # noqa: BLE001 — a request whose turns cannot be read carries no note
        return {}
    heads: dict[str, int] = {}
    for message in messages:
        size = (getattr(message, "response_metadata", None) or {}).get(SHARED_HEAD)
        text = _turn_text(getattr(message, "content", None))
        if isinstance(size, int) and not isinstance(size, bool) and size > 0 and text:
            heads[text] = size
    return heads


_PRESERVED_CLASSES: dict[tuple[type, str], type] = {}


def with_preserved_thinking(chat_class: Any, cache_ttl: str = "5m") -> Any:
    """``chat_class`` whose every request keeps replayed thinking valid and caches what repeats.

    Applied under the tool-reply completion (``tool_replies``), which only
    adds a reply a history lacks and adds the same one to the same history on
    every request: what is checked here is what is sent, less those replies.
    """
    if not isinstance(chat_class, type) or not hasattr(chat_class, "_get_request_payload"):
        return chat_class
    cached = _PRESERVED_CLASSES.get((chat_class, cache_ttl))
    if cached is not None:
        return cached
    base: Any = chat_class
    marker = {"type": "ephemeral", **({"ttl": "1h"} if cache_ttl == "1h" else {})}

    def _get_request_payload(self: Any, input_: Any, *, stop: Any = None, **kwargs: Any) -> Any:
        payload = base._get_request_payload(self, input_, stop=stop, **kwargs)
        if not isinstance(payload, dict):
            return payload
        attached, loop = _notes_of(self, input_)
        return prepared(
            payload,
            memory_of(self),
            bound=binds_thinking_to_prefix(getattr(self, "model", "")),
            cache_marker=marker,
            attached=attached,
            loop=loop,
            heads=_heads_of(self, input_),
        )

    def _generate_with_cache(self: Any, *args: Any, **kwargs: Any) -> Any:
        holder: list[str] = []
        token = _PENDING.set(holder)
        try:
            result = base._generate_with_cache(self, *args, **kwargs)
        finally:
            _PENDING.reset(token)
        note_answer(result, holder[0] if holder else "", memory_of(self))
        return result

    async def _agenerate_with_cache(self: Any, *args: Any, **kwargs: Any) -> Any:
        holder: list[str] = []
        token = _PENDING.set(holder)
        try:
            result = await base._agenerate_with_cache(self, *args, **kwargs)
        finally:
            _PENDING.reset(token)
        note_answer(result, holder[0] if holder else "", memory_of(self))
        return result

    preserved = type(
        chat_class.__name__,
        (chat_class,),
        {
            "_get_request_payload": _get_request_payload,
            "_generate_with_cache": _generate_with_cache,
            "_agenerate_with_cache": _agenerate_with_cache,
            "_maljan_keeps_turns": True,
        },
    )
    preserved.__module__ = __name__
    preserved.__qualname__ = chat_class.__qualname__
    _PRESERVED_CLASSES[(chat_class, cache_ttl)] = preserved
    return preserved
