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
  request's last user turn and comes off it once that turn is no longer last.
  Here it is taken off that turn and sent instead as a turn-scoped
  mid-conversation system message (``"role": "system"``, ``"clear_at":
  "next_user_message"``, beta ``mid-conversation-system-clear-at-2026-08-21``)
  right after it: the documented per-turn reminder. Its text renders only
  until the next user message (a tool result is one), and on every later
  request the same system message is sent again verbatim after the turn it
  followed, cleared, rendering nothing and costing no input tokens
  (https://platform.claude.com/docs/en/build-with-claude/mid-conversation-system-messages).
  The model reads one block, the current one, as on every other provider, and
  the history only grows.

* **Assistant turns are sent as they were received.** The callers keep a
  ``[thinking, tool_use]`` turn whole on this provider, and a call that never
  ran is answered by the tool-reply completion (``tool_replies``) rather than
  taken off its turn; nothing here rebuilds or empties an assistant turn.

* **Any other change to a history** — a salvage cut to fit — is found rather
  than listed: each thinking block received is remembered with a running
  digest of the request it was written after, and each block sent back is
  compared with the history as it stands before it. Where one no longer
  matches, every block still goes back exactly as received, and the request
  asks the API to drop the blocks whose prefix changed
  (``thinking.block_binding.prefix_mismatch_behavior: "drop_block"``, beta
  ``thinking-binding-controls-2026-08-01``), the recovery the Preserved
  thinking page documents; the choice is kept for every later request of the
  model.

**Prompt caching** is asked for only where a prefix is sent again: a request
that carries an earlier assistant turn continues a conversation, and gets two
explicit breakpoints, on the last block of its newest user turn (written now,
read next step) and on the last block of the user turn before its newest
assistant turn (where the previous request's write ended, so the lookback
always finds it). A single-shot call carries none and pays no write premium
(https://platform.claude.com/docs/en/build-with-claude/prompt-caching).

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

CLEAR_AT_BETA = "mid-conversation-system-clear-at-2026-08-21"
BINDING_BETA = "thinking-binding-controls-2026-08-01"

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
        # turn-scoped system message sent after it.
        self.reminder_after: dict[str, dict[str, Any]] = {}
        # Set once a request found a block whose prefix changed: every later
        # request of this model asks the API to drop such blocks.
        self.dropping = False

    def clear(self) -> None:
        with self.lock:
            self.produced_after.clear()
            self.reminder_after.clear()
            self.dropping = False


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


def _thinking_blocks(message: Any) -> list[dict[str, Any]]:
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, list):
        return []
    return [b for b in content if isinstance(b, dict) and b.get("type") in _THINKING_KINDS]


# ── The run-state block as a turn-scoped system message ───────────────────


def _split_text(text: Any) -> tuple[Any, str]:
    """``(text without its run-state tail, the block)``; the block ``""`` where there is none."""
    from maljan.pipeline.run_state import without_run_state_tail

    if not isinstance(text, str):
        return text, ""
    bare = without_run_state_tail(text)
    if bare == text:
        return text, ""
    block = text[len(bare) :].lstrip("\n")
    return bare, block


def _split_part(part: Any) -> tuple[Any, str]:
    """``(the part without a run-state block at its end, the block or "")``."""
    from maljan.pipeline.run_state import is_run_state_block

    if isinstance(part, str):
        return _split_text(part)
    if not isinstance(part, dict):
        return part, ""
    if part.get("type") == "text":
        bare, block = _split_text(part.get("text"))
        return ({**part, "text": bare}, block) if block else (part, "")
    if part.get("type") == "tool_result":
        content = part.get("content")
        if isinstance(content, str):
            bare, block = _split_text(content)
            return ({**part, "content": bare}, block) if block else (part, "")
        if isinstance(content, list) and content:
            last = content[-1]
            if isinstance(last, dict) and last.get("type") == "text":
                text = last.get("text")
                if is_run_state_block(text) and len(content) > 1:
                    return {**part, "content": content[:-1]}, str(text).strip()
                bare, block = _split_text(text)
                if block:
                    return {**part, "content": [*content[:-1], {**last, "text": bare}]}, block
    return part, ""


def _split_turn(message: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """A user turn without the run-state block at its end, and the block (``""`` if none)."""
    from maljan.pipeline.run_state import is_run_state_block

    content = message.get("content")
    if isinstance(content, str):
        bare, block = _split_text(content)
        return ({**message, "content": bare}, block) if block and bare else (message, "")
    if not isinstance(content, list) or not content:
        return message, ""
    last = content[-1]
    if (
        len(content) > 1
        and isinstance(last, dict)
        and last.get("type") == "text"
        and is_run_state_block(last.get("text"))
    ):
        return {**message, "content": content[:-1]}, str(last.get("text")).strip()
    bare_last, block = _split_part(last)
    if not block:
        return message, ""
    return {**message, "content": [*content[:-1], bare_last]}, block


def _reminder(block: str) -> dict[str, Any]:
    return {"role": "system", "clear_at": "next_user_message", "content": block}


def _run_state_as_reminders(memory: Memory, messages: list[Any]) -> tuple[list[Any], bool]:
    """Each run-state block as the turn-scoped system message after the turn it rode on.

    The newest user turn's block is taken off it and sent after it; every
    earlier user turn that was once newest is followed again by the message
    sent after it then, verbatim. Returns the messages and whether any carry
    such a message.
    """
    users = [i for i, m in enumerate(messages) if isinstance(m, dict) and m.get("role") == "user"]
    last_user = users[-1] if users else -1
    out: list[Any] = []
    any_reminder = False
    for index, message in enumerate(messages):
        if not (isinstance(message, dict) and message.get("role") == "user"):
            out.append(message)
            continue
        following = messages[index + 1] if index + 1 < len(messages) else None
        if index == last_user and following is None:
            bare, block = _split_turn(message)
            if block:
                reminder = _reminder(block)
                with memory.lock:
                    memory.reminder_after[_digest(bare)] = reminder
                out += [bare, reminder]
                any_reminder = True
                continue
            out.append(message)
            continue
        out.append(message)
        if isinstance(following, dict) and following.get("role") == "assistant":
            with memory.lock:
                sent = memory.reminder_after.get(_digest(message))
            if sent is not None:
                out.append(sent)
                any_reminder = True
    return out, any_reminder


# ── Thinking blocks ───────────────────────────────────────────────────────


def _stale_blocks(memory: Memory, payload: dict[str, Any], messages: list[Any]) -> tuple[int, str]:
    """``(how many blocks sent back no longer match their prefix, the whole request's digest)``.

    One running digest over the request: each assistant turn's blocks are
    compared with the history before them as it stands in this request.
    """
    running = hashlib.sha256(
        _dump({"system": payload.get("system"), "tools": payload.get("tools")})
    )
    stale = 0
    for message in messages:
        blocks = _thinking_blocks(message) if message.get("role") == "assistant" else []
        if blocks:
            here = running.copy().hexdigest()
            with memory.lock:
                produced = [memory.produced_after.get(_signature_key(b)) for b in blocks]
            stale += sum(1 for p in produced if p is not None and p != here)
        running.update(b"\x00" + _dump(message))
    return stale, running.hexdigest()


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
        if content[-1].get("type") in _THINKING_KINDS:
            return message
        return {**message, "content": [*content[:-1], {**content[-1], "cache_control": marker}]}
    return message


def _cache_breakpoints(messages: list[Any], marker: dict[str, str]) -> list[Any]:
    """Two explicit breakpoints on a conversation that re-sends its prefix, none otherwise."""
    roles = [m.get("role") if isinstance(m, dict) else None for m in messages]
    if "assistant" not in roles:
        return messages
    users = [i for i, role in enumerate(roles) if role == "user"]
    last_assistant = max(i for i, role in enumerate(roles) if role == "assistant")
    before = [i for i in users if i < last_assistant]
    marks = {users[-1]} if users else set()
    if before:
        marks.add(before[-1])
    return [_marked(m, marker) if i in marks else m for i, m in enumerate(messages)]


# ── The request hook ──────────────────────────────────────────────────────

# The digest of the request a call is about to send, handed from the request
# hook to the code that reads the answer. A one-element list, so a hook running
# in a copied context (the deadline wrapper runs the call in a task of its own)
# still writes where the caller reads.
_PENDING: ContextVar[list[str] | None] = ContextVar("maljan_anthropic_pending", default=None)


def prepared(
    payload: dict[str, Any], memory: Memory, *, bound: bool, cache_marker: dict[str, str]
) -> dict[str, Any]:
    """The request ``payload`` built to keep its replayed thinking valid and cache what repeats.

    ``bound`` is whether the model binds thinking to its prefix
    (:func:`binds_thinking_to_prefix`); only such a model's run-state block is
    sent as a turn-scoped system message and only its blocks are checked.
    Never raises: a request this cannot read is sent as it was built.
    """
    try:
        messages = payload.get("messages")
        if not isinstance(messages, list):
            return payload
        payload = dict(payload)
        if bound:
            messages, reminded = _run_state_as_reminders(memory, messages)
            if reminded:
                _with_beta(payload, CLEAR_AT_BETA)
            stale, whole = _stale_blocks(memory, payload, messages)
            if stale and not memory.dropping:
                memory.dropping = True
                logger.warning(
                    "anthropic provider: the history before %d thinking block(s) changed since "
                    "they were written; they go back as received and the API is asked to drop "
                    "the ones it can no longer read, on this and every later request.",
                    stale,
                )
            if memory.dropping:
                _drop_mismatched(payload)
            pending = _PENDING.get()
            if pending is not None:
                pending[:] = [whole]
        payload["messages"] = _cache_breakpoints(messages, cache_marker)
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
                if isinstance(block, dict) and block.get("type") in _THINKING_KINDS:
                    key = _signature_key(block)
                    if key:
                        with memory.lock:
                            memory.produced_after[key] = prefix
    except Exception as exc:  # noqa: BLE001 — an answer not remembered is one not checked
        logger.debug("anthropic provider: thinking blocks not noted (%s).", exc)


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
        return prepared(
            payload,
            memory_of(self),
            bound=binds_thinking_to_prefix(getattr(self, "model", "")),
            cache_marker=marker,
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
