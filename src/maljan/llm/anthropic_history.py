"""Every Anthropic request keeps the thinking blocks it replays valid.

A model that thinks by default (Claude Haiku 5.5 among them) returns
``thinking`` blocks whose ``signature`` is bound to what came before them: the
``system`` prompt, the ``tools`` and every earlier message. A later request
that sends a block back after any of those changed is refused with a 400 on
the accounts the API checks it for by default, and on the others the API may
drop the block (the Preserved thinking page:
https://platform.claude.com/docs/en/build-with-claude/preserved-thinking).
The same page lists what keeps a request valid: appending messages, removing
thinking blocks from the end of the history or all of them, and changing
``cache_control`` markers or any request field outside ``system``, ``tools``
and ``messages``.

Maljan edits the history it re-sends in two kinds of place, and each is
handled here, on the request as the client built it:

* **The run-state block** (``pipeline.run_state``) rides at the end of the
  request's last message and comes off it once that message is no longer last
  — an edit of an earlier user turn on every tool-loop turn. Here the block a
  message was sent with is put back on it, exactly as it was sent, so the
  history this provider sends only ever grows: each request is the one before
  it plus the new turns. The model reads each earlier block where it read it
  the first time; the newest is still the last.

* **Everything else that rewrites a history** — a salvage sent without the
  loop's tools and cut to fit, a re-ask that adds a question to a turn already
  sent, a turn whose unrun calls were taken out — is found rather than listed:
  every thinking block this process received is remembered with a digest of
  the request that produced it, and a block whose prefix no longer matches is
  stale. The first stale block and every thinking block after it are left out
  of the request, which the page lists as valid ("Remove thinking blocks from
  the end"); the model then reads that part of the history without its earlier
  reasoning, as it would after any edit. A block this process did not receive
  is sent as it is, unless a stale one came before it.

The conversation the caller keeps is never touched; only the request is.
Nothing here adds words a model or an operator did not write.

**What is remembered stays with the model object that sent it.** Both
memories live on the chat model (:func:`memory_of`), which a job's service
container builds for its own agents and drops when the job ends; nothing is
held at module level. A request of one job can only be completed from what
that job's own model sent, so no text, run-state block or thinking block of
one job reaches another job's request, however many jobs one worker runs.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import OrderedDict
from contextvars import ContextVar
from typing import Any

from maljan.core.logger import logger

# How many entries each memory holds before the oldest goes: thinking blocks
# received and run-state blocks sent. A job's tool loops send a few hundred of
# each; a block forgotten is one that is no longer checked, never one that is
# dropped.
MEMORY_ENTRIES = 20_000

_THINKING_KINDS = ("thinking", "redacted_thinking")

# Where a chat model keeps its memory, in its own ``__dict__``.
_MEMORY_ATTR = "_maljan_preserved_thinking"


class Memory:
    """What one chat model sent and received, for its own later requests only."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        # signature digest -> digest of the request prefix the block was written after.
        self.produced_after: OrderedDict[str, str] = OrderedDict()
        # digest of a user-turn part as it reads without its run-state block ->
        # the part as it was sent, block and all.
        self.sent_with_block: OrderedDict[str, Any] = OrderedDict()

    def clear(self) -> None:
        with self.lock:
            self.produced_after.clear()
            self.sent_with_block.clear()

    def remember(self, which: OrderedDict[str, Any], key: str, value: Any) -> None:
        with self.lock:
            which[key] = value
            which.move_to_end(key)
            while len(which) > MEMORY_ENTRIES:
                which.popitem(last=False)

    def get(self, which: OrderedDict[str, Any], key: str) -> Any:
        with self.lock:
            return which.get(key)


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


# The prefix digest of the request a call is about to send, handed from the
# request hook to the code that reads the answer. A one-element list, so a
# hook running in a copied context (the deadline wrapper runs the call in a
# task of its own) still writes where the caller reads.
_PENDING: ContextVar[list[str] | None] = ContextVar("maljan_anthropic_pending", default=None)


def _without_markers(value: Any) -> Any:
    """``value`` without its ``cache_control`` markers, which the binding does not cover."""
    if isinstance(value, dict):
        return {k: _without_markers(v) for k, v in value.items() if k != "cache_control"}
    if isinstance(value, list):
        return [_without_markers(v) for v in value]
    return value


def _digest(value: Any) -> str:
    text = json.dumps(_without_markers(value), sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _prefix_digest(payload: dict[str, Any], messages: list[Any]) -> str:
    return _digest(
        {"system": payload.get("system"), "tools": payload.get("tools"), "messages": messages}
    )


def _signature_key(block: dict[str, Any]) -> str:
    signed = block.get("signature") if block.get("type") == "thinking" else block.get("data")
    return hashlib.sha256(str(signed or "").encode("utf-8")).hexdigest() if signed else ""


# ── The run-state block ───────────────────────────────────────────────────


def _bare(part: Any) -> tuple[Any, bool]:
    """``part`` as it reads without a run-state block at its end, and whether it had one."""
    from maljan.pipeline.run_state import is_run_state_block, without_run_state_tail

    if isinstance(part, str):
        bare = without_run_state_tail(part)
        return bare, bare != part
    if not isinstance(part, dict):
        return part, False
    kind = part.get("type")
    if kind == "text":
        text = part.get("text")
        stripped: Any = without_run_state_tail(text) if isinstance(text, str) else text
        return ({**part, "text": stripped}, True) if stripped != text else (part, False)
    if kind == "tool_result":
        content = part.get("content")
        if isinstance(content, str):
            bare = without_run_state_tail(content)
            return ({**part, "content": bare}, True) if bare != content else (part, False)
        if isinstance(content, list) and content:
            last = content[-1]
            if isinstance(last, dict) and last.get("type") == "text":
                if is_run_state_block(last.get("text")):
                    return {**part, "content": content[:-1]}, True
                tail = last.get("text")
                kept: Any = without_run_state_tail(tail) if isinstance(tail, str) else tail
                if kept != tail:
                    return {**part, "content": [*content[:-1], {**last, "text": kept}]}, True
    return part, False


def _parts(message: dict[str, Any]) -> list[Any]:
    content = message.get("content")
    return list(content) if isinstance(content, list) else [content]


def _with_parts(message: dict[str, Any], parts: list[Any]) -> dict[str, Any]:
    if not isinstance(message.get("content"), list):
        return {**message, "content": parts[0]}
    return {**message, "content": parts}


def _list_tail_block(message: dict[str, Any]) -> bool:
    """Whether a user turn's content ends on a text part that is a whole run-state block."""
    from maljan.pipeline.run_state import is_run_state_block

    content = message.get("content")
    if not isinstance(content, list) or not content:
        return False
    last = content[-1]
    return (
        isinstance(last, dict)
        and last.get("type") == "text"
        and is_run_state_block(last.get("text"))
    )


def _note_blocks_sent(memory: Memory, messages: list[Any]) -> None:
    """Remember each user-turn part that carries a run-state block, as it is sent."""
    for message in messages:
        if not (isinstance(message, dict) and message.get("role") == "user"):
            continue
        parts = _parts(message)
        if _list_tail_block(message) and len(parts) > 1:
            # A block sent as a part of its own belongs to the part before it.
            memory.remember(memory.sent_with_block, _digest(("after", parts[-2])), parts[-1])
            parts = parts[:-1]
        for part in parts:
            bare, had = _bare(part)
            if had:
                memory.remember(memory.sent_with_block, _digest(bare), part)


def _restore_blocks(memory: Memory, messages: list[Any]) -> tuple[list[Any], int]:
    """Every earlier user turn with the run-state block it was sent with put back."""
    restored = 0
    out: list[Any] = []
    last_user = max(
        (i for i, m in enumerate(messages) if isinstance(m, dict) and m.get("role") == "user"),
        default=-1,
    )
    for index, message in enumerate(messages):
        if index >= last_user or not (isinstance(message, dict) and message.get("role") == "user"):
            out.append(message)
            continue
        parts = _parts(message)
        changed = False
        new_parts: list[Any] = []
        for part in parts:
            _bare_part, had = _bare(part)
            sent = None if had else memory.get(memory.sent_with_block, _digest(part))
            if sent is not None:
                new_parts.append(sent)
                changed = True
            else:
                new_parts.append(part)
        if (
            isinstance(message.get("content"), list)
            and new_parts
            and not _list_tail_block({"content": new_parts})
        ):
            tail = memory.get(memory.sent_with_block, _digest(("after", new_parts[-1])))
            if tail is not None:
                new_parts.append(tail)
                changed = True
        if changed:
            restored += 1
            out.append(_with_parts(message, new_parts))
        else:
            out.append(message)
    return out, restored


# ── Thinking blocks ───────────────────────────────────────────────────────


def _drop_stale_thinking(
    memory: Memory, payload: dict[str, Any], messages: list[Any]
) -> tuple[list[Any], int]:
    """``messages`` without the first stale thinking block and every one after it."""
    out: list[Any] = []
    dropping = False
    dropped = 0
    for message in messages:
        if not (isinstance(message, dict) and message.get("role") == "assistant"):
            out.append(message)
            continue
        content = message.get("content")
        blocks = content if isinstance(content, list) else []
        thinking = [b for b in blocks if isinstance(b, dict) and b.get("type") in _THINKING_KINDS]
        if thinking and not dropping:
            prefix = _prefix_digest(payload, out)
            for block in thinking:
                produced = memory.get(memory.produced_after, _signature_key(block))
                if produced is not None and produced != prefix:
                    dropping = True
                    break
        if dropping and thinking:
            kept = [
                b for b in blocks if not (isinstance(b, dict) and b.get("type") in _THINKING_KINDS)
            ]
            dropped += len(blocks) - len(kept)
            out.append({**message, "content": kept})
            continue
        out.append(message)
    return out, dropped


def prepared(payload: dict[str, Any], memory: Memory) -> dict[str, Any]:
    """The request ``payload`` with its history kept valid for the thinking blocks it replays.

    Run-state blocks put back where they were sent, stale thinking blocks
    left out from the first one on, the prefix of the request noted for the
    answer it brings back. Never raises: a request this cannot read is sent as
    it was built.
    """
    try:
        messages = payload.get("messages")
        if not isinstance(messages, list):
            return payload
        messages, restored = _restore_blocks(memory, messages)
        messages, dropped = _drop_stale_thinking(memory, payload, messages)
        _note_blocks_sent(memory, messages)
        if restored or dropped:
            payload = {**payload, "messages": messages}
        if restored:
            logger.debug(
                "anthropic provider: %d earlier user turn(s) sent with the run-state block they "
                "were first sent with, so the history only grows.",
                restored,
            )
        if dropped:
            logger.warning(
                "anthropic provider: the history before %d thinking block(s) changed since they "
                "were written, so they and every later one are left out of this request.",
                dropped,
            )
        last = messages[-1] if messages else None
        if isinstance(last, dict) and last.get("role") == "assistant":
            logger.warning(
                "anthropic provider: the request ends on an assistant turn, which a model that "
                "thinks by default refuses as a prefill."
            )
        pending = _PENDING.get()
        if pending is not None:
            pending[:] = [_prefix_digest(payload, messages)]
    except Exception as exc:  # noqa: BLE001 — the request is sent as it was built
        logger.debug("anthropic provider: history left as built (%s).", exc)
    return payload


def note_answer(result: Any, prefix: str, memory: Memory) -> None:
    """Remember each thinking block an answer carries with the prefix it was written after."""
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
                        memory.remember(memory.produced_after, key, prefix)
    except Exception as exc:  # noqa: BLE001 — an answer not remembered is one not checked
        logger.debug("anthropic provider: thinking blocks not noted (%s).", exc)


_PRESERVED_CLASSES: dict[type, type] = {}


def with_preserved_thinking(chat_class: Any) -> Any:
    """``chat_class`` whose every request keeps the thinking blocks it replays valid.

    Applied under the tool-reply completion (``tool_replies``), which only
    adds a reply a history lacks and adds the same one to the same history on
    every request: what is checked here is what is sent, less those replies.
    """
    if not isinstance(chat_class, type) or not hasattr(chat_class, "_get_request_payload"):
        return chat_class
    cached = _PRESERVED_CLASSES.get(chat_class)
    if cached is not None:
        return cached
    base: Any = chat_class

    def _get_request_payload(self: Any, input_: Any, *, stop: Any = None, **kwargs: Any) -> Any:
        payload = base._get_request_payload(self, input_, stop=stop, **kwargs)
        return prepared(payload, memory_of(self)) if isinstance(payload, dict) else payload

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
        },
    )
    preserved.__module__ = __name__
    preserved.__qualname__ = chat_class.__qualname__
    _PRESERVED_CLASSES[chat_class] = preserved
    return preserved
