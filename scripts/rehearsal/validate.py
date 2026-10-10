"""What the real APIs refuse, refused here the same way, and the prompt cache they keep.

A rehearsal is worth something only if a request the paid API would refuse is
refused here too, with the API's own status and error body: a 400 hours into a
paid run is the most expensive failure there is. :func:`check_anthropic` and
:func:`check_openai` hold each request to the documented hard rules:

* the credential and version headers;
* a model's output cap and window (``scripts.rehearsal.models``);
* the sampling parameters a model refuses, the effort levels and thinking
  types its description says it takes, and a forced tool choice while it
  thinks;
* every ``tool_use`` answered by a ``tool_result`` in the next user turn (and
  every OpenAI ``tool_calls`` by its ``tool`` messages), and no result without
  its call;
* at most four ``cache_control`` breakpoints;
* no empty or whitespace-only text block, and no empty turn but a final
  assistant prefill;
* every ``thinking`` and ``redacted_thinking`` block sent back exactly as it
  was received — for a model whose blocks are bound to their prefix, bound to
  the system prompt, the tools and every earlier message too — unless the
  request asks the API to drop a mismatched block
  (``thinking.block_binding.prefix_mismatch_behavior: "drop_block"`` with the
  binding beta), in which case it is dropped.

:class:`Signer` issues the signatures the stub's own thinking blocks carry, and
:class:`PromptCache` reports cache reads and writes the way each API does:
Anthropic at the request's explicit breakpoints, with the write's lifetime;
OpenAI-compatible automatically, on a prefix sent before.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import dataclass, field
from typing import Any

from scripts.rehearsal import wire
from scripts.rehearsal.models import ModelFacts

BINDING_BETA = "thinking-binding-controls-2026-08-01"
MAX_BREAKPOINTS = 4
_SAMPLING = ("temperature", "top_p", "top_k")


@dataclass
class ApiError(Exception):
    """A refusal, as the API would answer it."""

    status: int
    message: str


def _without_markers(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _without_markers(v) for k, v in value.items() if k != "cache_control"}
    if isinstance(value, list):
        return [_without_markers(v) for v in value]
    return value


def _canonical(value: Any) -> bytes:
    text = json.dumps(_without_markers(value), sort_keys=True, ensure_ascii=False, default=str)
    return text.encode("utf-8")


class Signer:
    """Signs a thinking block to what it was written after, and checks one sent back."""

    def __init__(self) -> None:
        self._key = secrets.token_bytes(32)
        # The ids of the tool calls the stub wrote after a thinking block: a
        # turn carrying one must come back with its thinking block in front.
        self.thought_tool_ids: set[str] = set()

    def sign(self, prefix: Any, thinking: str) -> str:
        mac = hmac.new(self._key, _canonical(prefix) + b"\x00" + thinking.encode(), "sha256")
        return "stubsig-" + mac.hexdigest()

    def redacted(self, prefix: Any) -> str:
        return "stubredacted-" + self.sign(prefix, "")[8:]

    def valid(self, prefix: Any, block: dict[str, Any]) -> bool:
        if block.get("type") == "redacted_thinking":
            return hmac.compare_digest(str(block.get("data") or ""), self.redacted(prefix))
        return hmac.compare_digest(
            str(block.get("signature") or ""), self.sign(prefix, str(block.get("thinking") or ""))
        )


def anthropic_prefix(body: dict[str, Any], upto: int, facts: ModelFacts) -> Any:
    """What a thinking block written after ``messages[:upto]`` is bound to."""
    if not facts.prefix_bound:
        return {}
    return {
        "system": body.get("system"),
        "tools": body.get("tools"),
        "messages": (body.get("messages") or [])[:upto],
    }


def _blocks(message: dict[str, Any]) -> list[dict[str, Any]]:
    content = message.get("content")
    if isinstance(content, list):
        return [b for b in content if isinstance(b, dict)]
    return []


def _check_headers_anthropic(headers: dict[str, str], key: str | None) -> None:
    given = headers.get("x-api-key", "")
    if not given and not headers.get("authorization", "").lower().startswith("bearer "):
        raise ApiError(401, "x-api-key header is required")
    if key is not None and given != key:
        raise ApiError(401, "invalid x-api-key")
    if not headers.get("anthropic-version"):
        raise ApiError(400, "anthropic-version: header is required")


def check_credentials(api: str, request: wire.Request, key: str | None) -> None:
    """The credential check each API makes before it reads anything else."""
    if api == "anthropic":
        _check_headers_anthropic(request.headers, key)
        return
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer ") or not auth[7:].strip():
        raise ApiError(401, "You didn't provide an API key.")
    if key is not None and auth[7:].strip() != key:
        raise ApiError(401, "Incorrect API key provided.")


def _check_size(request: wire.Request, facts: ModelFacts) -> None:
    cap = request.max_tokens
    if cap is not None and cap > facts.max_output:
        raise ApiError(
            400,
            f"max_tokens: {cap} > {facts.max_output}, which is the maximum allowed number "
            f"of output tokens for {request.model}",
        )
    prompt = request.input_tokens
    if prompt > facts.window:
        raise ApiError(400, f"prompt is too long: {prompt} tokens > {facts.window} maximum")


def _check_tool_pairs_anthropic(messages: list[dict[str, Any]]) -> None:
    for index, message in enumerate(messages):
        if message.get("role") != "assistant":
            continue
        uses = [b.get("id") for b in _blocks(message) if b.get("type") == "tool_use"]
        if not uses:
            continue
        following = messages[index + 1] if index + 1 < len(messages) else None
        answered = (
            {b.get("tool_use_id") for b in _blocks(following) if b.get("type") == "tool_result"}
            if following is not None and following.get("role") == "user"
            else set()
        )
        missing = [u for u in uses if u not in answered]
        if missing and following is not None:
            raise ApiError(
                400,
                f"messages.{index + 1}: `tool_use` ids were found without `tool_result` blocks "
                f"immediately after: {', '.join(map(str, missing))}. Each `tool_use` block must "
                "have a corresponding `tool_result` block in the next message.",
            )
    for index, message in enumerate(messages):
        results = [b.get("tool_use_id") for b in _blocks(message) if b.get("type") == "tool_result"]
        if not results:
            continue
        before = messages[index - 1] if index > 0 else {}
        called = {b.get("id") for b in _blocks(before) if b.get("type") == "tool_use"}
        stray = [r for r in results if r not in called]
        if stray:
            raise ApiError(
                400,
                f"messages.{index}.content: unexpected `tool_use_id` found in `tool_result` "
                f"blocks: {', '.join(map(str, stray))}. Each `tool_result` block must have a "
                "corresponding `tool_use` block in the previous message.",
            )


def _check_text_blocks_anthropic(body: dict[str, Any]) -> None:
    """Every text block holds text that is not all whitespace, and no turn but a prefill is empty.

    The API's own refusals, word for word: an empty text block anywhere in the
    messages (the 400 a paid run met when a streamed answer's joined content
    went back with the empty string its first chunk carried), one holding only
    whitespace, the same in the system prompt, and a turn whose content is an
    empty string anywhere but the final assistant turn.
    """
    system = body.get("system")
    if isinstance(system, list):
        for block in system:
            if isinstance(block, dict) and block.get("type") == "text":
                _check_text("system", block.get("text"))
    messages = list(body.get("messages") or [])
    for index, message in enumerate(messages):
        content = message.get("content")
        if isinstance(content, str):
            final_prefill = index == len(messages) - 1 and message.get("role") == "assistant"
            if not content and not final_prefill:
                raise ApiError(
                    400,
                    f"messages.{index}: all messages must have non-empty content except for "
                    "the optional final assistant message",
                )
            if content:
                # A string is read as one text block.
                _check_text("messages", content)
            continue
        for block in _blocks(message):
            if block.get("type") == "text":
                _check_text("messages", block.get("text"))


def _check_text(where: str, text: Any) -> None:
    if not str(text or ""):
        raise ApiError(400, f"{where}: text content blocks must be non-empty")
    if not str(text).strip():
        raise ApiError(400, f"{where}: text content blocks must contain non-whitespace text")


def breakpoints(body: dict[str, Any]) -> list[tuple[str, int, int]]:
    """Every ``cache_control`` mark as (where, message index or -1, block index)."""
    found: list[tuple[str, int, int]] = []
    for n, tool in enumerate(body.get("tools") or []):
        if isinstance(tool, dict) and tool.get("cache_control"):
            found.append(("tools", -1, n))
    system = body.get("system")
    if isinstance(system, list):
        for n, block in enumerate(system):
            if isinstance(block, dict) and block.get("cache_control"):
                found.append(("system", -1, n))
    for index, message in enumerate(body.get("messages") or []):
        for n, block in enumerate(_blocks(message)):
            if block.get("cache_control"):
                found.append(("messages", index, n))
    if body.get("cache_control"):
        messages = body.get("messages") or []
        found.append(("messages", len(messages) - 1, -1))
    return found


def _check_sampling_and_effort(body: dict[str, Any], facts: ModelFacts) -> None:
    if facts.fixed_sampling:
        sent = [name for name in _SAMPLING if name in body and body[name] is not None]
        if sent:
            raise ApiError(
                400,
                f"{', '.join(sent)}: sampling parameters are not supported for {facts.id}; "
                "this model uses its own sampling",
            )
    effort = (body.get("output_config") or {}).get("effort")
    if effort and not facts.takes_effort(str(effort)):
        raise ApiError(400, f"output_config.effort: {effort!r} is not supported by {facts.id}")
    thinking = body.get("thinking") or {}
    kind = str(thinking.get("type") or "")
    if kind and facts.thinking_types and not facts.thinking_types.get(kind, False):
        raise ApiError(400, f"thinking.type: {kind!r} is not supported by {facts.id}")
    choice = body.get("tool_choice") or {}
    forced = isinstance(choice, dict) and choice.get("type") in ("any", "tool")
    if forced and thinking_on(body, facts):
        raise ApiError(400, "Thinking may not be enabled when tool_choice forces tool use.")


def thinking_on(body: dict[str, Any], facts: ModelFacts) -> bool:
    """Whether the request thinks: enabled, adaptive, or unset on a model thinking by default."""
    kind = str((body.get("thinking") or {}).get("type") or "")
    return kind in ("enabled", "adaptive") or (
        not kind and bool(facts.thinking_types.get("adaptive"))
    )


def check_anthropic(
    body: dict[str, Any],
    request: wire.Request,
    facts: ModelFacts,
    signer: Signer,
    *,
    api_key: str | None = None,
) -> list[int]:
    """Refuse ``body`` as the Messages API would; answer the indexes of blocks it dropped."""
    _check_headers_anthropic(request.headers, api_key)
    if not isinstance(request.max_tokens, int) or request.max_tokens < 1:
        raise ApiError(400, "max_tokens: Field required")
    _check_size(request, facts)
    marks = breakpoints(body)
    if len(marks) > MAX_BREAKPOINTS:
        raise ApiError(
            400,
            f"A maximum of {MAX_BREAKPOINTS} blocks with cache_control may be provided. "
            f"Found {len(marks)}.",
        )
    _check_sampling_and_effort(body, facts)
    _check_text_blocks_anthropic(body)
    messages = list(body.get("messages") or [])
    _check_tool_pairs_anthropic(messages)
    if thinking_on(body, facts):
        # With thinking off, an assistant turn without its thinking block is
        # what the API expects to be sent.
        _check_thinking_kept(messages, signer)
    binding = ((body.get("thinking") or {}).get("block_binding") or {}).get(
        "prefix_mismatch_behavior"
    )
    betas = ",".join(request.headers.get("anthropic-beta", "").split())
    may_drop = binding == "drop_block" and BINDING_BETA in betas
    dropped: list[int] = []
    for index, message in enumerate(messages):
        if message.get("role") != "assistant":
            continue
        for n, block in enumerate(_blocks(message)):
            if block.get("type") not in ("thinking", "redacted_thinking"):
                continue
            if signer.valid(anthropic_prefix(body, index, facts), block):
                continue
            if may_drop:
                dropped.append(index)
                continue
            raise ApiError(
                400, f"messages.{index}.content.{n}: Invalid `signature` in `thinking` block"
            )
    return dropped


def _check_thinking_kept(messages: list[dict[str, Any]], signer: Signer) -> None:
    """The assistant turn a tool loop continues starts with the thinking block it was written with.

    The rule the API holds a thinking model's tool loop to: the last assistant
    turn, whose tool calls the request answers, must lead with its thinking
    (or redacted thinking) block. Held only for a turn whose calls the stub
    itself wrote after a thinking block, so a model that answered without
    thinking is not refused.
    """
    for index in range(len(messages) - 1, -1, -1):
        message = messages[index]
        if message.get("role") != "assistant":
            continue
        blocks = _blocks(message)
        uses = {b.get("id") for b in blocks if b.get("type") == "tool_use"}
        if not uses & signer.thought_tool_ids:
            return
        first = str(blocks[0].get("type")) if blocks else "nothing"
        if first not in ("thinking", "redacted_thinking"):
            raise ApiError(
                400,
                f"messages.{index}.content.0.type: Expected `thinking` or `redacted_thinking`, "
                f"but found `{first}`. When `thinking` is enabled, a final `assistant` message "
                "must start with a thinking block (preceeding the lastmost set of `tool_use` and "
                "`tool_result` blocks). We recommend you include thinking blocks from previous "
                "turns.",
            )
        return


def check_openai(
    body: dict[str, Any],
    request: wire.Request,
    facts: ModelFacts,
    *,
    api_key: str | None = None,
) -> None:
    """Refuse ``body`` as an OpenAI-compatible chat completions API would."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer ") or not auth[7:].strip():
        raise ApiError(401, "You didn't provide an API key.")
    if api_key is not None and auth[7:].strip() != api_key:
        raise ApiError(401, "Incorrect API key provided.")
    cap = request.max_tokens
    if cap is not None and cap > facts.max_output:
        raise ApiError(
            400,
            f"Invalid max_tokens value, the valid range of max_tokens is [1, {facts.max_output}]",
        )
    if request.input_tokens > facts.window:
        raise ApiError(
            400,
            f"This model's maximum context length is {facts.window} tokens. However, you "
            f"requested {request.input_tokens} tokens.",
        )
    messages = list(body.get("messages") or [])
    for index, message in enumerate(messages):
        calls = [c.get("id") for c in message.get("tool_calls") or [] if isinstance(c, dict)]
        if message.get("role") == "assistant" and calls:
            answered = set()
            for later in messages[index + 1 :]:
                if later.get("role") != "tool":
                    break
                answered.add(later.get("tool_call_id"))
            missing = [c for c in calls if c not in answered]
            if missing:
                raise ApiError(
                    400,
                    "An assistant message with 'tool_calls' must be followed by tool messages "
                    "responding to each 'tool_call_id'. The following tool_call_ids did not "
                    f"have response messages: {', '.join(map(str, missing))}",
                )
        if message.get("role") == "tool":
            before = index - 1
            while before >= 0 and messages[before].get("role") == "tool":
                before -= 1
            previous = messages[before] if before >= 0 else {}
            ids = {c.get("id") for c in previous.get("tool_calls") or [] if isinstance(c, dict)}
            if message.get("tool_call_id") not in ids:
                raise ApiError(
                    400,
                    "Messages with role 'tool' must be a response to a preceeding message with "
                    "'tool_calls'.",
                )


@dataclass
class PromptCache:
    """The prefixes a provider has cached, and what each request reads and writes."""

    _held: dict[str, str] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def anthropic(
        self, body: dict[str, Any], output_tokens: int, reasoning: int, floor: int = 1024
    ) -> wire.Usage:
        """Reads at the longest cached breakpoint; writes up to the last breakpoint."""
        total = wire.tokens_of(json.dumps(_trimmed(body), ensure_ascii=False, sort_keys=True))
        read = written = 0
        lifetime = "5m"
        marks = breakpoints(body)
        prefixes = []
        for where, index, n in marks:
            prefix = _prefix_upto(body, where, index, n)
            prefixes.append((hashlib.sha256(_canonical(prefix)).hexdigest(), prefix))
            marker = _marker_at(body, where, index, n)
            if isinstance(marker, dict) and marker.get("ttl") == "1h":
                lifetime = "1h"
        with self._lock:
            for digest, prefix in reversed(prefixes):
                if digest in self._held:
                    read = _size(prefix)
                    break
            if prefixes:
                last = _size(prefixes[-1][1])
                if last >= floor and prefixes[-1][0] not in self._held:
                    written = max(0, last - read)
                for digest, prefix in prefixes:
                    if _size(prefix) >= floor:
                        self._held[digest] = lifetime
        read = min(read, total)
        written = min(written, total - read)
        return wire.Usage(
            input_tokens=total - read - written,
            output_tokens=output_tokens,
            cache_read=read,
            cache_write_5m=written if lifetime == "5m" else 0,
            cache_write_1h=written if lifetime == "1h" else 0,
            reasoning_tokens=reasoning,
        )

    def openai(
        self, body: dict[str, Any], output_tokens: int, reasoning: int, floor: int = 1024
    ) -> wire.Usage:
        """Automatic caching: the longest earlier prefix at a message boundary is read."""
        messages = list(body.get("messages") or [])
        head = {"tools": body.get("tools")}
        total = wire.tokens_of(json.dumps(_trimmed(body), ensure_ascii=False, sort_keys=True))
        read = 0
        digests = []
        for upto in range(1, len(messages) + 1):
            prefix = {**head, "messages": messages[:upto]}
            digests.append((hashlib.sha256(_canonical(prefix)).hexdigest(), prefix))
        with self._lock:
            for digest, prefix in reversed(digests[:-1] or digests):
                if digest in self._held:
                    read = min(total, _size(prefix))
                    break
            for digest, prefix in digests:
                if _size(prefix) >= floor:
                    self._held[digest] = "auto"
        return wire.Usage(
            input_tokens=total - read,
            output_tokens=output_tokens,
            cache_read=read,
            reasoning_tokens=reasoning,
        )


def _trimmed(body: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in body.items() if k in ("system", "messages", "tools")}


def _size(prefix: Any) -> int:
    return wire.tokens_of(
        json.dumps(_without_markers(prefix), ensure_ascii=False, sort_keys=True, default=str)
    )


def _marker_at(body: dict[str, Any], where: str, index: int, n: int) -> Any:
    if where == "tools":
        return (body.get("tools") or [])[n].get("cache_control")
    if where == "system":
        return body["system"][n].get("cache_control")
    if n < 0:
        return body.get("cache_control")
    return _blocks((body.get("messages") or [])[index])[n].get("cache_control")


def _prefix_upto(body: dict[str, Any], where: str, index: int, n: int) -> Any:
    tools = body.get("tools") or []
    if where == "tools":
        return {"tools": tools[: n + 1]}
    if where == "system":
        system = body.get("system") or []
        return {"tools": tools, "system": system[: n + 1]}
    messages = body.get("messages") or []
    head = messages[:index]
    last = dict(messages[index]) if index >= 0 else {}
    if n >= 0 and isinstance(last.get("content"), list):
        last["content"] = last["content"][: n + 1]
    return {"tools": tools, "system": body.get("system"), "messages": [*head, last]}
