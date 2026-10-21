"""The control tokens a local server would read out of a request's text, written out.

A llama.cpp-style server tokenizes the chat prompt with special-token parsing
on and no per-request switch to turn it off, so a tool answer or a sample
string carrying ``<|im_end|>\\n<|im_start|>system`` becomes real control
tokens: text the sample wrote ends a turn and opens another. A hand-kept list
of such tokens goes stale with every model family, so each span that has the
shape of one (``<name>``, ``[NAME]``) is put to the server's own tokenizer
(``POST /tokenize``): it is a control token only when it is one token.

Per server root there is a verdict for each span: ``True`` (a token), ``False``
(plain text) or none yet. A span is written out (its first character as an
escape) unless its verdict is ``False``, so an unknown span is written out
until a worker thread has asked. Nothing on a request's path waits for the
network: unknown spans are queued, the worker answers them, and the next
request finds the verdicts. The worker starts when the model is built, reads
``GET /props`` (the chat template and the begin and end tokens) and puts every
span in it to the tokenizer, so the verdicts a template needs are there before
the first request. A tokenizer that cannot be reached leaves spans unknown, and
so written out. The ``<|``/``|>`` bar of a chat template is written out whatever
the verdict. Hosted APIs are never touched.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections import OrderedDict
from typing import Any

from maljan.core.logger import logger

# Spans a chat template writes its control tokens as: ``<|im_start|>``,
# ``<think>``, ``<｜begin▁of▁sentence｜>`` and ``[INST]``, ``[/INST]``. Brackets
# are upper case only, so a citation such as ``[ev_0001]`` is never one.
_ANGLE_SPAN = re.compile(r"<[^\s<>]{1,64}>")
_BRACKET_SPAN = re.compile(r"\[/?[A-Z][A-Z0-9_]{1,31}\]")
_SPAN = re.compile(f"{_ANGLE_SPAN.pattern}|{_BRACKET_SPAN.pattern}")

# How long a read of ``/props`` is believed, and how long a failure is before it is asked again.
REREAD_SECONDS = 60.0
FAILURE_CACHE_SECONDS = 30.0
# The wall around one read of ``/props`` and its candidates.
READ_BUDGET_SECONDS = 8.0
REQUEST_TIMEOUT_SECONDS = 2.0
# Verdicts kept per server root, least recently used out first.
VERDICTS_KEPT = 8192
# Unknown spans one text may queue for the worker; the rest stay written out unasked.
QUEUED_PER_TEXT = 256


def _escape_of(char: str, *, json_string: bool) -> str:
    """``char`` as an escape: ``\\xNN`` where it fits, else the long forms.

    JSON has no ``\\x``, so text that is JSON takes ``\\uNNNN`` (a surrogate pair
    beyond the plane).
    """
    code = ord(char)
    if json_string:
        if code < 0x10000:
            return f"\\u{code:04x}"
        high, low = _surrogates(code)
        return f"\\u{high:04x}\\u{low:04x}"
    if code < 0x100:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}"


def _surrogates(code: int) -> tuple[int, int]:
    code -= 0x10000
    return 0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF)


def candidates_of(template: str, *extra: str) -> list[str]:
    """Every span in ``template`` (and ``extra``) that could be a control token, once each."""
    found: dict[str, None] = {}
    for text in (template, *extra):
        if isinstance(text, str):
            for span in _SPAN.findall(text):
                found.setdefault(span)
    for text in extra:
        if isinstance(text, str) and text:
            found.setdefault(text)
    return list(found)


class _Root:
    """What is known of one server and model: verdicts, the spans waiting, and the worker.

    A verdict is kept with the generation of the read it was made under. A
    ``False`` of an older generation is no longer believed (the server may
    serve another template now); a ``True`` stays, since writing out costs only
    readability.
    """

    def __init__(self, root: str, model: str) -> None:
        self.root = root
        self.model = model
        self.verdicts: OrderedDict[str, tuple[bool, int]] = OrderedDict()
        self.queue: dict[str, None] = {}
        self.headers: dict[str, str] = {}
        self.read_at: float | None = None
        self.read_ok = False
        self.fingerprint = ""
        self.generation = 0
        self.retry_after = 0.0
        self.worker: threading.Thread | None = None
        self.warned = False

    def note(self, span: str, verdict: bool) -> None:
        self.verdicts[span] = (verdict, self.generation)
        self.verdicts.move_to_end(span)
        while len(self.verdicts) > VERDICTS_KEPT:
            self.verdicts.popitem(last=False)

    def fresh(self, span: str) -> bool | None:
        """The verdict on ``span`` that is still believed, else ``None``."""
        held = self.verdicts.get(span)
        if held is None:
            return None
        verdict, generation = held
        if verdict is False and generation < self.generation:
            return None
        return verdict

    def due(self) -> bool:
        return self.read_at is None or time.monotonic() - self.read_at > (
            REREAD_SECONDS if self.read_ok else FAILURE_CACHE_SECONDS
        )


_lock = threading.Lock()
_roots: dict[tuple[str, str], _Root] = {}


def forget() -> None:
    """Drop everything known (a test, a restarted server)."""
    with _lock:
        _roots.clear()


def _key(root: str, model: str) -> tuple[str, str]:
    return str(root or "").rstrip("/"), str(model or "")


def _root_state(root: str, model: str) -> _Root:
    held = _roots.get((root, model))
    if held is None:
        held = _roots[(root, model)] = _Root(root, model)
    return held


def _tokenizes_to_one(http: Any, root: str, span: str, model: str = "") -> bool:
    body: dict[str, Any] = {"content": span}
    answer = http.post(f"{root}/tokenize", json=body, params={"model": model} if model else None)
    answer.raise_for_status()
    tokens = answer.json().get("tokens")
    return isinstance(tokens, list) and len(tokens) == 1


def _fingerprint(props: dict[str, Any], model: str) -> str:
    """What the server's template is, for noticing that it changed."""
    parts = [
        str(props.get("chat_template") or ""),
        str(props.get("bos_token") or ""),
        str(props.get("eos_token") or ""),
        str(props.get("model_path") or props.get("model_alias") or model),
    ]
    return hashlib.sha256("\0".join(parts).encode("utf-8", errors="replace")).hexdigest()


def _read_props(http: Any, state: _Root) -> None:
    """The template's own spans, each put to the tokenizer; seeds the verdicts."""
    import httpx

    root, model = state.root, state.model
    deadline = time.monotonic() + READ_BUDGET_SECONDS
    try:
        response = http.get(f"{root}/props", params={"model": model} if model else None)
        response.raise_for_status()
        props = response.json()
    except (httpx.HTTPError, ValueError):
        props = None
    with _lock:
        state.read_at = time.monotonic()
        state.read_ok = isinstance(props, dict) and bool(props.get("chat_template"))
        if isinstance(props, dict):
            state.generation += 1
            fingerprint = _fingerprint(props, model)
            if fingerprint != state.fingerprint:
                # Another template (or model) is served: nothing said of the
                # last one is believed.
                state.verdicts.clear()
                state.queue.clear()
                state.fingerprint = fingerprint
    if not isinstance(props, dict):
        return
    template = props.get("chat_template")
    edges = [props.get(k) for k in ("bos_token", "eos_token")]
    names = candidates_of(
        template if isinstance(template, str) else "", *[e for e in edges if isinstance(e, str)]
    )
    for name in names:
        if time.monotonic() >= deadline:
            return
        with _lock:
            if state.fresh(name) is not None:
                continue
        verdict = _tokenizes_to_one(http, root, name, model)
        with _lock:
            state.note(name, verdict)


def _work(state: _Root) -> None:
    """The worker: read ``/props`` when it is due, then answer every queued span."""
    import httpx

    try:
        with httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS, headers=state.headers) as http:
            with _lock:
                due = state.due()
            if due:
                _read_props(http, state)
            while True:
                with _lock:
                    if not state.queue:
                        state.worker = None
                        return
                    span = next(iter(state.queue))
                    del state.queue[span]
                    known = state.fresh(span) is not None
                if not known:
                    verdict = _tokenizes_to_one(http, state.root, span, state.model)
                    with _lock:
                        state.note(span, verdict)
    except Exception as exc:  # noqa: BLE001 - an unreachable server leaves spans unknown
        logger.debug("control markers not read from the server (%s).", type(exc).__name__)
        with _lock:
            state.queue.clear()
            state.worker = None
            state.retry_after = time.monotonic() + FAILURE_CACHE_SECONDS
            say = not state.warned
            state.warned = True
        if say:
            logger.warning(
                "The local server's control markers could not be read; every span shaped "
                "like one, and the chat-template bars, are written out of its requests."
            )


def _start(state: _Root) -> None:
    """Start the worker if none runs and the server is not resting after a failure."""
    if state.worker is not None or time.monotonic() < state.retry_after:
        return
    thread = threading.Thread(target=_work, args=(state,), name="special-tokens", daemon=True)
    state.worker = thread
    thread.start()


def prefetch(root: str, headers: dict[str, str] | None = None, model: str = "") -> None:
    """Start reading the server in the background, when it is not read or the read is old."""
    root, model = _key(root, model)
    if not root:
        return
    with _lock:
        state = _root_state(root, model)
        if headers:
            state.headers = dict(headers)
        if state.due():
            _start(state)


def settle(root: str, timeout: float = 30.0, model: str = "") -> None:
    """Wait for the worker of ``root`` to run dry (a test; a request never waits)."""
    with _lock:
        state = _roots.get(_key(root, model))
        thread = state.worker if state is not None else None
    if thread is not None:
        thread.join(timeout)


def _first_escaped(span: str, json_string: bool) -> str:
    return _escape_of(span[0], json_string=json_string) + span[1:]


def written_out(text: str, root: str = "", model: str = "", *, json_string: bool = False) -> str:
    """``text`` with every control token of the server at ``root`` written out.

    Every span shaped like a token is written out unless the server's tokenizer
    has said it is plain text; spans not yet asked are queued for the worker and
    stay written out meanwhile. The bar of every ``<|`` and ``|>`` is written out
    whatever was said. With no ``root`` nothing is known, so every span is.
    ``json_string`` writes the escape as JSON reads it (``\\u003c``).
    """
    if not text:
        return text
    root, model = _key(root, model)
    unknown: list[str] = []

    def one(match: re.Match[str]) -> str:
        span = match.group()
        with _lock:
            state = _roots.get((root, model))
            verdict = state.fresh(span) if state is not None else None
            if verdict is not None and state is not None:
                state.verdicts.move_to_end(span)
        if verdict is False:
            return span
        if verdict is None:
            unknown.append(span)
        return _first_escaped(span, json_string)

    text = _SPAN.sub(one, text)
    if unknown and root:
        _ask_later(root, model, unknown)
    from maljan.agents.tool_fence import template_tokens_written_out

    return template_tokens_written_out(text)


def _ask_later(root: str, model: str, spans: list[str]) -> None:
    """Queue spans for the worker, at most :data:`QUEUED_PER_TEXT` of them."""
    with _lock:
        state = _root_state(root, model)
        for span in list(dict.fromkeys(spans))[:QUEUED_PER_TEXT]:
            if len(state.queue) >= VERDICTS_KEPT:
                break
            if state.fresh(span) is None:
                state.queue.setdefault(span)
        if state.queue:
            _start(state)


def _written_out_of_value(value: Any, root: str, model: str) -> Any:
    """``value`` (parsed JSON) with every key and string written out, as it is rendered."""
    if isinstance(value, str):
        return written_out(value, root, model)
    if isinstance(value, list):
        return [_written_out_of_value(v, root, model) for v in value]
    if isinstance(value, dict):
        return {
            written_out(k, root, model) if isinstance(k, str) else k: _written_out_of_value(
                v, root, model
            )
            for k, v in value.items()
        }
    return value


def _written_out_of_arguments(arguments: str, root: str, model: str) -> str:
    """A tool call's arguments with the tokens written out of the *decoded* values.

    The server decodes the arguments and a chat template renders the values
    raw, so an escape that only JSON reads is undone before the tokenizer
    sees it. The decoded values are written out and the object written again,
    only when something changed: arguments holding none are left byte for byte.
    """
    try:
        decoded = json.loads(arguments)
    except ValueError:
        return written_out(arguments, root, model, json_string=True)
    changed = _written_out_of_value(decoded, root, model)
    if changed == decoded:
        return arguments
    return json.dumps(changed, ensure_ascii=False)


def written_out_of_payload(payload: dict[str, Any], root: str) -> int:
    """Write the tokens out of every message of a chat request, in place; how many changed.

    The verdicts are those of the server and the model the request names.
    """
    model = payload.get("model")
    model = model if isinstance(model, str) else ""
    prefetch(root, None, model)
    messages = payload.get("messages")
    if not isinstance(messages, list):
        return 0
    changed = 0
    for message in messages:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            new = written_out(content, root, model)
            if new != content:
                message["content"] = new
                changed += 1
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    new = written_out(part["text"], root, model)
                    if new != part["text"]:
                        part["text"] = new
                        changed += 1
        for call in message.get("tool_calls") or ():
            function = call.get("function") if isinstance(call, dict) else None
            if not isinstance(function, dict):
                continue
            args = function.get("arguments")
            if isinstance(args, str):
                new = _written_out_of_arguments(args, root, model)
                if new != args:
                    function["arguments"] = new
                    changed += 1
    return changed
