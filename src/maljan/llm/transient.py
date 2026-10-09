"""One retry policy for a provider saying "not now", on every model call.

A provider that answers 500, 503, 529 or 429, drops the connection, or ends a
stream with an ``overloaded_error`` event is describing its own state for a
second or two. The judge, the mediator and the reporting layer already asked
again (``retry_on_connection_error``); an analyst's own calls did not, and one
5xx on its first turn lost the whole analyst. This module is that one policy,
used in two places:

* :func:`retry_on_connection_error`, which wraps a whole call where the caller
  writes it (the judge, the mediator, the composer), and
* :func:`with_transient_retries`, which gives a provider's chat class the same
  retry on ``invoke`` and ``ainvoke``, so every call made through the model —
  an analyst's tool loop turns, its validation retry, its drops question, its
  revision — is asked again the same way.

The two never stack: a call already inside the policy (a judge call the
wrapper is retrying) is made once by the model, and the wrapper decides.

What is retried is narrow on purpose. A transport failure, the statuses a
provider uses to say "not now" (:data:`RETRYABLE_STATUSES`), and an error the
provider sent inside a stream that names its own overload or failure. A
refusal — 401, 402, 403, 404, 422 and the rest of the 400 family — is answered
once, because asking again cannot change it. A stall surfaces as
``TimeoutError`` (``ModelCallDeadline``) and is never retried here: that is
the anti-storm purpose ``max_retries=0`` on the provider SDKs exists for.

A retry repeats one model request and nothing else. No tool runs inside a
model request, so no tool call and no ledger entry is made twice.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import random
import time
from collections.abc import Awaitable, Callable
from typing import Any

from langchain_core.callbacks import BaseCallbackHandler

from maljan.core.logger import logger

# The statuses that mean "not now" rather than "no". A provider answering any
# of these is describing its own state, and a second attempt a couple of
# seconds later is the difference between a thin run and a lost one. Every
# other 4xx is a refusal about the request itself and is answered once. 529 is
# Anthropic's "overloaded".
RETRYABLE_STATUSES: frozenset[int] = frozenset({408, 409, 429, 500, 502, 503, 504, 529})

# The error types a provider names inside a stream (or a body) for its own
# state: overloaded, failing, rate limiting. Anthropic sends these as an
# ``error`` event after the stream began, on a response whose status was 200.
TRANSIENT_ERROR_TYPES: frozenset[str] = frozenset(
    {
        "overloaded_error",
        "api_error",
        "rate_limit_error",
        "timeout_error",
        "server_error",
        "internal_server_error",
        "service_unavailable",
        "service_unavailable_error",
    }
)

# The longest delay a provider's ``Retry-After`` may impose on us. Beyond this
# the caller's own budget is the shorter answer, so the backoff below is used
# instead and the run degrades rather than parking on one request.
MAX_RETRY_AFTER_SECONDS = 30

# How many times a call is made in all: the number the mediator's retry has
# always used.
DEFAULT_ATTEMPTS = 3

# Where an answer that needed a retry says so: one line per failed attempt.
# The token ledger reads it into the run summary.
RETRIES_KEY = "maljan_retries"

# What an error the provider sent inside a stream that had begun is called.
STREAM_ERROR_KIND = "error event in the stream"

# Set on an exception the policy gave up on after asking again: a model list
# reads it and moves on rather than waiting on the same model once more.
RETRIED_ATTRIBUTE = "maljan_retries_spent"

# The provider SDKs whose exceptions carry a status or a body this module reads.
_PROVIDER_PACKAGES = frozenset({"openai", "anthropic", "ollama"})

# Set while a call runs inside the policy, so a model call nested in it is made
# once and the policy around it decides.
_INSIDE: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "maljan_inside_transient_retry", default=False
)


def _from_a_provider(exc: BaseException) -> bool:
    """Whether ``exc`` is a provider SDK's error, or a class built on one.

    LangChain raises its own subclasses of the SDK's errors (a 503 from
    ``ChatOpenAI`` is ``langchain_openai``'s ``OpenAIAPIError``), so the whole
    class line is read, not the class's own module.
    """
    return any(package in _PROVIDER_PACKAGES for package, _name in _class_names(exc))


def _class_names(exc: BaseException) -> set[tuple[str, str]]:
    return {
        ((klass.__module__ or "").split(".", 1)[0], klass.__name__) for klass in type(exc).__mro__
    }


def _status(exc: BaseException) -> int | None:
    if not _from_a_provider(exc):
        return None
    for value in (
        getattr(exc, "status_code", None),
        getattr(getattr(exc, "response", None), "status_code", None),
    ):
        if isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599:
            return value
    return None


def _error_types(exc: BaseException) -> set[str]:
    """The error type and code a provider wrote in the body of ``exc``, lower-cased."""
    found: set[str] = set()
    body = getattr(exc, "body", None)
    layers = [body]
    if isinstance(body, dict):
        layers.append(body.get("error"))
    for layer in layers:
        if isinstance(layer, dict):
            for key in ("type", "code"):
                value = layer.get(key)
                if isinstance(value, str) and value:
                    found.add(value.strip().lower())
    for attribute in ("type", "code"):
        value = getattr(exc, attribute, None)
        if isinstance(value, str) and value:
            found.add(value.strip().lower())
    return found


def _transport_failure(exc: BaseException) -> bool:
    from maljan.llm.generation_rate import _transport_failure as transport_failure

    return transport_failure(exc)


def _a_stall(exc: BaseException) -> bool:
    """Whether ``exc`` is a request that went silent until a timeout ended it.

    ``TimeoutError`` (``ModelCallDeadline`` among them), and the SDKs' own
    timeout classes, which both SDKs derive from ``APIConnectionError`` and
    LangChain derives again (``langchain_openai``'s ``OpenAITimeoutError``):
    asking a stalled request again is the storm ``max_retries=0`` prevents.
    """
    if isinstance(exc, TimeoutError):
        return True
    names = _class_names(exc)
    if any((package, "APITimeoutError") in names for package in ("openai", "anthropic")):
        return True
    from maljan.llm.generation_rate import _transport_read_timeout

    return _transport_read_timeout(exc)


def transient_failure(exc: BaseException) -> str | None:
    """What transient provider failure ``exc`` is, in a few words, or ``None``.

    Never raises: an exception it cannot read is not transient, so it reaches
    the caller exactly as it did before.
    """
    try:
        if _a_stall(exc):
            return None
        # A server saying the request did not fit its window (some llama.cpp
        # builds answer it as 500): asking again cannot fit it, and the loop's
        # own window handling is what reads it.
        from maljan.llm.context_window import window_full_error

        if window_full_error(exc):
            return None
        names = _class_names(exc)
        if any((package, "APIConnectionError") in names for package in ("openai", "anthropic")):
            return "connection error"
        status = _status(exc)
        # The provider's own word on this answer, as the Anthropic SDK read it.
        told = should_retry_header(exc) if _from_a_provider(exc) else None
        if told is False:
            return None
        if status is not None and (status in RETRYABLE_STATUSES or told):
            return f"HTTP {status}"
        if status is not None and status >= 400:
            # A refusal about the request: asking again cannot change it.
            return None
        if _from_a_provider(exc) and _error_types(exc) & TRANSIENT_ERROR_TYPES:
            # A stream that began and then carried the provider's own error:
            # its status is the stream's own 200, and the body says what
            # happened.
            return STREAM_ERROR_KIND
        if status is not None:
            return None
        if _transport_failure(exc):
            return "connection error"
    except Exception:  # noqa: BLE001 — unreadable is not transient
        return None
    return None


def provider_fault(exc: BaseException) -> str:
    """One bounded line about a provider failure, safe to put in a log.

    The class and, for a status error, the status. Deliberately not the body:
    a provider that quotes the offending request back has quoted a credential
    back, and this line is written to a log file that outlives the run.
    """
    note_a_window_that_moved(exc)
    status = getattr(exc, "status_code", None)
    return f"{type(exc).__name__}" + (f" {status}" if status else "")


def note_a_window_that_moved(exc: BaseException) -> None:
    """Retire the learned windows when a server says a request did not fit.

    The learned window is believed for a while, so a server restarted with a
    smaller one is sized against the figure it used to serve — and the room
    check cannot catch that, because the room check measures against the
    believed window. The server itself says so the first time a request
    overflows, and that sentence is the only free correction there is.

    The message is read here and nowhere else it could leak: what is taken
    from it is a yes or a no, and nothing of it is logged or stored.
    """
    from maljan.llm.context_window import note_provider_error

    with contextlib.suppress(Exception):
        note_provider_error(str(exc))


def cause_chain(exc: BaseException, limit: int = 4) -> str:
    """``exc``'s causes, innermost last, as one line.

    ``str(APIConnectionError)`` is the words "Connection error." whatever
    produced it: a refused socket, a TLS failure, and an httpx pool being used
    from an event loop other than the one it was opened on all read the same.
    The last of those is a bug in this process rather than a blip on the wire,
    and the chain is where the difference is, so the chain is what gets logged.
    """
    parts: list[str] = []
    seen: set[int] = {id(exc)}
    cause: BaseException | None = exc.__cause__ or exc.__context__
    while cause is not None and len(parts) < limit and id(cause) not in seen:
        parts.append(repr(cause))
        seen.add(id(cause))
        cause = cause.__cause__ or cause.__context__
    return " <- ".join(parts) if parts else "no cause recorded"


def retry_after(exc: BaseException, default: int) -> int:
    """The provider's own ``Retry-After``, when it sent a usable one.

    Both forms RFC 9110 allows: delta-seconds, and an HTTP-date, which several
    hosted providers send on 429 and 503. Either way the answer is clamped —
    a provider asking for an hour is asking for longer than the caller has.
    """
    headers = getattr(getattr(exc, "response", None), "headers", None)
    raw = ""
    if headers is not None:
        with contextlib.suppress(Exception):
            raw = str(headers.get("retry-after") or "").strip()
    if not raw:
        return default
    try:
        seconds = int(float(raw))
    except (TypeError, ValueError):
        seconds = _seconds_until(raw)
    if 0 < seconds <= MAX_RETRY_AFTER_SECONDS:
        return seconds
    return default


def _seconds_until(http_date: str) -> int:
    """An HTTP-date as seconds from now, or ``0`` when it is not one."""
    from datetime import UTC, datetime
    from email.utils import parsedate_to_datetime

    try:
        when = parsedate_to_datetime(http_date)
    except (TypeError, ValueError):
        return 0
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return int((when - datetime.now(UTC)).total_seconds())


# The most a provider's own wait is lengthened by, as a share of it: enough
# that analysts told the same wait by one provider do not all ask again in the
# same instant, never so much that the wait is shorter than it asked.
RETRY_AFTER_JITTER = 0.1


def _header(exc: BaseException, name: str) -> str:
    headers = getattr(getattr(exc, "response", None), "headers", None)
    if headers is None:
        return ""
    with contextlib.suppress(Exception):
        return str(headers.get(name) or "").strip()
    return ""


def asked_wait(exc: BaseException) -> float | None:
    """The wait the provider asked for, in seconds, or ``None`` when it asked for none usable.

    ``retry-after-ms`` first, as the Anthropic SDK read it, then
    ``Retry-After`` (:func:`retry_after`). A wait past
    :data:`MAX_RETRY_AFTER_SECONDS` is no usable answer.
    """
    raw = _header(exc, "retry-after-ms")
    if raw:
        try:
            seconds = float(raw) / 1000.0
        except ValueError:
            seconds = 0.0
        if 0 < seconds <= MAX_RETRY_AFTER_SECONDS:
            return seconds
    asked = retry_after(exc, 0)
    return float(asked) if asked else None


def should_retry_header(exc: BaseException) -> bool | None:
    """The provider's ``x-should-retry`` answer, as the Anthropic SDK read it, or ``None``."""
    raw = _header(exc, "x-should-retry").lower()
    if raw == "true":
        return True
    if raw == "false":
        return False
    return None


def _wait_for(exc: BaseException, attempt: int) -> float:
    """The delay before the next attempt: the provider's own wait, else jittered backoff.

    The provider's wait is honoured and lengthened by up to
    :data:`RETRY_AFTER_JITTER` of itself, never shortened. The backoff is 1 s
    then 2 s, each drawn from half to one and a half times itself, so analysts
    that failed together do not ask again together.
    """
    asked = asked_wait(exc)
    if asked is not None:
        return asked * (1.0 + RETRY_AFTER_JITTER * random.random())  # noqa: S311 — spacing
    backoff = float(2**attempt)
    return backoff * (0.5 + random.random())  # noqa: S311 — spacing, not security


def _stamp(result: Any, retried: list[str]) -> Any:
    """``result`` with the failed attempts written on the answer that followed them."""
    if not retried:
        return result
    message = result.get("raw") if isinstance(result, dict) else result
    metadata = getattr(message, "response_metadata", None)
    if isinstance(metadata, dict):
        with contextlib.suppress(Exception):
            metadata[RETRIES_KEY] = [*list(metadata.get(RETRIES_KEY) or []), *retried]
    return result


def retries_of(message: Any) -> list[str]:
    """The failed attempts an answer says came before it, one line each."""
    metadata = getattr(message, "response_metadata", None)
    if not isinstance(metadata, dict):
        return []
    rows = metadata.get(RETRIES_KEY)
    return [str(row) for row in rows] if isinstance(rows, list) else []


class RetryRecorder(BaseCallbackHandler):
    """Where one model's failed attempts are written for the run: the job's token ledger.

    Attached to a model's callbacks where the job builds it
    (:func:`attach_retry_recorder`), so every retry of that model is a row the
    moment it is decided — whether the call is then answered, handed to the
    next model of a list, or lost. It takes no part in the call's own
    callbacks.
    """

    ignore_llm = True
    ignore_chat_model = True
    ignore_chain = True
    ignore_agent = True
    ignore_retriever = True
    ignore_retry = True
    ignore_custom_event = True

    def __init__(self, ledger: Any, agent: str, model: str) -> None:
        super().__init__()
        self.ledger = ledger
        self.agent = agent
        self.model = model

    def retried(self, reason: str) -> None:
        """One retry, as a row of the run summary's Provider Retries."""
        add = getattr(self.ledger, "add_retry", None)
        if callable(add):
            with contextlib.suppress(Exception):
                add(agent=self.agent, model=self.model, reason=reason)


# Set on an exception the policy gave up on, where no recorder took the rows:
# the retries made before it, one line each, for whoever records the loss.
RETRIES_ATTRIBUTE = "maljan_retries"


def recorder_of(model: Any) -> RetryRecorder | None:
    """The recorder attached to ``model``'s callbacks, or ``None``."""
    callbacks = getattr(model, "callbacks", None)
    if not isinstance(callbacks, list):
        return None
    return next((cb for cb in callbacks if isinstance(cb, RetryRecorder)), None)


def attach_retry_recorder(llm: Any, ledger: Any, agent: str) -> Any:
    """Add a :class:`RetryRecorder` for ``agent`` to ``llm``'s callbacks, once; returns ``llm``.

    A model list gets one per model, each filed under the model it records.
    Never raises: a model that takes no callbacks keeps its retries on the
    answers that follow them.
    """
    if ledger is None or llm is None:
        return llm
    from maljan.llm.generation_rate import _fallback_list, model_name_of

    models = _fallback_list(llm)
    if models is not None:
        for inner in models:
            attach_retry_recorder(inner, ledger, agent)
        return llm
    try:
        existing = list(getattr(llm, "callbacks", None) or [])
        if any(isinstance(cb, RetryRecorder) for cb in existing):
            return llm
        recorder = RetryRecorder(ledger, agent, model_name_of(llm))
        object.__setattr__(llm, "callbacks", [*existing, recorder])
    except Exception:  # noqa: BLE001 — recording must never break a model
        return llm
    return llm


# The recorders of the models a policy around them asked, set while it runs:
# the policy writes its retries through the model that failed.
_ASKED: contextvars.ContextVar[list[RetryRecorder] | None] = contextvars.ContextVar(
    "maljan_transient_asked", default=None
)


class _Attempts:
    """The bookkeeping one retried call shares between its sync and async forms."""

    def __init__(
        self, attempts: int, what: str, log: Any, recorder: RetryRecorder | None = None
    ) -> None:
        self.attempts = max(1, int(attempts))
        self.what = what
        self.emit = log or logger
        self.recorder = recorder
        self.asked: list[RetryRecorder] = []
        # The retries no recorder took, carried by the answer or the error.
        self.retried: list[str] = []

    def _record(self, line: str) -> None:
        recorder = self.recorder or (self.asked[-1] if self.asked else None)
        if recorder is not None:
            recorder.retried(line)
        else:
            self.retried.append(line)

    def failed(self, exc: BaseException, attempt: int) -> float | None:
        """The delay before the next attempt, or ``None`` when ``exc`` is to be raised."""
        kind = transient_failure(exc)
        if kind is None:
            return None
        # The cause chain tells a dropped socket from a pool used on the wrong
        # loop, and it is worth having for a transport failure. A status error
        # or a stream's error event has no such ambiguity, and its chain can
        # carry the provider's own body — where a credential quoted back would
        # be — so those lines say what happened and stop.
        cause_clause = ""
        cause_args: tuple[str, ...] = ()
        if kind == "connection error":
            cause_clause, cause_args = " (caused by %s)", (cause_chain(exc),)
        if attempt >= self.attempts - 1:
            if self.attempts > 1:
                with contextlib.suppress(Exception):
                    setattr(exc, RETRIED_ATTRIBUTE, True)
            if self.retried:
                with contextlib.suppress(Exception):
                    setattr(exc, RETRIES_ATTRIBUTE, list(self.retried))
            self.emit.error(
                "%s: %s after %d attempts: %r" + cause_clause,
                self.what,
                kind,
                self.attempts,
                provider_fault(exc),
                *cause_args,
            )
            return None
        wait = _wait_for(exc, attempt)
        self.emit.warning(
            "%s: %s (attempt %d/%d): %r" + cause_clause + " — retrying in %.1fs.",
            self.what,
            kind,
            attempt + 1,
            self.attempts,
            provider_fault(exc),
            *cause_args,
            wait,
        )
        self._record(f"{self.what}: {kind} (attempt {attempt + 1} of {self.attempts})")
        return wait


async def retry_on_connection_error(
    make_awaitable: Callable[[], Awaitable[Any]],
    *,
    attempts: int = DEFAULT_ATTEMPTS,
    what: str = "LLM call",
    log: Any = None,
    recorder: RetryRecorder | None = None,
) -> Any:
    """Await ``make_awaitable()``, asking again only after a transient provider failure.

    Backoff is 1 s then 2 s with jitter, or the provider's own wait
    (:func:`asked_wait`) lengthened a little. Takes a *factory* rather than an
    awaitable because a coroutine cannot be awaited twice. Each retry is a row
    of the run summary, written through ``recorder`` or the recorder of the
    model that failed; where neither exists the answer that followed carries
    them under :data:`RETRIES_KEY`, and an error given up on under
    :data:`RETRIES_ATTRIBUTE`.
    """
    state = _Attempts(attempts, what, log, recorder)
    token = _INSIDE.set(True)
    asked = _ASKED.set(state.asked)
    try:
        for attempt in range(state.attempts):
            try:
                return _stamp(await make_awaitable(), state.retried)
            except Exception as exc:
                wait = state.failed(exc, attempt)
                if wait is None:
                    raise
                await asyncio.sleep(wait)
    finally:
        _ASKED.reset(asked)
        _INSIDE.reset(token)
    raise AssertionError("unreachable")  # pragma: no cover


def retry_on_connection_error_sync(
    make_call: Callable[[], Any],
    *,
    attempts: int = DEFAULT_ATTEMPTS,
    what: str = "LLM call",
    log: Any = None,
    recorder: RetryRecorder | None = None,
) -> Any:
    """:func:`retry_on_connection_error` for a blocking call."""
    state = _Attempts(attempts, what, log, recorder)
    token = _INSIDE.set(True)
    asked = _ASKED.set(state.asked)
    try:
        for attempt in range(state.attempts):
            try:
                return _stamp(make_call(), state.retried)
            except Exception as exc:
                wait = state.failed(exc, attempt)
                if wait is None:
                    raise
                time.sleep(wait)
    finally:
        _ASKED.reset(asked)
        _INSIDE.reset(token)
    raise AssertionError("unreachable")  # pragma: no cover


def inside_a_retry() -> bool:
    """Whether the current call is already being retried by the policy around it."""
    return _INSIDE.get()


_RETRYING_CLASSES: dict[type, type] = {}


def _what(model: Any) -> str:
    name = getattr(model, "model_name", None) or getattr(model, "model", None) or ""
    return f"model call ({name})" if name else "model call"


def _failed_once(model: Any, exc: BaseException, prompt: Any) -> None:
    """One failed request of ``model``, named to a policy around it."""
    recorder = recorder_of(model)
    if recorder is None:
        return
    asked = _ASKED.get()
    if asked is not None and recorder not in asked:
        asked.append(recorder)


def with_transient_retries(chat_class: Any) -> Any:
    """``chat_class`` asking again, by :func:`retry_on_connection_error`, after a transient failure.

    ``invoke`` and ``ainvoke`` are what every caller reaches — langgraph's tool
    loop through the bound model, a structured-output chain, a model list
    asking one of its models — so the retry sits there and a whole request is
    made again, never a part of one. A call made inside the policy already is
    made once.
    Anything that is not a class is returned as it is.
    """
    if not isinstance(chat_class, type):
        return chat_class
    cached = _RETRYING_CLASSES.get(chat_class)
    if cached is not None:
        return cached
    base: Any = chat_class

    async def ainvoke(self: Any, input: Any, config: Any = None, **kwargs: Any) -> Any:  # noqa: A002
        async def _once() -> Any:
            try:
                return await base.ainvoke(self, input, config, **kwargs)
            except Exception as exc:
                _failed_once(self, exc, input)
                raise

        if _INSIDE.get():
            return await _once()
        return await retry_on_connection_error(_once, what=_what(self), recorder=recorder_of(self))

    def invoke(self: Any, input: Any, config: Any = None, **kwargs: Any) -> Any:  # noqa: A002
        def _once() -> Any:
            try:
                return base.invoke(self, input, config, **kwargs)
            except Exception as exc:
                _failed_once(self, exc, input)
                raise

        if _INSIDE.get():
            return _once()
        return retry_on_connection_error_sync(_once, what=_what(self), recorder=recorder_of(self))

    retrying = type(chat_class.__name__, (chat_class,), {"ainvoke": ainvoke, "invoke": invoke})
    # Named where it is made, so a log line or a repr says whose class it is.
    retrying.__module__ = __name__
    retrying.__qualname__ = chat_class.__qualname__
    _RETRYING_CLASSES[chat_class] = retrying
    return retrying


def retries_given_up(exc: BaseException | None) -> list[str]:
    """The retries an error given up on carries (:data:`RETRIES_ATTRIBUTE`), its causes read too."""
    seen: set[int] = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        rows = getattr(current, RETRIES_ATTRIBUTE, None)
        if isinstance(rows, list) and rows:
            return [str(row) for row in rows]
        current = current.__cause__ or current.__context__
    return []
