"""A rule read over an answer while it streams, which may end the call.

A model that writes the same claims again and again runs to its output cap,
and the check that sees it (``pipeline.validation.claims_repeated``) used to
run only on the finished answer: one analyst's answer ran 838 s to a
32,768-token cap with 399 repeated claims before the check was reached, and a
hosted model with a cap twelve times that would be billed for every one of
them. The same rule is read here while the answer arrives.

The rule is not this module's. Whoever makes the call names it for the length
of the call (:func:`watching`): a function that makes a :class:`Watcher` for
one answer, which is handed each piece of the answer's text as it arrives and
says why to end it, or ``None``. The streamed paths read each answer through
:func:`watched` or :func:`awatched`; once the watcher says to end it, no
further piece is read, the stream is closed (which ends the request, and the
server stops generating), and the answer is what arrived up to there —
nothing the model wrote is removed. The call's maker learns that it was ended,
and why, inside :func:`ends_recorded`; the answer carries it under
:data:`ENDED_KEY`. The caller's own check then reads that answer as it reads
any other.

A path that does not stream gets no watch and keeps the check on the finished
answer.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator, Callable, Iterator
from contextvars import ContextVar
from typing import Any, Protocol

logger = logging.getLogger(__name__)

__all__ = [
    "ENDED_KEY",
    "ESTIMATED_USAGE_KEY",
    "ESTIMATED_USAGE_SOURCE",
    "estimated_usage",
    "StopRule",
    "Watcher",
    "awatched",
    "current_rule",
    "ended_while_streaming",
    "ends_recorded",
    "mark_ended",
    "text_rule",
    "watched",
    "watching",
]

# Where an answer the watch ended says so, and why, in its ``response_metadata``.
ENDED_KEY = "ended_while_streaming"

# Where an ended answer that reported no usage carries a stated estimate of it,
# for the spend ceiling only (``openai_provider._estimate_usage``), and what the
# estimate says it is.
ESTIMATED_USAGE_KEY = "estimated_usage"
ESTIMATED_USAGE_SOURCE = "estimated: the stream was ended before the provider reported usage"

# The characters ``str.splitlines`` ends a line at.
_LINE_ENDS = frozenset("\n\r\x0b\x0c\x1c\x1d\x1e\x85  ")


class Watcher(Protocol):
    """One answer's reader: handed each piece of its text, says why to end it, or ``None``."""

    def feed(self, piece: str) -> str | None: ...


# Makes the watcher of one answer.
StopRule = Callable[[], Watcher]

_RULE: ContextVar[StopRule | None] = ContextVar("maljan_stream_stop_rule", default=None)
# The records of the calls being made, innermost last: each is told when the
# watch ends an answer inside it.
_ENDED: ContextVar[tuple[list[str], ...]] = ContextVar("maljan_stream_ended", default=())


def current_rule() -> StopRule | None:
    """The rule the running code's model calls are read under, or ``None``."""
    return _RULE.get()


@contextlib.contextmanager
def watching(rule: StopRule | None) -> Iterator[None]:
    """Read every streamed answer made inside this block under ``rule``; ``None`` reads none."""
    token = _RULE.set(rule)
    try:
        yield
    finally:
        _RULE.reset(token)


@contextlib.contextmanager
def ends_recorded() -> Iterator[list[str]]:
    """A list that receives why, each time the watch ends an answer inside this block."""
    found: list[str] = []
    token = _ENDED.set((*_ENDED.get(), found))
    try:
        yield found
    finally:
        _ENDED.reset(token)


def text_rule(check: Callable[[str], str | None]) -> StopRule:
    """A rule over the whole text so far, read at each line's end.

    Each read joins the whole answer again, so its cost grows with the square
    of the answer; for a short answer or a test. A rule read over long answers
    keeps its own state (``agents.repeat_watch``).
    """

    class _Whole:
        def __init__(self) -> None:
            self._pieces: list[str] = []

        def feed(self, piece: str) -> str | None:
            self._pieces.append(piece)
            if not any(ch in _LINE_ENDS for ch in piece):
                return None
            return check("".join(self._pieces))

    return _Whole


def _piece_text(chunk: Any) -> str:
    """The answer text one streamed chunk carries, reasoning aside."""
    message = getattr(chunk, "message", chunk)
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            str(part.get("text") or "")
            if isinstance(part, dict) and part.get("type") == "text"
            else (part if isinstance(part, str) else "")
            for part in content
        )
    return ""


class _Reader:
    """One answer's watcher, handed the text of each chunk; a watcher that fails ends nothing."""

    def __init__(self, rule: StopRule) -> None:
        try:
            self._watcher: Watcher | None = rule()
        except Exception as exc:  # noqa: BLE001 — a rule that fails never ends an answer
            logger.debug("stream watch: the rule could not start (%s).", exc)
            self._watcher = None

    def ends_after(self, chunk: Any) -> str | None:
        if self._watcher is None:
            return None
        piece = _piece_text(chunk)
        if not piece:
            return None
        try:
            return self._watcher.feed(piece)
        except Exception as exc:  # noqa: BLE001 — a rule that fails never ends an answer
            logger.debug("stream watch: the rule could not be read (%s).", exc)
            self._watcher = None
            return None


def _ended(why: str) -> None:
    logger.warning("The model's answer was ended while it streamed: %s.", why)
    for found in _ENDED.get():
        found.append(why)


def watched[T](chunks: Iterator[T]) -> Iterator[T]:
    """``chunks``, ending after the piece on which the current rule says to end.

    The source is closed when it ends early, which ends the request.
    """
    rule = current_rule()
    if rule is None:
        yield from chunks
        return
    reader = _Reader(rule)
    try:
        for chunk in chunks:
            yield chunk
            why = reader.ends_after(chunk)
            if why is not None:
                _ended(why)
                return
    finally:
        close = getattr(chunks, "close", None)
        if callable(close):
            close()


async def awatched[T](chunks: AsyncIterator[T]) -> AsyncIterator[T]:
    """``chunks`` read asynchronously, ending as :func:`watched` does."""
    rule = current_rule()
    reader = _Reader(rule) if rule is not None else None
    try:
        async for chunk in chunks:
            yield chunk
            why = reader.ends_after(chunk) if reader is not None else None
            if why is not None:
                _ended(why)
                return
    finally:
        close = getattr(chunks, "aclose", None)
        if callable(close):
            await close()


def mark_ended(result: Any, why: str) -> Any:
    """``result`` with each answer it holds saying that the watch ended it, and why."""
    for generation in getattr(result, "generations", None) or []:
        metadata = getattr(getattr(generation, "message", None), "response_metadata", None)
        if isinstance(metadata, dict):
            metadata[ENDED_KEY] = why
    return result


def estimated_usage(response: Any) -> dict[str, Any] | None:
    """The stated estimate of an ended answer's usage, or ``None`` where it carries none."""
    metadata = getattr(response, "response_metadata", None)
    found = metadata.get(ESTIMATED_USAGE_KEY) if isinstance(metadata, dict) else None
    if not isinstance(found, dict):
        return None
    try:
        return {
            "input_tokens": max(0, int(found.get("input_tokens") or 0)),
            "output_tokens": max(0, int(found.get("output_tokens") or 0)),
            "source": str(found.get("source") or ESTIMATED_USAGE_SOURCE),
        }
    except (TypeError, ValueError):
        return None


def ended_while_streaming(response: Any) -> str | None:
    """Why the watch ended ``response`` while it streamed, or ``None`` when it did not."""
    metadata = getattr(response, "response_metadata", None)
    why = metadata.get(ENDED_KEY) if isinstance(metadata, dict) else None
    return why if isinstance(why, str) and why else None
