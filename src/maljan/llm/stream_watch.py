"""A rule read over an answer while it streams, which may end the call.

A model that writes the same claims again and again runs to its output cap,
and the check that sees it (``pipeline.validation.claims_repeated``) used to
run only on the finished answer: one analyst's answer ran 838 s to a
32,768-token cap with 399 repeated claims before the check was reached, and a
hosted model with a cap twelve times that would be billed for every one of
them. The same rule is read here while the answer arrives.

The rule is not this module's. Whoever makes the call names it for the length
of the call (:func:`watching`): a function given the answer's text so far that
says why to end it, or ``None``. The streamed paths read each answer through
:func:`watched` or :func:`awatched`; once the rule says to end it, no further
piece is read, the stream is closed (which ends the request, and the server
stops generating), and the answer is what arrived up to there — nothing the
model wrote is removed. The caller's own check then reads that answer as it
reads any other.

A path that does not stream gets no watch and keeps the check on the finished
answer.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator, Callable, Iterator
from contextvars import ContextVar
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["StopRule", "awatched", "current_rule", "watched", "watching"]

# Given the answer's text so far, why the call ends there, or ``None``.
StopRule = Callable[[str], str | None]

_RULE: ContextVar[StopRule | None] = ContextVar("maljan_stream_stop_rule", default=None)


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
    """One answer's text as it arrives, and the rule read over it.

    The rule is read when a piece completes a line: a claim's block is made of
    lines, and the text up to a line's end is what a check on the finished
    answer would read had the answer ended there.
    """

    def __init__(self, rule: StopRule) -> None:
        self._rule = rule
        self._pieces: list[str] = []

    def ends_after(self, chunk: Any) -> str | None:
        piece = _piece_text(chunk)
        if not piece:
            return None
        self._pieces.append(piece)
        if "\n" not in piece:
            return None
        text = "".join(self._pieces)
        self._pieces = [text]
        try:
            return self._rule(text)
        except Exception as exc:  # noqa: BLE001 — a rule that fails never ends an answer
            logger.debug("stream watch: the rule could not be read (%s).", exc)
            return None


def _ended(why: str) -> None:
    logger.warning("The model's answer was ended while it streamed: %s.", why)


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
