"""A job that is cancelled stops: between nodes, before every model call, and in flight.

The benchmark cancelled a job at 11:34:13 and the worker issued the judge's
model call two seconds later, started the report stage eleven minutes after
that, held 16–19 connections open to the model server, ignored SIGTERM for
three minutes and ended only on SIGKILL. The cancel reached the pipeline task
as a ``CancelledError``, the bridge to the agent loop turned it into an
ordinary error (``AgentLoopCancelled``), the negotiation node caught that as a
failed mediation, and the graph went on to the judge. Nothing a thread was
blocked on — an analyst's loop on the agent loop, a model call in flight — was
ever told.

Three things close that, and this module holds what they share:

* ``Cancellation`` — one per job, on the container. Setting it stops every
  model call the job has in flight on the agent loop (each bridge registers
  its call with ``track``) and makes the next check raise.
* ``JobCancelled`` — what a check raises. A ``BaseException``, like
  ``asyncio.CancelledError``, so the broad ``except Exception`` a node or a
  salvage keeps for its own failures does not read a cancelled job as one of
  them and carry on.
* ``CancellationGate`` — a callback every LangChain model call in the job's
  context runs before it sends anything (``bound``), so no model is asked
  anything once the job is cancelled. The graph's nodes check the same flag on
  the way in (``stops_when_cancelled``, applied by ``pipeline.builder``).
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Callable, Iterator
from contextvars import ContextVar
from typing import Any

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.tracers.context import register_configure_hook

from maljan.core.logger import logger


class JobCancelled(BaseException):
    """The job was cancelled; the pipeline stops where this is raised."""


class Cancellation:
    """Whether one job has been cancelled, why, and where the pipeline first noticed.

    Thread-safe: it is set from the worker's event loop and read from the
    graph's node threads and the agent loop's thread.
    """

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self.reason = ""
        # The first place a check stopped the pipeline, for the record.
        self.stopped_at = ""
        self._in_flight: dict[int, Callable[[], None]] = {}
        self._next = 0

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self, reason: str) -> None:
        """Mark the job cancelled and stop every call it has in flight. Idempotent."""
        with self._lock:
            if self._event.is_set():
                return
            self.reason = str(reason or "the job was cancelled")
            self._event.set()
            stops = list(self._in_flight.values())
            self._in_flight.clear()
        logger.warning(
            "job cancelled (%s); stopping %d call(s) in flight.", self.reason, len(stops)
        )
        for stop in stops:
            try:
                stop()
            except Exception as exc:  # noqa: BLE001 — one call that will not stop does not keep the rest
                logger.debug("a call in flight could not be stopped (%s).", exc)

    def check(self, where: str) -> None:
        """Raise ``JobCancelled`` when the job has been cancelled; record where, the first time."""
        if not self._event.is_set():
            return
        with self._lock:
            if not self.stopped_at:
                self.stopped_at = str(where)
        raise JobCancelled(f"{self.reason}; stopped {where}")

    def track(self, stop: Callable[[], None]) -> Callable[[], None]:
        """Register a call in flight; ``stop`` ends it on cancel. Returns the unregister.

        A call registered after the job was cancelled is stopped at once.
        """
        with self._lock:
            if not self._event.is_set():
                self._next += 1
                token = self._next
                self._in_flight[token] = stop
                return lambda: self._forget(token)
        stop()
        return lambda: None

    def _forget(self, token: int) -> None:
        with self._lock:
            self._in_flight.pop(token, None)


_CURRENT: ContextVar[Cancellation | None] = ContextVar("maljan_cancellation", default=None)


def current() -> Cancellation | None:
    """The cancellation of the job this code runs for, or ``None`` outside one."""
    return _CURRENT.get()


def check(where: str) -> None:
    """``current().check(where)`` where there is a job; nothing outside one."""
    cancellation = _CURRENT.get()
    if cancellation is not None:
        cancellation.check(where)


class CancellationGate(BaseCallbackHandler):
    """Refuses every model call of a cancelled job before anything is sent.

    ``raise_error`` so the callback manager lets the exception through, and
    ``run_inline`` so an async call checks on its own thread rather than on an
    executor's. Model calls made on threads the job did not start — a model
    list's per-turn daemon thread — are checked by the call that started them.
    """

    raise_error = True
    run_inline = True

    def __init__(self, cancellation: Cancellation) -> None:
        self.cancellation = cancellation

    def on_chat_model_start(self, serialized: Any, messages: Any, **kwargs: Any) -> None:
        self.cancellation.check("before a model call")

    def on_llm_start(self, serialized: Any, prompts: Any, **kwargs: Any) -> None:
        self.cancellation.check("before a model call")


_GATE: ContextVar[CancellationGate | None] = ContextVar("maljan_cancellation_gate", default=None)
# Every callback manager LangChain configures in a context where the variable
# is set gets the gate, inherited by every child run — which is every model
# call the job makes, however deep in the graph, the agent loop or a thread
# started with the context copied.
register_configure_hook(_GATE, inheritable=True)


@contextlib.contextmanager
def bound(cancellation: Cancellation) -> Iterator[Cancellation]:
    """Run the block, and everything it starts with its context, under ``cancellation``."""
    token = _CURRENT.set(cancellation)
    gate = _GATE.set(CancellationGate(cancellation))
    try:
        yield cancellation
    finally:
        _GATE.reset(gate)
        _CURRENT.reset(token)


def stops_when_cancelled(name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a graph node so it does not start once its job is cancelled.

    The job is the one the graph runs for (``bound``); a graph run outside one
    — a test, a script — runs its nodes as before.
    """
    import asyncio
    import functools

    where = f"before node {name}"

    if asyncio.iscoroutinefunction(fn):

        @functools.wraps(fn)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            check(where)
            return await fn(*args, **kwargs)

        return async_wrapper

    @functools.wraps(fn)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        check(where)
        return fn(*args, **kwargs)

    return sync_wrapper
