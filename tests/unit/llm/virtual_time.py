"""An event loop whose clock moves only when every task is waiting on it.

A model call's deadline is tens of minutes on a slow local model. The tests
that hold a call to it run on this loop: when nothing is ready to run, the
loop's clock jumps to the next timer instead of sleeping until it, so half an
hour of a call passes in a few milliseconds and the arithmetic is exact.
Work handed to the default executor runs inline, so no thread finishes behind
the clock's back.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import selectors
from collections.abc import Coroutine
from typing import Any


class _JumpingSelector(selectors.SelectSelector):
    def __init__(self) -> None:
        super().__init__()
        self.now = 0.0

    def select(self, timeout: float | None = None) -> list[Any]:
        if timeout is None:
            raise RuntimeError("nothing is scheduled: the call under test would wait forever")
        if timeout > 0:
            self.now += timeout
        return super().select(0)


class _InlineExecutor(concurrent.futures.ThreadPoolExecutor):
    def submit(self, fn: Any, /, *args: Any, **kwargs: Any) -> concurrent.futures.Future[Any]:
        future: concurrent.futures.Future[Any] = concurrent.futures.Future()
        try:
            future.set_result(fn(*args, **kwargs))
        except BaseException as exc:  # noqa: BLE001 — handed back through the future
            future.set_exception(exc)
        return future


class VirtualTimeLoop(asyncio.SelectorEventLoop):
    def __init__(self) -> None:
        self._jumping = _JumpingSelector()
        super().__init__(self._jumping)
        self.set_default_executor(_InlineExecutor())

    def time(self) -> float:
        return self._jumping.now


def run(main: Coroutine[Any, Any, Any]) -> tuple[Any, float]:
    """``main``'s result, or its exception raised, and the virtual seconds it took."""
    loop = VirtualTimeLoop()
    try:
        started = loop.time()
        task = loop.create_task(main)
        try:
            loop.run_until_complete(task)
        finally:
            elapsed = loop.time() - started
            loop.run_until_complete(loop.shutdown_asyncgens())
        return task.result(), elapsed
    finally:
        loop.close()


def run_expecting(error: type[BaseException], main: Coroutine[Any, Any, Any]) -> tuple[Any, float]:
    """The ``error`` that ``main`` raised, and the virtual seconds it took."""
    loop = VirtualTimeLoop()
    try:
        started = loop.time()
        task = loop.create_task(main)
        try:
            loop.run_until_complete(task)
        except error as exc:
            return exc, loop.time() - started
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
        raise AssertionError(f"expected {error.__name__}, the call returned {task.result()!r}")
    finally:
        loop.close()
