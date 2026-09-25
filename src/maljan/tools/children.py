"""The child processes a long-running analysis tool starts, and one run of each at a time.

capa and FLOSS run their work in a child process — vivisect has no point at
which it can be interrupted from inside — and on the analysis server neither
has a wall clock of its own. So the server has to be able to stop them from
outside: when the caller gives up or its job ends, the MCP request is
cancelled, and the child of that call is killed with its whole process group.

A child registers itself under the run it belongs to (:func:`running_as`, set
by the server on the thread that does the work) and is killed by
:func:`kill`. :func:`joined` makes a second call of the same tool on the same
sample wait for the run already going instead of starting another child: a
model that retries a slow call is otherwise how two vivisect workspaces of one
large sample come to be held at once.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import threading
from collections.abc import Callable, Hashable
from typing import Any

from maljan.core.logger import logger

_local = threading.local()
_lock = threading.Lock()
# The kill of each child, by the run it belongs to.
_children: dict[Hashable, list[Callable[[], None]]] = {}


def current_run() -> Hashable | None:
    """The run the calling thread's work belongs to, or ``None`` outside one."""
    return getattr(_local, "run", None)


@contextlib.contextmanager
def running_as(run: Hashable) -> Any:
    """Mark the calling thread's work as belonging to ``run`` while it lasts."""
    before = getattr(_local, "run", None)
    _local.run = run
    try:
        yield
    finally:
        _local.run = before
        with _lock:
            _children.pop(run, None)


def register(kill: Callable[[], None]) -> None:
    """Record how to kill a child the calling thread's run just started."""
    run = current_run()
    if run is None:
        return
    with _lock:
        _children.setdefault(run, []).append(kill)


def kill(run: Hashable) -> int:
    """Kill every child ``run`` started; how many were asked to die."""
    with _lock:
        kills = _children.pop(run, [])
    for each in kills:
        try:
            each()
        except Exception as exc:  # noqa: BLE001 — a child already gone is not an error
            logger.debug("a child of %r could not be killed (%s).", run, exc)
    return len(kills)


def kill_process_group(pid: int) -> None:
    """Kill the process group ``pid`` leads, or the process alone where it leads none.

    Never this process or its own group, and never a pid that names no child
    (0 and 1 are the caller's group and init): a mistaken pid here would
    signal the server itself.
    """
    pid = int(pid or 0)
    if pid <= 1 or pid == os.getpid() or pid == os.getpgrp():
        logger.debug("refused to kill pid %d: it is not a child of this run.", pid)
        return
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.kill(pid, signal.SIGKILL)


class _Run:
    __slots__ = ("task", "waiters")

    def __init__(self, task: asyncio.Future[Any]) -> None:
        self.task = task
        self.waiters = 0


_runs: dict[Hashable, _Run] = {}


async def joined(run: Hashable, work: Callable[[], Any]) -> Any:
    """``work()`` on a thread, as ``run``; a second caller of the same run waits for the first.

    When every caller waiting on a run has gone — cancelled with its request —
    the run's children are killed and the run is forgotten. A caller that
    stays gets the one answer.
    """
    loop = asyncio.get_running_loop()
    current = _runs.get(run)
    if current is None or current.task.done():

        def _in_thread() -> Any:
            with running_as(run):
                return work()

        current = _Run(loop.run_in_executor(None, _in_thread))
        _runs[run] = current
    current.waiters += 1
    try:
        return await asyncio.shield(current.task)
    except asyncio.CancelledError:
        current.waiters -= 1
        if current.waiters <= 0 and not current.task.done():
            killed = kill(run)
            logger.warning(
                "%r was cancelled by every caller waiting on it; %d child process(es) killed.",
                run,
                killed,
            )
            if _runs.get(run) is current:
                _runs.pop(run, None)
        raise
    finally:
        if current.task.done() and _runs.get(run) is current:
            _runs.pop(run, None)
