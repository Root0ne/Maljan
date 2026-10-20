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
# Set by ``kill_all``: the server is ending, and a child registered after it
# is killed as it registers. Read and written under ``_lock``.
_closing = False


def closing() -> bool:
    """Whether ``kill_all`` has run: no new child should be started."""
    with _lock:
        return _closing


def reopen() -> None:
    """Clear what ``kill_all`` set. For tests, which end no server."""
    global _closing
    with _lock:
        _closing = False


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
    with _lock:
        late = _closing
        if not late and run is not None:
            _children.setdefault(run, []).append(kill)
    if late:
        # Started after the server began ending: killed now, so it cannot
        # outlive the server ``kill_all`` already swept.
        try:
            kill()
        except Exception as exc:  # noqa: BLE001 — a child already gone is not an error
            logger.debug("a child started while the server ended could not be killed (%s).", exc)


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


def kill_all() -> int:
    """Kill every child every run started; how many were asked to die.

    For the server's end: a child runs in a session of its own and has no
    wall clock of its own, so one the server leaves behind outlives it.
    """
    # Bounded, so a signal that arrives while this thread holds the lock
    # still ends the server rather than waiting on itself.
    global _closing
    held = _lock.acquire(timeout=1.0)
    try:
        _closing = True
        kills = [each for run in list(_children) for each in _children.pop(run, [])]
    finally:
        if held:
            _lock.release()
    for each in kills:
        try:
            each()
        except Exception as exc:  # noqa: BLE001 — a child already gone is not an error
            logger.debug("a child could not be killed at exit (%s).", exc)
    return len(kills)


def kill_all_on_exit() -> None:
    """Kill every child when this process ends on SIGTERM, SIGHUP or SIGINT.

    The signal's own action follows the kill, so the process still ends the
    way the signal says. Installed from the main thread, where Python runs
    signal handlers.
    """

    def _on_signal(number: int, _frame: Any) -> None:
        kill_all()
        signal.signal(number, signal.SIG_DFL)
        os.kill(os.getpid(), number)

    for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(number, _on_signal)


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
