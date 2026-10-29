"""Cost measures for tests that hold a reader to linear cost, none of them a bare wall-clock bound.

A test that says "the cost grows with the input, not with its square" must not
fail on a slow or loaded machine, and must still fail on a quadratic reader.

* :func:`cpu_seconds` is the CPU time of a call (the calling thread's, or the
  process's where the work crosses threads), best of several runs. CPU time
  does not grow when the machine is busy with other work, and the work a C
  operation does (a list copy, a membership test on a list) is in it. Compare
  two of them by a size ratio only: four times the input must take less than
  eight times the CPU time (:data:`TIME_RATIO_LIMIT`). Size the inputs so the
  smaller run takes about 10 ms or more, or the clock's grain is the ratio.
* :func:`assert_scales` times a call at one size and at ``factor`` times that
  size by :func:`cpu_seconds` and holds the ratio under three times ``factor``
  (a quadratic reader takes ``factor`` times more); :data:`FLOOR_SECONDS` keeps
  the clock's grain out of the ratio. Where a test guards a wait rather than
  a cost, its bound is a multiple of the wait it injects, never seconds by hand.
* :func:`calls` counts the function calls (Python and built-in) a call makes.
  It does not move with load, but it cannot see work done inside one C
  operation, so it is an extra assertion, never the only one.
"""

from __future__ import annotations

import gc
import sys
import time
from collections.abc import Callable
from typing import Any

__all__ = [
    "FLOOR_SECONDS",
    "SCALING_SLACK",
    "TIME_RATIO_LIMIT",
    "assert_scales",
    "calls",
    "cpu_seconds",
]

# Four times the input may take under eight times as long; a quadratic reader
# takes sixteen times as long.
TIME_RATIO_LIMIT = 8

# A linear call on k times the input takes k times as long; up to this many
# times that is noise and cache effects, a quadratic call takes k times more.
SCALING_SLACK = 3.0

# The CPU clock's grain: a smaller measured time says nothing about the ratio.
FLOOR_SECONDS = 0.002


def calls(call: Callable[[], Any]) -> int:
    """How many function calls ``call`` makes: a count, not a time."""
    made = 0

    def _count(_frame: Any, event: str, _arg: Any) -> None:
        nonlocal made
        if event in ("call", "c_call"):
            made += 1

    previous = sys.getprofile()
    sys.setprofile(_count)
    try:
        call()
    finally:
        sys.setprofile(previous)
    return made


def cpu_seconds(
    call: Callable[[], Any],
    repeats: int = 5,
    *,
    whole_process: bool = False,
    clock: Callable[[], float] | None = None,
) -> float:
    """The best of ``repeats`` CPU times of ``call``, in seconds, with the collector off.

    The calling thread's CPU time, or the whole process's with
    ``whole_process`` for work that crosses threads. ``clock`` replaces both,
    for work whose time is a wait (``time.perf_counter``).
    """
    if clock is None:
        clock = time.process_time if whole_process else time.thread_time
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        best = float("inf")
        for _ in range(repeats):
            started = clock()
            call()
            best = min(best, clock() - started)
        return best
    finally:
        if was_enabled:
            gc.enable()


def assert_scales(
    build: Callable[[int], Any],
    small: int,
    call: Callable[[Any], Any] | None = None,
    *,
    factor: int = 8,
    repeats: int = 3,
) -> tuple[float, float]:
    """Assert ``factor`` times the input costs under ``SCALING_SLACK * factor`` times as much.

    ``build(size)`` makes the input, so the setup is outside the measure, and
    ``call(input)`` is what is timed; without ``call``, ``build(size)`` returns
    the zero-argument call itself. Size ``small`` so its call takes a few
    milliseconds.
    """

    def timed(size: int) -> Callable[[], Any]:
        made = build(size)
        return made if call is None else (lambda: call(made))

    first = cpu_seconds(timed(small), repeats)
    second = cpu_seconds(timed(small * factor), repeats)
    ratio = second / max(first, FLOOR_SECONDS)
    limit = SCALING_SLACK * factor
    assert ratio < limit, (
        f"{factor} times the input took {ratio:.1f} times as long "
        f"({first * 1000:.1f} ms to {second * 1000:.1f} ms), over {limit:.0f}"
    )
    return first, second
