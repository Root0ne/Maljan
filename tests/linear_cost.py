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
* :func:`calls` counts the function calls (Python and built-in) a call makes.
  It does not move with load, but it cannot see work done inside one C
  operation, so it is an extra assertion, never the only one.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from typing import Any

__all__ = ["TIME_RATIO_LIMIT", "calls", "cpu_seconds"]

# Four times the input may take under eight times as long; a quadratic reader
# takes sixteen times as long.
TIME_RATIO_LIMIT = 8


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


def cpu_seconds(call: Callable[[], Any], repeats: int = 5, *, whole_process: bool = False) -> float:
    """The best of ``repeats`` CPU times of ``call``, in seconds.

    The calling thread's CPU time, or the whole process's with
    ``whole_process`` for work that crosses threads.
    """
    clock = time.process_time if whole_process else time.thread_time
    best = float("inf")
    for _ in range(repeats):
        started = clock()
        call()
        best = min(best, clock() - started)
    return best
