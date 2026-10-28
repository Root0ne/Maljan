"""Two agents asking each other are refused at once, whether or not their callers have a clock.

Each holds its own lock through its own stage run, so each ask waits for a
lock only the other's end lets go. Only a caller with no time limit used to
look at who the busy callee was waiting for; two callers with a clock each
waited out all they could spare, about 885 s, before either was told.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from maljan.agents.delegation import _held_unless_waiting_on_each_other


class _Agent:
    def __init__(self, name: str) -> None:
        self.name = name
        self.delegation_lock = threading.Lock()


def _ask_each_other(wait: float | None) -> tuple[Any, float]:
    """The first answer either ask gets, and how long it took to come."""
    first, second = _Agent("a"), _Agent("b")
    # Each is busy with its own stage run.
    first.delegation_lock.acquire()
    second.delegation_lock.acquire()
    answers: list[Any] = []
    heard = threading.Event()
    started = time.monotonic()

    def _ask(caller: _Agent, callee: _Agent) -> None:
        answers.append(
            _held_unless_waiting_on_each_other(callee.delegation_lock, wait, caller, callee)
        )
        heard.set()

    threads = [
        threading.Thread(target=_ask, args=(first, second), daemon=True),
        threading.Thread(target=_ask, args=(second, first), daemon=True),
    ]
    for thread in threads:
        thread.start()
    heard.wait(timeout=20)
    took = time.monotonic() - started
    answer = answers[0] if answers else "nothing heard"
    # The refused side goes on with its stage run and lets its lock go.
    first.delegation_lock.release()
    second.delegation_lock.release()
    for thread in threads:
        thread.join(timeout=20)
    return answer, took


def test_callers_with_a_clock_are_told_they_wait_on_each_other() -> None:
    answer, took = _ask_each_other(wait=600.0)
    assert answer is None, "one side hears that no wait ends it"
    assert took < 10.0, "told within a poll or two, not at the end of the clock"


def test_callers_with_no_time_limit_are_told_as_before() -> None:
    answer, took = _ask_each_other(wait=None)
    assert answer is None
    assert took < 10.0


def test_a_clocked_wait_for_a_merely_busy_callee_still_ends_at_its_bound() -> None:
    caller, callee = _Agent("a"), _Agent("b")
    callee.delegation_lock.acquire()
    started = time.monotonic()
    assert _held_unless_waiting_on_each_other(callee.delegation_lock, 0.2, caller, callee) is False
    assert time.monotonic() - started < 30.0


def test_a_callee_that_frees_up_is_taken() -> None:
    caller, callee = _Agent("a"), _Agent("b")
    callee.delegation_lock.acquire()
    threading.Timer(0.2, callee.delegation_lock.release).start()
    assert _held_unless_waiting_on_each_other(callee.delegation_lock, 30.0, caller, callee) is True


def test_an_agent_waiting_on_two_threads_keeps_each_wait() -> None:
    """The first wait to end does not take the other thread's entry with it."""
    from maljan.agents.delegation import _WAITING_FOR, _waits_on

    caller, first, second = _Agent("a"), _Agent("b"), _Agent("c")
    first.delegation_lock.acquire()
    second.delegation_lock.acquire()
    ended = threading.Event()

    def _short() -> None:
        _held_unless_waiting_on_each_other(first.delegation_lock, 0.2, caller, first)
        ended.set()

    def _long() -> None:
        _held_unless_waiting_on_each_other(second.delegation_lock, 30.0, caller, second)

    long_wait = threading.Thread(target=_long, daemon=True)
    long_wait.start()
    threading.Thread(target=_short, daemon=True).start()
    assert ended.wait(timeout=10)
    assert _waits_on(caller, second), "the longer wait is still registered"
    second.delegation_lock.release()
    long_wait.join(timeout=10)
    assert id(caller) not in _WAITING_FOR
