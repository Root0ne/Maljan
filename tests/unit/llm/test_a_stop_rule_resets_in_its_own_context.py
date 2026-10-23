"""A watch closed in another context ends quietly and leaks nothing into a later call."""

from __future__ import annotations

import asyncio
import contextvars
import gc
import logging
import sys

import pytest

from maljan.core.spend import carrying, current_admission
from maljan.llm.stream_watch import _RULE as _RULE_VAR
from maljan.llm.stream_watch import current_rule, ends_recorded, watching


def _rule() -> object:
    raise AssertionError("never made")


def test_closing_a_watch_in_another_context_raises_nothing_and_sets_nothing() -> None:
    unraisable: list[object] = []
    previous = sys.unraisablehook
    sys.unraisablehook = lambda args: unraisable.append(args)
    try:
        cm = watching(_rule)  # type: ignore[arg-type]
        contextvars.copy_context().run(cm.__enter__)
        # Closed here, not in the context that entered it.
        cm.__exit__(None, None, None)
        gc.collect()
    finally:
        sys.unraisablehook = previous
    assert not unraisable
    assert current_rule() is None


def test_each_scope_is_context_safe_and_resets_in_its_own_context() -> None:
    for make in (lambda: ends_recorded(), lambda: carrying(None)):
        cm = make()
        contextvars.copy_context().run(cm.__enter__)
        cm.__exit__(None, None, None)
    assert current_admission() is None
    with watching(_rule):  # type: ignore[arg-type]
        assert current_rule() is _rule
    assert current_rule() is None


def test_a_watch_inside_a_task_torn_down_by_the_loop_closing_resets_quietly(
    caplog: pytest.LogCaptureFixture,
) -> None:
    entered_in: list[contextvars.Context] = []
    unraisable: list[object] = []
    previous = sys.unraisablehook
    sys.unraisablehook = lambda args: unraisable.append(args)

    async def hold() -> None:
        with watching(_rule):  # type: ignore[arg-type]
            entered_in.append(contextvars.copy_context())
            await asyncio.sleep(3600)

    loop = asyncio.new_event_loop()
    try:
        task = loop.create_task(hold())
        loop.run_until_complete(asyncio.sleep(0))
        assert not task.done()
        with caplog.at_level(logging.WARNING, logger="maljan.core.context_reset"):
            # The coroutine is closed from the GC's context, not the task's.
            contextvars.copy_context().run(task.get_coro().close)  # type: ignore[union-attr]
    finally:
        loop.close()
        sys.unraisablehook = previous
        gc.collect()

    assert not unraisable
    # The value lived in the task's own context only, and this one is untouched.
    assert entered_in and entered_in[0].get(_RULE_VAR) is _rule
    assert current_rule() is None
    assert any("maljan_stream_stop_rule" in r.getMessage() for r in caplog.records)
