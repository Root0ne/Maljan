"""``deadline_hit``'s deadline counts from the run's first model call, never from its start.

The sidecars and tools before the first call take most of the 12 s on an idle
machine and all of it on a loaded one, so a deadline counted from the start
fired before any call. ``_held_from_first_call`` waits for the stub's first
entry, then holds the run to its deadline from there: a run that ends first
answers as it ends, one that never calls is stopped and fails as no deadline
would, and a wait cancelled from outside takes the run with it.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, cast

import pytest
from scripts.rehearsal import inprocess
from scripts.rehearsal.checklist import RunRecord
from scripts.rehearsal.checklist import _check_job as check_job

# The bound on the wait for a first call in these tests, in seconds.
FIRST_CALL_WAIT = 0.3


class _Stub:
    """The stub's log as ``_held_from_first_call`` reads it."""

    def __init__(self) -> None:
        self.log: list[dict[str, Any]] = []

    def calls(self) -> list[dict[str, Any]]:
        return list(self.log)


class _Run:
    """A run that calls the model after ``first_call_after`` seconds, then waits.

    ``cancelled`` says whether the run was cancelled, ``wound_down`` whether
    it then finished the cleanup it takes a moment over.
    """

    def __init__(self, stub: _Stub, first_call_after: float | None) -> None:
        self.stub = stub
        self.first_call_after = first_call_after
        self.cancelled = False
        self.wound_down = False

    async def __call__(self) -> None:
        try:
            if self.first_call_after is not None:
                await asyncio.sleep(self.first_call_after)
                self.stub.log.append({"role": "analyst"})
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            self.cancelled = True
            await asyncio.sleep(0.05)  # closing what it holds
            self.wound_down = True
            raise


def _held(run: Any, stub: _Stub, deadline_s: float) -> Any:
    """``_held_from_first_call`` over the fake stub, which answers ``calls()`` as the stub does."""
    return inprocess._held_from_first_call(run, cast(Any, stub), deadline_s)


@pytest.fixture(autouse=True)
def _short_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(inprocess, "FIRST_CALL_WAIT_S", FIRST_CALL_WAIT)


def test_a_run_that_ends_before_any_call_answers_its_result() -> None:
    async def run() -> str:
        await asyncio.sleep(0.01)
        return "ended"

    assert asyncio.run(_held(run(), _Stub(), 12.0)) == "ended"


def test_a_run_that_fails_before_any_call_raises_its_own_error() -> None:
    class Broken(Exception):
        pass

    async def run() -> None:
        await asyncio.sleep(0.01)
        raise Broken("the sidecar did not start")

    with pytest.raises(Broken, match="the sidecar did not start"):
        asyncio.run(_held(run(), _Stub(), 12.0))


def test_a_run_that_never_calls_is_stopped_and_fails_as_no_deadline() -> None:
    stub = _Stub()
    run = _Run(stub, first_call_after=None)
    began = time.monotonic()
    with pytest.raises(inprocess.NoModelCall) as raised:
        asyncio.run(_held(run(), stub, 12.0))
    assert time.monotonic() - began < FIRST_CALL_WAIT + 5
    assert run.cancelled
    said = str(raised.value).lower()
    assert all(word not in said for word in ("deadline", "timeout", "timed out")), said
    # How rehearse records it, and the job check reads it as no deadline reached.
    record = RunRecord(
        scenario="deadline_hit",
        job_status="failed",
        job_error=f"{type(raised.value).__name__}: {raised.value}",
    )
    assert check_job(record).ok is False


def test_the_deadline_counts_from_the_first_call() -> None:
    stub = _Stub()
    run = _Run(stub, first_call_after=0.2)
    deadline = FIRST_CALL_WAIT
    began = time.monotonic()
    with pytest.raises(TimeoutError) as raised:
        asyncio.run(_held(run(), stub, deadline))
    took = time.monotonic() - began
    # The first call came at 0.2 s and the deadline ran from it, not from 0.
    assert took >= 0.2 + deadline
    assert run.cancelled
    assert inprocess.timeout_message(12.0, took, raised.value) == (
        "the run passed its 12.0s deadline"
    )


def test_a_wait_cancelled_from_outside_takes_the_run_with_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Cancelled long before the wait for a first call would end on its own.
    monkeypatch.setattr(inprocess, "FIRST_CALL_WAIT_S", 60.0)
    stub = _Stub()
    run = _Run(stub, first_call_after=None)

    async def main() -> None:
        waiting = asyncio.ensure_future(_held(run(), stub, 12.0))
        await asyncio.sleep(0.1)
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
        # Read at once, while the loop still runs (``asyncio.run`` cancels
        # whatever is left as it ends): the run was cancelled and had wound
        # down before the wait raised, so nothing is closed under it.
        assert run.cancelled, "the run kept going after its wait was cancelled"
        assert run.wound_down, "the wait raised before the run had wound down"

    asyncio.run(main())
