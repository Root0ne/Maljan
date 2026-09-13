"""No pipeline node may do minutes of synchronous work on the worker's loop (OBS 4).

The live run of 2026-09-07 logged its 15-second "Pipeline heartbeat" and then
went quiet for 209 seconds during the judge/report phase. The job completed, so
nothing failed — the worker's event loop was simply not running. The py-spy
dump taken during the same window caught the main thread mid-callback in
`sigma_layer.from_rules_dir`, 2902 rules into a `read_text`, reached from a
rule scan the judge node ran inline. That scan is a tool an agent calls now and
runs in the sidecar, so the judge node no longer builds a rule corpus at all.

What remains on this list is the synchronous work the nodes still do
themselves: the capa evidence collection in the report node and the
deterministic report build. Each is one synchronous call in an `async def`, and
each is minutes long the first time it runs.

These tests do not measure how long a layer takes. They assert the property
that matters and that a reader can check: while the slow synchronous work runs,
a task on the same loop keeps getting turns.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from typing import Any

import pytest


async def _ticks_during(work: Any, seconds: float = 0.6) -> int:
    """Run ``work`` on this loop and count the turns another task still gets.

    A loop that is blocked in synchronous code services no callbacks at all, so
    the counter stays where it started — which is exactly what the worker's
    heartbeat did for 209 seconds.
    """
    ticks = 0
    stop = False

    async def _heartbeat() -> None:
        nonlocal ticks
        while not stop:
            ticks += 1
            await asyncio.sleep(0.01)

    beat = asyncio.create_task(_heartbeat())
    await asyncio.sleep(0.05)
    before = ticks
    try:
        await work
    finally:
        stop = True
        beat.cancel()
        with pytest.raises(asyncio.CancelledError):
            await beat
    return ticks - before


def _assert_offloaded(source: str, call: str) -> None:
    """Every occurrence of ``call`` in ``source`` must be handed to a thread.

    Checked against the text that *precedes* the call rather than its own line,
    because a call split across lines carries ``asyncio.to_thread(`` on the line
    above it. Comment lines are skipped: a mention is not a call.
    """
    for line_no, line in enumerate(source.splitlines(), start=1):
        if call not in line or line.strip().startswith("#"):
            continue
        index = source.index(line)
        window = source[max(0, index - 200) : index + len(line)]
        assert "to_thread" in window, (
            f"{call} runs on the event loop at line {line_no}: {line.strip()!r}"
        )


class TestTheHarnessItselfIsHonest:
    @pytest.mark.asyncio
    async def test_a_blocking_call_stops_the_counter(self) -> None:
        """The control: this is what a node that blocks the loop looks like."""

        async def blocking() -> None:
            time.sleep(0.4)

        assert await _ticks_during(blocking()) == 0

    @pytest.mark.asyncio
    async def test_the_same_call_in_a_thread_does_not(self) -> None:
        async def offloaded() -> None:
            await asyncio.to_thread(time.sleep, 0.4)

        assert await _ticks_during(offloaded()) > 5


class TestTheReportNodeOffloadsItsSynchronousWork:
    def test_capa_evidence_and_the_report_build_are_offloaded(self) -> None:
        """`collect_evidence` shells out to capa under a 900s budget, and
        `build_deterministic` walks every report section; both used to run on
        the loop, back to back, in the phase the heartbeat went quiet in."""
        from maljan.pipeline import nodes

        source = inspect.getsource(nodes.make_report_node)
        for call in ("collect_evidence", "build_deterministic"):
            _assert_offloaded(source, call)


class TestTheSandboxStageOffloadsItsSynchronousClient:
    def test_submit_and_poll_run_in_a_thread(self) -> None:
        """`TriageSandboxProvider` drives a *synchronous* `httpx.Client`, and
        `wait_for_completion` polls with `time.sleep` for as long as the
        provider's completion budget allows. Called bare from
        `_submit_to_sandbox`, that is the worker's loop stopped for the whole
        detonation."""
        from maljan.app import MaljanApp

        source = inspect.getsource(MaljanApp._submit_to_sandbox)
        for call in ("client.submit(", "client.wait_for_completion(", "client.fetch_report("):
            _assert_offloaded(source, call)
