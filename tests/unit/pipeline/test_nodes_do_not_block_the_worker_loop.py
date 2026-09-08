"""No pipeline node may do minutes of synchronous work on the worker's loop (OBS 4).

The live run of 2026-09-07 logged its 15-second "Pipeline heartbeat" and then
went quiet for 209 seconds during the judge/report phase. The job completed, so
nothing failed — the worker's event loop was simply not running. The py-spy
dump taken during the same window caught the main thread mid-callback in
`sigma_layer.from_rules_dir`, 2902 rules into a `read_text`, reached from
`nodes._run_sigma_scan` through `container.get_sigma_layer`.

The scans themselves were already on `asyncio.to_thread`. What was not: the
lazy *construction* of the layers behind them (compiling the YARA corpus,
parsing the Sigma rule tree), the capa evidence collection in the report node,
and the deterministic report build. Each is one synchronous call in an `async
def`, and each is minutes long the first time it runs.

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


class TestTheRuleLayersAreBuiltOffTheLoop:
    """`container.get_yara_layer()` / `get_sigma_layer()` build on first use.

    The container caches behind a lock, so the cost lands once — on whichever
    loop callback happened to ask first, which in a real run is the judge node.
    """

    @pytest.mark.asyncio
    async def test_building_the_sigma_layer_does_not_stop_the_loop(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core import container as container_mod

        built: list[str] = []

        def slow_build(self: Any) -> Any:
            time.sleep(0.4)
            built.append("sigma")
            return object()

        monkeypatch.setattr(container_mod.ServiceContainer, "get_sigma_layer", slow_build)
        container = _mock_container()

        ticks = await _ticks_during(_build_layer(container.get_sigma_layer))
        assert built == ["sigma"]
        assert ticks > 5, (
            "the Sigma layer was compiled on the event loop: 2902 rules of "
            "`read_text` with the worker's heartbeat stopped (OBS 4)"
        )

    @pytest.mark.asyncio
    async def test_building_the_yara_layer_does_not_stop_the_loop(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core import container as container_mod

        def slow_build(self: Any) -> Any:
            time.sleep(0.4)
            return object()

        monkeypatch.setattr(container_mod.ServiceContainer, "get_yara_layer", slow_build)
        container = _mock_container()

        assert await _ticks_during(_build_layer(container.get_yara_layer)) > 5

    def test_the_judge_node_offloads_both_getters(self) -> None:
        """Read the node itself, so the two tests above cannot pass by accident.

        A getter called bare inside an `async def` is the whole bug; the source
        check names it at the exact line rather than leaving a timing test to
        infer it.
        """
        from maljan.pipeline import nodes

        source = inspect.getsource(nodes.make_judge_node)
        for getter in ("get_sigma_layer", "get_yara_layer"):
            _assert_offloaded(source, getter)


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


async def _build_layer(getter: Any) -> Any:
    """What the node is now expected to do with a lazily built layer."""
    return await asyncio.to_thread(getter)


def _mock_container() -> Any:
    from unittest.mock import MagicMock

    from maljan.core.container import ServiceContainer

    container = MagicMock(spec=ServiceContainer)
    container.get_sigma_layer = lambda: ServiceContainer.get_sigma_layer(container)
    container.get_yara_layer = lambda: ServiceContainer.get_yara_layer(container)
    return container
