"""The worker's real teardown sequence, against the real stdio sidecars.

The fast property tests in `tests/unit/test_teardown_cannot_hang_a_job.py`
pin the routing rule with a fake toolkit. This one refuses to take the fake's
word for it: it starts the two in-repo MCP servers — `network-mcp/server.py`
and `threatintel-mcp/server.py`, both of which come up with no network access
and no API keys — attaches them exactly the way a job does, and then drives
`ServiceContainer.aclose()` under the worker's own fence.

"Exactly the way a job does" is the whole point, and it is asymmetric:

  * the network analyst attaches through `registry.tools_for(...)`, whose
    `ServerHandle.open` hands `initialize` to the shared agent loop;
  * the mediator judge attaches through `registry.atools_for(...)`, which the
    negotiation node runs inside `run_on_agent_loop` — so that toolkit's exit
    stack is wound on the shared agent loop too, while `aclose` is awaited on
    the graph loop.

That second asymmetry is what a live run turned into a Critical: the close
parked on the agent loop's machinery, the 60s fence in `run_analysis` was
discarded rather than raised, and the job held `j_ongoing=1` with both
sidecars alive until the worker was killed.

Marked `slow` because it spawns two real subprocesses.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import threading
import time
from typing import Any

import pytest


def _own_children() -> set[int]:
    """The pids of this process's direct children."""
    out = subprocess.run(
        ["pgrep", "-P", str(os.getpid())], capture_output=True, text=True, check=False
    )
    return {int(pid) for pid in out.stdout.split()}


def _run_isolated(coro_factory: Any, timeout: float) -> Any:
    """Run an async scenario on its own loop in a thread, bounded by a watchdog.

    The failure under test is a hang, so it must not be able to take the suite
    with it: on a timeout the thread is abandoned as a daemon and the test
    fails with a message.
    """
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["result"] = asyncio.run(coro_factory())
        except BaseException as exc:  # noqa: BLE001 — re-raised on the main thread
            box["error"] = exc

    thread = threading.Thread(target=target, name="teardown-scenario", daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        pytest.fail(f"the teardown scenario did not finish within {timeout}s — it hung")
    if "error" in box:
        raise box["error"]
    return box.get("result")


def _cached_judge(container: Any) -> Any:
    """The mediator judge, cached where `ServiceContainer.aclose` looks for it.

    Built directly rather than through `get_judge_agent`, whose LLM factory
    refuses to run in mock mode. Nothing here calls the model: the judge is
    present only so that its `aclose` runs where a job's would, ahead of the
    registry's synchronous `close_all`.
    """
    from unittest.mock import MagicMock

    from maljan.agents.judge_agent import JudgeAgent

    judge = JudgeAgent(llm=MagicMock(), config=container.config)
    judge._container = container
    container._judge_agent_cache["expert"] = judge
    return judge


@pytest.mark.slow
def test_a_job_shaped_attach_tears_down_inside_the_budget() -> None:
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    before = _own_children()
    result: dict[str, Any] = {}

    async def scenario() -> None:
        from maljan.agents.base_agent import run_on_agent_loop

        container = ServiceContainer(config=Settings(_env_file=None), mock=True)
        registry = container.get_server_registry()

        # The network analyst's path: `open` on the shared agent loop.
        tools, reasons = registry.tools_for("network", "job-1")
        assert tools and not reasons, f"the network sidecar did not attach: {reasons}"

        # The mediator judge's path: the whole attach runs on the agent loop,
        # because `make_negotiation_node` awaits `judge.mediate(...)` through
        # `run_on_agent_loop`. Going through the cached judge rather than the
        # registry directly is not decoration — it is what puts the judge's
        # handle *first* in `ServiceContainer.aclose`, ahead of the registry's
        # synchronous `close_all`, which is the order the live worker died in.
        judge = _cached_judge(container)
        await run_on_agent_loop(
            judge._initialize_mcp_client(), hard_timeout=60.0, label="mediation"
        )
        assert judge.tools, "the threatintel sidecar did not attach"
        assert registry.get("threatintel")._opened_async is True

        result["children"] = _own_children() - before
        started = time.monotonic()
        # The worker's own fence, shortened. It has to *return*, not be
        # discarded: before the fix neither this nor the handle's own 20s
        # bound could end the close.
        await asyncio.wait_for(container.aclose(), timeout=10)
        result["elapsed"] = time.monotonic() - started

    _run_isolated(scenario, timeout=90)

    assert len(result["children"]) == 2, "both sidecars should have started"
    assert result["elapsed"] < 10

    # The children must be gone, not merely abandoned. They exit on their own
    # once the transport's shutdown runs; give the reap a moment either way.
    deadline = time.monotonic() + 10
    survivors = result["children"] & _own_children()
    while survivors and time.monotonic() < deadline:
        time.sleep(0.2)
        survivors = result["children"] & _own_children()
    assert not survivors, f"mcp sidecars outlived the job: {sorted(survivors)}"
