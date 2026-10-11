"""Attach one tool server long enough to read its manifest, then let go.

The connection test of any provider that drives an MCP server: the settings
probe calls it for a server of the registry, and a provider's own ``probe()``
calls it for the server it drives. It is ``ServerHandle``, so a server that
answers here answers the same way in a run.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from typing import Any

from maljan.core.logger import logger

# A connection test is a person waiting at a button. Five seconds is long
# enough for a local stdio server to answer tools/list and short enough that a
# wedged one is reported rather than endured.
PROBE_BUDGET_SECONDS = 5.0

_CLEANUP_TASKS: set[asyncio.Task[Any]] = set()


def detach_cleanup(coro: Any, label: str) -> None:
    """Run ``coro`` to completion without making the caller wait for it.

    ``handle.aclose()`` is internally bounded (its own 20 s timeout); awaiting
    it on top of a failed or timed-out open re-adds that whole budget to a
    probe documented at five seconds. A strong reference is kept until it
    finishes so the task is not garbage collected mid-flight.
    """
    task = asyncio.ensure_future(coro)
    _CLEANUP_TASKS.add(task)

    def _done(t: asyncio.Task[Any]) -> None:
        _CLEANUP_TASKS.discard(t)
        if not t.cancelled() and (exc := t.exception()) is not None:
            logger.warning("probe cleanup for '%s' failed (non-fatal): %s", label, exc)

    task.add_done_callback(_done)


async def handshake(
    config: Any,
    name: str,
    *,
    budget: float = PROBE_BUDGET_SECONDS,
    handle_factory: Callable[[str, Any], Any] | None = None,
) -> tuple[list[str], dict[str, Any] | None]:
    """The tool names ``config``'s server offers and its ``capabilities`` manifest, if any.

    Whatever happens, the handle is eventually closed: a probe that leaves a
    child process behind turns a mistyped command into a slow leak of
    subprocesses. ``asyncio.wait`` never cancels the handshake past the budget
    and waits for that: it stops waiting, asks it to stop, and closes the
    handle once it does, so a wedged server costs the budget and not the
    handle's own cleanup on top. Raises ``TimeoutError`` past the budget and
    whatever ended the handshake otherwise.
    """
    from maljan.tools import staging

    if handle_factory is None:
        from maljan.providers.servers import ServerHandle

        handle_factory = ServerHandle
    handle = handle_factory(name, config)
    # Per call, not per server: two people pressing Test on one server at the
    # same time would otherwise share a staging leaf, and one call's cleanup
    # would remove the other's directory while it was still in use.
    probe_key = f"probe-{name}-{uuid.uuid4().hex[:8]}"

    async def _run() -> tuple[list[str], dict[str, Any] | None]:
        await handle.aopen(probe_key)
        capabilities = getattr(handle, "capabilities", None)
        to_dict = getattr(capabilities, "to_dict", None)
        return handle.all_tool_names(), (to_dict() if callable(to_dict) else None)

    try:
        task: asyncio.Task[tuple[list[str], dict[str, Any] | None]] = asyncio.ensure_future(_run())
        done, _pending = await asyncio.wait({task}, timeout=budget)
        if task not in done:
            task.cancel()
            done2, _pending2 = await asyncio.wait({task}, timeout=0.1)
            if task in done2:
                await handle.aclose()
            else:
                task.add_done_callback(lambda _t: detach_cleanup(handle.aclose(), probe_key))
            raise TimeoutError(f"no MCP handshake within {budget:.0f} s")
        try:
            return task.result()
        finally:
            await handle.aclose()
    finally:
        staging.remove_job_staging(probe_key)
