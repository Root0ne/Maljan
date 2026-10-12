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
from dataclasses import dataclass, field
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


@dataclass
class Inspection:
    """What one attach read: the names, the manifest, each tool's definition, the probe answers.

    ``answers`` holds, per tool called, the harmless call made and what it
    returned (the text the toolkit hands a model, carrying the server's
    structured content where it gave one); ``probed`` says per tool whether it
    was called and, when it was not, why.
    """

    names: list[str]
    capabilities: dict[str, Any] | None
    definitions: list[Any] = field(default_factory=list)
    answers: dict[str, tuple[Any, Any]] = field(default_factory=dict)
    probed: dict[str, str] = field(default_factory=dict)


async def _call_harmlessly(
    handle: Any, calls: list[Any], budget: float
) -> tuple[dict[str, tuple[Any, Any]], dict[str, str]]:
    """Make each planned harmless call through the tool a run would call, one at a time.

    Each call has ``budget`` seconds. A call that raises or overruns is noted
    and the next one is made; nothing it returned is logged.
    """
    answers: dict[str, tuple[Any, Any]] = {}
    probed: dict[str, str] = {}
    for call in calls:
        tool = handle.advertised_tool(call.tool)
        if tool is None:
            probed[call.tool] = "not advertised"
            continue
        try:
            answer = await asyncio.wait_for(tool.ainvoke(dict(call.arguments)), budget)
        except TimeoutError:
            probed[call.tool] = f"no answer within {budget:.0f} s"
            continue
        except Exception as exc:  # noqa: BLE001 — one tool's failure is that tool's note
            probed[call.tool] = f"the call raised {type(exc).__name__}"
            continue
        answers[call.tool] = (call, answer)
        probed[call.tool] = "called"
    return answers, probed


async def inspect(
    config: Any,
    name: str,
    *,
    budget: float | None = None,
    handle_factory: Callable[[str, Any], Any] | None = None,
    plan: Callable[[list[Any]], list[Any]] | None = None,
) -> Inspection:
    """Attach ``config``'s server, read what it says about its tools, then let go.

    With ``plan``, the tool definitions are handed to it and each call it
    returns (``core.declaration_proposals.ProbeCall``) is made through the
    same toolkit tool a run calls, ``budget`` seconds each, before the handle
    is closed. The calls are the operator's request: ``plan`` is passed only
    when they asked, and it fills no argument with a sample.

    Whatever happens, the handle is eventually closed (see :func:`handshake`).
    Raises ``TimeoutError`` past the budget and whatever ended the attach
    otherwise.
    """
    from maljan.tools import staging

    if budget is None:
        budget = PROBE_BUDGET_SECONDS
    if handle_factory is None:
        from maljan.providers.servers import ServerHandle

        handle_factory = ServerHandle
    handle = handle_factory(name, config)
    handle.keeps_tool_definitions = True
    probe_key = f"probe-{name}-{uuid.uuid4().hex[:8]}"
    planned: list[Any] = []

    async def _open() -> None:
        await handle.aopen(probe_key)

    async def _read() -> Inspection:
        capabilities = getattr(handle, "capabilities", None)
        to_dict = getattr(capabilities, "to_dict", None)
        reader = getattr(handle, "tool_definitions", None)
        definitions = list(reader()) if callable(reader) else []
        found = Inspection(
            names=handle.all_tool_names(),
            capabilities=to_dict() if callable(to_dict) else None,
            definitions=definitions,
        )
        if planned:
            found.answers, found.probed = await _call_harmlessly(handle, planned, budget)
        return found

    try:
        task: asyncio.Task[None] = asyncio.ensure_future(_open())
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
            task.result()
            if plan is not None:
                reader = getattr(handle, "tool_definitions", None)
                planned = list(plan(list(reader()) if callable(reader) else []))
            # Each planned call keeps its own budget inside ``_read``.
            return await asyncio.wait_for(_read(), budget * (len(planned) + 1))
        finally:
            await handle.aclose()
    finally:
        staging.remove_job_staging(probe_key)


async def handshake(
    config: Any,
    name: str,
    *,
    budget: float | None = None,
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

    if budget is None:
        budget = PROBE_BUDGET_SECONDS
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
