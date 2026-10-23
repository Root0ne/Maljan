"""A call that queued for a server slot is timed from when it was sent.

The tool clock used to start when the wrapper was entered, so calls issued
together behind one stalled call of a server all read the stalled call's
duration, and ``tool_latency.slowest`` named whichever finished last. The
transport now says when the call left (``note_call_began``); the entry's
``duration_ms`` runs from there and the wait is its own ``waited_ms``.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

from langchain_core.tools import StructuredTool
from mcp.types import CallToolResult, TextContent

from maljan.agents.evidence_recorder import EvidenceRecorder, RepeatGuard, record_tools
from maljan.agents.mcp_client import MCPLangChainToolkit
from maljan.core.exceptions import SampleNotOpened
from maljan.llm.context_window import note_call_began
from maljan.providers.server_guard import ServerGuard
from maljan.schemas.evidence import EvidenceCounter, LedgerEntry, build_entry


class _Sink:
    def __call__(self, event_type: str, data: dict[str, Any]) -> None:
        pass


def _tool(name: str, gate: asyncio.Event | None, work: float) -> StructuredTool:
    async def run(item: str = "") -> str:
        if gate is not None:
            await gate.wait()
        note_call_began()
        await asyncio.sleep(work)
        return f"{name} done"

    return StructuredTool.from_function(coroutine=run, name=name, description=name)


def test_a_queued_call_s_duration_excludes_the_wait() -> None:
    recorder = EvidenceRecorder("static", counter=EvidenceCounter(), sink=_Sink())

    async def main() -> None:
        gate = asyncio.Event()
        queued, free = record_tools(
            [_tool("queued", gate, 0.05), _tool("free", None, 0.05)], recorder, RepeatGuard()
        )
        first = asyncio.create_task(queued.ainvoke({"item": "a"}))
        second = asyncio.create_task(free.ainvoke({"item": "b"}))
        await asyncio.sleep(1.0)
        gate.set()
        await asyncio.gather(first, second)

    asyncio.run(main())
    by_tool = {e.tool: e for e in recorder.entries}

    assert by_tool["queued"].waited_ms >= 900
    assert by_tool["queued"].duration_ms < 500
    assert by_tool["free"].waited_ms == 0
    assert by_tool["free"].duration_ms < 500


def _failing_tool(raises: Exception, gate: asyncio.Event) -> StructuredTool:
    async def run(item: str = "") -> str:
        await gate.wait()
        note_call_began()
        await asyncio.sleep(0.05)
        raise raises

    return StructuredTool.from_function(coroutine=run, name="failing", description="failing")


def _failed_after_a_wait(raises: Exception) -> LedgerEntry:
    recorder = EvidenceRecorder("static", counter=EvidenceCounter(), sink=_Sink())

    async def main() -> None:
        gate = asyncio.Event()
        (tool,) = record_tools([_failing_tool(raises, gate)], recorder, RepeatGuard())
        call = asyncio.create_task(tool.ainvoke({"item": "a"}))
        await asyncio.sleep(1.0)
        gate.set()
        try:
            await call
        except SampleNotOpened:
            pass

    asyncio.run(main())
    return recorder.entries[0]


def test_a_failed_call_that_queued_keeps_its_wait_apart_from_its_duration() -> None:
    entry = _failed_after_a_wait(RuntimeError("the server said no"))

    assert entry.ok is False
    assert entry.waited_ms >= 900
    assert entry.duration_ms < 500


def test_a_call_that_ended_the_loop_keeps_its_wait_apart_from_its_duration() -> None:
    entry = _failed_after_a_wait(SampleNotOpened("no sample", provider="static"))

    assert entry.ok is False
    assert entry.waited_ms >= 900
    assert entry.duration_ms < 500


def test_the_client_says_a_call_began_only_after_it_holds_a_slot() -> None:
    """Two calls to a one-slot server: the second begins when the first lets go."""
    sent_at: dict[str, float] = {}

    class _Session:
        async def call_tool(self, name: str, arguments: dict[str, Any], **_: Any) -> Any:
            sent_at[arguments["item"]] = asyncio.get_running_loop().time()
            await asyncio.sleep(1.0 if arguments["item"] == "first" else 0.05)
            return CallToolResult(content=[TextContent(type="text", text="ok")], isError=False)

    toolkit = MCPLangChainToolkit(None, guard=ServerGuard("srv", max_concurrent_calls=1))
    toolkit.session = _Session()  # type: ignore[assignment]
    attached = toolkit._create_langchain_tool(
        SimpleNamespace(
            name="lookup",
            description="lookup",
            inputSchema={"properties": {"item": {"type": "string"}}, "required": ["item"]},
            annotations=None,
        )
    )
    recorder = EvidenceRecorder("static", counter=EvidenceCounter(), sink=_Sink())
    (tool,) = record_tools([attached], recorder, RepeatGuard())

    async def main() -> None:
        first = asyncio.create_task(tool.ainvoke({"item": "first"}))
        await asyncio.sleep(0.1)
        second = asyncio.create_task(tool.ainvoke({"item": "second"}))
        await asyncio.gather(first, second)

    asyncio.run(main())
    by_item = {e.args["item"]: e for e in recorder.entries}

    assert by_item["first"].waited_ms < 300
    assert by_item["second"].waited_ms >= 800
    assert by_item["second"].duration_ms < 500
    # What the second asked of the server was sent only once the first had let go.
    assert sent_at["second"] - sent_at["first"] >= 0.9


def test_an_entry_that_never_waited_dumps_without_the_field() -> None:
    entry = build_entry(
        entry_id="ev_0001", seq=1, agent="a", tool="t", args={}, server=None, output="x"
    )
    assert "waited_ms" not in entry.model_dump()
    waited = build_entry(
        entry_id="ev_0002",
        seq=2,
        agent="a",
        tool="t",
        args={},
        server=None,
        output="x",
        waited_ms=40,
    )
    assert waited.model_dump()["waited_ms"] == 40
    assert LedgerEntry.model_validate(entry.model_dump()).waited_ms == 0
