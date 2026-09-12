"""Write down every tool call an agent makes, and show the model its id.

The ReAct loop runs inside LangGraph's executor, so there is no seam between
"the model asked for a tool" and "the tool answered" that the agent itself can
stand in. Wrapping each tool is that seam: the wrapper starts a clock, calls
the tool it wrapped, and hands back the answer with the ledger id of the entry
it just wrote stamped on the front.

The stamp is the point. Without it a model can describe what a tool said but
cannot cite it, and the report is back to trusting prose. With it the model
sees ``[ev_0007]`` above the section table and can write ``evidence_ids:
["ev_0007"]`` next to the finding it drew from it, which is what makes a
report section checkable against the call that produced it.

Rebuilding the tool rather than mutating it, and never letting a wrapper cost
a tool call, follow ``agents.tool_pinning`` — the two wrappers compose, path
guard inside, recorder outside.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.schemas.evidence import EvidenceCounter, LedgerEntry, build_entry

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool


def result_text(value: Any) -> str:
    """A tool's return value as the text both the model and the ledger see.

    JSON rather than ``repr`` for a dict or a list: the in-process tools all
    return JSON-shaped data, and a Python repr of it is neither what the
    ledger can parse back into ``structured`` nor what a model reads best.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict | list):
        try:
            return json.dumps(value, default=str)
        except (TypeError, ValueError):
            return str(value)
    return str(value)


class EvidenceRecorder:
    """One agent's tool calls for one loop, in the order they happened."""

    def __init__(
        self,
        agent: str,
        *,
        counter: EvidenceCounter | None = None,
        stage: str = "analysis",
    ) -> None:
        self.agent = agent
        self.stage = stage
        # A recorder without a counter is an agent running outside a job — a
        # test, a script, the CLI. Its ids are still monotonic, they are just
        # monotonic within this loop rather than within a job.
        self.counter = counter if counter is not None else EvidenceCounter()
        self.entries: list[LedgerEntry] = []

    def record(
        self,
        *,
        tool: str,
        args: dict[str, Any] | None,
        server: str | None,
        output: str,
        ok: bool = True,
        error: str | None = None,
        started_at: float = 0.0,
        duration_ms: int = 0,
    ) -> LedgerEntry:
        """Append one entry and return it, so the caller can quote its id."""
        entry_id, seq = self.counter.next_id()
        entry = build_entry(
            entry_id=entry_id,
            seq=seq,
            agent=self.agent,
            tool=tool,
            args=args,
            server=server,
            output=output,
            ok=ok,
            error=error,
            started_at=started_at,
            duration_ms=duration_ms,
            stage=self.stage,
        )
        self.entries.append(entry)
        return entry


def record_tools(tools: list[Any], recorder: EvidenceRecorder) -> list[BaseTool]:
    """Every tool, each writing its call to ``recorder`` and stamping the id."""
    return [_record_tool(tool, recorder) for tool in tools]


def _record_tool(tool: Any, recorder: EvidenceRecorder) -> Any:
    """One tool, rebuilt so its result is recorded and stamped.

    Fail-safe in both directions: a tool this cannot rebuild faithfully is
    returned exactly as it was, and a tool that raises is recorded as a failed
    entry whose error text goes back to the model rather than being turned
    into an exception the loop has to survive.
    """
    from langchain_core.tools import StructuredTool

    from maljan.agents.tool_pinning import server_of

    func = getattr(tool, "func", None)
    coroutine = getattr(tool, "coroutine", None)
    args_schema = getattr(tool, "args_schema", None)
    if (func is None and coroutine is None) or args_schema is None:
        return tool

    name = str(getattr(tool, "name", "") or "unknown")
    server = server_of(tool) or None

    def _stamp(kwargs: dict[str, Any], started: float, wall_clock: float, value: Any) -> str:
        text = result_text(value)
        entry = recorder.record(
            tool=name,
            args=kwargs,
            server=server,
            output=text,
            started_at=wall_clock,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        # ``text``, not ``entry.output``: the ledger trims what it stores, and
        # what the model reads is not the ledger's business. The size of a tool
        # result in a prompt is decided where it has always been decided —
        # ``llm.max_tool_output_chars`` and the summariser guardrail the MCP
        # toolkit applies before the tool ever returns — and a second, silent
        # cut here would make raising that setting do nothing.
        return f"[{entry.id}]\n{text}"

    def _stamp_error(
        kwargs: dict[str, Any], started: float, wall_clock: float, exc: Exception
    ) -> str:
        message = f"{type(exc).__name__}: {exc}"
        entry = recorder.record(
            tool=name,
            args=kwargs,
            server=server,
            output=message,
            ok=False,
            error=message,
            started_at=wall_clock,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        return f"[{entry.id}] tool call failed: {message}"

    wrapped_func = None
    wrapped_coroutine = None
    if func is not None:

        def wrapped_func(**kwargs: Any) -> str:  # noqa: F811
            # Two clocks: the wall clock says when the call happened and
            # correlates with a log line, the monotonic one measures how long
            # it took and cannot go backwards.
            started, wall_clock = time.monotonic(), time.time()
            try:
                return _stamp(kwargs, started, wall_clock, func(**kwargs))
            except Exception as exc:  # noqa: BLE001 — a failed call is evidence
                return _stamp_error(kwargs, started, wall_clock, exc)

    if coroutine is not None:

        async def wrapped_coroutine(**kwargs: Any) -> str:  # noqa: F811
            started, wall_clock = time.monotonic(), time.time()
            try:
                return _stamp(kwargs, started, wall_clock, await coroutine(**kwargs))
            except Exception as exc:  # noqa: BLE001 — a failed call is evidence
                return _stamp_error(kwargs, started, wall_clock, exc)

    try:
        return StructuredTool.from_function(
            func=wrapped_func,
            coroutine=wrapped_coroutine,
            name=name,
            description=getattr(tool, "description", ""),
            args_schema=args_schema,
            infer_schema=False,
            metadata=getattr(tool, "metadata", None),
        )
    except Exception as exc:  # noqa: BLE001 — the ledger never costs a tool
        logger.warning("evidence recorder skipped for tool '%s': %s", name, exc)
        return tool
