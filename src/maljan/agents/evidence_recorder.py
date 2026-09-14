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
from collections.abc import Sequence
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
        repeated_of: str | None = None,
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
            repeated_of=repeated_of,
        )
        self.entries.append(entry)
        return entry


class RepeatGuard:
    """How often each ``(tool, arguments)`` pair has been asked for in one loop.

    A local model that likes an answer will ask for it again, and the live run
    has a static analyst calling ``identify_file`` with identical arguments ten
    times in a row -- ten steps of its budget, ten identical ledger entries,
    and the same bytes back through the context every time.

    One repeat is served: a model re-reading a result it half-remembers is
    ordinary, and refusing the second call would break a legitimate retry after
    a transient failure. From the third on the tool is not run and the model is
    told where the answer already is.

    Telling it is not the same as steering it. A live static analyst called
    ``strings`` seventeen times with identical arguments — ten of them
    short-circuited here — because "the result is in [ev_0007]" answers where
    the answer is and not what to do instead. The second call, the one that is
    still served, is where the model is told, and both messages name the
    arguments of that tool it has not used.
    """

    SERVED = 2

    def __init__(self) -> None:
        self._first: dict[str, str] = {}
        self._count: dict[str, int] = {}

    @staticmethod
    def _key(tool: str, kwargs: dict[str, Any]) -> str:
        """The call, canonically: same arguments in any order are the same call."""
        try:
            arguments = json.dumps(kwargs, sort_keys=True, default=str)
        except (TypeError, ValueError):
            arguments = repr(sorted(kwargs.items()))
        return f"{tool}({arguments})"

    def answered_by(self, tool: str, kwargs: dict[str, Any]) -> str | None:
        """The entry that already answers this call, when it must not run again."""
        key = self._key(tool, kwargs)
        if self._count.get(key, 0) < self.SERVED:
            return None
        return self._first.get(key)

    def repeat_of(self, tool: str, kwargs: dict[str, Any]) -> str | None:
        """The first entry for a call that is being served again, or ``None``.

        Asked before the call runs, so a second identical call sees the count
        of one the first left behind. This is the turn worth spending a
        sentence on: the answer still arrives, and the model is told not to ask
        a third time while it can still do something else with the step.
        """
        key = self._key(tool, kwargs)
        if not 0 < self._count.get(key, 0) < self.SERVED:
            return None
        return self._first.get(key)

    def note(self, tool: str, kwargs: dict[str, Any], entry_id: str) -> None:
        """Record that the call ran, and which entry first answered it."""
        key = self._key(tool, kwargs)
        self._count[key] = self._count.get(key, 0) + 1
        self._first.setdefault(key, entry_id)


def _do_something_else(tool: str, unused_args: Sequence[str]) -> str:
    """The half of both notices that says what to do instead.

    The arguments come from the tool's own schema, so the sentence names what
    this tool can actually be asked differently — ``pattern``, ``start`` and
    ``end`` for ``strings`` — rather than a hint written for one tool and
    repeated at every other.
    """
    if unused_args:
        named = ", ".join(f"`{name}`" for name in unused_args)
        return f"narrow it with {named}, or call another tool."
    return "call it with different arguments, or call another tool."


def repeat_notice(tool: str, entry_id: str, unused_args: Sequence[str] = ()) -> str:
    """What the model is told instead of the same answer a third time."""
    return (
        f"You already called {tool} with these arguments; the result is in "
        f"[{entry_id}]. Do not call it again with these arguments; "
        f"{_do_something_else(tool, unused_args)}"
    )


def served_repeat_notice(tool: str, entry_id: str, unused_args: Sequence[str] = ()) -> str:
    """The steering appended to the second identical call, which is still served.

    The answer is above it: this is a note, not a refusal. Said here because a
    model that is going to ask a third time has already decided to by the time
    the third call is refused, and one turn earlier it still has a step to
    spend on something else.
    """
    return (
        f"This is the second call to {tool} with these arguments and the answer above is "
        f"also in [{entry_id}]. A third will not be run: "
        f"{_do_something_else(tool, unused_args)}"
    )


def record_tools(
    tools: list[Any], recorder: EvidenceRecorder, repeats: RepeatGuard | None = None
) -> list[BaseTool]:
    """Every tool, each writing its call to ``recorder`` and stamping the id."""
    return [_record_tool(tool, recorder, repeats) for tool in tools]


def _record_tool(tool: Any, recorder: EvidenceRecorder, repeats: RepeatGuard | None = None) -> Any:
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
    accepted = tuple(getattr(args_schema, "model_fields", {}) or {})

    def _unused(kwargs: dict[str, Any]) -> tuple[str, ...]:
        """The arguments this tool takes that the call did not really set.

        Truthiness rather than presence: langchain fills a tool's defaults
        before calling it, so a caller that asked nothing of ``start`` still
        arrives here with ``start=0``, and a hint that omitted it would omit
        every optional argument the model has not thought to use.
        """
        return tuple(arg for arg in accepted if not kwargs.get(arg))

    def _already_answered(kwargs: dict[str, Any]) -> str | None:
        """The note for a call that has been made twice already, if it has."""
        if repeats is None:
            return None
        first = repeats.answered_by(name, kwargs)
        if first is None:
            return None
        message = repeat_notice(name, first, _unused(kwargs))
        entry = recorder.record(
            tool=name,
            args=kwargs,
            server=server,
            output=message,
            started_at=time.time(),
            repeated_of=first,
        )
        return f"[{entry.id}]\n{message}"

    def _note(kwargs: dict[str, Any], entry_id: str) -> None:
        """Count the call against the repeat budget, however it turned out.

        A call that raised is a call. Counting only the ones that returned left
        a tool that throws on the same arguments — an unreachable server, a
        path the sidecar will never read — free to be re-run for the whole step
        budget, which is the one case the guard exists for.
        """
        if repeats is not None:
            repeats.note(name, kwargs, entry_id)

    def _stamp(kwargs: dict[str, Any], started: float, wall_clock: float, value: Any) -> str:
        text = result_text(value)
        # Asked before the call is noted, so it sees the count the previous
        # identical call left behind.
        repeated = repeats.repeat_of(name, kwargs) if repeats is not None else None
        entry = recorder.record(
            tool=name,
            args=kwargs,
            server=server,
            output=text,
            started_at=wall_clock,
            duration_ms=int((time.monotonic() - started) * 1000),
        )
        _note(kwargs, entry.id)
        # ``text``, not ``entry.output``: the ledger trims what it stores, and
        # what the model reads is not the ledger's business. The size of a tool
        # result in a prompt is decided where it has always been decided —
        # ``llm.max_tool_output_chars`` and the summariser guardrail the MCP
        # toolkit applies before the tool ever returns — and a second, silent
        # cut here would make raising that setting do nothing.
        if repeated is not None:
            # Appended to what the model reads, not to the ledger: the entry
            # records what the tool said, and the tool did not say this.
            return (
                f"[{entry.id}]\n{text}\n\n{served_repeat_notice(name, repeated, _unused(kwargs))}"
            )
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
        _note(kwargs, entry.id)
        return f"[{entry.id}] tool call failed: {message}"

    wrapped_func = None
    wrapped_coroutine = None
    if func is not None:

        def wrapped_func(**kwargs: Any) -> str:  # noqa: F811
            answered = _already_answered(kwargs)
            if answered is not None:
                return answered
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
            answered = _already_answered(kwargs)
            if answered is not None:
                return answered
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
