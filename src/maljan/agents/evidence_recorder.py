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
from maljan.pipeline.events import (
    EventSink,
    emit_tool_call_finished,
    emit_tool_call_started,
    summarize_args,
    summarize_result,
)
from maljan.schemas.evidence import EvidenceCounter, LedgerEntry, build_entry

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool


# The closers a repair may append, and nothing else. A repair that deleted a
# character, changed one or inserted one anywhere but the end would be this
# code deciding what the model meant.
_CLOSERS = {"{": "}", "[": "]"}


def repair_arguments(text: str) -> dict[str, Any] | None:
    """One truncated tool call's arguments, closed off, or ``None``.

    A local model that runs out of generation mid-call emits arguments that
    stop in the middle: an unterminated string, an array with no ``]``, an
    object with no ``}``. langchain marks the call invalid, no tool runs and
    nothing answers it, so the loop ends on a turn that cost a step and
    produced nothing.

    The repair closes brackets and nothing else. Read the text once, tracking
    whether the cursor is inside a string and which brackets are open, and
    append the closers that are missing. Nothing is removed, nothing is
    substituted and nothing is inserted anywhere but the end.

    A value cut in the middle of a string is *not* repaired, and that is the
    rule this exists under: closing the quote would hand the tool an argument
    the model never finished writing — ``{"path": "/tmp/dropper.ex`` becomes a
    path that exists nowhere, and a ``strings`` pattern cut mid-token becomes
    a different search. The call is refused with the message it was already
    refused with, which is the honest answer to a call whose meaning is
    genuinely unknown. A trailing comma, a key with no value and a missing
    colon are refused the same way.
    """
    raw = str(text or "")
    if not raw.strip():
        return None
    stack: list[str] = []
    in_string = False
    escaped = False
    for char in raw:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in _CLOSERS:
            stack.append(char)
        elif char in _CLOSERS.values() and stack and _CLOSERS[stack[-1]] == char:
            stack.pop()
    if in_string:
        # The model was still writing a value. Whatever it meant to type next
        # is not something this may guess.
        return None
    tail = "".join(_CLOSERS[open_] for open_ in reversed(stack))
    if not tail:
        # Nothing was left open, so whatever is wrong with this call is not
        # something appending can fix.
        return None
    try:
        parsed = json.loads(raw + tail)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


class ArgumentRepairs:
    """The repairs made for one loop, so the ledger can say a call was one.

    The repair happens where the model's turn is read and the call happens a
    node later, with the arguments langchain filled the defaults into, so the
    two cannot be matched on the arguments as sent. They are matched on the
    arguments the repair produced being what the call carries: every key the
    repair wrote, with the value it wrote, present in the call.
    """

    def __init__(self) -> None:
        self._pending: list[tuple[str, dict[str, Any], str]] = []

    def note(self, tool: str, args: dict[str, Any], raw: str) -> None:
        self._pending.append((str(tool), dict(args), str(raw)))

    def take(self, tool: str, kwargs: dict[str, Any]) -> str | None:
        """The original text of the repaired call ``kwargs`` came from, once."""
        for index, (name, args, raw) in enumerate(self._pending):
            if name != tool:
                continue
            if all(key in kwargs and kwargs[key] == value for key, value in args.items()):
                self._pending.pop(index)
                return raw
        return None


def repair_invalid_tool_calls(message: Any, repairs: ArgumentRepairs) -> Any | None:
    """``message`` with its repairable calls made, or ``None`` when none were.

    The one seam between the model's turn and the tool node: langgraph runs
    the tools named by ``tool_calls`` and ignores ``invalid_tool_calls``
    entirely, so a call whose arguments never parsed is not refused anywhere —
    it simply never happens, and the loop ends holding a turn it paid for. A
    call this could close off is moved across; one it could not is left where
    it was, and the final-answer nudge drops it as it always has.
    """
    invalid = list(getattr(message, "invalid_tool_calls", None) or [])
    if not invalid:
        return None
    calls = list(getattr(message, "tool_calls", None) or [])
    still_invalid: list[Any] = []
    repaired_any = False
    for call in invalid:
        name = str(call.get("name") or "")
        args = repair_arguments(call.get("args")) if name else None
        if args is None:
            still_invalid.append(call)
            continue
        repairs.note(name, args, str(call.get("args") or ""))
        calls.append({"name": name, "args": args, "id": call.get("id"), "type": "tool_call"})
        repaired_any = True
        logger.warning(
            "tool call arguments for '%s' were truncated and were closed off to be read.", name
        )
    if not repaired_any:
        return None
    return message.model_copy(update={"tool_calls": calls, "invalid_tool_calls": still_invalid})


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
    """One agent's tool calls for one loop, in the order they happened.

    The same object is also the live feed of those calls. A ledger entry is
    written the moment a call answers, which is exactly when the console wants
    to draw the result, so the event goes out from here rather than from a
    second place that would have to be kept in step with it: one entry, one
    ``tool_call_finished``, always carrying the id the entry was filed under.
    The pack (``pipeline.triage_pack``) writes its steps through this same
    method and is fed out live for free.
    """

    def __init__(
        self,
        agent: str,
        *,
        counter: EvidenceCounter | None = None,
        stage: str = "analysis",
        sink: EventSink | None = None,
    ) -> None:
        self.agent = agent
        self.stage = stage
        # A recorder without a counter is an agent running outside a job — a
        # test, a script, the CLI. Its ids are still monotonic, they are just
        # monotonic within this loop rather than within a job.
        self.counter = counter if counter is not None else EvidenceCounter()
        self.entries: list[LedgerEntry] = []
        # ``None`` outside a job, which makes every emit a no-op, exactly as
        # it does everywhere else in the pipeline.
        self.sink = sink

    def call_started(
        self, *, tool: str, args: dict[str, Any] | None = None, server: str | None = None
    ) -> None:
        """Announce a call that is about to run. Never raises."""
        emit_tool_call_started(
            self.sink,
            stage=self.stage,
            agent=self.agent,
            tool=tool,
            server=server,
            args_summary=summarize_args(args),
        )

    def entry_failed(self, entry_id: str) -> bool:
        """Whether the entry with this id recorded a failure.

        Asked by the repeat guard, which points at an earlier entry and has to
        say what is in it: one live notice sent a model to ``[ev_0017]`` for
        "the result", and ``ev_0017`` was a call that had raised.
        """
        wanted = str(entry_id or "").strip()
        for entry in reversed(self.entries):
            if entry.id == wanted:
                return not entry.ok
        return False

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
        remediation: str | None = None,
        args_repaired: bool = False,
        args_raw: str | None = None,
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
            remediation=remediation,
            args_repaired=args_repaired,
            args_raw=args_raw,
        )
        self.entries.append(entry)
        emit_tool_call_finished(
            self.sink,
            stage=self.stage,
            agent=self.agent,
            tool=tool,
            server=server,
            evidence_id=entry.id,
            ok=ok,
            duration_ms=duration_ms,
            # The entry's own output, which the ledger has already trimmed,
            # rather than the text the model reads: what goes to the console
            # is a headline, and the whole result is one ledger lookup away.
            # A failure travels as the remediation the tool offered and not as
            # its error text, which is the half that names hosts and paths.
            summary=summarize_result(entry.output, ok=ok, remediation=remediation or ""),
        )
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

    # Identical calls answered before the third is refused.
    SERVED = 2
    # The served repeat whose notice says the loop is about to end, and the
    # number of served repeats that ends it. Two live runs made the case: a
    # static analyst spent 16 of its 19 steps on ``pe_info`` with identical
    # arguments, and another spent 11 on one ``strings`` regex. Being told
    # where the answer is does not stop a model that has decided to ask again,
    # so after three of them the loop is ended and what was gathered is
    # synthesised — which is what the step budget running out already does,
    # only sooner and with the steps still unspent.
    WARNS_AT = 2
    ENDS_AT = 3

    def __init__(self) -> None:
        self._first: dict[str, str] = {}
        self._count: dict[str, int] = {}
        # Across the whole loop, not per call: a model that asks for three
        # different answers twice each is in the same place as one that asks
        # for one answer three times.
        self.served_repeats = 0

    @staticmethod
    def _key(tool: str, kwargs: dict[str, Any]) -> str:
        """The call, canonically: same arguments in any order are the same call."""
        try:
            arguments = json.dumps(kwargs, sort_keys=True, default=str)
        except (TypeError, ValueError):
            arguments = repr(sorted(kwargs.items()))
        return f"{tool}({arguments})"

    def answered_by(self, tool: str, kwargs: dict[str, Any]) -> str | None:
        """The entry that already answers this call, when it must not run again.

        A query and nothing else. What counts a repeat is ``note_repeat``, from
        the wrapper, so the served branch and the refused branch are counted in
        one place — counting here, where only the refused branch passes,
        produced a guard that could reach 1 per call and never its own
        threshold.
        """
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

    def note_repeat(self) -> None:
        """Count one repeated call, whether it was served or refused.

        Both are the same fact about the loop: the model asked for an answer it
        already has. The first version counted only the served one, so a
        sixteen-call ``pe_info`` run — the failure this guard was written from
        — counted exactly one repeat and was never ended, because every call
        after the second was refused without passing the counter.
        """
        self.served_repeats += 1

    def reset(self) -> None:
        """Forget this loop's calls, for a conversation that is starting again.

        A connection error replays the whole conversation from the first
        message, and the model then re-makes the calls it already made. Those
        are not repeats: from the model's point of view it is asking for the
        first time, and counting them ended an analyst for a dropped socket.
        """
        self._first = {}
        self._count = {}
        self.served_repeats = 0

    def ending_the_loop(self) -> bool:
        """Whether this loop has repeated itself often enough to be ended."""
        return self.served_repeats >= self.ENDS_AT

    def warning_of_the_end(self) -> bool:
        """Whether the notice being written is the one before the last."""
        return self.served_repeats >= self.WARNS_AT

    def note(self, tool: str, kwargs: dict[str, Any], entry_id: str) -> None:
        """Record that the call ran, and which entry first answered it."""
        key = self._key(tool, kwargs)
        self._count[key] = self._count.get(key, 0) + 1
        self._first.setdefault(key, entry_id)


# What the model is told when its call ran on arguments that were closed off.
# It is on the result rather than only in the ledger, because the model is the
# one that can look at the answer and say the brackets were not what it meant.
REPAIRED_NOTICE = (
    "\n\nThe arguments for this call stopped in the middle and were closed off "
    "before it ran. Read the answer against what you meant to ask, and call it "
    "again with the whole arguments if it is not."
)


# What both notices say on the call before the loop ends. One sentence, in one
# place, because the model reads it from whichever branch it lands in.
_ENDING_SENTENCE = (
    " One more repeated call ends this analysis and what you have gathered "
    "is written up as it stands."
)


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


def repeat_notice(
    tool: str,
    entry_id: str,
    unused_args: Sequence[str] = (),
    *,
    last_warning: bool = False,
    failed: bool = False,
) -> str:
    """What the model is told instead of the same answer a third time.

    A message to the model and nothing else: no tool ran, so there is no entry
    to write and no id to hand out. It used to be recorded as a successful
    call — ``ok=true``, ``duration_ms=0`` — which inflated the ledger, inflated
    the report's "tool call(s) recorded" line, and gave the model a citable
    evidence id whose entry held no evidence.

    ``failed`` says the entry it points at is a failure rather than an answer,
    which is the difference between "the result is in [ev_0017]" and the truth
    about a call that raised. ``last_warning`` carries the same sentence the
    served notice carries, for the same reason: the call before the last one is
    where saying it can still change what the model does. A loop that repeats
    one call reaches the end through this branch rather than through the served
    one.
    """
    where = (
        f"You already called {tool} with these arguments and it failed, in [{entry_id}]"
        if failed
        else f"You already called {tool} with these arguments; the result is in [{entry_id}]"
    )
    return (
        f"{where}. Do not call it again with these arguments; "
        f"{_do_something_else(tool, unused_args)}{_ENDING_SENTENCE if last_warning else ''}"
    )


def served_repeat_notice(
    tool: str,
    entry_id: str,
    unused_args: Sequence[str] = (),
    *,
    last_warning: bool = False,
    failed: bool = False,
) -> str:
    """The steering appended to the second identical call, which is still served.

    The answer is above it: this is a note, not a refusal. Said here because a
    model that is going to ask a third time has already decided to by the time
    the third call is refused, and one turn earlier it still has a step to
    spend on something else.

    ``last_warning`` is the second such notice in one loop, where the sentence
    stops being advice: the next repeated call ends the loop and the analyst
    writes its answer from what it has. ``failed`` is the second call raising
    as the first did, where what is above is a failure and so is the entry it
    points at, and the sentence says so instead of calling it an answer.
    """
    what_happened = (
        f"This call to {tool} failed the same way before, in [{entry_id}]"
        if failed
        else (
            f"This is the second call to {tool} with these arguments and the answer above is "
            f"also in [{entry_id}]"
        )
    )
    return (
        f"{what_happened}. A third will not be run: "
        f"{_do_something_else(tool, unused_args)}{_ENDING_SENTENCE if last_warning else ''}"
    )


def record_tools(
    tools: list[Any],
    recorder: EvidenceRecorder,
    repeats: RepeatGuard | None = None,
    repairs: ArgumentRepairs | None = None,
) -> list[BaseTool]:
    """Every tool, each writing its call to ``recorder`` and stamping the id."""
    return [_record_tool(tool, recorder, repeats, repairs) for tool in tools]


def _record_tool(
    tool: Any,
    recorder: EvidenceRecorder,
    repeats: RepeatGuard | None = None,
    repairs: ArgumentRepairs | None = None,
) -> Any:
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

    required = tuple(
        name
        for name, field in (getattr(args_schema, "model_fields", {}) or {}).items()
        if getattr(field, "is_required", lambda: False)()
    )

    def _unused(kwargs: dict[str, Any]) -> tuple[str, ...]:
        """The arguments this tool takes that the call did not really set.

        Truthiness rather than presence: langchain fills a tool's defaults
        before calling it, so a caller that asked nothing of ``start`` still
        arrives here with ``start=0``, and a hint that omitted it would omit
        every optional argument the model has not thought to use.

        The schema's required fields are excluded, because for those the same
        reading is wrong: a call that correctly passed ``offset=0`` set it, and
        offering it back as a way to narrow the search is noise.
        """
        return tuple(arg for arg in accepted if arg not in required and not kwargs.get(arg))

    def _already_answered(kwargs: dict[str, Any]) -> str | None:
        """The note for a call that has been made twice already, if it has."""
        if repeats is None:
            return None
        first = repeats.answered_by(name, kwargs)
        if first is None:
            return None
        repeats.note_repeat()
        # Told to the model, written nowhere. No tool ran: an entry here would
        # be a successful call that made none, and the id on it would be an
        # evidence id a report could cite for evidence that does not exist.
        return repeat_notice(
            name,
            first,
            _unused(kwargs),
            last_warning=repeats.warning_of_the_end(),
            failed=recorder.entry_failed(first),
        )

    def _note(kwargs: dict[str, Any], entry_id: str) -> None:
        """Count the call against the repeat budget, however it turned out.

        A call that raised is a call. Counting only the ones that returned left
        a tool that throws on the same arguments — an unreachable server, a
        path the sidecar will never read — free to be re-run for the whole step
        budget, which is the one case the guard exists for.
        """
        if repeats is not None:
            repeats.note(name, kwargs, entry_id)

    def _served_again(kwargs: dict[str, Any]) -> str | None:
        """The first entry for a call being served a second time, counted as a repeat.

        Asked before the call runs, so it sees the count the previous identical
        call left behind, and before the outcome is known, so a repeat that
        raises counts the same as one that returns: a tool that throws on the
        same arguments is the one case the guard exists for.
        """
        if repeats is None:
            return None
        repeated = repeats.repeat_of(name, kwargs)
        if repeated is not None:
            repeats.note_repeat()
        return repeated

    def _steering(kwargs: dict[str, Any], repeated: str | None, *, failed: bool = False) -> str:
        """What is appended to a served repeat, and nothing for a first call.

        Appended to what the model reads, not to the ledger: the entry records
        what the tool said, and the tool did not say this.
        """
        if repeated is None or repeats is None:
            return ""
        notice = served_repeat_notice(
            name,
            repeated,
            _unused(kwargs),
            last_warning=repeats.warning_of_the_end(),
            failed=failed,
        )
        return f"\n\n{notice}"

    def _was_repaired(kwargs: dict[str, Any]) -> str | None:
        """The arguments as the model wrote them, when this call was closed off."""
        return repairs.take(name, kwargs) if repairs is not None else None

    def _stamp(
        kwargs: dict[str, Any], started: float, wall_clock: float, value: Any, repeated: str | None
    ) -> str:
        text = result_text(value)
        raw = _was_repaired(kwargs)
        entry = recorder.record(
            tool=name,
            args=kwargs,
            server=server,
            output=text,
            started_at=wall_clock,
            duration_ms=int((time.monotonic() - started) * 1000),
            args_repaired=raw is not None,
            args_raw=raw,
        )
        _note(kwargs, entry.id)
        if raw is not None:
            text = f"{text}{REPAIRED_NOTICE}"
        # ``text``, not ``entry.output``: the ledger trims what it stores, and
        # what the model reads is not the ledger's business. The size of a tool
        # result in a prompt is decided where it has always been decided —
        # ``llm.max_tool_output_chars`` and the summariser guardrail the MCP
        # toolkit applies before the tool ever returns — and a second, silent
        # cut here would make raising that setting do nothing.
        # ``failed=not entry.ok``: a tool that answers with an error twice is
        # repeating a failure, and the notice that calls it an answer reads as
        # if the model already has what it asked for.
        return f"[{entry.id}]\n{text}{_steering(kwargs, repeated, failed=not entry.ok)}"

    def _stamp_error(
        kwargs: dict[str, Any],
        started: float,
        wall_clock: float,
        exc: Exception,
        repeated: str | None,
    ) -> str:
        message = f"{type(exc).__name__}: {exc}"
        raw = _was_repaired(kwargs)
        entry = recorder.record(
            tool=name,
            args=kwargs,
            server=server,
            output=message,
            ok=False,
            error=message,
            started_at=wall_clock,
            duration_ms=int((time.monotonic() - started) * 1000),
            args_repaired=raw is not None,
            args_raw=raw,
        )
        _note(kwargs, entry.id)
        return f"[{entry.id}] tool call failed: {message}{_steering(kwargs, repeated, failed=True)}"

    wrapped_func = None
    wrapped_coroutine = None
    if func is not None:

        def wrapped_func(**kwargs: Any) -> str:  # noqa: F811
            # The guard first, and nothing is announced when it refuses: no
            # tool runs, no entry is written, and a start with no finish behind
            # it would leave the console holding a bubble open for a call that
            # never happened.
            answered = _already_answered(kwargs)
            if answered is not None:
                return answered
            recorder.call_started(tool=name, args=kwargs, server=server)
            # Two clocks: the wall clock says when the call happened and
            # correlates with a log line, the monotonic one measures how long
            # it took and cannot go backwards.
            started, wall_clock = time.monotonic(), time.time()
            repeated = _served_again(kwargs)
            try:
                return _stamp(kwargs, started, wall_clock, func(**kwargs), repeated)
            except Exception as exc:  # noqa: BLE001 — a failed call is evidence
                return _stamp_error(kwargs, started, wall_clock, exc, repeated)

    if coroutine is not None:

        async def wrapped_coroutine(**kwargs: Any) -> str:  # noqa: F811
            answered = _already_answered(kwargs)
            if answered is not None:
                return answered
            recorder.call_started(tool=name, args=kwargs, server=server)
            started, wall_clock = time.monotonic(), time.time()
            repeated = _served_again(kwargs)
            try:
                return _stamp(kwargs, started, wall_clock, await coroutine(**kwargs), repeated)
            except Exception as exc:  # noqa: BLE001 — a failed call is evidence
                return _stamp_error(kwargs, started, wall_clock, exc, repeated)

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
