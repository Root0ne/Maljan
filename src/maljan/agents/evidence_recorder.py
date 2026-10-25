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
import re
import time
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, Any

from maljan.agents.mcp_client import structured_content_of
from maljan.agents.null_arguments import (
    NO_NULLS,
    current_call_nulls,
    noting_class,
    nulls_of_call,
    rules_of,
    take_call_nulls,
)
from maljan.agents.tool_fence import fenced
from maljan.core.exceptions import SampleNotOpened
from maljan.core.logger import logger
from maljan.core.undeclared_tools import entry_decompiles
from maljan.llm.context_window import CallAnswer, answering_for
from maljan.llm.stream_watch import watching
from maljan.pipeline.events import (
    EventSink,
    emit_tool_call_finished,
    emit_tool_call_started,
    remember_resolved_names,
    summarize_args,
    summarize_result,
)
from maljan.pipeline.validation import listed_function
from maljan.schemas.evidence import (
    EvidenceCounter,
    LedgerEntry,
    build_entry,
    holds_its_answer,
    not_shown_record,
)

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

    from maljan.agents.image_range import ImageRange


# The servers whose ``resolve_api_hashes`` is this platform's own: the triage
# pack (recorded as ``pipeline``) and the analysis server.
_RESOLVING_SERVERS = frozenset({"pipeline", "analysis"})


def _platforms_own_resolution(entry: Any) -> bool:
    """Whether ``entry`` is an API hash resolution the platform's own resolver answered.

    By its declared kind, from a source that declares ``platform_owned``; an
    entry with no stored facts by the legacy reading and the server it was
    made to (``_RESOLVING_SERVERS``).
    """
    from maljan.core.declared_reading import declarations, kind_of, read_by_name
    from maljan.core.tool_declarations import ToolDeclarations

    if kind_of(entry) != "api_hash_resolution":
        return False
    if read_by_name(entry):
        return str(getattr(entry, "server", "") or "") in _RESOLVING_SERVERS
    ref = ToolDeclarations.source_of(entry)
    held = declarations().source(ref) if ref is not None else None
    return bool(held is not None and held.platform_owned)


# The closers a repair may append, and nothing else. A repair that deleted a
# character, changed one or inserted one anywhere but the end would be this
# code deciding what the model meant.
_CLOSERS = {"{": "}", "[": "]"}
# A JSON number the text ends on, nothing after it, not even a line break
# (``\Z``, never ``$``): a run of its characters not following a letter
# (``true`` and ``false`` end on ``e``).
_OPEN_NUMBER = re.compile(r"[0-9+\-.eE]+\Z")


def platform_refusal(exc: BaseException) -> bool:
    """Whether ``exc`` is a refusal the platform composed, in words of its own.

    An ask the delegation layer would not make (``DelegationRefused``), an
    attached report the platform will not read (``AttachedReportRefused``)
    and a call stopped at the job's spend ceiling (``SpendCeilingStop``) are
    sentences the platform wrote from its own state; every other failure a
    tool call raises carries a third party's message.
    """
    from maljan.agents.delegation import DelegationRefused
    from maljan.core.spend import SpendCeilingStop
    from maljan.providers.errors import AttachedReportRefused

    return isinstance(exc, DelegationRefused | AttachedReportRefused | SpendCeilingStop)


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

    A number at the very end (nothing after it, not even whitespace) and a
    list left open are not repaired either: a number may have been cut short (``4198`` of ``4198400``) and a list may
    have had more items, and closing either hands the tool a value the model
    did not write.

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
    if "[" in stack:
        # A list left open was cut somewhere in its items: closing it would
        # hand the tool the items written so far as if they were all of them.
        return None
    cut_number = _OPEN_NUMBER.search(raw)
    if cut_number is not None and not raw[: cut_number.start()][-1:].isalpha():
        # A number at the very end may be one cut short: ``4198`` of
        # ``4198400`` closes into a valid call at the wrong address. One the
        # model followed with whitespace or a line break, it ended.
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
        from maljan.core.safe_json import dumps

        try:
            # Depth-safe: a value nested past the guard is written with a
            # marked placeholder there, never a raise (``core.safe_json``).
            return dumps(value, default=str)
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
        corpus: Any = None,
        model: str = "",
        agent_role: str | None = None,
        agent_tab: str | None = None,
        spill: Any = None,
    ) -> None:
        self.agent = agent
        self.agent_tab = agent_tab or None
        # The role the agent's definition declares, written on every entry
        # (``LedgerEntry.agent_role``); ``None`` for the pack and an agent
        # running outside a container.
        self.agent_role = agent_role or None
        # The model whose turn the next calls answer: the agent's first model
        # until a turn says otherwise (``note_turn``). A fallback list stamps
        # every answer with the model that gave it, and the calls a turn asks
        # for are that model's.
        self.default_model = model
        self.model = model
        self.stage = stage
        # A recorder without a counter is an agent running outside a job — a
        # test, a script, the CLI. Its ids are still monotonic, they are just
        # monotonic within this loop rather than within a job.
        self.counter = counter if counter is not None else EvidenceCounter()
        self.entries: list[LedgerEntry] = []
        # Each entry by its id, kept beside the list so following a repeat to
        # its holder is one lookup per hop.
        self._by_id: dict[str, LedgerEntry] = {}
        # The narrowing arguments the tool that made each entry's answer
        # offered, by the entry's id: what a read-again answer's completeness
        # line names for the tool that made it, never looked up by a name.
        self._narrowing: dict[str, tuple[str, ...]] = {}
        # ``None`` outside a job, which makes every emit a no-op, exactly as
        # it does everywhere else in the pipeline.
        self.sink = sink
        # The run's own record of what its tools answered, kept in memory for
        # the length of the job. ``None`` outside a job, as the sink is. It is
        # written here rather than beside the stored entry because the byte
        # budget blanks the entry later, after the model has read it, and a
        # grounding check over what survived is a check over the wrong thing.
        self.corpus = corpus
        # The job's store for the parts of an answer an entry does not keep
        # whole (``schemas.evidence_spill``): given to every entry written
        # here, so a byte budget or a structure eviction that later takes a
        # part keeps it there first. ``None`` outside a job: nothing is kept.
        self.spill = spill

    def note_turn(self, message: Any) -> None:
        """The model that gave ``message`` asked for the calls that follow it. Never raises."""
        try:
            from maljan.llm.fallback import turn_model

            self.model = turn_model(message, self.default_model)[0]
        except Exception:  # noqa: BLE001 — a label is never worth a lost call
            self.model = self.default_model

    def call_started(
        self, *, tool: str, args: dict[str, Any] | None = None, server: str | None = None
    ) -> None:
        """Announce a call that is about to run. Never raises."""
        nulls = current_call_nulls(self)
        emit_tool_call_started(
            self.sink,
            stage=self.stage,
            agent=self.agent,
            tool=tool,
            server=server,
            args_summary=summarize_args(args),
            nulls_dropped=nulls.dropped,
            nulls_withheld=nulls.withheld,
        )

    def holder_of(self, entry_id: str) -> str:
        """The entry that holds the answer ``entry_id`` names: itself, or its repeat chain's end.

        So no repeat is ever filed as a repeat of a repeat, and no id a model
        is told to cite is one whose entry holds only a note.
        """
        by_id = self._by_id
        wanted, seen = str(entry_id or "").strip(), set()
        while wanted in by_id and by_id[wanted].repeated_of and wanted not in seen:
            seen.add(wanted)
            wanted = str(by_id[wanted].repeated_of)
        return wanted

    def filed(self, entry_id: str) -> bool:
        """Whether this loop filed an entry under this id."""
        return str(entry_id or "").strip() in self._by_id

    def entry_of(self, entry_id: str) -> LedgerEntry | None:
        """The entry this loop filed under this id, or ``None``."""
        return self._by_id.get(str(entry_id or "").strip())

    def cut_of(self, entry_id: str) -> int:
        """The characters the platform left out of the answer this entry holds (``platform_cut``)."""
        from maljan.schemas.answer_completeness import platform_cut

        entry = self._by_id.get(str(entry_id or "").strip())
        return platform_cut(entry) if entry is not None else 0

    def note_narrowing(self, entry_id: str, narrowing: Sequence[str]) -> None:
        """Remember the narrowing arguments the tool that answered this entry offered."""
        self._narrowing[str(entry_id or "").strip()] = tuple(narrowing)

    def narrowing_of(self, entry_id: str) -> tuple[str, ...]:
        """The narrowing arguments of the tool that made this entry's answer, as it offered them."""
        return self._narrowing.get(str(entry_id or "").strip(), ())

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
        waited_ms: int = 0,
        repeated_of: str | None = None,
        remediation: str | None = None,
        args_repaired: bool = False,
        args_raw: str | None = None,
        not_shown: int | None = None,
        cut: int | None = None,
        guard_answer: bool = False,
        source: str | None = None,
        declared_name: str | None = None,
        structured_content: dict[str, Any] | None = None,
        whole: str | None = None,
        whole_structure: dict[str, Any] | None = None,
        hints: Any = None,
        failure_note: Callable[[], str] | None = None,
    ) -> LedgerEntry:
        """Append one entry and return it, so the caller can quote its id.

        ``guard_answer`` files a call a guard answered with no tool run and no
        earlier entry behind the answer: its ``repeated_of`` is its own id
        (``schemas.evidence.is_guard_answer``).

        ``not_shown`` is the length of an answer the conversation had no room
        for: the entry is recorded as cut (``schemas.evidence.not_shown_record``)
        and ``output``, what the model was handed instead, is what the run's
        corpus remembers. ``cut`` is the characters the tool-output guardrail
        dropped from an answer it cut to fit: the entry keeps what the model
        read and is marked ``truncated`` with ``chars_dropped``. ``source`` is
        where the tool's declaration lives (``mcp:<key>``, ``provider:<id>``,
        ``sandbox``, ``pack``), as the caller knows it; it is never guessed
        later from the tool's name. ``declared_name`` is the name that source
        declares the tool under, given for a tool the request
        offered, the original name where it was renamed: the entry's facts are
        resolved by it, exactly. ``structured_content`` is the structured
        answer the tool's server returned beside its text (MCP
        ``structuredContent``), filed on the entry as returned.

        ``whole`` is the answer as the tool gave it before the guardrail, and
        ``whole_structure`` the structured answer its server returned beside
        it, whether or not it reached this call. Where the job has a store, an
        entry that does not hold them keeps a reference to them whole
        (``schemas.evidence_spill``): the answer when the guardrail cut it or
        the conversation had no room for it, the structure when the entry
        keeps none although it adds something to the text. A repeat keeps
        neither; the entry it names holds the answer. ``hints`` are the MCP
        hints the tool's own server gave it when it was attached, kept on the
        entry's facts record beside the declaration.

        ``failure_note`` is asked, only when the entry is a failure, for a
        sentence the platform adds to its remediation (an address outside the
        loaded image, ``agents.image_range``), after the server's own
        remediation, which keeps the headline.

        A call with a ``null`` the tool boundary dropped or the transport
        withheld (``agents.null_arguments``) names each such field on
        ``args_nulls_dropped`` or ``args_nulls_withheld``; ``args`` are the
        call's arguments as validated, a withheld field never sent and
        recorded as its default.
        """
        if repeated_of:
            repeated_of = self.holder_of(repeated_of)
        nulls = current_call_nulls(self)
        entry_id, seq = self.counter.next_id()
        if guard_answer:
            repeated_of = entry_id
        entry = build_entry(
            entry_id=entry_id,
            seq=seq,
            agent=self.agent,
            tool=tool,
            args=args,
            server=server,
            output=output if not_shown is None else not_shown_record(not_shown),
            ok=ok,
            error=error,
            started_at=started_at,
            duration_ms=duration_ms,
            waited_ms=waited_ms,
            stage=self.stage,
            repeated_of=repeated_of,
            remediation=remediation,
            args_repaired=args_repaired,
            args_raw=args_raw,
            args_nulls_dropped=nulls.dropped,
            args_nulls_withheld=nulls.withheld,
            model=self.model or None,
            not_shown=not_shown is not None,
            chars_dropped=int(cut or 0) if not_shown is None else 0,
            source=source,
            declared_name=declared_name,
            structured_content=structured_content,
            agent_role=self.agent_role,
            agent_tab=self.agent_tab,
            hints=hints,
        )
        if failure_note is not None and not entry.ok and not repeated_of:
            note = failure_note()
            if note:
                entry.remediation = f"{entry.remediation}; {note}" if entry.remediation else note
        entry._spill = self.spill
        if self.spill is not None and not repeated_of:
            self._keep_whole(
                entry, output, whole, whole_structure, lost=not_shown is not None or bool(cut)
            )
        self.entries.append(entry)
        self._by_id[entry.id] = entry
        # The function names a hash resolution read are names, and the event
        # and transcript scrub keeps them as written for the rest of the job.
        # Only this platform's own resolver answers them: an API hash
        # resolution (its declared kind) from a source the platform owns (the
        # pack, the analysis server). Another server's tool of that name is not.
        if entry.ok and not repeated_of and _platforms_own_resolution(entry):
            remember_resolved_names(output)
        # ``output``, the text the model was handed, and not ``entry.output``,
        # which the ledger has already trimmed and the byte budget may blank
        # to nothing. What the run saw is what a grounding check must search.
        # A repeat holds the note the guard wrote, not a tool's answer: the
        # answer is the earlier entry's, and the corpus already has it.
        if self.corpus is not None and not repeated_of:
            try:
                self.corpus.remember(entry.id, tool, output)
            except Exception:  # noqa: BLE001 — a record is never worth a lost call
                pass
        emit_tool_call_finished(
            self.sink,
            stage=self.stage,
            agent=self.agent,
            tool=tool,
            server=server,
            evidence_id=entry.id,
            # The entry's answer, not the caller's. Whether a call succeeded is
            # decided once, in ``build_entry``, which is the only place that
            # reads a *returned* structured error and turns it into a failure —
            # a caller that did not raise hands ``ok=True`` down and always
            # did. Reading the argument here published a green tick beside six
            # failed calls whose ledger rows said they had failed, and a reader
            # of the conversation could not see that anything had gone wrong.
            ok=entry.ok,
            duration_ms=duration_ms,
            # The entry's own output, which the ledger has already trimmed,
            # rather than the text the model reads: what goes to the console
            # is a headline, and the whole result is one ledger lookup away.
            # A failure travels as the remediation the tool offered and not as
            # its error text, which is the half that names hosts and paths.
            summary=summarize_result(
                entry.output, ok=entry.ok, remediation=entry.remediation or ""
            ),
            repeated_of=entry.repeated_of or "",
        )
        return entry

    def _keep_whole(
        self,
        entry: LedgerEntry,
        output: str,
        whole: str | None,
        structure: dict[str, Any] | None,
        *,
        lost: bool,
    ) -> None:
        """Keep the parts of the answer ``entry`` does not hold whole in the job's store."""
        from maljan.schemas.evidence import _structured_beside, parse_structured
        from maljan.schemas.evidence_spill import ANSWER, STRUCTURED_CONTENT, spill_into

        if whole is not None and lost:
            spill_into(entry, self.spill, ANSWER, whole)
        if structure and not entry.structured_from_server:
            text = whole if whole is not None else output
            if _structured_beside(structure, text, parse_structured(text)) is not None:
                spill_into(entry, self.spill, STRUCTURED_CONTENT, structure)

    def record_repeat(
        self,
        *,
        tool: str,
        args: dict[str, Any] | None,
        server: str | None,
        first: str,
        said: str,
        ok: bool = True,
        source: str | None = None,
        declared_name: str | None = None,
    ) -> LedgerEntry:
        """File a call the repeat guard answered without running, as a repeat of ``first``.

        The call was made, so it is written down and announced like any other:
        a chunk whose every call an earlier chunk had already answered left no
        entry and no event at all, and a reader of the ledger could not tell
        nine calls from none. ``repeated_of`` says which entry holds the
        answer, and ``said`` is the note the model was handed in its place.
        ``ok`` is false when the earlier entry is a failure. The model is never
        shown this entry's id: the answer it reads carries the earlier one,
        which is the one to cite.
        """
        self.call_started(tool=tool, args=args, server=server)
        return self.record(
            tool=tool,
            args=args,
            server=server,
            output=said,
            ok=ok,
            error=None if ok else said,
            started_at=time.time(),
            duration_ms=0,
            repeated_of=str(first),
            source=source,
            declared_name=declared_name,
        )

    def record_guard_answer(
        self,
        *,
        tool: str,
        args: dict[str, Any] | None,
        server: str | None,
        said: str,
        source: str | None = None,
        declared_name: str | None = None,
    ) -> LedgerEntry:
        """File a call a guard answered without running any tool, as the guard's answer.

        Filed and announced as a repeat is, so a reader of the ledger sees that
        the model asked and what it was told (``said``, which is empty when not
        even a line fitted). No entry holds an answer to it: its
        ``repeated_of`` is its own id, which every reader of a repeat already
        leaves out of the tool results, the run's grounding corpus, the
        evidence byte budget and the citable texts (a chain that comes round
        to itself holds no answer, ``schemas.evidence.repeat_holders``). It is
        a failure, since nothing answered, and never a tool failure: the model
        is never shown its id.
        """
        self.call_started(tool=tool, args=args, server=server)
        return self.record(
            tool=tool,
            args=args,
            server=server,
            output=said,
            ok=False,
            error=said or None,
            started_at=time.time(),
            duration_ms=0,
            guard_answer=True,
            source=source,
            declared_name=declared_name,
        )


# An address written with its ``0x`` prefix, and a bare one: hex digits with
# at least one decimal digit and at least one hex letter among them.
_PREFIXED_ADDRESS = re.compile(r"\s*0[xX]([0-9a-fA-F]{1,16})\s*")
_BARE_ADDRESS = re.compile(r"\s*((?=[0-9a-fA-F]*\d)(?=[0-9]*[a-fA-F])[0-9a-fA-F]{1,16})\s*")
# The words of an argument's name, as ``named_as_address`` splits them.
_NAME_WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")


def _address_spelling(name: str, value: Any, *, bare: bool = False) -> Any:
    """``value`` as a repeat is keyed by: an address as ``0x`` and its value, else as written.

    Only for an argument whose name says it takes an address in the binary,
    read from the name alone (``undeclared_tools.named_as_address``). A value
    written with ``0x`` is keyed by its value. A bare value is read as one only
    for a lookup (``bare``), only where it holds a decimal digit and a hex
    letter, and only for an argument whose name has no ``name`` word: a symbol
    such as ``add`` is no address, and a tool nobody declared may read bare
    digits in another base. Any other value is kept as written.
    """
    from maljan.core.undeclared_tools import named_as_address

    if not isinstance(value, str) or not named_as_address(name):
        return value
    found = _PREFIXED_ADDRESS.fullmatch(value)
    if found is None and bare and "name" not in _name_words(name):
        found = _BARE_ADDRESS.fullmatch(value)
    if found is None:
        return value
    return f"0x{int(found.group(1), 16):x}"


def _name_words(name: str) -> set[str]:
    return {word.lower() for word in _NAME_WORDS.findall(str(name or ""))}


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
        # The calls earlier chunks of the same analysis made (``seed``), kept
        # apart so a replayed conversation forgets its own calls and not these.
        self._seeded: dict[str, str] = {}
        self._seeded_failures: set[str] = set()
        # The earlier calls whose result the run did not keep whole (the byte
        # budget blanked it): nothing recorded can answer them, so one ask is
        # run, as a failure's retry is.
        self._seeded_reruns: set[str] = set()
        # What each answered earlier call recorded, by entry id: the result a
        # later chunk's identical call is answered with.
        self._recorded: dict[str, str] = {}
        # The seeded calls this conversation has already been answered about:
        # the first answer is the first time this model hears of the earlier
        # call, and only asking again after it is a repeat.
        self._told: set[str] = set()
        # The listings each decompile answered with, by the key the answer
        # prints (``validation.listed_function``), with the entry that holds
        # each. The printed name only finds candidates: it is text the sample
        # can shape (a forged or a shared name), so a call is a repeat only
        # when its listing is the held one, or a prefix of it.
        self._functions: dict[tuple[str, Any], list[tuple[str, str]]] = {}
        # Where each seeded entry was made: an earlier chunk of this input
        # (``EARLIER_CHUNK``) or an earlier round of this analysis
        # (``EARLIER_ROUND``), which is what its answer says.
        self._origins: dict[str, str] = {}
        # The server each earlier round's seeded call was made on, by its key:
        # a call on that server that may change state makes the seed stale
        # (:meth:`forget_round_seeds`).
        self._seed_servers: dict[str, str] = {}
        # The characters the platform left out of each seeded answer
        # (``platform_cut``), which its replay states as its first showing did.
        self._cuts: dict[str, int] = {}

    def _seeded_count(self, key: str) -> int:
        """Where a seeded call's count starts: one served retry for a failure or an unkept result."""
        entry = self._seeded.get(key)
        return 1 if entry in self._seeded_failures | self._seeded_reruns else self.SERVED

    def seed(
        self,
        tool: str,
        kwargs: dict[str, Any],
        entry_id: str,
        *,
        failed: bool = False,
        recorded: str | None = None,
        rerun: bool = False,
        origin: str = "",
        server: str = "",
        cut: int = 0,
    ) -> None:
        """A call an earlier chunk made: an identical one is answered from its entry, not run.

        A later chunk is a new conversation, and its loop re-ran the calls the
        earlier chunks had made. An answered call is seeded as already asked the
        served number of times, so the first identical call is answered without
        running: with the result its entry recorded when ``recorded`` is given
        (:meth:`recorded_answer`), and otherwise with ``repeat_notice`` naming
        the entry. A failed one (``failed``), and one whose result the run did
        not keep (``rerun``), is seeded as asked once, so one retry is served,
        as the guard serves any retry after a failure. No first touch counts
        toward the loop's repeats (:meth:`first_touch_of_seed`). ``origin`` is
        where the call was made (``EARLIER_CHUNK`` when not given, or
        ``EARLIER_ROUND``), which the answer to an identical call says.
        """
        key = self._key(tool, kwargs)
        self._seeded.setdefault(key, str(entry_id))
        self._origins.setdefault(str(entry_id), origin or EARLIER_CHUNK)
        if origin == EARLIER_ROUND:
            self._seed_servers.setdefault(key, str(server or ""))
        if failed:
            self._seeded_failures.add(str(entry_id))
        elif rerun:
            self._seeded_reruns.add(str(entry_id))
        elif recorded is not None:
            self._recorded.setdefault(str(entry_id), str(recorded))
            if cut:
                self._cuts.setdefault(str(entry_id), int(cut))
        self._first.setdefault(key, str(entry_id))
        self._count[key] = max(self._count.get(key, 0), self._seeded_count(key))

    def recorded_answer(self, tool: str, kwargs: dict[str, Any]) -> tuple[str, str] | None:
        """``(entry id, recorded result)`` for this conversation's first ask of an earlier call.

        Only for a call an earlier chunk made and answered, whose result was
        kept; the ask is marked as told, and it is not a repeat. ``None``
        otherwise, and for every later ask of it.
        """
        key = self._lookup_key(tool, kwargs)
        entry = self._seeded.get(key)
        if entry is None or entry not in self._recorded or key in self._told:
            return None
        self._told.add(key)
        return entry, self._recorded[entry]

    def recorded_cut(self, entry_id: str) -> int:
        """The characters the platform left out of a seeded answer when it was first shown."""
        return self._cuts.get(str(entry_id), 0)

    def first_touch_of_seed(self, tool: str, kwargs: dict[str, Any]) -> bool:
        """Whether this is the conversation's first ask of a seeded call; marks it asked.

        That ask is answered (refused with its entry, or a failure's one retry
        served) and not counted as a repeat: the model has not yet been told
        in this conversation. An ask after it counts as any repeat does.
        """
        key = self._lookup_key(tool, kwargs)
        if key not in self._seeded or key in self._told:
            return False
        self._told.add(key)
        return True

    def note_function(self, key: tuple[str, Any] | None, entry_id: str, listing: str) -> None:
        """Record that ``entry_id`` holds ``listing``, a listing of the function ``key`` names."""
        body = listing_body(listing)
        if key is None or not entry_id or not body:
            return
        self._functions.setdefault(key, []).append((str(entry_id), body))

    def function_entry(self, key: tuple[str, Any] | None, listing: str) -> str | None:
        """The entry whose listing already holds all of ``listing``, or ``None``.

        Content decides, never the name alone: the listing must be the held
        one, or the held one cut shorter. A listing under a name another entry
        printed that says anything else, or shows more, is new evidence.
        """
        body = listing_body(listing)
        if key is None or not body:
            return None
        for entry_id, held in self._functions.get(key, ()):
            if held.startswith(body):
                return entry_id
        return None

    def forget_round_seeds(self, server: str) -> int:
        """Drop every earlier round's seed made on ``server``: a call there may have changed it.

        Called after a call that is not read-only runs on ``server``. Its
        seeds' recorded answers may no longer be what the server would answer,
        so an identical call runs again. ``""`` is the server of a call whose
        server is unknown, and drops only the seeds whose server is unknown
        too. A chunk's seeds are kept. Returns how many were dropped.
        """
        dropped = 0
        for key, held in list(self._seed_servers.items()):
            if held != str(server or ""):
                continue
            entry = self._seeded.pop(key, None)
            del self._seed_servers[key]
            if entry is None:
                continue
            # Its answer, told or not, is no longer what the server holds: the
            # next identical call runs and answers for the call from then on.
            if self._first.get(key) == entry:
                del self._first[key]
                self._count.pop(key, None)
            dropped += 1
        return dropped

    def origin_of(self, entry_id: str) -> str:
        """Where a seeded entry was made: ``EARLIER_CHUNK`` or ``EARLIER_ROUND``."""
        return self._origins.get(str(entry_id), EARLIER_CHUNK)

    def seeded_failure(self, entry_id: str) -> bool:
        """Whether a seeded entry recorded a failure."""
        return str(entry_id) in self._seeded_failures

    @staticmethod
    def _key(tool: str, kwargs: dict[str, Any], *, bare: bool = False) -> str:
        """The call, canonically: same arguments in any order are the same call.

        An argument named for an address in the binary
        (``undeclared_tools.named_as_address``) is keyed by its value where it
        is written with ``0x`` (:func:`_address_spelling`): ``0x1360BC03868``
        and ``0x1360bc03868`` are one call. ``bare`` also reads a bare spelling
        as its value, the key a lookup tries second (:meth:`_lookup_key`).
        Every other argument is keyed as written.
        """
        canonical = {
            name: _address_spelling(name, value, bare=bare) for name, value in kwargs.items()
        }
        try:
            arguments = json.dumps(canonical, sort_keys=True, default=str)
        except (TypeError, ValueError):
            arguments = repr(sorted(canonical.items()))
        return f"{tool}({arguments})"

    def _lookup_key(self, tool: str, kwargs: dict[str, Any]) -> str:
        """The key an ask is counted and answered under.

        Its own key, unless that names nothing yet and the ask spells an
        address bare that an earlier call wrote with ``0x``: then that call's
        key. Never the other way: a ``0x`` ask is not answered from a call
        made with the bare spelling.
        """
        key = self._key(tool, kwargs)
        if key in self._first or key in self._seeded:
            return key
        read = self._key(tool, kwargs, bare=True)
        if read != key and (read in self._first or read in self._seeded):
            return read
        return key

    def answered_by(self, tool: str, kwargs: dict[str, Any]) -> str | None:
        """The entry that already answers this call, when it must not run again.

        A query and nothing else. What counts a repeat is ``note_repeat``, from
        the wrapper, so the served branch and the refused branch are counted in
        one place — counting here, where only the refused branch passes,
        produced a guard that could reach 1 per call and never its own
        threshold.
        """
        key = self._lookup_key(tool, kwargs)
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
        key = self._lookup_key(tool, kwargs)
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

    def ending_the_loop(self) -> bool:
        """Whether this loop has repeated itself often enough to be ended."""
        return self.served_repeats >= self.ENDS_AT

    def warning_of_the_end(self) -> bool:
        """Whether the notice being written is the one before the last."""
        return self.served_repeats >= self.WARNS_AT

    def note(self, tool: str, kwargs: dict[str, Any], entry_id: str) -> None:
        """Record that the call ran, and which entry first answered it."""
        key = self._lookup_key(tool, kwargs)
        self._count[key] = self._count.get(key, 0) + 1
        # A retry of an earlier chunk's failure, or of a call whose result the
        # run did not keep, answers for the call from here on: its entry is
        # the one a later refusal names.
        retried = self._seeded_failures | self._seeded_reruns
        if self._first.get(key) in retried and key in self._seeded:
            self._first[key] = entry_id
        self._first.setdefault(key, entry_id)


# A structured answer's fields that explain an outcome: a reason, an error or
# a message makes the answer one not to hand back later (the backend may have
# been unavailable then); a status is settled only with a word of completion.
_EXPLANATION_KEY_RE = re.compile(
    r"(?:^|_)(?:reason|error|errors|message|detail|details|warning)$", re.IGNORECASE
)
_STATUS_KEY_RE = re.compile(r"(?:^|_)status$", re.IGNORECASE)
_SETTLED_STATUS = frozenset(
    {"ok", "success", "succeeded", "complete", "completed", "done", "finished"}
)


def holds_a_settled_answer(entry: Any) -> bool:
    """Whether an entry's answer may be handed back for an identical call later: a settled one.

    Not for a call that failed (``ok`` false), an answer that only says the
    call failed (``undeclared_tools.prose_error``), or a structured answer
    that carries a reason, an error or a message, or a status that is not a
    word of completion ("pending", "running"): what it answered then may not
    be what it answers now. An empty answer is settled when nothing explains
    it ("matches": [] alone, or beside a status "ok"). Anything in doubt is
    not.
    """
    from maljan.core.undeclared_tools import prose_error

    if not bool(getattr(entry, "ok", True)) or getattr(entry, "repeated_of", None):
        return False
    if prose_error(getattr(entry, "output", "") or ""):
        return False
    structured = getattr(entry, "structured", None)
    if isinstance(structured, Mapping):
        for key, value in structured.items():
            if _EXPLANATION_KEY_RE.search(str(key)) and value:
                return False
            if _STATUS_KEY_RE.search(str(key)) and value is not None:
                if not isinstance(value, str) or value.strip().lower() not in _SETTLED_STATUS:
                    return False
    return True


def entry_server(entry: Any) -> str:
    """The server a ledger entry's call was made on: its server key, else its source, else ``""``."""
    return str(getattr(entry, "server", None) or getattr(entry, "source", None) or "")


# Where a call a loop's guard was seeded with was made.
EARLIER_CHUNK = "chunk"
EARLIER_ROUND = "round"


def seeded_repeat_guard(
    entries: Sequence[Any] | None, *, earlier_rounds: Sequence[Any] | None = None
) -> RepeatGuard:
    """A loop's repeat guard, seeded with the calls earlier chunks made (``RepeatGuard.seed``).

    ``earlier_rounds`` are the calls this agent made in earlier rounds of the
    run (a revision's first answer and the revisions before it), seeded first
    and answered the same way: a revision that repeats an identical call reads
    the result its entry recorded, and no tool runs.

    An answered call is seeded with the result its entry recorded, which is
    what a later identical call is answered with. A call whose entry does not
    hold the answer the model read — the byte budget blanked it, a ceiling cut
    it, or the conversation had no room for it — has nothing recorded to
    answer with and is served once more. An answer the tool-output guardrail
    cut is held as the model read it, which a second call would hand back.
    """
    guard = RepeatGuard()
    seeds = [
        *((entry, EARLIER_ROUND) for entry in earlier_rounds or ()),
        *((entry, EARLIER_CHUNK) for entry in entries or ()),
    ]
    for entry, origin in seeds:
        server = entry_server(entry)
        tool = str(getattr(entry, "tool", "") or "")
        entry_id = str(getattr(entry, "id", "") or "")
        args = getattr(entry, "args", None)
        if not (tool and entry_id and isinstance(args, dict)):
            continue
        # A repeat names the entry that answered it, which is seeded itself.
        if getattr(entry, "repeated_of", None):
            continue
        if not bool(getattr(entry, "ok", True)):
            guard.seed(tool, args, entry_id, failed=True, origin=origin, server=server)
            continue
        if not holds_its_answer(entry):
            guard.seed(tool, args, entry_id, rerun=True, origin=origin, server=server)
            continue
        output = str(getattr(entry, "output", "") or "")
        from maljan.schemas.answer_completeness import platform_cut

        guard.seed(
            tool,
            args,
            entry_id,
            recorded=output,
            origin=origin,
            server=server,
            cut=platform_cut(entry),
        )
        if entry_decompiles(entry):
            guard.note_function(listed_function(output), entry_id, output)
    return guard


# The marker both tool-output guardrails end a character cut with
# (``mcp_client.TRUNCATION_MARKER``, ``ghidra_http_client.TRUNCATION_MARKER``).
_CUT_MARKER = "\n\n[OUTPUT TRUNCATED]"


def listing_body(listing: str) -> str:
    """A listing without the guardrail's cut marker, so a cut copy is a prefix of the whole."""
    text = str(listing or "")
    return text[: -len(_CUT_MARKER)] if text.endswith(_CUT_MARKER) else text


def decompiles(tool: str, facts: Any = None) -> bool:
    """Whether a tool lists decompiled code, the way the decompiled-function list reads it.

    By the kind its declaration (``facts``) gives, else, for a tool that
    declares nothing, by its name (``core.undeclared_tools``).
    """
    from maljan.core.undeclared_tools import decompiles as by_declaration

    return by_declaration(facts, tool)


def _function_label(text: str, key: tuple[str, Any] | None) -> str:
    """The function's name as the listing prints it, for the notice."""
    from maljan.pipeline.validation import _listing_text, _signature_name

    printed = _signature_name(_listing_text(text))
    if printed:
        return printed
    return f"the function at {key[1]:#x}" if key and key[0] == "start" else "the same function"


def same_function_notice(name: str, entry_id: str) -> str:
    """What a decompile is told when its answer is a function an earlier entry already holds."""
    return (
        f"The answer above is {name} again, the function [{entry_id}] already holds: an "
        f"address inside a function is answered with the whole function. Cite [{entry_id}] "
        "for it."
    )


def earlier_chunk_answer(
    tool: str,
    entry_id: str,
    recorded: str,
    narrowing: Sequence[str] = (),
    *,
    origin: str = EARLIER_CHUNK,
    args: Mapping[str, Any] | None = None,
    cut: int = 0,
    charge: Callable[[str], str] | None = None,
) -> str:
    """What a later chunk's call an earlier chunk made is answered with.

    The result as its entry recorded it, stamped with that entry's id the way
    a call's own answer is stamped, and one sentence saying where it came
    from. No tool runs. The call is filed as a repeat of that entry
    (``EvidenceRecorder.record_repeat``), whose id the model is not shown:
    the entry that holds the result is the one to cite. ``cut`` is the
    characters the platform left out of it when it was first shown, which its
    completeness line states again; ``charge`` charges that line to the
    conversation it enters.
    """
    # The notice the original answer carried when it was shortened, read off
    # the recorded text the same way (``_stamp``).
    shortened = shortened_notice(recorded, narrowing=narrowing)
    # And how complete the recorded answer is, read off it the same way, with
    # the cut its first showing stated.
    complete = completeness_notice(
        recorded, narrowing=narrowing, args=args, cut=cut, shortened=bool(shortened)
    )
    if charge is not None:
        complete = charge(complete)
    shown = fenced(entry_id, recorded)
    said = earlier_chunk_sentence(tool, entry_id, origin=origin)
    return f"[{entry_id}]\n{shown}{shortened}{complete}\n\n{said}"


def earlier_chunk_sentence(tool: str, entry_id: str, *, origin: str = EARLIER_CHUNK) -> str:
    """The sentence under an earlier chunk's (or round's) result, and the note its repeat keeps."""
    if origin == EARLIER_ROUND:
        return (
            f"This call to {tool} with these arguments was made in an earlier round of this "
            f"analysis and is not run again: the text above is the result recorded in "
            f"[{entry_id}]."
        )
    return (
        f"This call to {tool} with these arguments was made in an earlier chunk of this "
        f"input and is not run again: the text above is the result recorded in [{entry_id}]."
    )


# What the model is told when its call ran on arguments that were closed off.
# It is on the result rather than only in the ledger, because the model is the
# one that can look at the answer and say the brackets were not what it meant.
def out_of_image_notice(noted: Sequence[str]) -> str:
    """The platform's line beside a failed answer given an address outside the image, else ``""``.

    ``noted`` holds the note the entry's remediation was given
    (``agents.image_range``), asked only of a failed entry.
    """
    note = noted[-1] if noted else ""
    return f"\n\n[platform] {note}" if note else ""


REPAIRED_NOTICE = (
    "\n\nThe arguments for this call stopped in the middle and were closed off "
    "before it ran. Read the answer against what you meant to ask, and call it "
    "again with the whole arguments if it is not."
)


def shortened_notice(text: str, *, narrowing: Sequence[str] = ()) -> str:
    """What the model is told when its answer had to be shortened, or ``""``.

    On the result rather than only in the ledger, for the same reason the
    repaired-arguments notice is: the model is the one that can ask again for
    the part it did not get. The answer already carries the arithmetic under
    its own key; this says what that key is, that asking again the same way
    gets the same answer, and which of this tool's own arguments reach what
    was left out — a model that met a shortened answer three times re-issued
    the identical call each time.

    ``narrowing`` is read off the schema the tool offered, in
    ``output_shortening.narrowing_arguments``, and the guardrail that
    shortened the answer kept room for the sentence those same names produce.
    """
    from maljan.agents.output_shortening import (
        BOOKKEEPING_KEY,
        our_key_in,
        shortening_sentence,
    )

    if BOOKKEEPING_KEY not in text:
        return ""
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return ""
    # Whichever key the map ended up under: a tool that owns the ordinary name
    # keeps it, and the sentence has to name the one the model will find.
    ours = our_key_in(parsed)
    if not ours:
        return ""
    return shortening_sentence(narrowing, key=ours)


def completeness_notice(
    text: str,
    *,
    narrowing: Sequence[str] = (),
    bounds: Sequence[str] = (),
    args: Mapping[str, Any] | None = None,
    cut: int = 0,
    shortened: bool = False,
    original: str | None = None,
) -> str:
    """The line under an answer known to be partial, or ``""`` (``schemas.answer_completeness``).

    Read off the answer as the model reads it, before any notice is appended:
    its own paging words and counts, the call's bounding arguments, and the
    characters the platform left out of it. An answer whose completeness
    cannot be read gets nothing. A reading that fails costs the call nothing
    and is logged. ``shortened`` says the platform shortened the answer as a
    document; the line is then read off the ``original`` when it is at hand,
    exactly as the guardrail measured the room it kept for it
    (``answer_completeness.shortened_line_room``).
    """
    from maljan.schemas.answer_completeness import completeness_line
    from maljan.schemas.evidence import parse_structured

    read = original if shortened and original is not None else text
    try:
        return completeness_line(
            parse_structured(read),
            narrowing=narrowing,
            bounds=() if shortened else bounds,
            args=args,
            cut=cut,
            text_chars=len(read),
            platform_shortened=shortened,
        )
    except Exception as exc:  # noqa: BLE001 — a notice is never worth a lost call
        logger.warning("completeness of a tool answer could not be read: %s", exc)
        return ""


# What both notices say on the call before the loop ends. One sentence, in one
# place, because the model reads it from whichever branch it lands in.
_ENDING_SENTENCE = (
    " One more repeated call ends this analysis and what you have gathered "
    "is written up as it stands."
)


def _do_something_else(tool: str, narrowing: Sequence[str]) -> str:
    """The half of both notices that says what to do instead.

    The arguments are the ones the tool's own schema offers for narrowing or
    paging an answer — ``limit``, ``offset`` and ``pattern`` for ``strings`` —
    so the sentence names what this tool can actually be asked differently
    rather than a hint written for one tool and repeated at every other. The
    shortening notice reads the same list, so one tool has one answer to the
    question however the model arrives at it.
    """
    from maljan.agents.output_shortening import narrowing_arguments

    named = ", ".join(f"`{name}`" for name in narrowing_arguments(narrowing))
    if named:
        return f"narrow it with {named}, or call another tool."
    return "call it with different arguments, or call another tool."


def repeat_notice(
    tool: str,
    entry_id: str,
    narrowing: Sequence[str] = (),
    *,
    last_warning: bool = False,
    failed: bool = False,
) -> str:
    """What the model is told instead of the same answer a third time.

    No tool ran, so no id is handed out: the call is filed as a repeat of the
    entry named here (``EvidenceRecorder.record_repeat``), counted apart from
    the calls that ran, and the model cites the earlier entry. It was once
    recorded as a successful call — ``ok=true``, ``duration_ms=0`` — which
    inflated the report's count of calls made and gave the model a citable
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
        f"{_do_something_else(tool, narrowing)}{_ENDING_SENTENCE if last_warning else ''}"
    )


def served_repeat_notice(
    tool: str,
    entry_id: str,
    narrowing: Sequence[str] = (),
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
        f"{_do_something_else(tool, narrowing)}{_ENDING_SENTENCE if last_warning else ''}"
    )


# The question a call is answered with when an argument's value is the name of
# its own parameter. A static analyst sent ``strings`` the pattern
# ``"\"pattern\""`` twice — the parameter's name, quoted — which searched for
# the word "pattern", matched eleven noise runs past the page it asked for, and
# spent two of its repeats on it. The call is not run and the argument is not
# rewritten: the model is asked for the value it meant.
SELF_NAMED_ARGUMENT_CODE = "tool.argument_names_its_parameter"

# The ways a value can be nothing but the name of its parameter: the name, or
# the name in the placeholder brackets a template or a schema example writes it
# in. One pair of quotes around the whole value is read off first, the way the
# tool servers read it.
_PLACEHOLDER_FORMS = ("{}", "<{}>", "{{{}}}", "${{{}}}", "[{}]")


def _names_its_parameter(name: str, value: Any) -> bool:
    from maljan.tools.arguments import unquoted

    if isinstance(value, list):
        return bool(value) and all(_names_its_parameter(name, item) for item in value)
    if not isinstance(value, str):
        return False
    read = unquoted(value).strip().lower()
    return any(read == form.format(name.lower()) for form in _PLACEHOLDER_FORMS)


def self_named_arguments(kwargs: dict[str, Any]) -> list[tuple[str, Any]]:
    """``(name, value)`` for each argument whose value is only its own parameter's name."""
    return [(name, value) for name, value in kwargs.items() if _names_its_parameter(name, value)]


def self_named_notice(tool: str, found: Sequence[tuple[str, Any]]) -> str:
    """What the model is told instead of an answer to a call that named its own parameters."""
    listed = "; ".join(f"`{name}` is {json.dumps(value)}" for name, value in found)
    return (
        f"{tool} was not run: {listed}, which is the name of the parameter itself and not a "
        "value for it. Call it again with the value you mean, or leave the argument out."
    )


def record_tools(
    tools: list[Any],
    recorder: EvidenceRecorder,
    repeats: RepeatGuard | None = None,
    repairs: ArgumentRepairs | None = None,
    context_budget: Any | None = None,
    on_question: Callable[[str], None] | None = None,
    image_range: Callable[[], ImageRange | None] | None = None,
) -> list[BaseTool]:
    """Every tool, each writing its call to ``recorder`` and stamping the id.

    ``on_question`` is told the code of every question a call is answered with
    instead of being run, so the run summary counts what the model was asked.
    ``image_range`` answers, when a call failed, the loaded image's range by
    the facts the run holds (``agents.image_range``): a failed call given an
    address outside it is told so.
    """
    return [
        _record_tool(tool, recorder, repeats, repairs, context_budget, on_question, image_range)
        for tool in tools
    ]


def _record_tool(
    tool: Any,
    recorder: EvidenceRecorder,
    repeats: RepeatGuard | None = None,
    repairs: ArgumentRepairs | None = None,
    context_budget: Any | None = None,
    on_question: Callable[[str], None] | None = None,
    image_range: Callable[[], ImageRange | None] | None = None,
) -> Any:
    """One tool, rebuilt so its result is recorded and stamped.

    Fail-safe in both directions: a tool this cannot rebuild faithfully is
    returned exactly as it was, and a tool that raises is recorded as a failed
    entry whose error text goes back to the model rather than being turned
    into an exception the loop has to survive. The one exception handed on
    after it is filed is :class:`SampleNotOpened`, which ends the loop.
    """
    from langchain_core.tools import StructuredTool

    from maljan.agents.output_shortening import bounding_arguments, narrowing_arguments
    from maljan.agents.server_names import ServerNamedTool, server_names, to_server_names
    from maljan.agents.tool_pinning import (
        declared_facts_of,
        declared_name_of,
        declared_source_of,
        server_of,
    )

    func = getattr(tool, "func", None)
    coroutine = getattr(tool, "coroutine", None)
    args_schema = getattr(tool, "args_schema", None)
    if (func is None and coroutine is None) or args_schema is None:
        return tool

    name = str(getattr(tool, "name", "") or "unknown")
    server = server_of(tool) or None
    # Where the tool's declaration lives (``core.tool_declarations``), read
    # from the tool itself as it was built and written on every entry.
    source = declared_source_of(tool)
    # The name its server declares it under (the original, where the request
    # offers it renamed): the declaration is read by that name, never by taking
    # a prefix off the offered one.
    declared_name = declared_name_of(tool)
    # What the tool declares about itself, read once for every call it makes.
    facts = declared_facts_of(tool)
    # What its own MCP server said of it when it was attached, kept on each
    # entry beside the declaration (``core.declared_reading.with_hints``).
    from maljan.agents.tool_pinning import SERVER_HINTS_METADATA_KEY

    hints = (getattr(tool, "metadata", None) or {}).get(SERVER_HINTS_METADATA_KEY)
    # By the server's names (``agents.server_names``), as every call below is.
    accepted = server_names(args_schema)
    # What the tool does with a ``null`` (``agents.null_arguments``): when it
    # drops or withholds any, the boundary names each such field of a call.
    null_rules = rules_of(args_schema)
    notes_nulls = bool(null_rules)

    # The arguments of this tool that reach a part its answer left out, read
    # off the same schema the model was offered. Per tool rather than per call:
    # what narrows an answer is a property of the tool, and every notice that
    # tells the model to ask differently names this one list — a model told to
    # narrow with one set of arguments on one turn and another set on the next
    # is being given two accounts of the same tool. The guardrail that shortens
    # an answer reserves room for the sentence naming exactly these.
    narrowing = narrowing_arguments(accepted)
    # Of those, the ones that bound how many rows come back: a call that passed
    # one and got a list exactly that long is told its page is full.
    bounds = bounding_arguments(accepted)
    # The read-again tool (``agents.tool_answer_clearing``): its answer is
    # another entry's, filed as a repeat of it.
    from maljan.agents.tool_answer_clearing import READS_EVIDENCE

    reads_evidence = bool((getattr(tool, "metadata", None) or {}).get(READS_EVIDENCE))
    # Whether the tool changes nothing and answers the same (``answers_again``).
    from maljan.agents.tool_pinning import answers_again

    reads_only = answers_again(tool)
    # Whether a failed call is held against the loaded image's range: the tool
    # declares an address argument and that it does not run the sample's code.
    from maljan.agents.image_range import locates_in_image, out_of_image_note

    locates = image_range is not None and locates_in_image(facts)

    def _outside(kwargs: dict[str, Any], noted: list[str]) -> Callable[[], str] | None:
        """The failure note for this call (``EvidenceRecorder.record``), kept in ``noted``."""
        if not locates or image_range is None:
            return None

        def _note() -> str:
            try:
                note = out_of_image_note(facts, kwargs, image_range())
            except Exception as exc:  # noqa: BLE001 — a note is never worth a lost call
                logger.debug("image range for '%s' not read (%s).", name, exc)
                note = ""
            noted.append(note)
            return note

        return _note

    def _charged(line: str, reserved: bool = False) -> str:
        """``line``, charged to this agent's conversation: it enters it beside the answer.

        Not where the guardrail kept the line's room for this call's answer
        (``reserved``, ``context_window.note_answer_line_room``): beside a text
        cut or a summary (``answer_completeness.cut_line_room``) or from a
        shortening's target (``answer_completeness.shortened_line_room``).
        """
        from maljan.llm.context_window import ContextBudget

        if line and not reserved and isinstance(context_budget, ContextBudget):
            context_budget.charge(len(line), recorder.agent)
        return line

    def _the_room_is_gone(kwargs: dict[str, Any]) -> str | None:
        """The line a call gets once this agent's conversation has no room left.

        The first answer that would not fit was met by the guardrail, which
        told the model so in a sentence and ended this agent's tool phase. From
        here the tool is **not run**: running it would spend a server's time on
        an answer with nowhere to go, and repeating the sentence would pay a
        few hundred characters a round to say a thing already said. What a
        model that asks anyway gets is one short charged line, and the
        run-state block carries the same fact every turn at no cumulative cost.

        The ask is filed as the guard's answer (``record_guard_answer``): no
        tool ran, and the entry holds no evidence a report could cite.
        """
        from maljan.llm.context_window import TOOL_PHASE_ENDED_NOTICE, ContextBudget

        if not isinstance(context_budget, ContextBudget):
            return None
        if not context_budget.out_of_room(recorder.agent):
            return None
        if not context_budget.room_for(len(TOOL_PHASE_ENDED_NOTICE), recorder.agent):
            # Not even a line fits. Handing one over anyway is how a loop that
            # had already stopped being given answers walked past the window a
            # word at a time.
            said = ""
        else:
            context_budget.charge(len(TOOL_PHASE_ENDED_NOTICE), recorder.agent)
            said = TOOL_PHASE_ENDED_NOTICE
        recorder.record_guard_answer(
            tool=name,
            args=kwargs,
            server=server,
            source=source,
            declared_name=declared_name,
            said=said,
        )
        return said

    # How often each self-named call has been asked about in this loop. The
    # first time is a question; asking the same thing again is a repeat, and
    # counts toward the end the repeat guard gives a loop that only repeats.
    asked_about: dict[str, int] = {}

    def _names_its_own_parameter(kwargs: dict[str, Any]) -> str | None:
        """The question for a call whose argument is its own parameter's name, if it is one.

        Not run, and filed as the guard's answer (``record_guard_answer``): no
        tool ran and no earlier entry holds an answer to it, so the entry holds
        no evidence a report could cite. The model is told which argument and
        why, and the value is left exactly as it wrote it.
        """
        found = self_named_arguments(kwargs)
        if not found:
            return None
        key = RepeatGuard._key(name, kwargs)
        asked_about[key] = asked_about.get(key, 0) + 1
        if asked_about[key] > 1 and repeats is not None:
            repeats.note_repeat()
        logger.warning(
            "%s: %s was not run; its argument names its own parameter (%s).",
            recorder.agent,
            name,
            ", ".join(argument for argument, _value in found),
        )
        if on_question is not None:
            try:
                on_question(SELF_NAMED_ARGUMENT_CODE)
            except Exception as exc:  # noqa: BLE001 — a count never costs a call
                logger.debug("the question was not counted (%s).", exc)
        notice = self_named_notice(name, found)
        recorder.record_guard_answer(
            tool=name,
            args=kwargs,
            server=server,
            source=source,
            declared_name=declared_name,
            said=notice,
        )
        return notice

    def _already_answered(kwargs: dict[str, Any]) -> str | None:
        """The note for a call that has been made twice already, if it has."""
        if repeats is None:
            return None
        first = repeats.answered_by(name, kwargs)
        if first is None:
            return None
        # An earlier chunk's call, asked for the first time in this
        # conversation: answered with the result that call recorded, not run
        # and not a repeat.
        recorded = repeats.recorded_answer(name, kwargs)
        if recorded is not None:
            earlier, _text = recorded
            recorder.record_repeat(
                tool=name,
                args=kwargs,
                server=server,
                source=source,
                declared_name=declared_name,
                first=earlier,
                said=earlier_chunk_sentence(name, earlier, origin=repeats.origin_of(earlier)),
            )
            # Charged whole: this answer went through no guardrail now.
            return earlier_chunk_answer(
                name,
                *recorded,
                narrowing,
                origin=repeats.origin_of(earlier),
                args=kwargs,
                cut=repeats.recorded_cut(earlier),
                charge=_charged,
            )
        if not repeats.first_touch_of_seed(name, kwargs):
            repeats.note_repeat()
        failed = recorder.entry_failed(first) or repeats.seeded_failure(first)
        notice = repeat_notice(
            name,
            first,
            narrowing,
            last_warning=repeats.warning_of_the_end(),
            failed=failed,
        )
        # Filed as a repeat of the entry that holds the answer, and the model
        # is handed the notice with no id of its own: an id here would be one
        # a report could cite for evidence that does not exist.
        recorder.record_repeat(
            tool=name,
            args=kwargs,
            server=server,
            source=source,
            declared_name=declared_name,
            first=first,
            said=notice,
            ok=not failed,
        )
        return notice

    def _note(kwargs: dict[str, Any], entry_id: str) -> None:
        """Count the call against the repeat budget, however it turned out.

        A call that raised is a call. Counting only the ones that returned left
        a tool that throws on the same arguments — an unreachable server, a
        path the sidecar will never read — free to be re-run for the whole step
        budget, which is the one case the guard exists for.
        """
        if repeats is not None:
            repeats.note(name, kwargs, entry_id)
            # A call that may change its server's state makes every earlier
            # round's answer from that server stale.
            if not reads_only:
                repeats.forget_round_seeds(server or source or "")

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
            # An earlier chunk's failure, retried for the first time in this
            # conversation: served as a first call, with no steering.
            if repeats.first_touch_of_seed(name, kwargs):
                return None
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
            narrowing,
            last_warning=repeats.warning_of_the_end(),
            failed=failed,
        )
        return f"\n\n{notice}"

    def _was_repaired(kwargs: dict[str, Any]) -> str | None:
        """The arguments as the model wrote them, when this call was closed off."""
        return repairs.take(name, kwargs) if repairs is not None else None

    def _read_again(
        kwargs: dict[str, Any],
        started: float,
        wall_clock: float,
        text: str,
        repeated: str | None,
        cut: int | None,
    ) -> str | None:
        """A read-again answer, filed and shown as a repeat of the entry it reads; ``None`` if unfiled.

        The way a repeated decompilation is filed: the entry is a repeat of
        the one that holds the answer, keeping only a note, so the ledger, the
        byte budget and the run's corpus hold the answer once and no second
        citable id exists; the model reads the answer under the original id.
        """
        from maljan.agents.tool_answer_clearing import read_again_note

        wanted = str(kwargs.get("evidence_id") or "").strip().lower()
        holder = recorder.holder_of(wanted)
        if not recorder.filed(holder):
            return None
        recorder.record(
            tool=name,
            args=kwargs,
            server=server,
            source=source,
            declared_name=declared_name,
            hints=hints,
            output=read_again_note(holder),
            ok=not recorder.entry_failed(holder),
            started_at=wall_clock,
            duration_ms=int((time.monotonic() - started) * 1000),
            repeated_of=holder,
            cut=cut,
        )
        _note(kwargs, holder)
        # A page read past what the entry stored is read by the model and by no
        # corpus entry yet: kept under its own key, so a value on it is found.
        if recorder.corpus is not None and (kwargs.get("offset") or kwargs.get("limit")):
            recorder.corpus.remember(
                f"{holder}@{kwargs.get('offset') or 0}+{kwargs.get('limit') or ''}", name, text
            )
        shortened = shortened_notice(text, narrowing=narrowing)
        # How complete the held answer is: the cut its first showing stated or
        # the cut this read made, whichever is more, and the paging arguments
        # of the tool that made it. Charged whole: the room this read's own
        # guardrail kept was for a line naming no argument.
        held = recorder.entry_of(holder)
        held_args = getattr(held, "args", None)
        paged = bool(kwargs.get("offset") or kwargs.get("limit"))
        complete = _charged(
            completeness_notice(
                text,
                # A page states its own cut only: the held answer's cut and its
                # tool's paging arguments are not what the page is.
                narrowing=() if paged else recorder.narrowing_of(holder),
                args=None if paged or not isinstance(held_args, Mapping) else held_args,
                cut=int(cut or 0) if paged else max(recorder.cut_of(holder), int(cut or 0)),
                shortened=bool(shortened),
            )
        )
        failed = recorder.entry_failed(holder)
        return f"[{holder}]\n{fenced(holder, text)}{shortened}{complete}" + _steering(
            kwargs, repeated, failed=failed
        )

    def _stamp(
        kwargs: dict[str, Any],
        started: float,
        wall_clock: float,
        value: Any,
        repeated: str | None,
        not_shown: int | None = None,
        cut: int | None = None,
        whole: str | None = None,
        whole_structure: dict[str, Any] | None = None,
        line_room: bool = False,
        waited_ms: int = 0,
    ) -> str:
        text = result_text(value)
        raw = _was_repaired(kwargs)
        if reads_evidence and not_shown is None:
            read = _read_again(kwargs, started, wall_clock, text, repeated, cut)
            if read is not None:
                return read
        # The function a decompile answered with, and the entry that already
        # holds it: a call given an address inside a function an earlier call
        # read is answered with that same function, and is a repeat of it
        # whatever address it was given; a served identical call whose listing
        # the holder holds is one too. Content decides (``function_entry``).
        # Not for an answer the conversation had no room for.
        function = (
            listed_function(text)
            if repeats is not None and decompiles(name, facts) and not_shown is None
            else None
        )
        holder = repeats.function_entry(function, text) if repeats is not None else None
        holder = recorder.holder_of(holder) if holder else None
        same = ""
        if holder:
            same = (
                served_repeat_notice(
                    name, holder, narrowing, last_warning=repeats.warning_of_the_end()
                )
                if repeated is not None and repeats is not None
                else same_function_notice(_function_label(text, function), holder)
            )
        noted: list[str] = []
        entry = recorder.record(
            tool=name,
            args=kwargs,
            server=server,
            source=source,
            declared_name=declared_name,
            hints=hints,
            failure_note=_outside(kwargs, noted),
            # A repeat keeps the note, not a second copy of the listing the
            # entry it names already holds.
            output=same or text,
            started_at=wall_clock,
            duration_ms=int((time.monotonic() - started) * 1000),
            waited_ms=waited_ms,
            repeated_of=holder,
            args_repaired=raw is not None,
            args_raw=raw,
            not_shown=not_shown,
            cut=cut,
            structured_content=None if same else structured_content_of(value),
            whole=whole,
            whole_structure=whole_structure,
        )
        # Kept by the entry's id, so a read-again answer of it names this
        # tool's paging arguments, not its own.
        recorder.note_narrowing(entry.id, narrowing)
        # A repeat is noted under the entry that holds its answer, so a later
        # served or refused identical call names that entry, never the repeat.
        _note(kwargs, entry.repeated_of or entry.id)
        if same:
            # Still handed the answer: the earlier listing may be gone from
            # what the window keeps of this conversation. It is stamped with
            # the entry that holds the function, which is the one to cite.
            shortened = shortened_notice(text, narrowing=narrowing)
            complete = _charged(
                completeness_notice(
                    text,
                    narrowing=narrowing,
                    bounds=bounds,
                    args=kwargs,
                    cut=int(cut or 0),
                    shortened=bool(shortened),
                    original=whole,
                ),
                line_room,
            )
            repaired = REPAIRED_NOTICE if raw is not None else ""
            return (
                f"[{holder}]\n{fenced(str(holder), text)}{repaired}{shortened}{complete}\n\n{same}"
            )
        if repeats is not None and entry.ok and function is not None:
            repeats.note_function(function, entry.id, text)
        # Read off the answer itself, before any notice is appended to it: a
        # notice is prose and prose does not parse.
        shortened = shortened_notice(text, narrowing=narrowing)
        # How complete the answer is known to be (``schemas.answer_completeness``):
        # its own paging words, the call's bounding arguments, and the cut the
        # platform made, which the entry holds as the coverage record reads it.
        from maljan.schemas.answer_completeness import platform_cut

        complete = _charged(
            completeness_notice(
                text,
                narrowing=narrowing,
                bounds=bounds,
                args=kwargs,
                cut=platform_cut(entry),
                shortened=bool(shortened),
                original=whole,
            ),
            line_room,
        )
        # The answer as the one view shows it (``agents.tool_fence``): a text
        # answer inside a fence its content cannot close, a JSON one with its
        # raw breaks escaped; the platform's own notices stand outside it.
        text = fenced(entry.id, text)
        if raw is not None:
            text = f"{text}{REPAIRED_NOTICE}"
        text = f"{text}{shortened}{complete}{_charged(out_of_image_notice(noted))}"
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
        sent: dict[str, Any] | None = None,
        waited_ms: int = 0,
    ) -> str:
        message = f"{type(exc).__name__}: {exc}"
        raw = _was_repaired(kwargs)
        noted: list[str] = []
        entry = recorder.record(
            tool=name,
            args=sent if sent is not None else kwargs,
            server=server,
            source=source,
            declared_name=declared_name,
            hints=hints,
            failure_note=_outside(kwargs, noted),
            output=message,
            ok=False,
            error=message,
            started_at=wall_clock,
            duration_ms=int((time.monotonic() - started) * 1000),
            waited_ms=waited_ms,
            args_repaired=raw is not None,
            args_raw=raw,
        )
        _note(kwargs, entry.id)
        # The failure's type is the platform's word; a third party's message
        # may repeat what the call was given or what the sample holds, so it
        # is shown as a tool answer is (``agents.tool_fence``), never as a line
        # of the platform's own. A refusal the platform composed is its own
        # sentence and stays as written (``platform_refusal``).
        outside = _charged(out_of_image_notice(noted))
        if platform_refusal(exc):
            return (
                f"[{entry.id}] tool call failed: {message}{outside}"
                f"{_steering(kwargs, repeated, failed=True)}"
            )
        said = str(exc)
        shown = f"\n{fenced(entry.id, said)}" if said.strip() else ""
        return (
            f"[{entry.id}] tool call failed: {type(exc).__name__}{shown}{outside}"
            f"{_steering(kwargs, repeated, failed=True)}"
        )

    def _stopped(
        kwargs: dict[str, Any],
        started: float,
        wall_clock: float,
        exc: SampleNotOpened,
        repeated: str | None,
        waited_ms: int = 0,
    ) -> str:
        """File a call that met an unopenable sample, and end this loop if it is this agent's.

        The entry is a failed call with the provider's sentence, as any raised
        call is. Then the exception goes on and ends this agent's loop — unless
        it already ended another agent's: an ask of an agent whose sample did
        not open is a failed ask for the agent that asked, which carries on.
        The entry records the arguments the call was actually sent with when
        the platform held them to its own path, not the ones the model wrote.
        """
        stamped = _stamp_error(
            kwargs, started, wall_clock, exc, repeated, sent=exc.sent_args, waited_ms=waited_ms
        )
        if exc.stopped_agent in (None, recorder.agent):
            exc.stopped_agent = recorder.agent
            raise exc
        return stamped

    def _began(issued: float, answer: CallAnswer | None) -> tuple[float, int]:
        """The moment the call started running, and how long it waited for it.

        ``issued`` is when the wrapper was entered; a call queued behind a
        server's slot began later, and the transport says when
        (``CallAnswer.began``). The call's duration runs from that moment, so
        a tool that waited is not charged for the tool it waited behind; the
        wait is its own figure. A call nothing queued began when it was issued.
        """
        began = getattr(answer, "began", None)
        if began is None or began < issued:
            return issued, 0
        return began, int((began - issued) * 1000)

    wrapped_func = None
    wrapped_coroutine = None
    if func is not None:

        def wrapped_func(**kwargs: Any) -> str:  # noqa: F811
            nulls = take_call_nulls(kwargs, null_rules) if notes_nulls else NO_NULLS
            # What is recorded, cited and keyed for a repeat is what is sent.
            kwargs = to_server_names(args_schema, kwargs)
            with nulls_of_call(recorder, nulls):
                return _recorded_func(kwargs)

        def _recorded_func(kwargs: dict[str, Any]) -> str:
            # The guards first. A call the repeat guard answers is filed and
            # announced as a repeat of the entry that holds its answer
            # (``record_repeat``); a call another guard answers is filed and
            # announced as the guard's answer (``record_guard_answer``). Each
            # files its own start and finish, so the console never holds a
            # bubble open for a call that never ran.
            ended = _the_room_is_gone(kwargs)
            if ended is not None:
                return ended
            question = _names_its_own_parameter(kwargs)
            if question is not None:
                return question
            answered = _already_answered(kwargs)
            if answered is not None:
                return answered
            recorder.call_started(tool=name, args=kwargs, server=server)
            # Two clocks: the wall clock says when the call happened and
            # correlates with a log line, the monotonic one measures how long
            # it took and cannot go backwards.
            started, wall_clock = time.monotonic(), time.time()
            repeated = _served_again(kwargs)
            call_answer: CallAnswer | None = None
            try:
                # Outside the analyst's repeated-claims watch: a model a tool
                # calls (a summariser, another agent asked) is not the
                # analyst's answer (``BaseAnalyst._claims_watched``).
                with answering_for(recorder.agent) as call_answer, watching(None):
                    value = func(**kwargs)
                ran, waited = _began(started, call_answer)
                return _stamp(
                    kwargs,
                    ran,
                    wall_clock,
                    value,
                    repeated,
                    call_answer.not_shown,
                    call_answer.cut,
                    call_answer.whole,
                    call_answer.structure,
                    call_answer.line_room,
                    waited_ms=waited,
                )
            except SampleNotOpened as exc:
                ran, waited = _began(started, call_answer)
                return _stopped(kwargs, ran, wall_clock, exc, repeated, waited)
            except Exception as exc:  # noqa: BLE001 — a failed call is evidence
                ran, waited = _began(started, call_answer)
                return _stamp_error(kwargs, ran, wall_clock, exc, repeated, waited_ms=waited)

    if coroutine is not None:

        async def wrapped_coroutine(**kwargs: Any) -> str:  # noqa: F811
            nulls = take_call_nulls(kwargs, null_rules) if notes_nulls else NO_NULLS
            # What is recorded, cited and keyed for a repeat is what is sent.
            kwargs = to_server_names(args_schema, kwargs)
            with nulls_of_call(recorder, nulls):
                return await _recorded_coroutine(kwargs)

        async def _recorded_coroutine(kwargs: dict[str, Any]) -> str:
            ended = _the_room_is_gone(kwargs)
            if ended is not None:
                return ended
            question = _names_its_own_parameter(kwargs)
            if question is not None:
                return question
            answered = _already_answered(kwargs)
            if answered is not None:
                return answered
            recorder.call_started(tool=name, args=kwargs, server=server)
            started, wall_clock = time.monotonic(), time.time()
            repeated = _served_again(kwargs)
            call_answer: CallAnswer | None = None
            try:
                # Named for the length of the call so the guardrail — two
                # layers down, behind a toolkit every agent of the job shares —
                # charges this answer to the conversation it is entering. The
                # name survives the ``asyncio.to_thread`` both tool paths hand
                # the guardrail to, because that copies the context.
                with answering_for(recorder.agent) as call_answer, watching(None):
                    value = await coroutine(**kwargs)
                ran, waited = _began(started, call_answer)
                return _stamp(
                    kwargs,
                    ran,
                    wall_clock,
                    value,
                    repeated,
                    call_answer.not_shown,
                    call_answer.cut,
                    call_answer.whole,
                    call_answer.structure,
                    call_answer.line_room,
                    waited_ms=waited,
                )
            except SampleNotOpened as exc:
                ran, waited = _began(started, call_answer)
                return _stopped(kwargs, ran, wall_clock, exc, repeated, waited)
            except Exception as exc:  # noqa: BLE001 — a failed call is evidence
                ran, waited = _began(started, call_answer)
                return _stamp_error(kwargs, ran, wall_clock, exc, repeated, waited_ms=waited)

    try:
        # The tool's own class where it opts in (``keeps_named_args``): a tool
        # that keeps to the arguments a call named keeps doing so in the recorder.
        # Any other is offered each argument under its server's own name
        # (``agents.server_names``), as the tool it wraps was.
        builder = (
            type(tool)
            if isinstance(tool, StructuredTool) and getattr(tool, "keeps_named_args", False)
            else ServerNamedTool
        )
        if notes_nulls:
            builder = noting_class(builder)
        return builder.from_function(
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
