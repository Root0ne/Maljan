"""``read_evidence`` for a model call made outside a tool loop.

The verdict, the technique question, the report's narrative and sections, its
question round and its section agreement round each ask the model over what
the run gathered, and used to send no tool: an entry the prompt shortened, or
one an answer cites and the prompt does not show, could not be read. Each now
offers ``read_evidence`` from its first turn — the tool an analyst's and the
mediator's loops offer, with the same definition — answered from the run's
ledger by id, paged where an answer is long.

**The loop.** A reply that reads (every call it makes is ``read_evidence``)
is answered with what each read returns and the conversation is sent again,
until a reply makes no read: that reply is the call's answer, read exactly as
the call's answer always was. A reply that calls another tool alongside a
read (a structured call's schema tool) is the answer too, kept without its
reads, so the other call is the first every reader of the answer takes.
Nothing caps the reads: each turn is the call's own model call, under its own
deadline, spend admission and usage record, and the call's wall clock covers
them all. The analysts' repeat rule holds: an identical read is served twice,
the second with the analysts' served-repeat notice where the entry it reads
recorded a failure, refused after that with where the answer already is, and
the loop ends after ``RepeatGuard.ENDS_AT`` refusals, the reply that read
again kept without its calls. A dropped socket is retried by the caller's
``retry_on_connection_error`` around the whole loop: the call starts again
from its first turn, under the admission that turn had, and the reads made
before the drop stay counted.

**What a read returns.** The entry's stored answer under its own id, fenced as
every tool answer is (``tool_fence``); a repeat's id reads the entry that holds
its answer; an answer the byte budget blanked is read from the job's store of
whole answers, and a paged read pages through the whole answer kept there.
Sized by the job's answer guardrail where it has one. A read is answered from
the ledger and filed nowhere: the entry it reads is already the run's, and a
report built over a fixed ledger could not cite a new one.

**A model that cannot bind it** is asked in the call it always was, with no
tool, and the run's degradation reasons say so once per agent.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Iterable, Mapping
from contextlib import AbstractContextManager, nullcontext
from typing import Any

from maljan.agents.tool_answer_clearing import (
    READ_EVIDENCE_TOOL,
    THE_RUNS_LEDGER,
    StoredCopy,
    read_evidence_tool,
)
from maljan.core.logger import logger


def _field(row: Any, name: str) -> Any:
    return row.get(name) if isinstance(row, Mapping) else getattr(row, name, None)


def not_bound_reason(agent: str) -> str:
    """The degradation reason for an agent whose model could not bind ``read_evidence``."""
    return (
        f"agent '{agent}': its model could not bind {READ_EVIDENCE_TOOL}; its calls outside "
        "a tool loop are asked without it"
    )


def say_once(reasons: list[Any] | None, reason: str) -> bool:
    """Append ``reason`` to ``reasons`` unless it is there; whether it was appended."""
    if not isinstance(reasons, list) or reason in reasons:
        return False
    reasons.append(reason)
    return True


class LedgerReads:
    """``read_evidence`` over one run's ledger, for the calls made outside a tool loop.

    ``entries`` are the run's ledger rows (``LedgerEntry`` or their dumps).
    ``sizer`` is the job's answer guardrail (``ServerRegistry.answer_sizer``),
    ``spill`` the job's store of whole answers; either may be ``None``.
    ``tally`` is the job's count of these reads (:func:`reads_tally`), or
    ``None`` to count nothing; ``container`` is the job's container, whose
    count is made on the first :meth:`bind` that succeeds, so a model that
    cannot bind the read records none. Built once per stage and shared by its
    calls, so every call offers the one tool definition, byte for byte.
    """

    def __init__(
        self,
        entries: Iterable[Any] = (),
        *,
        sizer: Any = None,
        spill: Any = None,
        tally: dict[str, Any] | None = None,
        container: Any = None,
    ):
        rows: dict[str, Any] = {}
        for row in entries or ():
            key = str(_field(row, "id") or "").strip().lower()
            if key and key not in rows:
                rows[key] = row
        self._rows = rows
        self._spill = spill
        self.tally = tally
        self._container = container
        self.tool = read_evidence_tool(
            self._stored_answer, sizer, self._stored_copy, holds=THE_RUNS_LEDGER
        )

    def __len__(self) -> int:
        return len(self._rows)

    def holder(self, entry_id: str) -> str:
        """The id of the entry holding ``entry_id``'s answer, or ``""`` for none the ledger holds."""
        wanted = str(entry_id or "").strip().lower()
        seen: set[str] = set()
        while wanted in self._rows and wanted not in seen:
            seen.add(wanted)
            first = str(_field(self._rows[wanted], "repeated_of") or "").strip().lower()
            if not first:
                return wanted
            wanted = first
        return ""

    def row(self, entry_id: str) -> Any:
        """The ledger row holding ``entry_id``'s answer, or ``None`` for an id the ledger does not hold."""
        holder = self.holder(entry_id)
        return self._rows[holder] if holder else None

    def failed(self, entry_id: str) -> bool:
        """Whether the entry holding ``entry_id``'s answer recorded a failure."""
        holder = self.holder(entry_id)
        return bool(holder) and _field(self._rows[holder], "ok") is False

    def lookup(self, entry_id: str) -> str | None:
        """The stored answer ``entry_id`` reads, or ``None`` for an id the ledger does not hold."""
        return self._stored_answer(entry_id)

    def stored_copy(self, entry_id: str) -> StoredCopy | None:
        """The whole answer the job's store keeps for ``entry_id``, or ``None``."""
        return self._stored_copy(entry_id)

    def _spilled(self, entry_id: str, parts: tuple[str, ...]) -> StoredCopy | None:
        reader = getattr(self._spill, "read", None)
        holder = self.holder(entry_id)
        if not callable(reader) or not holder:
            return None
        refs = [ref for ref in _field(self._rows[holder], "spilled") or () if isinstance(ref, dict)]
        for part in parts:
            for ref in refs:
                digest = str(ref.get("sha256") or "")
                if ref.get("part") == part and ref.get("key") and digest:

                    def read(offset: int, length: int | None, digest: str = digest) -> Any:
                        return reader(digest, offset, length)

                    return StoredCopy(total=int(ref.get("bytes") or 0), read=read)
        return None

    def _stored_copy(self, entry_id: str) -> StoredCopy | None:
        from maljan.schemas.evidence_spill import ANSWER, OUTPUT

        return self._spilled(entry_id, (ANSWER, OUTPUT))

    def _stored_answer(self, entry_id: str) -> str | None:
        from maljan.schemas.evidence_spill import OUTPUT

        holder = self.holder(entry_id)
        if not holder:
            return None
        output = str(_field(self._rows[holder], "output") or "")
        if output:
            return output
        # Blanked by the byte budget after the model read it: the store keeps it whole.
        copy = self._spilled(holder, (OUTPUT,))
        data = copy.read(0, None) if copy is not None else None
        return bytes(data).decode("utf-8", errors="replace") if data else output

    def read(self, args: Any, *, again: bool = False) -> str:
        """What one ``read_evidence`` call is answered with. Never raises.

        A partial answer says so under it, as the analysts' read-again says
        it: the line a shortened answer carries, and how complete the held
        answer is, by the cut the entry's first showing stated or the cut this
        read made, whichever is more, and the arguments of the call that made
        it; a page states its own cut only. ``again`` is a served repeat:
        where the entry it reads recorded a failure, it carries the notice the
        analysts' read-again carries then (``evidence_recorder.served_repeat_notice``).
        """
        from maljan.agents.evidence_recorder import (
            completeness_notice,
            served_repeat_notice,
            shortened_notice,
        )
        from maljan.agents.output_shortening import narrowing_arguments
        from maljan.agents.tool_fence import fenced
        from maljan.llm.context_window import answering_for, current_agent
        from maljan.schemas.answer_completeness import platform_cut
        from maljan.tools.errors import BAD_ARGUMENT, tool_error

        try:
            # Under the agent already answered for, so the guardrail charges
            # as it did; the call's record says what this read cut.
            with answering_for(current_agent()) as answer:
                text = str(self.tool.invoke(dict(args) if isinstance(args, Mapping) else args))
        except Exception as exc:  # noqa: BLE001 — a malformed call is answered, not raised
            return json.dumps(tool_error(BAD_ARGUMENT, str(exc), tool=READ_EVIDENCE_TOOL))
        holder = self.holder(str(_field(args, "evidence_id") or "")) if args else ""
        if not holder:
            return text
        narrowing = narrowing_arguments(getattr(self.tool, "args", None) or ())
        cut = int(answer.cut or 0)
        paged = bool(_field(args, "offset") or _field(args, "limit"))
        row = self._rows[holder]
        held_args = _field(row, "args")
        shortened = shortened_notice(text, narrowing=narrowing)
        complete = completeness_notice(
            text,
            args=None if paged or not isinstance(held_args, Mapping) else held_args,
            cut=cut if paged else max(platform_cut(row), cut),
            shortened=bool(shortened),
        )
        said = f"[{holder}]\n{fenced(holder, text)}{shortened}{complete}"
        if again and self.failed(holder):
            notice = served_repeat_notice(READ_EVIDENCE_TOOL, holder, narrowing, failed=True)
            said += f"\n\n{notice}"
        return said

    def _count(self, call: str, *, found: bool = True, refused: bool = False) -> None:
        tally = self.tally
        if not isinstance(tally, dict):
            return
        if refused:
            tally["refused"] = int(tally.get("refused", 0)) + 1
            return
        by_call = tally.setdefault("by_call", {})
        tally["reads"] = int(tally.get("reads", 0)) + 1
        by_call[call] = int(by_call.get(call, 0)) + 1
        if not found:
            tally["unfound"] = int(tally.get("unfound", 0)) + 1

    def bind(self, llm: Any, tools: Iterable[Any] = (), **kwargs: Any) -> Any:
        """``llm`` bound with ``tools`` and ``read_evidence`` after them; raises where it cannot."""
        binder = getattr(llm, "bind_tools", None)
        if not callable(binder):
            raise TypeError("the model has no way to bind tools")
        bound = binder([*tools, self.tool], **kwargs)
        # The read is offered from here: the job's count of it starts now.
        if self.tally is None and self._container is not None:
            self.tally = reads_tally(self._container)
        return bound

    async def answer(
        self,
        send: Callable[[list[Any]], Awaitable[Any]],
        turns: list[Any],
        *,
        on_read: Callable[[Any], None] | None = None,
        what: str = "call",
        call: str = "",
    ) -> Any:
        """The call's answer: ``send`` asked until a reply makes no read.

        ``send`` makes one model call of the conversation it is given through
        a model bound with this tool and returns the reply. ``on_read`` is
        handed each reply that reads, before its reads are answered. Each read
        is counted under ``call`` (``what`` when not given) in the job's tally.
        """
        from langchain_core.messages import ToolMessage

        from maljan.agents.evidence_recorder import RepeatGuard
        from maljan.llm.anthropic_history import TOOL_LOOP_TURN

        conversation = list(turns)
        asked: dict[str, int] = {}
        refused = 0
        while True:
            reply = await send(conversation)
            calls = list(getattr(reply, "tool_calls", None) or [])
            # A call whose arguments did not parse is a call the reply made too.
            made_all = [*calls, *(getattr(reply, "invalid_tool_calls", None) or [])]
            if not made_all:
                return reply
            if not calls or any(made.get("name") != READ_EVIDENCE_TOOL for made in made_all):
                # The answer is the other call: its reads are left out, so the
                # first call is the one every reader of the answer takes. A
                # reply whose only reads did not parse is its text alone.
                return _without_reads(reply)
            if on_read is not None:
                on_read(reply)
            answers: list[Any] = []
            for made in calls:
                args = made.get("args") or {}
                key = json.dumps(args, sort_keys=True, default=str)
                asked[key] = asked.get(key, 0) + 1
                if asked[key] > RepeatGuard.SERVED:
                    refused += 1
                    wanted = str(args.get("evidence_id") or "") if isinstance(args, Mapping) else ""
                    said = (
                        f"[{READ_EVIDENCE_TOOL}: {wanted or 'this read'} not read again; this "
                        "read's answer is above in this conversation. Pass another offset, and "
                        "a limit, to read another page of it]"
                    )
                    self._count(call or what, refused=True)
                else:
                    said = self.read(args, again=asked[key] > 1)
                    wanted = str(args.get("evidence_id") or "") if isinstance(args, Mapping) else ""
                    self._count(call or what, found=bool(self.holder(wanted)))
                answers.append(
                    ToolMessage(
                        content=said,
                        tool_call_id=str(made.get("id") or ""),
                        name=READ_EVIDENCE_TOOL,
                    )
                )
            logger.info(
                "%s: read %s.",
                what,
                ", ".join(str((c.get("args") or {}).get("evidence_id") or "?") for c in calls),
            )
            if refused >= RepeatGuard.ENDS_AT:
                logger.warning(
                    "%s: %d repeated read(s) refused; the reply is kept without its calls.",
                    what,
                    refused,
                )
                return _without_reads(reply, every_call=True)
            # Each turn after a read says it is a loop's, for a provider that
            # caches a conversation it sends again: the turns after it read
            # the prefix this one writes. The note rides the request alone.
            last = answers[-1].model_copy()
            last.response_metadata = {**(last.response_metadata or {}), TOOL_LOOP_TURN: True}
            conversation = [*conversation, reply, *answers[:-1], last]


def _without_reads(reply: Any, *, every_call: bool = False) -> Any:
    """``reply`` without its ``read_evidence`` calls, or without every call.

    A call is dropped from each place a reply keeps one: its parsed calls,
    the calls whose arguments did not parse, its ``tool_use`` blocks and, with
    the reads alone dropped, the provider's own call list in its extra fields.
    Its text and thinking blocks, ``response_metadata``, ``usage_metadata``
    and ``id`` are kept, and so is every call of another tool. With the reads
    alone dropped, the extra fields are kept (a reasoning text sent back with
    the turn); with every call dropped they are not.
    """
    from langchain_core.messages import AIMessage

    def _dropped(call: Any) -> bool:
        if every_call:
            return True
        if not isinstance(call, dict):
            return False
        function = call.get("function")
        name = function.get("name") if isinstance(function, dict) else call.get("name")
        return name == READ_EVIDENCE_TOOL

    extra: dict[str, Any] = {}
    if not every_call:
        extra = dict(getattr(reply, "additional_kwargs", None) or {})
        if isinstance(extra.get("tool_calls"), list):
            extra["tool_calls"] = [c for c in extra["tool_calls"] if not _dropped(c)]

    content = reply.content
    if isinstance(content, list):
        content = [
            block
            for block in content
            if not (isinstance(block, dict) and block.get("type") == "tool_use" and _dropped(block))
        ]
    return AIMessage(
        content=content,
        tool_calls=[c for c in getattr(reply, "tool_calls", None) or [] if not _dropped(c)],
        invalid_tool_calls=[
            c for c in getattr(reply, "invalid_tool_calls", None) or [] if not _dropped(c)
        ],
        additional_kwargs=extra,
        response_metadata=dict(getattr(reply, "response_metadata", None) or {}),
        usage_metadata=getattr(reply, "usage_metadata", None),
        id=getattr(reply, "id", None),
    )


# Where a job's container keeps the count of the reads its calls outside a
# tool loop made: unfiled, so no ledger row counts them.
_TALLY_ATTR = "_ledger_reads_tally"


def reads_tally(container: Any) -> dict[str, Any] | None:
    """The job's count of ``read_evidence`` reads outside a tool loop, made on first ask.

    ``{"reads", "by_call": {call: reads}, "unfound", "refused"}``; ``None``
    without a container. Its presence says the reads were offered.
    """
    if container is None:
        return None
    tally = getattr(container, _TALLY_ATTR, None)
    if not isinstance(tally, dict):
        tally = {"reads": 0, "by_call": {}}
        try:
            container._ledger_reads_tally = tally
        except Exception:  # noqa: BLE001 — a container that keeps nothing counts nothing
            return None
    return tally


def ledger_reads_record(container: Any) -> dict[str, Any] | None:
    """``efficiency.ledger_reads``: the job's tally, or ``None`` when no call offered the read."""
    tally = getattr(container, _TALLY_ATTR, None) if container is not None else None
    if not isinstance(tally, dict):
        return None
    record: dict[str, Any] = {
        "reads": int(tally.get("reads", 0)),
        "by_call": dict(sorted((tally.get("by_call") or {}).items())),
    }
    for key in ("unfound", "refused"):
        if tally.get(key):
            record[key] = int(tally[key])
    return record


def reading_model(owner: Any, tools: Iterable[Any] = (), *, agent: str = "reporter") -> Any:
    """``owner.llm`` bound with ``tools`` and the read of ``owner.ledger_reads``, or ``None``.

    ``None`` where the owner has no reads, and where its model cannot bind
    them: then the call is asked as it always was, and the owner's
    ``degradations`` say so once.
    """
    reads = getattr(owner, "ledger_reads", None)
    if not isinstance(reads, LedgerReads):
        return None
    try:
        return reads.bind(owner.llm, tools)
    except Exception as exc:  # noqa: BLE001 — said, and the call is asked without it
        logger.warning(
            "%s: its model could not bind %s (%s: %s); the call is asked without it.",
            agent,
            READ_EVIDENCE_TOOL,
            type(exc).__name__,
            exc,
        )
        note = getattr(owner, "_note_degradation", None)
        if callable(note):
            note(not_bound_reason(agent))
        else:
            say_once(getattr(owner, "degradations", None), not_bound_reason(agent))
        return None


class StructuredReads:
    """``with_structured_output(schema, include_raw=True)`` with ``read_evidence`` beside the schema.

    ``model`` is the owner's model bound with the schema and the read
    (:meth:`LedgerReads.bind`); ``ainvoke`` asks it until a reply makes no read
    and returns that reply read as the structured call reads it
    (:func:`structured_reply`). ``on_read`` is handed each reply that reads;
    its reads are counted under ``call``.
    ``admit(conversation, first)`` is the spend ceiling's word on each turn,
    a context held while the turn runs: the first is the call its caller
    admitted, each after a read is admitted there.
    """

    def __init__(
        self,
        reads: LedgerReads,
        model: Any,
        schema: Any,
        *,
        on_read: Callable[[Any], None] | None = None,
        admit: Callable[[list[Any], bool], AbstractContextManager[Any]] | None = None,
        what: str = "structured call",
        call: str = "",
    ) -> None:
        self.reads = reads
        self.model = model
        self.schema = schema
        self.on_read = on_read
        self.admit = admit or (lambda _conversation, _first: nullcontext())
        self.what = what
        self.call = call

    async def ainvoke(self, turns: list[Any], **kwargs: Any) -> dict[str, Any]:
        sent = [0]

        async def _turn(conversation: list[Any]) -> Any:
            first = not sent[0]
            sent[0] += 1
            with self.admit(conversation, first):
                return await self.model.ainvoke(conversation, **kwargs)

        raw = await self.reads.answer(
            _turn, turns, on_read=self.on_read, what=self.what, call=self.call
        )
        return structured_reply(raw, self.schema)


def schema_tool_name(schema: Any) -> str:
    """The name a structured call's schema tool is offered under."""
    from langchain_core.utils.function_calling import convert_to_openai_tool

    return str(convert_to_openai_tool(schema)["function"]["name"])


def structured_reply(raw: Any, schema: Any) -> dict[str, Any]:
    """``raw`` read as ``with_structured_output(schema, include_raw=True)`` reads its answer.

    ``{"raw", "parsed", "parsing_error"}``: the first call of the schema's
    tool validated into ``schema``, ``None`` for a reply that calls none, and
    the error with ``parsed`` ``None`` for one whose arguments do not validate.
    """
    name = schema_tool_name(schema)
    for call in getattr(raw, "tool_calls", None) or []:
        if call.get("name") != name:
            continue
        try:
            parsed = schema.model_validate(call.get("args") or {})
        except Exception as exc:  # noqa: BLE001 — an object the schema refuses is no parse
            return {"raw": raw, "parsed": None, "parsing_error": exc}
        return {"raw": raw, "parsed": parsed, "parsing_error": None}
    return {"raw": raw, "parsed": None, "parsing_error": None}
