"""The citable record of every tool call an analysis made.

A report is only as good as what it can point at. Before the ledger, a tool
result lived exactly as long as the ReAct message stream that produced it: the
model read it, wrote prose about it, and the bytes were gone. Anything the
report then said about a section table or a DNS lookup was the model's memory
of a number, and nothing downstream could check it.

A ``LedgerEntry`` is one tool call written down — which agent asked, which
server answered, the arguments, the timing, whether it worked, and what came
back, parsed when it parsed. Entries carry an id (``ev_0007``) that is
monotonic across the whole job, and that id is the citation: the tool loop
shows it to the model with the result, agents cite it in their findings, report
sections list the ids they were built from, and the API serves the entry those
ids name.

One bound keeps the ledger from becoming the thing it records: each agent gets
a byte budget (``report.evidence_budget_bytes``), and past it an entry keeps
its arguments, its outcome and its timing but drops its output and says so
with ``truncated``. What was dropped is counted in the truncation ledger, so
the report can state how many entries it is not showing rather than quietly
showing fewer.

There used to be a second, silent one: every output was cut to six thousand
characters on the way in, with a trailing ellipsis and no flag. That was
defensible while the model read six thousand characters too. It is not now
that what a model reads is derived from its context window — a decompilation
the model read forty thousand characters of was stored as its first six
thousand, and the stored record is what the evidence API serves and what the
report sections are built from, so a citation was checkable only as far as the
prefix went. The ledger stores the text the model was handed, whole; the byte
budget is the one storage decision this platform makes, and it announces
itself. A caller that passes a ``max_chars`` of its own still gets a cut, and
that entry is flagged ``truncated`` like any other — a stored record that is a
prefix and does not say so is the one shape this platform's principle forbids.
"""

from __future__ import annotations

import json
import re
import sys
import threading
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from maljan.schemas.tool_evidence import (
    CapturedToolOutput,
    _symbol_from_args,
    trim_output,
)

# The width of the numeric part of an entry id. Four digits holds ten thousand
# tool calls in one job, which is an order of magnitude past the busiest run
# observed, and fixed width means the ids sort lexically in the order they
# were issued.
_ID_DIGITS = 4


# An entry id wherever one is written: in a claim's evidence line, in a
# findings block, in a tool result the recorder stamped. Spelled once, beside
# the function that issues them, because two copies of it disagreed on case
# for ids that one counter produces. The counter issues lowercase; a model
# that writes ``EV_0002`` back is citing the same entry, and a false flag
# here costs a full analyst feedback turn.
ENTRY_ID_RE = re.compile(r"\bev_\d{3,}\b", re.IGNORECASE)

# Where an entry id's prefix meets its digits. A text that only mentions an id,
# such as a sample's string written into a triage pack line, has this underscore
# written out (``utils.written_forms.ids_written_out``). Neither ``ENTRY_ID_RE``
# nor a reader then finds a citation in it. On raw text it matches only where
# ``ENTRY_ID_RE`` would begin: ``ev_`` after a word boundary and before a digit,
# so ``prev_2024`` and ``dev_1`` are left alone. On text whose control characters
# are already written out, an id that stands right after an escape is matched
# too: ``\n``, ``\t``, ``\r``, ``\"`` and ``\x`` with any number of hex digits
# up to the widest code point. One hex digit covers the id whose ``e`` is the
# escape's own last digit (``\x0e`` then ``v_0003``), which a reader sees as
# ``ev_0003``.
_ESCAPE_HEX_DIGITS = len(f"{sys.maxunicode:x}")
_AFTER_AN_ESCAPE = "|".join(
    [r'(?<=\\[ntr"])'] + [rf"(?<=\\x[0-9a-f]{{{n}}})" for n in range(1, _ESCAPE_HEX_DIGITS + 1)]
)
ENTRY_ID_JOIN_RE = re.compile(rf"(?:(?<!\w)|{_AFTER_AN_ESCAPE})ev_(?=\d)", re.IGNORECASE)
# The same, only right after an escape: on a line the platform built, whose own
# ids stand after no escape, these are the ids a written-out control brought.
ENTRY_ID_AFTER_ESCAPE_RE = re.compile(rf"(?:{_AFTER_AN_ESCAPE})ev_(?=\d)", re.IGNORECASE)


def entry_ids_in(text: str) -> set[str]:
    """The entry ids written in ``text``, in the spelling the counter issues."""
    return {found.lower() for found in ENTRY_ID_RE.findall(text)}


def format_entry_id(seq: int) -> str:
    """The citation id for the ``seq``-th tool call of a job (1-based)."""
    return f"ev_{max(1, int(seq)):0{_ID_DIGITS}d}"


class EvidenceCounter:
    """The per-job source of entry ids.

    One counter per job rather than one per agent: an id is a citation, and two
    agents that both issued ``ev_0003`` would give the report two different
    entries under one name. The container owns it for the same reason it owns
    the token and truncation ledgers, and an agent that runs without a
    container falls back to a counter of its own.
    """

    def __init__(self) -> None:
        # Locked because ``parallel_analysts`` runs the analysts on threads
        # against this one counter, and two agents handed the same id would be
        # two different calls answering to one citation — exactly what the
        # counter exists to prevent. ``TruncationLedger`` locks for the same
        # reason.
        self._lock = threading.Lock()
        self._seq = 0

    def next_id(self) -> tuple[str, int]:
        """The next ``(entry_id, seq)`` pair, seq being 1-based."""
        with self._lock:
            self._seq += 1
            return format_entry_id(self._seq), self._seq

    @property
    def issued(self) -> int:
        """How many ids this counter has handed out."""
        with self._lock:
            return self._seq


# What the ledger holds for a call whose answer the conversation had no room
# for: the call was made and answered, and none of the answer reached the
# model. A statement of the cut in place of a tool result, on an entry marked
# ``truncated`` like any entry that is not the whole answer.
_NOT_SHOWN_HEAD = "[cut] Not shown: the conversation had no room left for this answer of "
_NOT_SHOWN_RE = re.compile(re.escape(_NOT_SHOWN_HEAD) + r"[\d,]+ characters\.")


def not_shown_record(chars: int) -> str:
    """The ledger's output for an answer of ``chars`` characters none of which reached the model."""
    return f"{_NOT_SHOWN_HEAD}{max(0, int(chars)):,} characters."


def lists_code(tool: Any) -> bool:
    """Whether an undeclared tool's name says it decompiles or disassembles.

    The name half of ``core.undeclared_tools``: a reader that holds the
    entry reads it by its declared kind (``entry_lists_any_code``) and comes
    here only for a tool whose name is all it has.
    """
    from maljan.core.undeclared_tools import named_as_code_listing, named_as_decompiler

    return named_as_decompiler(tool) or named_as_code_listing(tool)


def answer_not_shown(entry: Any) -> bool:
    """Whether ``entry`` is a call whose answer the conversation had no room for.

    Such a call was made and answered, and the model read none of it, so a
    reader asking whether a function was read skips it. An entry the byte
    budget blanked was read before it was blanked, and is not one.
    """
    if not getattr(entry, "truncated", False):
        return False
    return _NOT_SHOWN_RE.fullmatch(str(getattr(entry, "output", "") or "").strip()) is not None


def holds_its_answer(entry: Any) -> bool:
    """Whether ``entry`` keeps the answer its call gave the model, so it can answer the call again.

    An entry the byte budget blanked keeps nothing, and one whose answer the
    conversation had no room for holds a statement of the cut. One the
    tool-output guardrail cut keeps exactly what the model read, which is what
    making the call again would hand it: it holds its answer.
    """
    if not str(getattr(entry, "output", "") or ""):
        return False
    if not getattr(entry, "truncated", False):
        return True
    return int(getattr(entry, "chars_dropped", 0) or 0) > 0 and not answer_not_shown(entry)


def is_guard_answer(entry: Any) -> bool:
    """Whether the entry is a guard's answer: a call answered with no tool run and no holder.

    Such an entry names itself in ``repeated_of``, so every reader that leaves
    a repeat out of the tool results leaves it out too, and its chain holds no
    answer (``repeat_holders``).
    """
    if isinstance(entry, Mapping):
        first, own = entry.get("repeated_of"), entry.get("id")
    else:
        first, own = getattr(entry, "repeated_of", None), getattr(entry, "id", None)
    first = str(first or "").strip().lower()
    return bool(first) and first == str(own or "").strip().lower()


def answers_held(entries: Any) -> bool:
    """Whether any entry is a call that ran or a repeat of one: anything but a guard's answer."""
    return any(not is_guard_answer(entry) for entry in entries or ())


def repeat_holders(entries: Any) -> dict[str, str]:
    """Each repeat's id mapped to the id of the entry that holds its answer, lower-cased.

    A repeat names the entry it was answered from (``repeated_of``); a chain is
    followed to its end. A chain that comes round to an entry it already
    passed holds no answer and maps to ``""``; one that leads to an id not in
    ``entries`` maps to that id, which names nothing a reader holds. Entries
    that ran are not in the map.
    """
    named: dict[str, str] = {}
    for entry in entries or ():
        entry_id = str(getattr(entry, "id", "") or "").strip().lower()
        first = str(getattr(entry, "repeated_of", "") or "").strip().lower()
        if entry_id and first:
            named[entry_id] = first
    holders: dict[str, str] = {}
    for entry_id, first in named.items():
        seen = {entry_id}
        while first in named and first not in seen:
            seen.add(first)
            first = named[first]
        holders[entry_id] = "" if first in seen else first
    return holders


def parse_structured(output: str) -> dict[str, Any] | list[Any] | None:
    """The tool's output as JSON when it is JSON, else ``None``.

    Only a dict or a list counts. A tool that answered ``"4"`` or ``"null"``
    produced valid JSON and no structure, and storing that as ``structured``
    would give the section builders a shape they cannot read.
    """
    text = (output or "").strip()
    if not text or text[0] not in "{[":
        return None
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        # Nesting deeper than the interpreter reads is not a structure it can hold.
        return None
    return parsed if isinstance(parsed, dict | list) else None


class LedgerEntry(BaseModel):
    """One tool call and its result, addressable by id."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Citation id, monotonic per job, e.g. 'ev_0007'.")
    stage: str = Field(default="analysis", description="Pipeline stage the call was made in.")
    agent: str = Field(default="", description="Agent that made the call, e.g. 'static'.")
    server: str | None = Field(
        default=None,
        description="Tool server the tool came from; None for an in-process tool.",
    )
    tool: str = Field(default="", description="Tool name, e.g. 'pe_info'.")
    args: dict[str, Any] = Field(default_factory=dict, description="Arguments passed.")
    symbol: str | None = Field(
        default=None, description="Human label for the call target, parsed from the arguments."
    )
    ok: bool = Field(
        default=True,
        description="Whether the call answered rather than raised or returned an error.",
    )
    error: str | None = Field(default=None, description="Failure text when ok is false.")
    remediation: str | None = Field(
        default=None,
        description="What would make the call succeed, when the tool said; only with an error.",
    )
    output: str = Field(default="", description="Result text, trimmed.")
    structured: dict[str, Any] | list[Any] | None = Field(
        default=None, description="Parsed result when the tool returned JSON."
    )
    function_ranges: dict[str, list[list[str]]] | None = Field(
        default=None,
        description=(
            "The function index's alone: the file's own exception-directory ranges, by "
            "function start, as offsets from the image base, end exclusive. A fact beside the "
            "answer for evidence roots (analysis.evidence_roots): never shown to a model, never "
            "charged to the evidence byte budget, and not part of the answer."
        ),
    )
    truncated: bool = Field(
        default=False,
        description=(
            "Output not the whole answer: dropped because the agent's byte budget was "
            "spent, or cut by the tool-output guardrail (chars_dropped)."
        ),
    )
    chars_dropped: int = Field(
        default=0,
        description="Characters the tool-output guardrail cut from the answer; 0 for none.",
    )
    repeated_of: str | None = Field(
        default=None,
        description=(
            "Id of the earlier identical call this one was answered from; the entry's own id "
            "for a call a guard answered with no tool run and no earlier entry behind it."
        ),
    )
    args_repaired: bool = Field(
        default=False,
        description="Whether the model's arguments were closed off before the call ran.",
    )
    args_raw: str | None = Field(
        default=None,
        description="The arguments as the model wrote them, kept when they were repaired.",
    )
    model: str | None = Field(
        default=None,
        description=(
            "The model whose turn asked for this call, as provider/model; None where "
            "nothing named it."
        ),
    )
    started_at: float = Field(default=0.0, description="Unix timestamp the call started at.")
    duration_ms: int = Field(default=0, description="Wall-clock duration of the call.")
    seq: int = Field(default=0, description="Call order within the job, 1-based.")
    source: str | None = Field(
        default=None,
        # An entry with no source dumps exactly as one written before the
        # field existed, so every stored ledger, fixture and pinned dump is
        # unchanged; the schema still names the field.
        exclude_if=lambda value: value is None,
        description=(
            "Where the tool's declaration lives, recorded when the entry was written: "
            "'mcp:<server key>', 'provider:<static or sandbox provider id>', 'sandbox' (the "
            "platform's sandbox report tools) or 'pack' (the triage pack). None on an entry "
            "written before sources were recorded, which is read by the legacy readers only "
            "(core.tool_declarations)."
        ),
    )
    facts: dict[str, Any] | None = Field(
        default=None,
        # Like ``source``: an entry with none dumps as it always did.
        exclude_if=lambda value: value is None,
        description=(
            "What the tool declared about its answer when the entry was written, resolved "
            "under its source (core.declared_reading.facts_record): {'v': 1, 'kind', and "
            "where set 'reader', 'asserts_techniques', 'source', 'display_name', 'rows', "
            "'places', 'values', 'techniques', 'reputation', 'words', 'report_sections'}. "
            "{'v': 1} alone: the source declares nothing for the tool. None on an entry "
            "written before facts were recorded, which is read by the legacy readers. Read "
            "later from here, never from the reading process's settings."
        ),
    )
    reputation: dict[str, Any] | None = Field(
        default=None,
        # Like ``facts``: an entry with none dumps as it always did.
        exclude_if=lambda value: value is None,
        description=(
            "A reputation lookup's answer as its declaration read it when the entry was "
            "written (core.reputation.ReputationRecord): {'v': 1, 'service', and where the "
            "answer gave them 'malicious', 'suspicious', 'total', 'engines', 'stats', "
            "'labels', 'detections', 'first_seen', 'last_seen', 'link', 'summary'}. None for "
            "any other tool, a call that did not answer and an entry written before records "
            "were. Read later from here, never from the reading process's settings."
        ),
    )

    pack_step: dict[str, Any] | None = Field(
        default=None,
        # Like ``facts``: an entry with none dumps as it always did.
        exclude_if=lambda value: value is None,
        description=(
            "The triage pack step that wrote the entry, where an operator declared it "
            "(core.pack_steps): {'v': 1, 'id', and where set 'label' (what the pack's line "
            "calls it) and 'renderer' (how the pack's line shows its answer)}. None on an "
            "entry of a step as shipped, and on every other entry, which the pack reads by "
            "its shipped steps. Read later from here, never from the reading process's "
            "settings."
        ),
    )

    structured_from_server: bool = Field(
        default=False,
        # Like ``facts``: an entry without one dumps as it always did.
        exclude_if=lambda value: value is False,
        description=(
            "Whether structured is the structured answer the tool's server returned beside a "
            "prose text (MCP structuredContent) rather than the text parsed: kept only where "
            "the text is not JSON, the object is not the text wrapped again, its JSON is no "
            "longer than the model could be shown of the call, the answer was not cut, and "
            "the evidence budget had room for it after every text. The text in output is what "
            "the model read."
        ),
    )

    agent_role: str | None = Field(
        default=None,
        # Like ``source``: an entry written without one dumps as it did.
        exclude_if=lambda value: value is None,
        description=(
            "The role the calling agent's definition declared when the entry was written "
            "(core.config.AgentDefinition.role: static, dynamic, network, judge, generic …), "
            "read later from here, never from the reading process's settings. None for a "
            "call no agent definition made (the pack) and an entry written before roles were."
        ),
    )
    agent_tab: str | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
        description=(
            "The console tab the calling agent's definition declared when the entry was "
            "written (core.config.AgentDefinition.tab), which a section of an operator's tool "
            "is placed by when its kind places none. None where the definition declares none."
        ),
    )
    spilled: list[dict[str, Any]] | None = Field(
        default=None,
        # Like ``source``: an entry nothing was taken from dumps as it did.
        exclude_if=lambda value: value is None,
        description=(
            "Where the parts of the answer this entry does not keep whole are kept whole "
            "(schemas.evidence_spill): one reference per part the run shortened, blanked or "
            "dropped (answer, structured_content, output, structured), each with the object "
            "key, the byte length and the SHA-256 of the bytes, or with no key and the reason "
            "the upload failed. None where nothing was taken, or the run had no store."
        ),
    )
    # The job's store for those parts, set by the recorder that wrote the
    # entry; never dumped and never copied into a dump. ``None`` outside a job.
    _spill: Any = PrivateAttr(default=None)

    def to_captured(self) -> CapturedToolOutput:
        """This entry in the shape readers of the previous capture expect."""
        return CapturedToolOutput(
            agent_id=self.agent,
            tool_name=self.tool,
            args=dict(self.args),
            symbol=self.symbol,
            output=self.output,
            seq=max(0, self.seq - 1),
            source=self.source,
            facts=self.facts,
            ok=self.ok,
        )

    @classmethod
    def from_captured(
        cls, captured: CapturedToolOutput, *, entry_id: str = "", stage: str = "analysis"
    ) -> LedgerEntry:
        """A ledger entry from a captured output, for a producer without timing."""
        seq = int(captured.seq) + 1
        return cls(
            id=entry_id or format_entry_id(seq),
            stage=stage,
            agent=captured.agent_id,
            server=None,
            tool=captured.tool_name,
            args=dict(captured.args),
            symbol=captured.symbol,
            ok=captured.ok,
            output=captured.output,
            structured=parse_structured(captured.output),
            seq=seq,
            source=captured.source,
            facts=captured.facts,
        )


def build_entry(
    *,
    entry_id: str,
    seq: int,
    agent: str,
    tool: str,
    args: dict[str, Any] | None,
    server: str | None,
    output: str,
    ok: bool = True,
    error: str | None = None,
    started_at: float = 0.0,
    duration_ms: int = 0,
    stage: str = "analysis",
    max_chars: int = 0,
    repeated_of: str | None = None,
    remediation: str | None = None,
    args_repaired: bool = False,
    args_raw: str | None = None,
    model: str | None = None,
    not_shown: bool = False,
    chars_dropped: int = 0,
    source: str | None = None,
    structured_content: dict[str, Any] | None = None,
    agent_role: str | None = None,
    agent_tab: str | None = None,
    hints: Any = None,
    declared_name: str | None = None,
) -> LedgerEntry:
    """One entry, with the output trimmed and parsed the same way every time.

    A tool that *returned* an error answered, and the entry says so the same
    way it would for one that raised: ``ok`` false, ``error`` the message and
    ``remediation`` the remedy when the tool authored one
    (``maljan.tools.errors``). A caller that already decided ``ok`` and
    ``error`` keeps its decision; only an entry handed in as a success is
    read for a returned error.

    ``output`` is the text the model was handed, whole, and ``structured`` is
    parsed from the same text. A second cut here would be a prefix nobody
    asked for: what reaches this function has already met the tool-output
    guardrail, which is what decides how much of an answer a model may read,
    and cutting it again would make the stored record smaller than the thing
    the citation points at. What bounds the stored size is the per-agent
    evidence byte budget (``apply_budget``), which keeps the call, drops the
    output and says so.

    ``max_chars`` is off by default and exists for a caller with a ceiling of
    its own. A cut made under it sets ``truncated``, because a record that is
    a prefix has to say so.

    ``repeated_of`` names the earlier call this one repeats. Such an entry
    carries the note the model was given rather than a tool result, so it is
    never parsed into ``structured``: nothing downstream should read a
    reference to another entry as data.

    ``args_repaired`` says the model's arguments were truncated and were
    closed off before the call ran (``agents.evidence_recorder``), and
    ``args_raw`` keeps them as the model wrote them. Both so a reader can see
    that a call was made on repaired arguments and check the repair against
    what arrived.

    ``not_shown`` says the conversation had no room for any of the answer:
    ``output`` is then the statement of the cut (:func:`not_shown_record`),
    the entry is marked ``truncated`` and nothing is parsed out of it.

    ``error`` is held to ``max_chars`` as ``output`` is, and says so the same way.

    ``chars_dropped`` is what the tool-output guardrail cut from the answer
    before the model read it: ``output`` is what the model was handed, and
    the entry is marked ``truncated`` because it is not the whole answer.

    ``structured_content`` is the structured answer the tool's server
    returned beside its text (MCP ``structuredContent``): kept, and read as
    ``structured``, only where it adds something the text does not carry
    (the text is not JSON and the object is not the text wrapped again) and
    the entry holds the whole answer: an answer cut, not shown or repeated
    keeps no structure the model did not read.

    ``hints`` are the MCP hints the tool's own server gave it when it was
    attached: kept on the facts record, beside what its source declares
    (``core.declared_reading.with_hints``).

    ``declared_name`` is the name the tool's source declares it under (the original,
    where the request offered it renamed): the facts stored with the entry are
    the declaration of that name, found exactly, so a tool a server natively
    spells ``<its key>__x`` is never read as its tool ``x``.
    """
    safe_args = dict(args) if isinstance(args, dict) else {}
    full = str(output or "")
    text = trim_output(full, max_chars) if int(max_chars) > 0 else full
    if ok and error is None and not repeated_of:
        from maljan.tools.errors import error_parts

        returned = error_parts(full)
        if returned is not None:
            _code, message, hint = returned
            ok, error = False, message
            remediation = remediation or hint
    facts = _facts_at_write(source, tool, hints, declared_name)
    if ok and error is None and not repeated_of and _declares_no_kind(facts):
        # A tool its source declares nothing for has no declared way to say
        # it failed: an answer that is only an error line is filed as failed.
        from maljan.core.undeclared_tools import prose_error

        said = prose_error(full)
        if said is not None:
            ok, error = False, said
    # The platform cut or replaced the answer: the conversation had no room for
    # it, or the guardrail or a ceiling left a prefix. No reputation record is
    # read from such an output (``_reputation_at_write``).
    cut = bool(not_shown) or len(text) < len(full) or int(chars_dropped) > 0
    # A failure message is held to the same result budget as the output, and
    # the cut is stated the same way (the closing "…", the entry ``truncated``):
    # a server that answers a failure with a traceback would otherwise carry it
    # whole, with its paths, into every header that lists the failure.
    if error and int(max_chars) > 0 and len(error) > int(max_chars):
        error = trim_output(error, max_chars)
        cut = True
    structured = None if repeated_of or not_shown else parse_structured(full)
    content = (
        _structured_beside(structured_content, full, structured)
        if not (repeated_of or cut)
        else None
    )
    if content is not None:
        structured = content
    return LedgerEntry(
        id=entry_id,
        stage=stage,
        agent=agent,
        server=server or None,
        tool=tool,
        args=safe_args,
        symbol=_symbol_from_args(safe_args),
        ok=ok,
        error=error,
        remediation=remediation if error else None,
        output=text,
        truncated=cut,
        chars_dropped=max(0, int(chars_dropped)),
        structured=structured,
        repeated_of=repeated_of,
        args_repaired=bool(args_repaired),
        args_raw=args_raw if args_repaired else None,
        model=model or None,
        started_at=started_at,
        duration_ms=max(0, int(duration_ms)),
        seq=seq,
        source=source or None,
        facts=facts,
        structured_from_server=content is not None,
        agent_role=agent_role or None,
        agent_tab=agent_tab or None,
        reputation=_reputation_at_write(
            facts,
            ok=ok and not repeated_of and not cut,
            output=full,
            structured=structured,
            server=server,
        ),
    )


def _facts_at_write(
    source: str | None, tool: str, hints: Any = None, declared_name: str | None = None
) -> dict[str, Any] | None:
    """The tool's declared facts under ``source``, resolved now, to be stored with the entry.

    With the hints its own server gave it, where it gave any.
    """
    if not source:
        return None
    from maljan.core.declared_reading import facts_record, with_hints

    return with_hints(facts_record(source, tool, declared_name=declared_name), hints)


def _declares_no_kind(facts: dict[str, Any] | None) -> bool:
    """Whether the facts stored at write time say the tool's source declares no kind for it.

    ``None`` (no source recorded: the platform's own calls, a stored run's
    entries) is not such a record: those are read as they always were.
    """
    return isinstance(facts, dict) and not str(facts.get("kind") or "").strip()


def _reputation_at_write(
    facts: dict[str, Any] | None, *, ok: bool, output: str, structured: Any, server: str | None
) -> dict[str, Any] | None:
    """A reputation lookup's answer read through its stored facts, to be stored with the entry.

    Read from the whole answer, so a later budget that drops the output keeps
    what the answer said.
    """
    if facts is None or not ok:
        return None
    from maljan.core.reputation import record_at_write

    return record_at_write(facts, ok=ok, output=output, structured=structured, server=server)


def _structured_beside(content: Any, text: str, parsed: Any) -> dict[str, Any] | None:
    """The structured answer a server returned beside ``text``, where it adds something.

    Only a JSON object, and only beside a text that is not JSON itself: a
    JSON text already is the answer's structure, and the model read it (the
    MCP SDK's servers return a dict both ways). An object that only wraps the
    text again (``{"result": <the text>}``, the SDK's form for a text return)
    adds nothing either. ``None`` in every such case.
    """
    if not isinstance(content, dict) or not content or parsed is not None:
        return None
    if len(content) == 1 and next(iter(content.values())) == text:
        return None
    return dict(content)


def stored_bytes(entry: LedgerEntry) -> int:
    """What the entry's answer costs: the full parsed result when there is one, else the text.

    The row persists both columns, so what is written is their sum; what the
    budget charges is the larger of the two, because the text is a prefix of
    the result's JSON and charging it twice would halve the budget for
    nothing. A structure the server returned beside a prose text
    (``structured_from_server``) is not the answer's cost: it is charged on
    its own (:func:`beside_bytes`), after every text.
    """
    text = len(entry.output.encode("utf-8", errors="ignore"))
    if entry.structured is None or getattr(entry, "structured_from_server", False):
        return text
    try:
        parsed = len(json.dumps(entry.structured, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        return text
    return max(text, parsed)


def beside_bytes(entry: LedgerEntry) -> int:
    """What a structure the server returned beside a prose text costs; 0 for every other entry."""
    if not getattr(entry, "structured_from_server", False) or entry.structured is None:
        return 0
    try:
        return len(json.dumps(entry.structured, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        return 0


def _spill_before_loss(entry: Any, part: str, value: Any, spill: Any = None) -> None:
    """Keep ``value`` whole before the entry loses it, where the entry's job has a store."""
    from maljan.schemas.evidence_spill import spill_into

    sink = spill if spill is not None else getattr(entry, "_spill", None)
    spill_into(entry, sink, part, value)


def _drop_beside(entry: LedgerEntry) -> None:
    _spill_before_loss(entry, "structured", entry.structured)
    entry.structured = None
    entry.structured_from_server = False


def _get(entry: Any, name: str) -> Any:
    return entry.get(name) if isinstance(entry, Mapping) else getattr(entry, name, None)


def _text_cost(entry: Any) -> int:
    """:func:`stored_bytes` of a ledger entry or of its dump."""
    if isinstance(entry, LedgerEntry):
        return stored_bytes(entry)
    text = len(str(_get(entry, "output") or "").encode("utf-8", errors="ignore"))
    structured = _get(entry, "structured")
    if structured is None or _get(entry, "structured_from_server"):
        return text
    try:
        parsed = len(json.dumps(structured, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        return text
    return max(text, parsed)


def _beside_cost(entry: Any) -> int:
    """:func:`beside_bytes` of a ledger entry or of its dump."""
    if not _get(entry, "structured_from_server") or _get(entry, "structured") is None:
        return 0
    try:
        return len(json.dumps(_get(entry, "structured"), ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        return 0


def fit_structures_to_budget(
    entries: Sequence[Any], budget_bytes: int, *, spill: Any = None
) -> int:
    """Drop kept structures, largest first, until each agent's kept bytes fit its budget.

    The last pass over a run's ledger (ledger entries or their dumps) before
    it is saved and built into the report. Per agent, the entry's own
    ``agent``: its texts cost what :func:`apply_budget` charged them, and the
    structures servers returned beside prose texts (``structured_from_server``)
    are dropped largest first until texts and structures together are within
    ``budget_bytes``. A text is never touched. Nothing happens when no entry
    carries such a structure (every built-in's ledger) or with no budget.
    Returns how many structures were dropped.

    ``spill`` is the job's store (``schemas.evidence_spill.EvidenceSpill``)
    for a pass over dumps, which carry none of their own: a dropped structure
    is kept there whole and the dump references it. A ledger entry uses the
    store its recorder gave it.
    """
    if budget_bytes <= 0:
        return 0
    flagged = [entry for entry in entries if _beside_cost(entry)]
    if not flagged:
        return 0
    texts: dict[str, int] = {}
    for entry in entries:
        if _get(entry, "repeated_of"):
            continue
        agent = str(_get(entry, "agent") or "")
        texts[agent] = texts.get(agent, 0) + _text_cost(entry)
    dropped = 0
    for agent in dict.fromkeys(str(_get(entry, "agent") or "") for entry in flagged):
        own = sorted(
            (entry for entry in flagged if str(_get(entry, "agent") or "") == agent),
            key=lambda entry: (_beside_cost(entry), str(_get(entry, "id") or "")),
            reverse=True,
        )
        total = texts.get(agent, 0) + sum(_beside_cost(entry) for entry in own)
        for entry in own:
            if total <= budget_bytes:
                break
            total -= _beside_cost(entry)
            if isinstance(entry, LedgerEntry):
                if spill is not None and entry._spill is None:
                    _spill_before_loss(entry, "structured", entry.structured, spill)
                _drop_beside(entry)
            else:
                _spill_before_loss(entry, "structured", entry["structured"], spill)
                entry["structured"] = None
                entry.pop("structured_from_server", None)
            dropped += 1
    return dropped


def apply_budget(
    entries: list[LedgerEntry],
    budget_bytes: int,
    *,
    already_spent: int = 0,
    already_beside: int = 0,
    earlier: Sequence[LedgerEntry] = (),
) -> tuple[int, int]:
    """Drop the outputs that overrun ``budget_bytes``, in call order.

    Returns ``(trimmed, spent)`` — how many entries lost their output, and how
    many bytes of output are now kept in total. ``already_spent`` carries the
    running total forward, because the budget belongs to the agent and an agent
    that runs two loops must not get the budget twice.

    The entries themselves stay: which tool was called, with what, and whether
    it worked is the cheap half of the record and the half a reader needs in
    order to know something is missing.

    A structure a server returned beside a prose text (``structured_from_server``)
    never costs an answer anything, and kept structures are the first thing
    evicted. Every text is decided first, exactly as with no structure at all,
    and ``spent`` counts texts only, so every loop's texts are decided as they
    would be with none. Then the structures already kept are held to the room
    left after every text: ``earlier`` are the entries of earlier loops still in
    the agent's hands, whose structures are dropped largest first until they
    fit, and ``already_beside`` the bytes of structures already handed out of
    those hands, which can no longer be dropped. Last, this call's structures
    are kept in call order while the room left holds them; one that does not
    fit is dropped and its text stays.
    """
    if budget_bytes <= 0:
        return 0, already_spent
    spent = max(0, already_spent)
    trimmed = 0
    for entry in entries:
        # A repeat holds the guard's note and no new content: the answer is
        # the entry it names, already charged. Charging the note could blank
        # a later answer that is new.
        if getattr(entry, "repeated_of", None):
            continue
        size = stored_bytes(entry)
        if spent + size <= budget_bytes:
            spent += size
            continue
        # What the budget takes is kept whole first, where the job has a store.
        # A structure parsed from the output is that output read again; only
        # one the server returned beside it is a part of its own.
        _spill_before_loss(entry, "output", entry.output)
        if entry.structured_from_server:
            _spill_before_loss(entry, "structured", entry.structured)
        entry.output = ""
        entry.structured = None
        entry.structured_from_server = False
        entry.truncated = True
        trimmed += 1
    room = budget_bytes - spent - max(0, already_beside)
    held = sorted(
        (entry for entry in earlier if beside_bytes(entry)),
        key=lambda entry: (beside_bytes(entry), str(getattr(entry, "id", ""))),
        reverse=True,
    )
    total = sum(beside_bytes(entry) for entry in held)
    for entry in held:
        if total <= room:
            break
        total -= beside_bytes(entry)
        _drop_beside(entry)
    room -= total
    for entry in entries:
        size = beside_bytes(entry)
        if not size:
            continue
        if size <= room:
            room -= size
            continue
        _drop_beside(entry)
    return trimmed, spent
