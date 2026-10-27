"""A tool loop past its window clears its oldest tool answers to ledger references.

A tool loop sends its whole conversation on every turn, so every tool answer it
ever read is read again on every later turn. Two things clear the oldest of
them, and nothing else does; both only where the request would otherwise end
the loop:

* **A refusal.** When the provider refuses a request as over its window
  (``context_window.window_full_error``), the oldest answers are cleared in one
  batch and the turn is sent again; again only while each resend is refused and
  something is still clearable. Without it the loop ends there with what it
  gathered (``base_agent``'s ``window_full`` path) or, where nothing had
  answered, fails its agent.
* **A prompt past the window.** A request whose prompt alone is past the window
  the agent's own model serves is refused by every server, so it is cleared
  before it is sent. The window is the agent's own (its built window, else its
  assignment's), never the job's smallest.
* **A prompt past the price tier.** Where the agent's own model is priced by
  its prompt's length (a price row's ``tiers``: Claude Haiku 5.5 bills every
  token of a prompt over 100,000 tokens at five times the rate) and the request
  is past the first boundary, the oldest answers the model has already cited
  are cleared, and only where that loses nothing and saves money: no answer
  whose ledger id none of the model's own turns has written yet is cleared
  (:func:`cited_ids`), what no tier clear can take must already be under the
  boundary (otherwise a clear would only give up the cached prefix and keep
  the dearer price), and the request it sends must cost less at the model's
  prices than the one it replaces (``tier_pays``, :func:`tier_clear_pays`).
  The boundary is the model's own price row's, read where the loop is built,
  never a constant here.

**One batch, then the same text.** A clear takes the oldest answers until the
request weighs the part no clear can take (``fixed``: the framing, the pack, the
definitions, the agent's own turns and reasoning, the newest answers, and for a
tier clear the answers not cited yet) plus half of what lies between it and the
point (a refusal's point is the refused request itself), so the loop has room
to go on rather than being back at the edge on its next turn. The cleared ones stay cleared, each under the same reference
text, on every later turn.

**What is never cleared.** Only a tool answer is: the system prompt, the task
and its pack, the run-state block, the agent's own turns (its text, its CLAIM
blocks, its tool requests) and the reasoning a provider requires back on them
(DeepSeek's ``reasoning_content``: the API refuses a request that drops it) are
sent as they were. Of the tool answers, the newest turn's are never cleared —
the model has not answered them yet — nor is one that does not begin with the
recorder's own stamp, since a reference would have no id to name for it.

**Read again.** A reference names the id the recorder stamped on the answer
and the tool that reads it again (``read_evidence``). The read is filed as a
repeat of that entry and answered under its id, so no second citable id
exists. The tool exists in a loop — offered, run or named — only from the
request that carries its first clear: the loop's graph is built again with it
before that request (``base_agent``).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Annotated, Any, ClassVar

from pydantic import Field

from maljan.schemas.evidence import ENTRY_ID_RE

# The tool that reads a cleared answer again, by the ledger id its reference names.
READ_EVIDENCE_TOOL = "read_evidence"

# The mark the read-again tool carries in its metadata, by which the recorder
# files its answer as a repeat of the entry it reads.
READS_EVIDENCE = "maljan_reads_evidence"

# What the read-again tool's model is told it does. Said once, in its definition.
READ_EVIDENCE_DESCRIPTION = (
    "Read again the stored answer of an earlier tool call of this analysis, by the "
    "evidence id it was filed under (evidence_id, for example ev_0001). For an answer "
    "the conversation shows as [cleared …]: the answer comes back whole under its own "
    "id, as the ledger keeps it, shortened only where the room left for a tool answer "
    "requires. For an answer longer than one read, pass offset (a byte position, 0 for the "
    "start) and optionally limit (how many bytes) to read it page by page: each page names "
    "the offset the next one starts at. Without them the call is the one above."
)

# What an id the ledger does not hold is answered with.
UNKNOWN_EVIDENCE_REMEDIATION = "pass an id a [cleared …] line names, exactly as written"

# Why a clear happened, as the event and the log say it.
CLEARED_FOR_REFUSAL = "refused"
CLEARED_FOR_WINDOW = "window"
CLEARED_FOR_TIER = "tier"

# The recorder's stamp at the very front of an answer it filed
# (``evidence_recorder``: ``[ev_0007]`` and a line break, or ``[ev_0007] tool
# call failed``). Read at the front only: text further in is the tool's.
_STAMP = re.compile(r"\[(ev_\d{3,})\](?:\n| )")
# A ledger id as a model writes it in its text, in any case.
_CITED = re.compile(r"(?<![A-Za-z0-9_])(ev_\d{3,})(?![0-9])", re.IGNORECASE)


def cleared_reference(entry_id: str, chars: int) -> str:
    """What a cleared tool answer is replaced with: its id, its size and how to read it again."""
    return (
        f"[cleared {entry_id}] This tool answer ({int(chars):,} characters) was cleared from "
        "the conversation to keep the request small enough to send; the evidence ledger "
        f"keeps it. Call {READ_EVIDENCE_TOOL} with evidence_id {entry_id} to read it again, "
        f"and cite {entry_id} as before."
    )


# Whose ids a read-again answers by: a loop's own, or the run's ledger.
THIS_ANALYSIS = "this analysis filed"
THE_RUNS_LEDGER = "the run's ledger holds"


def unknown_evidence_message(wanted: str, holds: str = THIS_ANALYSIS) -> str:
    """What the read-again tool says about an id ``holds`` (whose ids it reads) does not hold."""
    return f"{wanted or 'no id'} is no evidence id {holds}"


def read_again_note(entry_id: str) -> str:
    """What the ledger keeps for a read-again call: a note naming the entry that holds the answer."""
    return f"Read again with {READ_EVIDENCE_TOOL}: the answer is the one {entry_id} holds."


def stamp_of(content: str) -> str | None:
    """The id the recorder stamped at the front of an answer, or ``None``."""
    found = _STAMP.match(content)
    return found.group(1).lower() if found else None


def _visible_text(content: Any) -> str:
    """A model turn's own text: a string as it is, a block list's ``text`` blocks joined.

    Reasoning blocks are left out: a thought is not a citation.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            str(block.get("text") or "")
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        )
    return ""


def cited_ids(messages: Sequence[Any]) -> set[str]:
    """The ledger ids the model's own turns write in their text, lower-cased."""
    found: set[str] = set()
    for message in messages:
        if _is_model_turn(message):
            found.update(match.lower() for match in _CITED.findall(_visible_text(message.content)))
    return found


def tier_clear_pays(
    price: Any,
    before_tokens: int,
    cached_tokens: int,
    after_tokens: int,
    output_tokens: int,
    *,
    hour_writes: bool = False,
) -> bool:
    """Whether a request cleared to ``after_tokens`` costs less than the one it replaces.

    ``price`` is the model's price row (``core.spend.Price``), each request
    priced at its own prompt's tier. The request as it stands reads
    ``cached_tokens`` from the prompt cache and writes the rest; the cleared one
    writes its whole prompt again (its first clear changes the tool list, and
    any clear the prefix after the oldest answer it takes). ``output_tokens``
    is the answer expected of the turn, priced at each request's tier.
    ``hour_writes``: the model's requests write the cache for an hour, and
    every write is priced so (``written_1h``).
    """
    before = max(0, int(before_tokens))
    cached = min(before, max(0, int(cached_tokens)))
    after = max(0, int(after_tokens))
    out = max(0, int(output_tokens))

    def priced(prompt: int, read: int) -> float:
        written = prompt - read
        return float(
            price.cost(
                {
                    "input_tokens": prompt,
                    "cached_input_tokens": read,
                    "cache_write_input_tokens": written,
                    "cache_write_1h_input_tokens": written if hour_writes else 0,
                    "output_tokens": out,
                }
            )
        )

    return priced(after, 0) < priced(before, cached)


@dataclass(frozen=True)
class Clearing:
    """One clear: when, why, how many answers and what the request weighed either side of it."""

    turn: int
    answers: int
    chars_before: int
    chars_after: int
    why: str
    point_chars: int
    target_chars: int


@dataclass
class FitResult:
    """A request after the standing clears and any new one, with what the measure must learn."""

    messages: list[Any]
    # Characters newly cleared ahead of the turn the server last counted, which
    # that count still holds and the next measure must take off it.
    freed_before_report: int = 0
    clearing: Clearing | None = None


def _is_tool_answer(message: Any) -> bool:
    return type(message).__name__ == "ToolMessage" or getattr(message, "type", "") == "tool"


def _is_model_turn(message: Any) -> bool:
    return getattr(message, "type", "") == "ai"


@dataclass(frozen=True)
class _Candidate:
    """One clearable answer: where it is, its call id and entry id, its cleared copy, the saving."""

    index: int
    key: str
    entry_id: str
    cleared: Any
    saving: int


@dataclass(frozen=True)
class _Plan:
    """The clear a request is due: which answers, down to what, and why."""

    candidates: list[_Candidate]
    target: int
    why: str
    point: int


@dataclass
class ToolAnswerClearing:
    """One tool loop's clears: which answers are cleared, and when more are.

    ``window_chars`` is the window the agent's own model serves, in the
    budget's characters, or ``None`` where it is not known: a prompt past it is
    refused by every server. A refusal clears whatever it is (:meth:`refused`).
    ``tier_chars`` is the first prompt length past which the agent's own model
    is priced higher, in the budget's characters, or ``None`` for a model priced
    by no prompt length; ``tier_pays(before, cached, after, messages)``, where
    given, says whether a request cleared to ``after`` characters costs less
    than the one of ``before``, ``cached`` of them read from the prompt cache.
    ``enabled`` false keeps the clears already made and makes no new one.
    """

    window_chars: int | None = None
    enabled: bool = True
    tier_chars: int | None = None
    tier_pays: Callable[[int, int, int, list[Any]], bool] | None = None
    # Each cleared answer's reference, by its tool call id: the same text on
    # every turn, so the front of the request stays what it was.
    _references: dict[str, str] = field(default_factory=dict)
    # Answers found not clearable, by tool call id, so none is read twice.
    _unclearable: set[str] = field(default_factory=set)
    _refused: bool = False
    clears: list[Clearing] = field(default_factory=list)

    @property
    def cleared(self) -> int:
        """How many answers this loop has cleared."""
        return len(self._references)

    def apply(self, messages: Sequence[Any]) -> list[Any]:
        """``messages`` with every answer this loop already cleared shown as its reference."""
        if not self._references:
            return list(messages)
        out: list[Any] = []
        for message in messages:
            reference = (
                self._references.get(str(getattr(message, "tool_call_id", "") or ""))
                if _is_tool_answer(message)
                else None
            )
            out.append(message if reference is None else _with_content(message, reference))
        return out

    def _candidates(
        self, out: list[Any], sizes: list[int], measure: Callable[[Any], int]
    ) -> list[_Candidate]:
        """The clearable answers, oldest first.

        Before the last model turn only: the newest turn's answers stay. An
        answer found not clearable is remembered and never looked at again.
        """
        last_turn = max((i for i, m in enumerate(out) if _is_model_turn(m)), default=-1)
        found: list[_Candidate] = []
        for index in range(max(0, last_turn)):
            message = out[index]
            if not _is_tool_answer(message):
                continue
            key = str(getattr(message, "tool_call_id", "") or "")
            if not key or key in self._references or key in self._unclearable:
                continue
            content = getattr(message, "content", None)
            entry_id = stamp_of(content) if isinstance(content, str) else None
            if entry_id is None or not isinstance(content, str):
                self._unclearable.add(key)
                continue
            cleared = _with_content(message, cleared_reference(entry_id, len(content)))
            saving = sizes[index] - measure(cleared)
            if saving <= 0:
                self._unclearable.add(key)
                continue
            found.append(_Candidate(index, key, entry_id, cleared, saving))
        return found

    def refused(self, messages: Sequence[Any], measure: Callable[[Any], int]) -> bool:
        """Arm a clear for the resend of a refused request; whether anything is left to clear."""
        out = self.apply(messages)
        if not self._candidates(out, [measure(m) for m in out], measure):
            return False
        self._refused = True
        return True

    def _size(
        self,
        out: list[Any],
        sizes: list[int],
        extra_chars: int,
        reported: Callable[[list[Any]], tuple[int, int]],
    ) -> tuple[int, int]:
        """``(size, index)``: the server's count where there is one, else the measure."""
        floor, report_at = reported(out)
        if report_at >= 0 and floor > 0:
            return floor, report_at
        return sum(sizes) + max(0, int(extra_chars)), report_at

    def _plan(
        self,
        out: list[Any],
        sizes: list[int],
        size: int,
        report_at: int,
        refused: bool,
        measure: Callable[[Any], int],
    ) -> _Plan | None:
        """The clear ``out`` is due, or ``None``; nothing is changed but the unclearable marks.

        A refusal or a prompt past the window takes any clearable answer, as
        it always did. Only where neither is due, a prompt past the tier takes
        the cited ones, and only where they bring it under the boundary and
        the request it sends costs less (``tier_pays``).
        """
        window, tier = self.window_chars, self.tier_chars
        past = window is not None and size > window
        over_tier = tier is not None and size > tier
        if not (refused or past or over_tier):
            return None
        candidates = self._candidates(out, sizes, measure)
        if not candidates:
            return None
        if refused or past:
            fixed = size - sum(candidate.saving for candidate in candidates)
            # What no clear can take, plus half of the room between it and the
            # point: the refused request, or the window.
            targets: list[tuple[int, str, int]] = []
            if refused:
                targets.append((fixed + (size - fixed) // 2, CLEARED_FOR_REFUSAL, size))
            if past and window is not None:
                targets.append((fixed + max(0, window - fixed) // 2, CLEARED_FOR_WINDOW, window))
            target, why, point = min(targets)
            return _Plan(candidates, target, why, point)
        assert tier is not None
        cited = cited_ids(out)
        chosen = [candidate for candidate in candidates if candidate.entry_id in cited]
        fixed = size - sum(candidate.saving for candidate in chosen)
        # A clear that cannot bring the request under the boundary keeps the
        # dearer price and only gives up the cached prefix.
        if not chosen or fixed >= tier:
            return None
        target = fixed + (tier - fixed) // 2
        if self.tier_pays is not None:
            after = size
            for candidate in chosen:
                if after <= target:
                    break
                after -= candidate.saving
            # What the server counted of the request before the turn it last
            # answered: the prefix the previous request wrote to the cache.
            cached = max(0, size - sum(sizes[report_at:])) if report_at >= 0 else 0
            try:
                if not self.tier_pays(size, cached, after, out):
                    return None
            except Exception:  # noqa: BLE001 — a clear in doubt is not made
                return None
        return _Plan(chosen, target, CLEARED_FOR_TIER, tier)

    def due(
        self,
        messages: Sequence[Any],
        *,
        extra_chars: int,
        measure: Callable[[Any], int],
        reported: Callable[[list[Any]], tuple[int, int]],
    ) -> bool:
        """Whether the next :meth:`fit` of ``messages`` would clear; nothing is changed."""
        if not self.enabled:
            return False
        out = self.apply(messages)
        if not self._refused and self.window_chars is None and self.tier_chars is None:
            return False
        sizes = [measure(m) for m in out]
        size, report_at = self._size(out, sizes, extra_chars, reported)
        return self._plan(out, sizes, size, report_at, self._refused, measure) is not None

    def fit(
        self,
        messages: Sequence[Any],
        *,
        extra_chars: int,
        measure: Callable[[Any], int],
        reported: Callable[[list[Any]], tuple[int, int]],
        turn: int,
    ) -> FitResult:
        """The request to send: the standing clears, and a new batch where one is due.

        ``extra_chars`` is what goes with the request outside its messages (the
        tool definitions, earlier run-state blocks a provider replays).
        ``measure`` sizes one message as the server sees it, and ``reported``
        answers ``(characters, index)``: what the server said the request up
        to the turn at ``index`` weighed, in the budget's characters, plus what
        came after, or ``(0, -1)`` (``base_agent._reported_request``). The
        request is sized by the server's count where there is one, since the
        window stands for what a server refuses, and by the measure only where
        nothing was counted yet. One pass over the messages.
        """
        out = self.apply(messages)
        refused, self._refused = self._refused, False
        if not self.enabled or (
            not refused and self.window_chars is None and self.tier_chars is None
        ):
            return FitResult(out)
        sizes = [measure(m) for m in out]
        size, report_at = self._size(out, sizes, extra_chars, reported)
        plan = self._plan(out, sizes, size, report_at, refused, measure)
        if plan is None:
            return FitResult(out)
        before = size
        answers = 0
        freed_before_report = 0
        for candidate in plan.candidates:
            if size <= plan.target:
                break
            self._references[candidate.key] = str(candidate.cleared.content)
            out[candidate.index] = candidate.cleared
            size -= candidate.saving
            if candidate.index < report_at:
                freed_before_report += candidate.saving
            answers += 1
        clearing = Clearing(
            turn=int(turn),
            answers=answers,
            chars_before=before,
            chars_after=size,
            why=plan.why,
            point_chars=plan.point,
            target_chars=plan.target,
        )
        self.clears.append(clearing)
        return FitResult(out, freed_before_report=freed_before_report, clearing=clearing)


def _with_content(message: Any, content: str) -> Any:
    """A copy of ``message`` with ``content``; every other field as it was."""
    copy = getattr(message, "model_copy", None)
    if callable(copy):
        return copy(update={"content": content})
    return message


@dataclass(frozen=True)
class StoredCopy:
    """The full copy of an answer kept in the job's store: its size and a reader of a byte range.

    ``read(offset, length)`` answers the bytes from ``offset`` (``length`` of
    them, or to the end for ``None``), or ``None`` when the store cannot be
    read now.
    """

    total: int
    read: Callable[[int, int | None], bytes | None]


def _whole_characters(data: bytes, *, more: bool) -> tuple[int, bytes]:
    """``data`` cut to whole UTF-8 characters: how many leading bytes were left out, and the rest.

    A page starts and ends at byte positions, which may fall inside a
    character. The partial one at the front is left out (the page before ends
    before it) and, where more follows, the partial one at the end too.
    """
    head = 0
    while head < min(3, len(data)) and data[head] & 0xC0 == 0x80:
        head += 1
    end = len(data)
    if more:
        for back in range(1, min(4, end - head) + 1):
            byte = data[end - back]
            if byte & 0xC0 == 0x80:
                continue
            need = 4 if byte >= 0xF0 else 3 if byte >= 0xE0 else 2 if byte >= 0xC0 else 1
            if need > back:
                end -= back
            break
    return head, data[head:end]


def _first_character(data: bytes) -> bytes:
    """The bytes of the first whole character of ``data`` (``data`` itself when it holds less)."""
    if not data:
        return data
    lead = data[0]
    width = 4 if lead >= 0xF0 else 3 if lead >= 0xE0 else 2 if lead >= 0xC0 else 1
    return data[:width]


def paged_answer(
    stored: str,
    copy: StoredCopy | None,
    offset: int,
    limit: int | None,
    *,
    room: int | None = None,
    shown: Callable[[str], int] | None = None,
) -> str:
    """One page of an answer by byte position, led by a line saying which bytes it holds.

    The page is read from ``copy``, the whole answer the job's store holds,
    where there is one and it can be read; otherwise from ``stored``, the
    answer as the ledger keeps it, and the line says which. Positions are
    bytes of the UTF-8 text; a character a position falls inside is left out
    of the page it is cut by and read whole in the next. A ``limit`` shorter
    than the character at the position still reads that character, so a walk
    by any limit reaches the end.

    ``room`` is how many characters of a tool answer the conversation can
    take now and ``shown(page)`` how many characters the page takes once
    shown (its line, the fence and the line under it): a page is never read
    longer than the room, and is shortened until it is inside it, so the
    guardrail never cuts a page. ``None`` reads as many bytes as asked.
    """
    stored_bytes = stored.encode("utf-8", errors="surrogatepass")
    state: dict[str, Any] = {
        "copy": copy,
        "what": "the stored full copy of the answer" if copy else "the stored answer",
    }

    def read(at: int, length: int | None) -> bytes:
        held = state["copy"]
        if held is not None:
            data = held.read(at, length)
            if data is not None:
                return bytes(data)
            # The copy cannot be read now: the stored answer is paged, and said so.
            state["copy"] = None
            state["what"] = "the stored answer (the full copy could not be read)"
        return stored_bytes[at : at + length] if length is not None else stored_bytes[at:]

    def size() -> int:
        held = state["copy"]
        return held.total if held is not None else len(stored_bytes)

    want = limit
    if room is not None:
        want = min(limit, room) if limit is not None else room
    if copy is not None and offset >= copy.total:
        return (
            f"[{READ_EVIDENCE_TOOL}: offset {offset} is at or past the end of "
            f"{state['what']} ({copy.total} bytes)]"
        )
    while True:
        data = read(offset, want)
        total = size()
        what = state["what"]
        if offset >= total:
            return (
                f"[{READ_EVIDENCE_TOOL}: offset {offset} is at or past the end of {what} "
                f"({total} bytes)]"
            )
        more = offset + len(data) < total
        head, page = _whole_characters(data, more=more)
        if not page and more:
            raw = read(offset, 7)
            head = 0
            while head < min(3, len(raw)) and raw[head] & 0xC0 == 0x80:
                head += 1
            page = _first_character(raw[head:])
        start = offset + head
        end = start + len(page)
        place = f"bytes {start}-{end} of {total} of {what}"
        note = f"; the next page starts at offset {end}" if end < total else "; this is the end"
        text = f"[{READ_EVIDENCE_TOOL}: {place}{note}]\n" + page.decode("utf-8", errors="replace")
        if shown is None or room is None or shown(text) <= room or len(data) <= 4:
            return text
        want = max(4, int(len(data) * 0.8))


def read_evidence_tool(
    lookup: Callable[[str], str | None],
    sizer: Any = None,
    stored_copy: Callable[[str], StoredCopy | None] | None = None,
    holds: str = THIS_ANALYSIS,
) -> Any:
    """The read-again tool: a stored answer by its evidence id, sized like any tool answer.

    ``lookup`` answers an id with the output the ledger keeps for it, or
    ``None`` for an id this analysis never filed; an unknown id is said to be
    none ``holds`` (:func:`unknown_evidence_message`). ``sizer`` is the job's
    answer guardrail (``ServerRegistry.answer_sizer``): the answer is measured
    against the room the conversation has and shortened as every tool answer
    is. The recorder files a found answer as a repeat of the entry it reads and
    fences it under that entry's id (``evidence_recorder``, :data:`READS_EVIDENCE`).

    ``offset`` and ``limit`` are optional: a call that passes neither is the
    read above, byte for byte. With either, the answer is read page by page
    (:func:`paged_answer`) from the full copy the job's store holds
    (``stored_copy``, by the id; ``None`` for an entry with none), else from
    the stored answer.
    """
    from langchain_core.tools import StructuredTool

    from maljan.tools.errors import BAD_ARGUMENT, tool_error

    class _ReadAgain(StructuredTool):
        """The tool keeping to the arguments the call named: an optional one left out is not filled.

        The ledger records a call's arguments as made, so a plain read stays
        ``{"evidence_id": ...}``, the record it always was.
        """

        keeps_named_args: ClassVar[bool] = True

        def _parse_input(self, tool_input: Any, tool_call_id: str | None) -> Any:
            parsed = super()._parse_input(tool_input, tool_call_id)
            if isinstance(tool_input, dict) and isinstance(parsed, dict):
                return {key: value for key, value in parsed.items() if key in tool_input}
            return parsed

    def _read(
        evidence_id: str,
        offset: Annotated[int, Field(ge=0)] = 0,
        limit: Annotated[int | None, Field(gt=0)] = None,
    ) -> str:
        wanted = str(evidence_id or "").strip().lower()
        found = lookup(wanted) if ENTRY_ID_RE.fullmatch(wanted) else None
        if found is None:
            return json.dumps(
                tool_error(
                    BAD_ARGUMENT,
                    unknown_evidence_message(wanted, holds),
                    tool=READ_EVIDENCE_TOOL,
                    remediation=UNKNOWN_EVIDENCE_REMEDIATION,
                )
            )
        if offset or limit is not None:
            from maljan.agents.tool_fence import fenced
            from maljan.llm.context_window import output_limit
            from maljan.schemas.answer_completeness import cut_line_room

            copy = stored_copy(wanted) if stored_copy is not None else None
            room = None
            if sizer is not None:
                room = output_limit(
                    getattr(sizer, "_max_output_chars", 0), getattr(sizer, "_context_budget", None)
                )

            def shown(page: str) -> int:
                # What the page takes once the recorder shows it: its id and the
                # fence, and the line a cut answer carries under it.
                return len(f"[{wanted}]\n{fenced(wanted, page)}") + cut_line_room(room or 0)

            found = paged_answer(found, copy, offset, limit, room=room, shown=shown)
            if sizer is None:
                return found
            return str(sizer._apply_output_guardrail(found, ()))
        if sizer is None:
            return found
        return str(sizer._apply_output_guardrail(found, ()))

    _read.__doc__ = READ_EVIDENCE_DESCRIPTION
    return _ReadAgain.from_function(
        func=_read,
        name=READ_EVIDENCE_TOOL,
        description=READ_EVIDENCE_DESCRIPTION,
        metadata={READS_EVIDENCE: True},
    )
