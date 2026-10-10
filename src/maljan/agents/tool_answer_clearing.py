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

**One batch, then the same text.** A clear takes the oldest answers until the
request weighs the part no clear can take (``fixed``: the framing, the pack, the
definitions, the agent's own turns and reasoning, the newest answers) plus half
of what lies between it and the point (a refusal's point is the refused request
itself), so the loop has room to go on rather than being back at the edge on
its next turn. The cleared ones stay cleared, each under the same reference
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
from typing import Any

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
    "requires."
)

# What an id the ledger does not hold is answered with.
UNKNOWN_EVIDENCE_REMEDIATION = "pass an id a [cleared …] line names, exactly as written"

# Why a clear happened, as the event and the log say it.
CLEARED_FOR_REFUSAL = "refused"
CLEARED_FOR_WINDOW = "window"

# The recorder's stamp at the very front of an answer it filed
# (``evidence_recorder``: ``[ev_0007]`` and a line break, or ``[ev_0007] tool
# call failed``). Read at the front only: text further in is the tool's.
_STAMP = re.compile(r"\[(ev_\d{3,})\](?:\n| )")


def cleared_reference(entry_id: str, chars: int) -> str:
    """What a cleared tool answer is replaced with: its id, its size and how to read it again."""
    return (
        f"[cleared {entry_id}] This tool answer ({int(chars):,} characters) was cleared from "
        "the conversation to keep the request small enough to send; the evidence ledger "
        f"keeps it. Call {READ_EVIDENCE_TOOL} with evidence_id {entry_id} to read it again, "
        f"and cite {entry_id} as before."
    )


def unknown_evidence_message(wanted: str) -> str:
    """What the read-again tool says about an id this loop never filed."""
    return f"{wanted or 'no id'} is no evidence id this analysis filed"


def read_again_note(entry_id: str) -> str:
    """What the ledger keeps for a read-again call: a note naming the entry that holds the answer."""
    return f"Read again with {READ_EVIDENCE_TOOL}: the answer is the one {entry_id} holds."


def stamp_of(content: str) -> str | None:
    """The id the recorder stamped at the front of an answer, or ``None``."""
    found = _STAMP.match(content)
    return found.group(1).lower() if found else None


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


@dataclass
class ToolAnswerClearing:
    """One tool loop's clears: which answers are cleared, and when more are.

    ``window_chars`` is the window the agent's own model serves, in the
    budget's characters, or ``None`` where it is not known: a prompt past it is
    refused by every server. A refusal clears whatever it is (:meth:`refused`).
    ``enabled`` false keeps the clears already made and makes no new one.
    """

    window_chars: int | None = None
    enabled: bool = True
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
    ) -> list[tuple[int, str, Any, int]]:
        """The clearable answers, oldest first: ``(index, call id, cleared copy, saving)``.

        Before the last model turn only: the newest turn's answers stay. An
        answer found not clearable is remembered and never looked at again.
        """
        last_turn = max((i for i, m in enumerate(out) if _is_model_turn(m)), default=-1)
        found: list[tuple[int, str, Any, int]] = []
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
            found.append((index, key, cleared, saving))
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
        if not self._refused and self.window_chars is None:
            return False
        sizes = [measure(m) for m in out]
        size, _ = self._size(out, sizes, extra_chars, reported)
        if not self._refused and size <= int(self.window_chars or 0):
            return False
        return bool(self._candidates(out, sizes, measure))

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
        window = self.window_chars
        if not self.enabled or (not refused and window is None):
            return FitResult(out)
        sizes = [measure(m) for m in out]
        size, report_at = self._size(out, sizes, extra_chars, reported)
        past = window is not None and size > window
        if not refused and not past:
            return FitResult(out)
        candidates = self._candidates(out, sizes, measure)
        if not candidates:
            return FitResult(out)
        fixed = size - sum(candidate[3] for candidate in candidates)
        # What no clear can take, plus half of the room between it and the
        # point: the refused request, or the window.
        targets: list[tuple[int, str, int]] = []
        if refused:
            targets.append((fixed + (size - fixed) // 2, CLEARED_FOR_REFUSAL, size))
        if past and window is not None:
            targets.append((fixed + max(0, window - fixed) // 2, CLEARED_FOR_WINDOW, window))
        target, why, point = min(targets)
        before = size
        answers = 0
        freed_before_report = 0
        for index, key, cleared, saving in candidates:
            if size <= target:
                break
            self._references[key] = str(cleared.content)
            out[index] = cleared
            size -= saving
            if index < report_at:
                freed_before_report += saving
            answers += 1
        clearing = Clearing(
            turn=int(turn),
            answers=answers,
            chars_before=before,
            chars_after=size,
            why=why,
            point_chars=point,
            target_chars=target,
        )
        self.clears.append(clearing)
        return FitResult(out, freed_before_report=freed_before_report, clearing=clearing)


def _with_content(message: Any, content: str) -> Any:
    """A copy of ``message`` with ``content``; every other field as it was."""
    copy = getattr(message, "model_copy", None)
    if callable(copy):
        return copy(update={"content": content})
    return message


def read_evidence_tool(
    lookup: Callable[[str], str | None],
    sizer: Any = None,
) -> Any:
    """The read-again tool: a stored answer by its evidence id, sized like any tool answer.

    ``lookup`` answers an id with the output the ledger keeps for it, or
    ``None`` for an id this analysis never filed. ``sizer`` is the job's
    answer guardrail (``ServerRegistry.answer_sizer``): the answer is measured
    against the room the conversation has and shortened as every tool answer
    is. The recorder files a found answer as a repeat of the entry it reads and
    fences it under that entry's id (``evidence_recorder``, :data:`READS_EVIDENCE`).
    """
    from langchain_core.tools import StructuredTool

    from maljan.tools.errors import BAD_ARGUMENT, tool_error

    def _read(evidence_id: str) -> str:
        wanted = str(evidence_id or "").strip().lower()
        found = lookup(wanted) if ENTRY_ID_RE.fullmatch(wanted) else None
        if found is None:
            return json.dumps(
                tool_error(
                    BAD_ARGUMENT,
                    unknown_evidence_message(wanted),
                    tool=READ_EVIDENCE_TOOL,
                    remediation=UNKNOWN_EVIDENCE_REMEDIATION,
                )
            )
        if sizer is None:
            return found
        return str(sizer._apply_output_guardrail(found, ()))

    _read.__doc__ = READ_EVIDENCE_DESCRIPTION
    return StructuredTool.from_function(
        func=_read,
        name=READ_EVIDENCE_TOOL,
        description=READ_EVIDENCE_DESCRIPTION,
        metadata={READS_EVIDENCE: True},
    )
