"""A long tool loop clears its oldest tool answers to ledger references, in batches.

A tool loop sends its whole conversation on every turn, so every tool answer it
ever read is read again on every later turn. Two things clear the oldest of
them, and nothing else does:

* **The window (always).** When the next request of a loop would not fit the
  window its model serves less the output the request asks room for
  (``llm.context_window``: the job's window, the agent's built output cap), the
  oldest tool answers are replaced by a reference until it fits. Without it the
  request goes out anyway, the server refuses it as a full window, and the loop
  ends with what it gathered (``base_agent``'s ``window_full`` path) — or, where
  no tool had answered yet, fails its agent. So this only changes a run that
  would have lost that agent's loop.
* **The operator (off by default).** ``react_agent_clear_tool_answers_at`` is a
  prompt size, in tokens, at which the same clearing starts earlier. Unset, only
  the window clears.

**Batches, never a sliding window.** Once a request passes the point in force,
the oldest answers are cleared until it weighs half of that point, and the
cleared ones stay cleared, each under the same reference text, on every later
turn. The request's front is then the same characters from one clear to the
next, which is what a provider's prompt cache reuses: a sliding window that
cleared one answer a turn would change the front on every turn. Half is the
point at which the next clear comes after the conversation has grown again by
as much as it keeps, so a clear is paid for by as many turns as it frees.

**What is never cleared.** Only a tool answer is: the system prompt, the task
and its pack, the run-state block, the agent's own turns (its text, its CLAIM
blocks, its tool requests) and the reasoning a provider requires back on them
(DeepSeek's ``reasoning_content``: the API refuses a request that drops it) are
sent as they were. Of the tool answers, the newest turn's are never cleared —
the model has not answered them yet — nor is an answer that names no ledger id,
since a reference has nothing to name for it.

**Read again.** A reference names every ledger id the answer carried and the
tool that reads one again (``read_evidence``), which answers with that entry's
stored output under the same fence and size rules as every tool answer. The
tool is offered to the model from the first clear on, not before: a loop that
never clears sends the tool list it always sent.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from maljan.schemas.evidence import ENTRY_ID_RE

# The tool that reads a cleared answer again, by the ledger id its reference names.
READ_EVIDENCE_TOOL = "read_evidence"

# What the read-again tool's model is told it does. Said once, in its definition.
READ_EVIDENCE_DESCRIPTION = (
    "Read again the stored answer of an earlier tool call of this analysis, by the "
    "evidence id it was filed under (evidence_id, for example ev_0001). For an answer "
    "the conversation shows as [cleared …]: the answer comes back whole, as the "
    "ledger keeps it, shortened only where the room left for a tool answer requires."
)

# What an id the ledger does not hold is answered with.
UNKNOWN_EVIDENCE_REMEDIATION = "pass an id a [cleared …] line names, exactly as written"

# Why a clear happened, as the event and the log say it.
CLEARED_FOR_WINDOW = "window"
CLEARED_FOR_SETTING = "setting"


def cleared_reference(entry_ids: Sequence[str], chars: int) -> str:
    """What a cleared tool answer is replaced with: its ids, its size and how to read it again."""
    ids = ", ".join(entry_ids)
    return (
        f"[cleared {ids}] This tool answer ({int(chars):,} characters) was cleared from "
        "the conversation to keep the request inside the model's window; the evidence "
        f"ledger keeps it. Call {READ_EVIDENCE_TOOL} with evidence_id {entry_ids[0]} to "
        f"read it again, and cite {ids} as before."
    )


def entry_ids_of(text: str) -> list[str]:
    """The ledger ids an answer carries, its own stamp first, each once, in order."""
    seen: list[str] = []
    for found in ENTRY_ID_RE.findall(text):
        key = found.lower()
        if key not in seen:
            seen.append(key)
    return seen


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
    """One tool loop's clears: which answers are cleared, and the point that clears more.

    ``window_chars`` is the room a request has before the window refuses it,
    in the budget's characters, or ``None`` where no window is known.
    ``setting_chars`` is the operator's point, or ``None``. At least one is
    set, or the loop has no clearing at all.
    """

    window_chars: int | None = None
    setting_chars: int | None = None
    # Each cleared answer's reference, by its tool call id: the same text on
    # every turn, so the front of the request stays what it was.
    _references: dict[str, str] = field(default_factory=dict)
    clears: list[Clearing] = field(default_factory=list)

    @property
    def point_chars(self) -> int | None:
        """The request size past which a clear starts: the smaller of the two that are set."""
        points = [p for p in (self.window_chars, self.setting_chars) if p is not None and p > 0]
        return min(points) if points else None

    @property
    def why(self) -> str:
        """Which of the two points is the one in force."""
        window, setting = self.window_chars, self.setting_chars
        if setting is not None and (window is None or setting < window):
            return CLEARED_FOR_SETTING
        return CLEARED_FOR_WINDOW

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

    def fit(
        self,
        messages: Sequence[Any],
        *,
        extra_chars: int,
        measure: Callable[[Any], int],
        reported: Callable[[list[Any]], tuple[int, int]],
        turn: int,
    ) -> FitResult:
        """The request to send: the standing clears, and a new batch when it is past the point.

        ``extra_chars`` is what goes with the request outside its messages (the
        tool definitions, earlier run-state blocks a provider replays).
        ``measure`` sizes one message as the server sees it, and ``reported``
        answers ``(characters, index)``: what the server said the request up
        to the turn at ``index`` weighed, in the budget's characters, plus what
        came after, or ``(0, -1)``. The same rule the loop's budget measures
        by (``base_agent.request_chars``). One pass over the messages.
        """
        out = self.apply(messages)
        point = self.point_chars
        if point is None:
            return FitResult(out)
        sizes = [measure(m) for m in out]
        measured = sum(sizes) + max(0, int(extra_chars))
        floor, report_at = reported(out)
        before = max(measured, floor)
        if before <= point:
            return FitResult(out)
        target = point // 2
        # The newest turn's answers are the ones after the last model turn:
        # never cleared, so the walk stops at that turn.
        last_turn = max((i for i, m in enumerate(out) if _is_model_turn(m)), default=-1)
        answers = 0
        freed_before_report = 0
        for index in range(last_turn):
            if max(measured, floor) <= target:
                break
            message = out[index]
            if not _is_tool_answer(message):
                continue
            key = str(getattr(message, "tool_call_id", "") or "")
            content = getattr(message, "content", None)
            if not key or key in self._references or not isinstance(content, str):
                continue
            ids = entry_ids_of(content)
            if not ids:
                continue
            reference = cleared_reference(ids, len(content))
            cleared = _with_content(message, reference)
            saving = sizes[index] - measure(cleared)
            if saving <= 0:
                continue
            self._references[key] = reference
            out[index] = cleared
            sizes[index] -= saving
            measured -= saving
            if index < report_at:
                floor -= saving
                freed_before_report += saving
            answers += 1
        if not answers:
            return FitResult(out)
        after = max(measured, floor)
        clearing = Clearing(
            turn=int(turn),
            answers=answers,
            chars_before=before,
            chars_after=after,
            why=self.why,
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
    is. The recorder files the call and fences the answer like any other.
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
                    f"{wanted or 'no id'} is no evidence id this analysis filed",
                    tool=READ_EVIDENCE_TOOL,
                    remediation=UNKNOWN_EVIDENCE_REMEDIATION,
                )
            )
        if sizer is None:
            return found
        return str(sizer._apply_output_guardrail(found, ()))

    _read.__doc__ = READ_EVIDENCE_DESCRIPTION
    return StructuredTool.from_function(
        func=_read, name=READ_EVIDENCE_TOOL, description=READ_EVIDENCE_DESCRIPTION
    )
