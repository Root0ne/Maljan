"""A validation retry is shown the ledger entries its answer cites, as the analyst had them.

The validation retry is a tools-free turn over the analyst's brief: the tool
results its first answer was written from are not in it. On haiku6 the
reverser's retry, asked for a whole answer, wrote "I could not re-read the
function bodies for this revision" and restated none of the 42 claims its
decompiles held. The retry now carries, in front of its closing, every entry
the answer's claims and findings cite that the conversation does not hold,
each the way the analyst had it in view (``base_agent.cited_entry_texts``, as
the kept-retry drops question shows them): its own calls whole, a pack entry
it saw only as its summary line named with a note. They are measured framed
against the window beside an answer of the cap the cards are measured with,
the names of all of them reserved first; an entry that does not fit beside the
ones shown is named by id. With no window known every entry is shown.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage, HumanMessage

from maljan.agents.base_agent import PACK_SUMMARY_NOTE, BaseAnalyst
from maljan.agents.tool_fence import fenced
from maljan.pipeline.validation import (
    ANALYST_FEEDBACK_CLOSING_BY_NUMBER,
    VALIDATION_ENTRIES_HEAD,
    VALIDATION_ENTRIES_UNFIT,
    validation_entries_text,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR

NAME = "all_tools_reverser_ghidra"
BODY = "void FUN_3868(void) { CreateMutexW(0, 0); if (GetLastError() == 0xb7) ExitProcess(0); }"
OTHER_BODY = "void FUN_3cf4(int code) { switch (code) { case 0xe: FUN_7170(); } }"
PACK_BODY = "PE32+ DLL, 60,928 bytes, five sections, four exports"

# The technique line is not ids, so the retry is asked; the claims cite an own
# decompile, another one and a pack entry.
FIRST = (
    "CLAIM: Routine 0x3868 exits when GetLastError returns 0xb7.\n"
    "EVIDENCE: [ev_0080] decompile; [ev_0001] identity\nCONFIDENCE: 0.9\n"
    "TECHNIQUE: T1480 or T1497\n---\n"
    "CLAIM: The command switch 0x3cf4 runs 0x7170 for code 0xe.\n"
    "EVIDENCE: [ev_0081] decompile\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)
FIXED = (
    "CLAIM 1: Routine 0x3868 exits when GetLastError returns 0xb7.\n"
    "EVIDENCE: [ev_0080] decompile; [ev_0001] identity\nCONFIDENCE: 0.9\n"
    "TECHNIQUE: T1480\n---\n"
)


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[Any]) -> None:
        super().__init__(llm=MagicMock(), name=NAME)
        self.pack_ledger_ids = ["ev_0001"]
        self._replies = list(replies)
        self.questions: list[str] = []
        self.sent: list[str] = []
        self.sent_framed: list[str] = []
        self._evidence_entries = [
            LedgerEntry(id="ev_0001", tool="identify_file", output=PACK_BODY),
            LedgerEntry(id="ev_0080", agent=NAME, tool="batch_decompile", output=BODY),
            LedgerEntry(id="ev_0081", agent=NAME, tool="batch_decompile", output=OTHER_BODY),
        ]

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.questions.append(str(messages[-1].content))
        self.sent.append("\n".join(str(m.content) for m in messages))
        self.sent_framed.append("".join(str(m.content or "") for m in messages))
        reply = self._replies.pop(0) if self._replies else "KEEP all: yes"
        if isinstance(reply, Exception):
            raise reply
        self._record_usage(AIMessage(content=reply))
        return reply


def _check(analyst: _Analyst, evidence: str = "evidence", first: str = FIRST) -> AgentISR:
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
    ):
        return analyst._validate_isr(isr, evidence)


def _window(prompt_chars: int) -> Any:
    from maljan.llm.context_window import WindowFact

    # Room for ``prompt_chars`` beside the analyst's 16,384-token cap, at 3 chars a token.
    return WindowFact(16_384 + prompt_chars // 3, "probed", "test")


class TestTheRetryShowsWhatTheAnswerCites:
    def test_each_cited_entry_is_shown_once_in_front_of_the_closing(self) -> None:
        analyst = _Analyst([FIXED])

        _check(analyst, evidence=f"[ev_0001] identity: {PACK_BODY}")

        retry = analyst.questions[0]
        assert VALIDATION_ENTRIES_HEAD in retry
        assert f"[ev_0080] batch_decompile:\n{fenced('ev_0080', BODY)}" in retry
        assert f"[ev_0081] batch_decompile:\n{fenced('ev_0081', OTHER_BODY)}" in retry
        assert retry.count(BODY) == 1
        # The brief holds the pack entry verbatim: it is not shown again.
        assert PACK_BODY not in retry.split(VALIDATION_ENTRIES_HEAD, 1)[1]
        # The entries come before the closing, which still ends the questions.
        assert retry.index(VALIDATION_ENTRIES_HEAD) < retry.index(
            ANALYST_FEEDBACK_CLOSING_BY_NUMBER
        )

    def test_a_pack_entry_seen_as_its_summary_line_is_named_as_that_line(self) -> None:
        analyst = _Analyst([FIXED])

        _check(analyst, evidence="[ev_0001] identity: pe windows, dll")

        retry = analyst.questions[0]
        assert f"[ev_0001] {PACK_SUMMARY_NOTE}." in retry
        assert PACK_BODY not in retry

    def test_an_answer_that_cites_nothing_held_is_asked_as_before(self) -> None:
        analyst = _Analyst([FIXED])
        analyst._evidence_entries = []

        _check(analyst)

        retry = analyst.questions[0]
        assert VALIDATION_ENTRIES_HEAD not in retry
        assert VALIDATION_ENTRIES_UNFIT not in retry

    def test_the_whole_answer_asked_after_a_retry_not_merged_shows_them_too(self) -> None:
        # The retry writes a block without its number: not merged, so the
        # analyst's whole answer is asked for with the same closing.
        unnumbered = FIXED.replace("CLAIM 1:", "CLAIM:")
        analyst = _Analyst([unnumbered + FIXED.replace("1:", "2:"), FIXED])

        _check(analyst)

        _retry, whole = analyst.sent
        assert "whole" in analyst.questions[1]
        assert f"[ev_0080] batch_decompile:\n{fenced('ev_0080', BODY)}" in whole


class TestTheEntriesFitTheWindow:
    def _analyst(self, window: Any) -> _Analyst:
        from maljan.llm.context_window import ContextBudget

        analyst = _Analyst([FIXED])
        analyst._evidence_entries[1] = LedgerEntry(
            id="ev_0080", agent=NAME, tool="batch_decompile", output="A" * 60_000
        )
        analyst._container = MagicMock(get_context_budget=lambda: ContextBudget(window))
        return analyst

    def test_an_entry_that_does_not_fit_is_named_by_id_and_the_rest_shown(self) -> None:
        analyst = self._analyst(_window(30_000))

        _check(analyst)

        retry = analyst.questions[0]
        assert "A" * 60_000 not in retry
        assert f"{VALIDATION_ENTRIES_UNFIT} ev_0080." in retry
        assert f"[ev_0081] batch_decompile:\n{fenced('ev_0081', OTHER_BODY)}" in retry

    def test_every_entry_is_shown_when_the_window_holds_them(self) -> None:
        analyst = self._analyst(_window(200_000))

        _check(analyst)

        retry = analyst.questions[0]
        assert "A" * 60_000 in retry
        assert VALIDATION_ENTRIES_UNFIT not in retry


class TestTheEntriesText:
    def test_entries_and_names_are_written_under_their_heads(self) -> None:
        text = validation_entries_text({"ev_0080": "[ev_0080] x:\nbody\n"}, ["ev_0090"])

        assert text == (
            f"{VALIDATION_ENTRIES_HEAD}\n[ev_0080] x:\nbody\n{VALIDATION_ENTRIES_UNFIT} ev_0090."
        )

    def test_nothing_to_show_is_no_text(self) -> None:
        assert validation_entries_text({}) == ""

    def test_many_entries_are_fitted_in_linear_time(self) -> None:
        """Four times the entries take about four times as long; quadratic would take sixteen."""
        from maljan.llm.context_window import ContextBudget

        def _fit(count: int) -> float:
            analyst = _Analyst([FIXED])
            analyst._evidence_entries = [
                LedgerEntry(id=f"ev_{n:05d}", agent=NAME, tool="batch_decompile", output="x" * 50)
                for n in range(1, count + 1)
            ]
            analyst._container = MagicMock(
                get_context_budget=lambda: ContextBudget(_window(count * 40))
            )
            isr = analyst._text_to_isr(FIRST, 0)
            isr.claims[0].evidence_ref = " ".join(f"[ev_{n:05d}]" for n in range(1, count + 1))
            best = float("inf")
            for _ in range(3):
                started = time.perf_counter()
                closing = analyst._with_cited_entries(
                    isr, [], "CLOSE", lambda text: [HumanMessage(content=text)], 16_384
                )
                best = min(best, time.perf_counter() - started)
            assert closing.endswith("\nCLOSE")
            assert VALIDATION_ENTRIES_UNFIT in closing
            return best

        small, large = _fit(2_000), _fit(8_000)

        assert large < 8 * small + 0.05


def _room(analyst: _Analyst) -> float:
    room = analyst._window_room_chars(int(analyst.output_cap_tokens() or 0))
    assert room is not None
    return room


def _sent_sizes(analyst: _Analyst) -> list[int]:
    return [len(text) for text in analyst.sent_framed]


class TestEveryTurnFitsTheLearnedWindow:
    """No ``_fits_the_window`` patch: a real learned budget, and every turn sent measured."""

    @staticmethod
    def _analyst(replies: list[Any], window: Any, body: int) -> _Analyst:
        from maljan.llm.context_window import ContextBudget

        analyst = _Analyst(replies)
        analyst._evidence_entries[1] = LedgerEntry(
            id="ev_0080", agent=NAME, tool="batch_decompile", output="A" * body
        )
        analyst._evidence_entries[2] = LedgerEntry(
            id="ev_0081", agent=NAME, tool="batch_decompile", output="B" * (body // 2)
        )
        analyst._container = MagicMock(get_context_budget=lambda: ContextBudget(window))
        return analyst

    @staticmethod
    def _validate(analyst: _Analyst) -> AgentISR:
        isr = analyst._text_to_isr(FIRST, 0)
        with patch("maljan.agents.base_agent.validity_check_available", return_value=True):
            return analyst._validate_isr(isr, "evidence")

    def test_the_retry_turn_fits_whatever_the_window(self) -> None:
        for prompt_chars in (12_000, 25_000, 40_000, 70_000, 200_000):
            analyst = self._analyst([FIXED], _window(prompt_chars), 30_000)

            self._validate(analyst)

            retry = analyst.sent_framed[0]
            assert len(retry) <= _room(analyst), prompt_chars
            # What did not fit is named, never cut.
            for marker, body in (("A", 30_000), ("B", 15_000)):
                assert marker * body in retry or marker * 100 not in retry

    def test_the_whole_answer_turn_fits_when_the_entries_filled_the_first(self) -> None:
        # The first turn holds both entries; the whole-answer turn also carries
        # the retry's own 20,000-character answer, so they are fitted again.
        unmerged = "Notes on the fix.\n" + "n" * 20_000 + "\n" + FIXED.replace("CLAIM 1:", "CLAIM:")
        analyst = self._analyst([unmerged, FIXED], _window(60_000), 30_000)

        self._validate(analyst)

        retry, whole = analyst.sent_framed[:2]
        assert "A" * 30_000 in retry and "B" * 15_000 in retry
        assert "whole" in analyst.questions[1]
        assert len(whole) <= _room(analyst)
        assert "n" * 20_000 in whole

    def test_no_entry_that_fits_leaves_the_turn_as_it_was(self) -> None:
        analyst = self._analyst([FIXED], _window(12_000), 30_000)
        analyst._evidence_entries[0] = LedgerEntry(
            id="ev_0001", tool="identify_file", output="P" * 30_000
        )
        analyst._evidence_entries[2] = LedgerEntry(
            id="ev_0081", agent=NAME, tool="batch_decompile", output="B" * 30_000
        )

        self._validate(analyst)

        retry = analyst.questions[0]
        assert VALIDATION_ENTRIES_HEAD not in retry
        assert VALIDATION_ENTRIES_UNFIT not in retry
