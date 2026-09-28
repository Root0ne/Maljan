"""An answer that writes the same claims again and again is told so and asked once for a whole one.

A local triage analyst's first answer began 639 claims in 32,768 tokens under
40 distinct headings; a dynamic analyst's retry ran to 99,854 characters. The
answer is read as it arrived: the claim headings it began and the distinct
headings among them. When the headings written again exceed a margin — the
number of distinct headings, or the operator's own number — the fact is
stated under its own validation code beside the cut-at-cap one, and the same
whole-answer question is asked once. The answer as written stays the
analyst's unless the answer to the question covers every distinct claim.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.claim_headings import claim_heading_counts
from maljan.core.config import Settings, ValidationConfig
from maljan.pipeline.validation import (
    ANALYST_CUT_CODE,
    ANALYST_REPEATED_CODE,
    analyst_repeated_violation,
    claims_repeated,
)
from maljan.schemas.isr_models import AgentISR


def _block(n: int, heading: str = "CLAIM") -> str:
    return (
        f"{heading}: The file carries configuration string number {n}.\n"
        "EVIDENCE: [ev_0001] strings\n"
        "CONFIDENCE: 0.8\n"
        "TECHNIQUE: NONE\n"
        "---\n"
    )


DISTINCT = "".join(_block(n) for n in range(1, 4))
# Three distinct claims, then the same three written four more times.
RUNAWAY = DISTINCT + "".join(
    _block(n, f"CLAIM {n + 3 * k}") for k in range(1, 5) for n in (1, 2, 3)
)
WHOLE = DISTINCT


class TestTheCount:
    def test_headings_begun_and_distinct_are_read_off_the_answer(self) -> None:
        assert claim_heading_counts(RUNAWAY) == (15, 3)

    def test_a_heading_with_nothing_after_its_label_is_named_by_its_next_line(self) -> None:
        text = "CLAIM 1:\nThe sample writes a file.\nCLAIM 2:\nThe sample opens a key.\n"
        assert claim_heading_counts(text) == (2, 2)

    def test_marks_numbering_and_case_do_not_make_a_heading_new(self) -> None:
        text = "**CLAIM 1:** The sample Writes a file.\n- CLAIM 7: the sample writes a file\n"
        assert claim_heading_counts(text) == (2, 1)

    def test_a_peer_s_claims_under_disputes_are_not_counted(self) -> None:
        assert claim_heading_counts(DISTINCT + "DISPUTES:\n" + DISTINCT) == (3, 3)

    def test_prose_after_the_last_claim_is_not_part_of_it(self) -> None:
        text = (DISTINCT * 3).rstrip("-\n") + "\n\nSummary: the sample is a loader.\n"

        assert claim_heading_counts(text) == (9, 3)

    def test_label_only_headings_with_different_evidence_are_different_claims(self) -> None:
        text = "".join(
            f"CLAIM {n}:\nEVIDENCE: [ev_000{n}] strings\nCONFIDENCE: 0.6\nTECHNIQUE: NONE\n---\n"
            for n in (1, 2, 3)
        )

        assert claim_heading_counts(text) == (3, 3)
        assert claims_repeated(text, margin=0) is None

    def test_claims_under_one_category_label_are_told_apart_by_their_sentences(self) -> None:
        sentences = [
            ("Persistence", "The sample writes a Run key."),
            ("Persistence", "The sample creates a scheduled task."),
            ("Persistence", "The sample copies itself to the startup folder."),
            ("Discovery", "The sample lists running processes."),
            ("Discovery", "The sample reads the computer name."),
            ("Discovery", "The sample enumerates drives."),
            ("Discovery", "The sample reads the user name."),
        ]
        text = "".join(
            f"CLAIM {n}: {label}\n{sentence}\nEVIDENCE: [ev_0001]\n\n"
            for n, (label, sentence) in enumerate(sentences, start=1)
        )

        assert claim_heading_counts(text) == (7, 7)
        assert claims_repeated(text, margin=0) is None


class TestTheMargin:
    def test_repeats_past_the_distinct_count_are_a_finding(self) -> None:
        found = claims_repeated(RUNAWAY)

        assert found is not None
        assert (found.begun, found.distinct, found.margin) == (15, 3, 3)

    def test_one_whole_copy_is_within_the_margin(self) -> None:
        assert claims_repeated(DISTINCT + DISTINCT) is None

    def test_an_answer_that_repeats_nothing_is_not_one(self) -> None:
        assert claims_repeated(DISTINCT) is None

    def test_an_operator_s_margin_overrides_the_derived_one(self) -> None:
        assert claims_repeated(DISTINCT + _block(1), margin=0) is not None
        assert claims_repeated(RUNAWAY, margin=20) is None

    def test_there_is_no_margin_by_default(self) -> None:
        assert ValidationConfig().claim_repeat_margin is None
        assert Settings(_env_file=None).validation.claim_repeat_margin is None

    def test_the_question_states_the_count_and_asks_for_the_whole_answer_once(self) -> None:
        found = claims_repeated(RUNAWAY)
        assert found is not None

        violation = analyst_repeated_violation(found, chunk="chunk 2 of 3")

        assert violation.code == ANALYST_REPEATED_CODE != ANALYST_CUT_CODE
        assert "answer to chunk 2 of 3" in violation.message
        assert "began 15 CLAIM block(s), 3 of them distinct" in violation.message
        assert "12 repeat a claim already written" in violation.message
        assert "shown above only up to CLAIM block 4" in violation.message
        assert "Write the whole answer again" in violation.message
        assert "each written once" in violation.message

    def test_the_part_before_the_first_repeat_is_what_was_written(self) -> None:
        found = claims_repeated(RUNAWAY)
        assert found is not None

        assert found.first_repeat == 4
        assert found.before == DISTINCT.rstrip()


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[str]) -> None:
        super().__init__(llm=MagicMock(), name="triage")
        self.pack_ledger_ids = ["ev_0001"]
        self._replies = list(replies)
        self.seen_turns: list[list[Any]] = []

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.seen_turns.append(list(messages))
        text = self._replies.pop(0)
        self._record_usage(AIMessage(content=text))
        return text


def _check(analyst: _Analyst, first: str = RUNAWAY) -> AgentISR:
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
    ):
        return analyst._validate_isr(isr, "evidence")


class TestTheValidationTurn:
    def test_the_question_is_asked_once_with_the_part_before_the_repeat_shown_back(
        self,
    ) -> None:
        analyst = _Analyst([WHOLE])

        _check(analyst)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert ANALYST_REPEATED_CODE in question
        assert "began 15 CLAIM block(s), 3 of them distinct" in question
        shown = [t for t in turns if getattr(t, "type", "") == "ai"]
        assert [str(t.content) for t in shown] == [DISTINCT.rstrip()]
        assert not any("CLAIM 12:" in str(t.content) for t in turns)

    def test_an_answer_both_cut_and_repeating_is_shown_up_to_its_first_repeat(self) -> None:
        analyst = _Analyst([WHOLE])
        isr = analyst._text_to_isr(RUNAWAY, 0)
        analyst._last_answer_cut = (4096, RUNAWAY)
        with (
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
            patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
        ):
            analyst._validate_isr(isr, "evidence")

        (turns,) = analyst.seen_turns
        shown = [t for t in turns if getattr(t, "type", "") == "ai"]
        assert [str(t.content) for t in shown] == [DISTINCT.rstrip()]

    def test_an_answer_both_cut_and_repeating_is_asked_one_question_saying_what_is_shown(
        self,
    ) -> None:
        analyst = _Analyst([WHOLE])
        isr = analyst._text_to_isr(RUNAWAY, 0)
        analyst._last_answer_cut = (4096, RUNAWAY)
        with (
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
            patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
        ):
            analyst._validate_isr(isr, "evidence")

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert ANALYST_REPEATED_CODE in question
        assert ANALYST_CUT_CODE not in question
        assert "It is shown above only up to CLAIM block 4" in question
        assert "stopped at the output limit of 4,096 tokens" in question
        assert "it is not shown to you again" not in question

    def _cut_and_repeating(self, retry: str) -> tuple[_Analyst, AgentISR]:
        analyst = _Analyst([retry])
        isr = analyst._text_to_isr(RUNAWAY, 0)
        analyst._last_answer_cut = (4096, RUNAWAY)
        with (
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
            patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
        ):
            return analyst, analyst._validate_isr(isr, "evidence")

    def test_a_cut_and_repeating_answer_is_not_replaced_by_a_retry_that_repeats(self) -> None:
        analyst, result = self._cut_and_repeating(DISTINCT * 6)

        assert len(result.claims) == len(analyst._text_to_isr(RUNAWAY, 0).claims)
        assert ANALYST_REPEATED_CODE in [v.code for v in analyst.validation_findings]

    def test_a_cut_and_repeating_answer_is_replaced_by_a_whole_one_that_does_not(self) -> None:
        _analyst, result = self._cut_and_repeating(WHOLE)

        assert len(result.claims) == 3

    def test_a_whole_answer_that_does_not_repeat_is_the_analyst_s(self) -> None:
        analyst = _Analyst([WHOLE])

        result = _check(analyst)

        assert len(result.claims) == 3
        assert ANALYST_REPEATED_CODE not in [v.code for v in analyst.validation_findings]

    def test_a_whole_answer_with_fewer_claims_stands_too(self) -> None:
        analyst = _Analyst([_block(1)])

        result = _check(analyst)

        assert len(result.claims) == 1
        assert ANALYST_REPEATED_CODE not in [v.code for v in analyst.validation_findings]

    def test_a_retry_that_repeats_again_keeps_what_was_written_and_records_the_finding(
        self,
    ) -> None:
        analyst = _Analyst([RUNAWAY])

        result = _check(analyst)

        assert len(result.claims) >= 3
        assert ANALYST_REPEATED_CODE in [v.code for v in analyst.validation_findings]

    def test_an_answer_that_does_not_repeat_is_not_asked(self) -> None:
        analyst = _Analyst([])

        _check(analyst, DISTINCT)

        assert analyst.seen_turns == []


def test_a_chunk_whose_answer_repeats_is_asked_inside_its_chunk() -> None:
    from maljan.loaders.binary_chunker import ChunkStrategy, TextChunk

    analyst = _Analyst([])
    answers = [RUNAWAY, DISTINCT]
    asked: list[tuple[str, bool]] = []

    def _analyze(data: str) -> AgentISR:
        return analyst._text_to_isr(answers.pop(0), 0)

    def _validate(isr: AgentISR, evidence: str, **kw: Any) -> AgentISR:
        asked.append((str(kw.get("chunk", "")), bool(kw.get("only_cut"))))
        return isr

    analyst.analyze_isr = _analyze  # type: ignore[method-assign]
    analyst._validate_isr = _validate  # type: ignore[method-assign]
    chunks = [
        TextChunk(
            index=i,
            total=2,
            strategy=ChunkStrategy.SLIDING_WINDOW,
            content=f"part {i}",
            char_count=6,
            token_estimate=1,
            domain="static",
        )
        for i in range(2)
    ]

    analyst.safe_analyze_isr_chunked(chunks)

    assert asked == [("chunk 1 of 2", True), ("", False)]
