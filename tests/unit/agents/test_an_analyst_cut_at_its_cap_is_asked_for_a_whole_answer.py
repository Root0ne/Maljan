"""An analyst whose answer ended at its output cap is asked once for a whole shorter one.

The reference run's static analyst answered in one step: 42 claims in exactly
the 4,096 tokens its cap allows, the last one cut. Its validation turn asked
fourteen questions over that answer, the retry spent the whole cap again and
returned no claim, and the first answer was kept with every question
unanswered. The judge and the composer were asked about a cut answer; an
analyst was not.

It is now, the way they are: the question states the cap, the characters the
answer ran to and the claims it began, and the length it was cut at as the
bound to stay under; the cut answer is not sent back; it is asked only when
the question and an answer of the cap's size fit the model's window; and a
whole answer that comes back is the analyst's, however many claims it has. The
cap is the one in force and nothing raises it.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import BaseAnalyst, answer_cut_at_cap
from maljan.pipeline.validation import ANALYST_CUT_CODE, analyst_cut_violation
from maljan.schemas.isr_models import AgentISR

CAP = 4096


def _block(n: int) -> str:
    return (
        f"CLAIM: The file carries configuration string number {n}.\n"
        "EVIDENCE: [ev_0001] strings\n"
        "CONFIDENCE: 0.8\n"
        "TECHNIQUE: NONE\n"
        "---\n"
    )


FIRST = "".join(_block(n) for n in range(1, 4)) + "CLAIM: The file carries configur"
WHOLE = _block(1)


def _message(text: str, tokens: int) -> AIMessage:
    return AIMessage(
        content=text,
        usage_metadata={"input_tokens": 900, "output_tokens": tokens, "total_tokens": 900 + tokens},
    )


class _Analyst(BaseAnalyst):
    """Answers each retry from a queue, recording each answer as the real call does."""

    def __init__(self, replies: list[tuple[str, int]]) -> None:
        super().__init__(llm=MagicMock(), name="static")
        self.pack_ledger_ids = ["ev_0001"]
        self._replies = list(replies)
        self.seen_turns: list[list[Any]] = []

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.seen_turns.append(list(messages))
        text, tokens = self._replies.pop(0)
        self._record_usage(_message(text, tokens))
        return text


def _check(analyst: _Analyst, first: str = FIRST, *, fits: bool = True) -> AgentISR:
    """The loop's own answer, cut at the cap, through the validation turn."""
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("maljan.agents.base_agent.analyst_output_cap", return_value=CAP),
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=fits),
    ):
        analyst._record_usage(_message(first, CAP))
        return analyst._validate_isr(isr, "evidence")


class TestTheSignal:
    def test_an_answer_that_used_the_whole_cap_was_cut(self) -> None:
        assert answer_cut_at_cap(_message(FIRST, CAP), CAP) == (CAP, FIRST)

    def test_one_that_ended_short_of_it_was_not(self) -> None:
        assert answer_cut_at_cap(_message(WHOLE, 300), CAP) is None

    def test_the_question_states_the_cap_what_was_begun_and_the_bound(self) -> None:
        message = analyst_cut_violation(CAP, FIRST).message

        assert f"output limit of {CAP} tokens" in message
        assert "began 4 CLAIM block(s)" in message
        assert f"shorter than those {len(FIRST):,} characters" in message
        assert "not shown to you again" in message


class TestTheValidationTurn:
    def test_the_cut_answer_is_asked_for_and_not_sent_back(self) -> None:
        analyst = _Analyst([(WHOLE, 300)])

        _check(analyst)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert ANALYST_CUT_CODE in question
        assert f"output limit of {CAP} tokens" in question
        assert not any("configuration string number 3" in str(t.content) for t in turns)

    def test_a_whole_shorter_answer_is_the_analyst_s(self) -> None:
        analyst = _Analyst([(WHOLE, 300)])

        result = _check(analyst)

        assert [c.claim for c in result.claims] == [
            "The file carries configuration string number 1."
        ]
        assert ANALYST_CUT_CODE not in [v.code for v in analyst.validation_findings]

    def test_a_retry_cut_again_keeps_the_first_and_records_the_cut(self) -> None:
        analyst = _Analyst([(_block(9) + "CLAIM: cut", CAP)])

        result = _check(analyst)

        assert len(result.claims) >= 3
        assert ANALYST_CUT_CODE in [v.code for v in analyst.validation_findings]

    def test_a_question_that_does_not_fit_the_window_is_recorded_not_asked(self) -> None:
        analyst = _Analyst([(FIRST, 300)])

        _check(analyst, fits=False)

        # The cut last claim still carries its own question, asked over the
        # answer as every other question is; the cut question is not among them.
        assert all(ANALYST_CUT_CODE not in str(t[-1].content) for t in analyst.seen_turns)
        (finding,) = [v for v in analyst.validation_findings if v.code == ANALYST_CUT_CODE]
        assert finding.asked is False
        assert "do not fit this model's window" in finding.message

    def test_an_answer_that_was_not_cut_is_asked_nothing_about_its_length(self) -> None:
        analyst = _Analyst([])
        isr = analyst._text_to_isr(WHOLE, 0)
        with (
            patch("maljan.agents.base_agent.analyst_output_cap", return_value=CAP),
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        ):
            analyst._record_usage(_message(WHOLE, 300))
            analyst._validate_isr(isr, "evidence")

        assert analyst.seen_turns == []
        assert analyst.validation_findings == []


class TestTheWindow:
    def test_a_conversation_and_the_cap_that_fit_are_asked(self) -> None:
        analyst = _Analyst([])
        budget = SimpleNamespace(
            derives=True, chars_per_token=3, window=SimpleNamespace(tokens=32768)
        )
        with patch.object(BaseAnalyst, "_context_budget", return_value=budget):
            assert analyst._fits_the_window([SimpleNamespace(content="x" * 60_000)], CAP)
            assert not analyst._fits_the_window([SimpleNamespace(content="x" * 90_000)], CAP)

    def test_with_no_window_learned_the_question_is_asked(self) -> None:
        analyst = _Analyst([])
        with patch.object(BaseAnalyst, "_context_budget", return_value=None):
            assert analyst._fits_the_window([SimpleNamespace(content="x" * 10**7)], CAP)
