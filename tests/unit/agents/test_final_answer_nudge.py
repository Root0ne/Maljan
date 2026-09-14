"""An answer that is not a report is asked for once, and never invented.

Live run, static analyst: the loop stopped after five tool calls on the
sentence "Let me search for more specific strings related to malware
indicators:" — an intention, not a finding. Nothing asked the model for the
report it had not written, and the free-text sentence splitter turned that one
sentence into the run's only claim at 0.5 confidence, which then became the
whole verdict's evidence base.

Two rules are pinned here. The loop nudges exactly once, in the same
conversation, bounded by the step and time budget it is already inside. And
when the nudge does not produce a report either, the analyst says so —
``status=no_claims`` with a reason — instead of a claim list built out of the
model thinking aloud.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from maljan.agents.base_agent import (
    FINAL_ANSWER_NUDGE,
    NO_STRUCTURED_REPORT_REASON,
    NO_STRUCTURED_REPORT_STATUS,
    BaseAnalyst,
    answer_is_isr,
)

_INTENTION = "Let me search for more specific strings related to malware indicators:"

_REPORT = (
    "CLAIM: The sample resolves its imports at runtime\n"
    "EVIDENCE: ev_0003 LoadLibraryA / GetProcAddress pair\n"
    "CONFIDENCE: 0.7\n"
    "TECHNIQUE: T1027\n"
)


class _FakeLLM:
    """Answers each ``ainvoke`` from a queue and records what it was sent."""

    def __init__(self, answers: list[str]) -> None:
        self._answers = list(answers)
        self.seen: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> AIMessage:
        self.seen.append(list(messages))
        return AIMessage(content=self._answers.pop(0) if self._answers else "")


class _Analyst(BaseAnalyst):
    """Concrete stand-in with only the fields the nudge path touches."""

    def __init__(self, llm: Any) -> None:
        self.name = "static"
        self.logger = logging.getLogger("test.nudge")
        self.llm = llm
        self.token_ledger = None
        self._answer_unstructured = False

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


def _conversation() -> list[Any]:
    return [
        SystemMessage(content="You are a static analyst."),
        HumanMessage(content="Analyse this binary."),
        AIMessage(content=_INTENTION),
    ]


class TestWhatCountsAsAReport:
    def test_a_claim_block_is_a_report(self) -> None:
        assert answer_is_isr(_REPORT)

    def test_a_findings_block_is_a_report(self) -> None:
        block = '```maljan-findings\n{"findings": []}\n```'
        assert answer_is_isr(f"Some prose.\n\n{block}")

    def test_an_intention_sentence_is_not(self) -> None:
        assert not answer_is_isr(_INTENTION)

    def test_an_empty_answer_is_not(self) -> None:
        assert not answer_is_isr("   ")


class TestTheNudge:
    def test_it_asks_once_in_the_same_conversation(self) -> None:
        llm = _FakeLLM([_REPORT])
        analyst = _Analyst(llm)

        answer = analyst._nudge_for_final_answer(
            _conversation(), timeout=60, elapsed=1.0, max_steps=40
        )

        assert answer == _REPORT
        assert len(llm.seen) == 1
        sent = llm.seen[0]
        # The whole conversation, plus one human turn saying what is missing.
        assert [m.content for m in sent[:3]] == [m.content for m in _conversation()]
        assert isinstance(sent[-1], HumanMessage)
        assert sent[-1].content == FINAL_ANSWER_NUDGE

    def test_it_is_skipped_when_the_step_budget_is_spent(self) -> None:
        llm = _FakeLLM([_REPORT])
        analyst = _Analyst(llm)

        answer = analyst._nudge_for_final_answer(
            _conversation(), timeout=60, elapsed=1.0, max_steps=3
        )

        assert answer is None
        assert llm.seen == []

    def test_it_is_skipped_when_the_time_budget_is_spent(self) -> None:
        llm = _FakeLLM([_REPORT])
        analyst = _Analyst(llm)

        answer = analyst._nudge_for_final_answer(
            _conversation(), timeout=60, elapsed=60.0, max_steps=40
        )

        assert answer is None
        assert llm.seen == []

    def test_a_failing_nudge_leaves_the_answer_alone(self) -> None:
        class _Broken:
            async def ainvoke(self, messages: list[Any]) -> AIMessage:
                raise RuntimeError("the server closed the connection")

        analyst = _Analyst(_Broken())
        assert analyst._nudge_for_final_answer(_conversation(), 60, 1.0, 40) is None


class TestNoFabricatedClaims:
    def test_an_intention_sentence_yields_no_claims(self) -> None:
        analyst = _Analyst(_FakeLLM([]))
        isr = analyst._text_to_isr(_INTENTION, revision_round=0)
        assert isr.claims == []

    def test_an_intention_inside_prose_is_dropped_but_the_rest_survives(self) -> None:
        analyst = _Analyst(_FakeLLM([]))
        text = (
            "Let me search for more specific strings related to malware indicators. "
            "The binary imports VirtualAllocEx from KERNEL32 and writes to a remote process."
        )
        isr = analyst._text_to_isr(text, revision_round=0)
        assert len(isr.claims) == 1
        assert "VirtualAllocEx" in isr.claims[0].claim

    def test_a_sentence_that_only_announces_the_next_step_is_dropped(self) -> None:
        analyst = _Analyst(_FakeLLM([]))
        for text in (
            "I will now run the strings tool against the whole file:",
            "Next, I check the import table for dynamic resolution:",
        ):
            assert analyst._text_to_isr(text, revision_round=0).claims == []

    def test_a_report_opening_with_a_heading_still_yields_claims(self) -> None:
        analyst = _Analyst(_FakeLLM([]))
        text = "Findings:\nThe sample writes a copy of itself into the user's startup folder."
        isr = analyst._text_to_isr(text, revision_round=0)
        assert len(isr.claims) == 1
        assert "startup folder" in isr.claims[0].claim


class TestTheStatusItReports:
    def test_an_unstructured_answer_reports_no_claims_with_a_reason(self) -> None:
        analyst = _Analyst(_FakeLLM([]))
        analyst._answer_unstructured = True

        isr = analyst._text_to_isr(_INTENTION, revision_round=0)

        assert isr.claims == []
        assert isr.status == NO_STRUCTURED_REPORT_STATUS
        assert isr.status_reason == NO_STRUCTURED_REPORT_REASON

    def test_an_ordinary_empty_answer_declares_nothing(self) -> None:
        analyst = _Analyst(_FakeLLM([]))
        isr = analyst._text_to_isr("No static data available for sample abc.", revision_round=0)
        assert isr.claims == []
        assert isr.status is None
        assert isr.status_reason is None

    def test_claims_win_over_the_flag(self) -> None:
        analyst = _Analyst(_FakeLLM([]))
        analyst._answer_unstructured = True
        isr = analyst._text_to_isr(_REPORT, revision_round=0)
        assert isr.claims
        assert isr.status is None


class TestTheStatusTheNodeReads:
    def test_the_declared_status_wins(self) -> None:
        from maljan.pipeline.nodes import isr_status
        from maljan.schemas.isr_models import AgentISR

        isr = AgentISR(
            agent_id="static",
            domain="static",
            status=NO_STRUCTURED_REPORT_STATUS,
            status_reason=NO_STRUCTURED_REPORT_REASON,
        )
        assert isr_status(isr) == NO_STRUCTURED_REPORT_STATUS

    def test_the_claim_list_decides_otherwise(self) -> None:
        from maljan.pipeline.nodes import isr_status
        from maljan.schemas.isr_models import AgentISR

        assert isr_status(AgentISR(agent_id="static", domain="static")) == "no_data"
