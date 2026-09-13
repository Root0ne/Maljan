"""An analyst is told what it got wrong, in its own conversation, once.

This is what replaced the ATT&CK autocorrect pass. That pass ran in the judge
node, matched each claim's evidence text against a TF-IDF index and wrote a
different technique id onto the claim; the report then printed an id no analyst
had ever produced, attributed to the analyst. Here the analyst is shown the
problem and answers again, and what it will not fix is labelled rather than
replaced.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.agents.base_agent import BaseAnalyst
from maljan.pipeline.validation import FEEDBACK_PREAMBLE
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


class _Attck:
    """``tools.knowledge`` without the fifty-megabyte bundle behind it."""

    known = {"T1055"}

    def attck_validate(self, ids: list[str]) -> dict[str, Any]:
        return {"invalid": [{"id": t} for t in ids if t not in self.known], "checked": len(ids)}

    def resolve_technique(self, text: str, k: int = 5) -> dict[str, Any]:
        return {"candidates": [{"technique_id": "T1055"}]}


class _Analyst(BaseAnalyst):
    """A minimal concrete analyst whose second answer is whatever it is told."""

    def __init__(self, first: AgentISR, replies: list[str]) -> None:
        super().__init__(llm=MagicMock(), name="static")
        self._first = first
        self._replies = list(replies)
        self.seen_turns: list[list[Any]] = []

    def analyze(self, data: str) -> str:  # pragma: no cover - unused by these tests
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def analyze_isr(self, data: str) -> AgentISR:
        return self._first

    def _invoke_llm_with_timeout(self, messages: list, timeout: int) -> str:
        self.seen_turns.append(list(messages))
        return self._replies.pop(0)


def _isr(*claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id="static", domain="static", claims=list(claims))


def _claim(technique_id: str | None = None, confidence: float = 0.8) -> ClaimEvidence:
    return ClaimEvidence(
        claim="allocates memory in another process",
        evidence_ref="API call: VirtualAllocEx @ 0x401234",
        confidence=confidence,
        technique_id=technique_id,
    )


_GOOD_ANSWER = (
    "CLAIM: allocates memory in another process\n"
    "EVIDENCE: API call: VirtualAllocEx @ 0x401234\n"
    "CONFIDENCE: 0.8\n"
    "TECHNIQUE: T1055\n"
)

# The analyst answering again with the same unknown id.
_STUBBORN_ANSWER = _GOOD_ANSWER.replace("TECHNIQUE: T1055", "TECHNIQUE: T1699")


@pytest.fixture(autouse=True)
def _offline_knowledge(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the loop's knowledge lookup at the stub, not at MITRE."""
    import maljan.tools.knowledge as knowledge

    stub = _Attck()
    monkeypatch.setattr(knowledge, "attck_validate", stub.attck_validate, raising=False)
    monkeypatch.setattr(knowledge, "resolve_technique", stub.resolve_technique, raising=False)


class TestTheAnalystGetsOneTurnToFixIt:
    def test_a_bad_id_earns_a_feedback_turn_and_the_second_answer_is_kept(self) -> None:
        analyst = _Analyst(_isr(_claim("T9999")), [_GOOD_ANSWER])

        result = analyst.safe_analyze_isr("raw data")

        assert [c.technique_id for c in result.claims] == ["T1055"]
        assert analyst.validation_findings == []
        assert analyst.validation_retries == 1

    def test_the_feedback_turn_names_the_problem_and_suggests_a_real_id(self) -> None:
        analyst = _Analyst(_isr(_claim("T9999")), [_GOOD_ANSWER])

        analyst.safe_analyze_isr("raw data")

        feedback = str(analyst.seen_turns[0][-1].content)
        assert feedback.startswith(FEEDBACK_PREAMBLE)
        assert "T9999" in feedback
        assert "T1055" in feedback
        assert feedback.rstrip().endswith("answer again in the same format.")

    def test_the_analysts_first_answer_is_in_the_conversation_it_is_asked_to_fix(self) -> None:
        analyst = _Analyst(_isr(_claim("T9999")), [_GOOD_ANSWER])

        analyst.safe_analyze_isr("raw data")

        turns = analyst.seen_turns[0]
        assert any("T9999" in str(getattr(turn, "content", "")) for turn in turns[:-1])

    def test_a_good_first_answer_costs_no_retry(self) -> None:
        analyst = _Analyst(_isr(_claim("T1055")), [])

        result = analyst.safe_analyze_isr("raw data")

        assert analyst.seen_turns == []
        assert analyst.validation_retries == 0
        assert [c.technique_id for c in result.claims] == ["T1055"]

    def test_an_id_that_survives_the_retry_is_labelled_not_replaced(self) -> None:
        # ``T1699`` is well-shaped and absent from the catalogue, which is the
        # case that matters: a malformed id never reaches the loop at all.
        analyst = _Analyst(_isr(_claim("T1699")), [_STUBBORN_ANSWER])

        result = analyst.safe_analyze_isr("raw data")

        assert [c.technique_id for c in result.claims] == ["T1699"]
        assert [c.technique_id_valid for c in result.claims] == [False]
        assert [v.code for v in analyst.validation_findings] == ["attck.unknown_id"]
        assert analyst.validation_retries == 1

    def test_only_one_retry_is_spent(self) -> None:
        analyst = _Analyst(_isr(_claim("T1699")), [_STUBBORN_ANSWER, _STUBBORN_ANSWER])

        analyst.safe_analyze_isr("raw data")

        assert len(analyst.seen_turns) == 1

    def test_a_retry_that_loses_claims_keeps_the_first_answer(self) -> None:
        """``_text_to_isr`` over a garbled second answer parses to an empty ISR
        as happily as over a good one, and taking it would delete the analyst's
        original findings with nothing recording that it happened."""
        analyst = _Analyst(_isr(_claim("T1699"), _claim("T1055")), ["   "])

        result = analyst.safe_analyze_isr("raw data")

        assert [c.technique_id for c in result.claims] == ["T1699", "T1055"]
        assert [v.code for v in analyst.validation_findings] == ["attck.unknown_id"]
        assert analyst.validation_retries == 1

    def test_a_retry_that_raises_keeps_the_first_answer(self) -> None:
        class _Broken(_Analyst):
            def _invoke_llm_with_timeout(self, messages: list, timeout: int) -> str:
                raise RuntimeError("the model is unreachable")

        analyst = _Broken(_isr(_claim("T9999")), [])

        result = analyst.safe_analyze_isr("raw data")

        assert [c.technique_id for c in result.claims] == ["T9999"]


class TestWhatTheNodeDrains:
    def test_the_findings_and_the_retry_count_come_off_once(self) -> None:
        analyst = _Analyst(_isr(_claim("T1699")), [_STUBBORN_ANSWER])
        analyst.safe_analyze_isr("raw data")

        rows, retries = analyst.drain_validation_findings()

        assert [row["code"] for row in rows] == ["attck.unknown_id"]
        assert retries == 1
        assert analyst.drain_validation_findings() == ([], 0)
