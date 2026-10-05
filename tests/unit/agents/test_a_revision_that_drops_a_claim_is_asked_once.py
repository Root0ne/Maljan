"""A revision that drops a claim of the answer in force is asked once, in its validation turn.

The question names each dropped claim that states a value and was not
withdrawn with a reason, and asks the analyst to keep it or withdraw it. What
it answers stands: a kept claim is back in the answer, a withdrawal leaves it
out with its reason, and a claim still dropped after the question is recorded
as a finding of the turn. A first answer is never asked: there is nothing in
force to drop from. Every value is synthetic.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import BaseAnalyst
from maljan.pipeline.claim_drops import CLAIMS_DROPPED_CODE
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

MAPPING = "The loop picks body format 0xa10 for kind 2 and 0xa20 for kind 1 (selector 0x3ff0)."

IN_FORCE = AgentISR(
    agent_id="reverser",
    domain="static",
    claims=[
        ClaimEvidence(claim=MAPPING, evidence_ref="[ev_0001]", confidence=0.8),
        ClaimEvidence(
            claim="The loop sleeps between rounds.", evidence_ref="[ev_0002]", confidence=0.8
        ),
    ],
)

DROPPING = (
    "CLAIM: The loop sleeps between rounds.\nEVIDENCE: [ev_0002]\nCONFIDENCE: 0.8\n"
    "TECHNIQUE: NONE\n---\nDISPUTES: NONE\n"
)
KEEPING = (
    f"CLAIM: {MAPPING}\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n" + DROPPING
)
WITHDRAWING = DROPPING.replace(
    "DISPUTES: NONE\n", "DISPUTES:\n- WITHDRAWN: 0x3ff0 — the selector is a loop counter.\n"
)


class _Answers:
    def __init__(self, answers: list[str]) -> None:
        self.answers = list(answers)
        self.sent: list[list[Any]] = []

    def invoke(self, messages: list[Any], *args: Any, **kwargs: Any) -> AIMessage:
        self.sent.append(list(messages))
        return AIMessage(content=self.answers.pop(0))

    async def ainvoke(self, messages: list[Any], *args: Any, **kwargs: Any) -> AIMessage:
        return self.invoke(messages)


class _Reviser(BaseAnalyst):
    revision_text = ""

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:
        return self.revision_text


def _revise(revision: str, answers: list[str], in_force: Any = IN_FORCE) -> Any:
    llm = _Answers(answers)
    analyst = _Reviser(llm=llm, name="reverser")  # type: ignore[arg-type]
    analyst.revision_text = revision
    with patch("maljan.agents.base_agent.validity_check_available", return_value=True):
        _text, isr = analyst.safe_revise_isr(
            "the evidence", "own report", {}, "feedback", 2, in_force=in_force
        )
    return analyst, llm, isr


def test_a_dropped_claim_is_asked_about_and_a_kept_one_is_back() -> None:
    analyst, llm, isr = _revise(DROPPING, [KEEPING])

    assert len(llm.sent) == 1
    question = str(llm.sent[0][-1].content)
    assert MAPPING in question and "WITHDRAWN:" in question
    assert [c.claim for c in isr.claims][0] == MAPPING
    assert analyst.validation_fed_back.get(CLAIMS_DROPPED_CODE) == 1
    assert CLAIMS_DROPPED_CODE not in {v.code for v in analyst.validation_findings}


def test_a_withdrawal_with_a_reason_answers_it() -> None:
    analyst, _llm, isr = _revise(DROPPING, [WITHDRAWING])

    assert [c.claim for c in isr.claims] == ["The loop sleeps between rounds."]
    assert CLAIMS_DROPPED_CODE not in {v.code for v in analyst.validation_findings}


def test_a_claim_still_dropped_after_the_question_stands_and_is_recorded() -> None:
    analyst, llm, isr = _revise(DROPPING, [DROPPING])

    assert len(llm.sent) == 1
    assert [c.claim for c in isr.claims] == ["The loop sleeps between rounds."]
    assert CLAIMS_DROPPED_CODE in {v.code for v in analyst.validation_findings}


def test_a_revision_that_withdrew_it_already_is_not_asked() -> None:
    _analyst, llm, _isr = _revise(WITHDRAWING, [])

    assert llm.sent == []


def test_a_revision_with_nothing_in_force_is_not_asked() -> None:
    _analyst, llm, _isr = _revise(DROPPING, [], in_force=None)

    assert llm.sent == []
