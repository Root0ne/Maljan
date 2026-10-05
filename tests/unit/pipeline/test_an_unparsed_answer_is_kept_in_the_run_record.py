"""An answer no claim could be read from is kept, whole, in the run record.

A paid run asked five revision answers to restate their claims because none
could be read, and the retries read twelve to twenty-eight claims each; the
answers that failed were in no artefact, so nobody could tell a model that
drifted from the format from a reader that was too strict. The question's
``validation_feedback`` event now carries the answer as the analyst wrote it,
bounded only by the answer itself, once: on the event that asks, not again on
the one that says the retry resolved it.
"""

from __future__ import annotations

from typing import Any

from maljan.pipeline.events import VALIDATION_FEEDBACK
from maljan.pipeline.validation import (
    UNPARSED_ANSWER_CODE,
    parse_violations,
    retry_with_feedback_sync,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

PROSE = "The loader resolves its imports by hash and beacons over HTTPS. " * 40


def _prose_isr(text: str = PROSE) -> AgentISR:
    isr = AgentISR(agent_id="static", domain="static", claims=[])
    isr.note_parse(unparsed_answer=text)
    isr.note_answer_text(text)
    return isr


def _claimed_isr() -> AgentISR:
    return AgentISR(
        agent_id="static",
        domain="static",
        claims=[ClaimEvidence(claim="x", evidence_ref="[ev_0001]", confidence=0.7)],
    )


def test_the_question_carries_the_answer_as_written() -> None:
    (question,) = [v for v in parse_violations(_prose_isr()) if v.code == UNPARSED_ANSWER_CODE]

    assert question.answer == PROSE
    # The answer is not the question: the producer reads the message only.
    assert PROSE not in question.message
    assert "answer" not in question.to_dict()


def test_a_question_about_anything_else_carries_no_answer() -> None:
    isr = _claimed_isr()
    isr.note_parse(blocks_without_confidence=1)

    assert all(not v.answer for v in parse_violations(isr))


def _run(answers: list[AgentISR]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    def sink(kind: str, data: dict[str, Any]) -> None:
        if kind == VALIDATION_FEEDBACK:
            events.append(data)

    pending = list(answers)
    retry_with_feedback_sync(
        lambda _turns: pending.pop(0),
        [],
        [parse_violations],
        parse=lambda answer: answer,
        sink=sink,
        agent="static",
        stage="static",
    )
    return events


def test_the_event_that_asks_keeps_the_answer_once() -> None:
    events = _run([_prose_isr(), _claimed_isr()])

    asked = [e for e in events if e["code"] == UNPARSED_ANSWER_CODE]
    assert [e["state"] for e in asked] == ["retried", "resolved"]
    assert asked[0]["answer"] == PROSE
    assert "answer" not in asked[1]


def test_an_answer_still_unread_after_the_retry_is_kept_on_its_survived_event() -> None:
    second = "Still prose after the question, with no claim block in it."
    events = _run([_prose_isr(), _prose_isr(second)])

    asked = [e for e in events if e["code"] == UNPARSED_ANSWER_CODE]
    assert [(e["state"], e.get("answer")) for e in asked] == [
        ("retried", PROSE),
        ("survived", second),
    ]
