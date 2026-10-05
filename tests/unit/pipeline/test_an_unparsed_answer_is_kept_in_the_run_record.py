"""An answer no claim could be read from is kept, whole and masked, in the run record.

A paid run asked five revision answers to restate their claims because none
could be read, and the retries read twelve to twenty-eight claims each; the
answers that failed were in no artefact, so nobody could tell a model that
drifted from the format from a reader that was too strict. Each such answer
is now kept in ``run_summary.validation.unparsed_answers``, bounded only by
the answer itself and masked as model text in the record is. The event that
asks carries one short sentence saying the answer could not be read and where
it is kept, never the answer: events reach every connected browser, the Redis
stream and ``job_events``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from maljan.pipeline import events
from maljan.pipeline.events import (
    FINDING_VALUE_LIMIT,
    UNPARSED_ANSWERS_RECORD,
    VALIDATION_FEEDBACK,
    remember_secret_values,
)
from maljan.pipeline.validation import (
    UNPARSED_ANSWER_CODE,
    parse_violations,
    retry_with_feedback_sync,
    unparsed_answer_rows,
    validation_metrics,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.credential_shapes import lowercase_body

PROSE = "The loader resolves its imports by hash and beacons over HTTPS.\n" * 40
MEGABYTE = 1024 * 1024


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


def _run(answers: list[AgentISR]) -> tuple[list[dict[str, Any]], list[Any]]:
    published: list[dict[str, Any]] = []
    shown: list[Any] = []

    def sink(kind: str, data: dict[str, Any]) -> None:
        published.append({"type": kind, "data": data})

    pending = list(answers)
    retry_with_feedback_sync(
        lambda _turns: pending.pop(0),
        [],
        [parse_violations],
        parse=lambda answer: answer,
        on_feedback=shown.extend,
        sink=sink,
        agent="static",
        stage="static",
    )
    return published, shown


def test_the_question_carries_the_answer_in_memory_only() -> None:
    (question,) = [v for v in parse_violations(_prose_isr()) if v.code == UNPARSED_ANSWER_CODE]

    assert question.answer == PROSE
    assert PROSE not in question.message
    assert "answer" not in question.to_dict()


def test_a_megabyte_answer_leaves_every_event_within_its_bounds() -> None:
    huge = ("The sample writes a long account of what it saw. " * 30_000)[:MEGABYTE]
    published, shown = _run([_prose_isr(huge), _claimed_isr()])

    feedback = [e["data"] for e in published if e["type"] == VALIDATION_FEEDBACK]
    asked = [e for e in feedback if e["code"] == UNPARSED_ANSWER_CODE]
    assert [e["state"] for e in asked] == ["retried", "resolved"]
    # No event holds the answer or any long run of it.
    for event in published:
        wire = json.dumps(event)
        assert huge[:FINDING_VALUE_LIMIT] not in wire
        assert len(wire) < 4_096
        assert all(
            len(value) <= events.REPORT_CHAR_LIMIT
            for value in event["data"].values()
            if isinstance(value, str)
        )
    # The asking event says where the answer is kept, and how long it was.
    assert UNPARSED_ANSWERS_RECORD in asked[0]["answer_kept"]
    assert f"{len(huge):,} characters" in asked[0]["answer_kept"]
    assert "answer_kept" not in asked[1]
    # The answer itself went to the run record's collector, whole.
    (row,) = unparsed_answer_rows("static", 2, shown)
    assert row == {"agent": "static", "round": "2", "answer": huge}


def test_the_run_record_holds_the_answer_whole_and_masked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = lowercase_body(24)
    monkeypatch.setattr(events, "_SECRET_SCOPES", {})
    monkeypatch.setattr(events, "_SHORT_SECRETS", {})
    monkeypatch.setattr(events, "_FAILED_SCOPES", set())
    monkeypatch.setattr(events, "_CONFIGURED_PATTERN", None)
    remember_secret_values([key], scope="job")
    answer = PROSE + f"The operator's value {key} was in the tool output.\n" + PROSE
    (question,) = [v for v in parse_violations(_prose_isr(answer)) if v.answer]
    summary = validation_metrics(
        1, [], {}, unparsed_answers=unparsed_answer_rows("static", 1, [question])
    )

    (kept,) = summary["unparsed_answers"]
    assert key not in kept["answer"]
    assert kept["answer"].startswith(PROSE)
    assert kept["answer"].endswith(PROSE)
    assert (kept["agent"], kept["round"]) == ("static", "1")


def test_a_run_with_no_unread_answer_records_no_key() -> None:
    assert "unparsed_answers" not in validation_metrics(0, [], {})


def test_the_analyst_hands_its_unread_answers_to_the_run_record_once() -> None:
    import logging

    from maljan.agents.static_analyst import StaticAnalyst

    analyst = StaticAnalyst.__new__(StaticAnalyst)
    analyst.name = "static"
    analyst.logger = logging.getLogger("test.unparsed")
    (question,) = [v for v in parse_violations(_prose_isr()) if v.answer]
    analyst._keep_unparsed_answers([question], 1)
    analyst._keep_unparsed_answers([question], 1)

    (row,) = analyst.drain_unparsed_answers()
    assert (row["agent"], row["round"], row["answer"].strip()) == ("static", "1", PROSE.strip())
    assert analyst.drain_unparsed_answers() == []
