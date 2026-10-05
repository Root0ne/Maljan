"""A CONFIDENCE value is read through the punctuation written after it.

The fixture is one analyst's revision answer as the model wrote it: eighteen
claims, fifteen of whose CONFIDENCE lines end in a full stop ("CONFIDENCE:
0.9."). A reader that took every digit and dot after the label read "0.9." as
no number, counted those fifteen blocks as stating no confidence, and reported
none of them unread: three claims of eighteen reached the run.

A value is the number that opens it, from 0 to 1, or a percentage. A label
with anything else after it is a confidence the analyst stated and the reader
could not read: that claim is unread, the unread sentence quotes the value,
and the validation turn asks about it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from maljan.agents.base_agent import ClaimRead, claims_unread_sentence, read_claim_blocks
from maljan.pipeline.validation import CLAIM_WITHOUT_CONFIDENCE_CODE, parse_violations
from maljan.schemas.isr_models import AgentISR

ANSWER = (
    Path(__file__).resolve().parents[2]
    / "fixtures"
    / "claims"
    / "revision_with_full_stop_confidences.txt"
).read_text(encoding="utf-8")


def _one(confidence_line: str) -> ClaimRead:
    return read_claim_blocks(
        f"CLAIM: The file keeps a table of values.\nEVIDENCE: [ev_0001]\n{confidence_line}\n"
    )


def test_every_claim_the_answer_began_is_read() -> None:
    read = read_claim_blocks(ANSWER)
    assert read.begun == 18
    assert len(read.claims) == 18
    assert (read.without_confidence, read.unread, read.confidence_unreadable) == (0, 0, ())


def test_the_strict_reading_reads_them_too() -> None:
    assert len(read_claim_blocks(ANSWER, require_evidence=True).claims) == 18


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("CONFIDENCE: 0.9.", 0.9),
        ("CONFIDENCE: 0.9,", 0.9),
        ("CONFIDENCE: 0.9;", 0.9),
        ("CONFIDENCE: 0.9, high", 0.9),
        ("CONFIDENCE: 0.9)", 0.9),
        ("CONFIDENCE: **0.9**.", 0.9),
        ("CONFIDENCE: `0.7`", 0.7),
        ("CONFIDENCE: (0.6)", 0.6),
        ("CONFIDENCE: 0.85 (one part of it lower, 0.7).", 0.85),
        ("CONFIDENCE: 1.0.", 1.0),
        ("CONFIDENCE: 0", 0.0),
        ("CONFIDENCE: .5", 0.5),
        ("CONFIDENCE: 85%", 0.85),
        ("CONFIDENCE: 85 %.", 0.85),
        ("CONFIDENCE: 100%", 1.0),
        ("- **CONFIDENCE:** 0.8.", 0.8),
    ],
)
def test_a_number_is_read_whatever_follows_it(line: str, expected: float) -> None:
    read = _one(line)
    assert [c.confidence for c in read.claims] == [pytest.approx(expected)]
    assert read.unread == 0


@pytest.mark.parametrize(
    ("line", "written"),
    [
        ("CONFIDENCE: high", "high"),
        ("CONFIDENCE: 85", "85"),
        ("CONFIDENCE: 1.5", "1.5"),
        ("CONFIDENCE: -0.2", "-0.2"),
        ("CONFIDENCE: 0.9.5", "0.9.5"),
        ("CONFIDENCE: 150%", "150%"),
        ("CONFIDENCE: 0,85", "0,85"),
        ("CONFIDENCE: 0.8-0.9", "0.8-0.9"),
        ("CONFIDENCE: 0.8 \u2013 0.9", "0.8 \u2013 0.9"),
        ("CONFIDENCE:", "(empty)"),
    ],
)
def test_a_value_that_is_not_one_of_the_two_forms_is_unread_and_quoted(
    line: str, written: str
) -> None:
    read = _one(line)
    assert read.claims == []
    assert read.without_confidence == 0
    assert read.confidence_unreadable == (written,)
    assert read.unread == 1
    sentence = claims_unread_sentence("reverser", read)
    assert "1 could not be read as a claim" in sentence
    assert repr(written) in sentence


def test_a_block_with_no_confidence_label_is_still_counted_apart() -> None:
    read = read_claim_blocks("CLAIM: The file keeps a table.\nEVIDENCE: [ev_0001]\n")
    assert (read.without_confidence, read.unread, read.confidence_unreadable) == (1, 0, ())


def test_an_unreadable_value_on_one_line_with_other_labels_is_quoted_alone() -> None:
    read = read_claim_blocks(
        "CLAIM: The file keeps a table.\nEVIDENCE: [ev_0001] CONFIDENCE: high TECHNIQUE: T1027\n"
    )
    assert read.confidence_unreadable == ("high",)


def test_the_validation_turn_asks_about_an_unreadable_value_quoting_it() -> None:
    read = _one("CONFIDENCE: high")
    isr = AgentISR(agent_id="a", domain="static", claims=[], dissent_items=[])
    isr.note_parse(
        blocks_without_confidence=read.without_confidence,
        confidence_unreadable=read.confidence_unreadable,
    )
    (violation,) = [v for v in parse_violations(isr) if v.code == CLAIM_WITHOUT_CONFIDENCE_CODE]
    assert "'high'" in violation.message
    assert "neither a number from 0.0 to 1.0 nor a percentage" in violation.message
