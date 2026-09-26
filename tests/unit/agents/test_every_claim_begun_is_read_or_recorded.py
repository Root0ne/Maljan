"""Every claim an analyst begins is read, or the run records that it was not.

Two analysts wrote their claims one after another, separated by blank lines,
with one ``---`` line before the first claim and one before DISPUTES. The
reader the base analyst used split only on ``---`` and kept the first
``CLAIM:`` of a block, so a revision of thirteen claims became one and an
answer of twenty-one became one, and nothing said so. The fixtures are those
two answers as the models wrote them.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from maljan.agents.base_agent import (
    ClaimRead,
    claims_unread_sentence,
    parse_structured_claims_counted,
    read_claim_blocks,
)
from maljan.agents.claim_headings import count_claims_begun
from maljan.agents.static_analyst import StaticAnalyst, _parse_claim_blocks
from maljan.core.truncation_ledger import TruncationLedger
from maljan.pipeline.validation import analyst_cut_violation

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "claims"
REVISION = (FIXTURES / "blank_line_separated_revision.txt").read_text(encoding="utf-8")
FINAL_ISR = (FIXTURES / "blank_line_separated_final_isr.txt").read_text(encoding="utf-8")

# The second claim is written where the first has no CONFIDENCE line yet, so
# the reader takes it into the first claim's block.
MALFORMED = (
    "CLAIM 1: The loader resolves its imports by hash.\n"
    "EVIDENCE: [ev_0002]\n"
    "\n"
    "CLAIM 2: The beacon sleeps 180 seconds before its first request.\n"
    "EVIDENCE: [ev_0003]\n"
    "CONFIDENCE: 0.8\n"
    "TECHNIQUE: NONE\n"
)


def _analyst() -> StaticAnalyst:
    analyst = StaticAnalyst.__new__(StaticAnalyst)
    analyst.name = "reverser"
    analyst.logger = logging.getLogger("test.claims")
    analyst.truncation_ledger = TruncationLedger()
    return analyst


@pytest.mark.parametrize(("text", "count"), [(REVISION, 13), (FINAL_ISR, 21)])
def test_blank_line_separated_claims_are_all_read_by_both_readings(text: str, count: int) -> None:
    lenient = read_claim_blocks(text)
    assert lenient.begun == count
    assert len(lenient.claims) == count
    assert lenient.unread == 0
    assert len(_parse_claim_blocks(text)) == count
    assert len(parse_structured_claims_counted(text)[0]) == count


def test_the_revision_keeps_the_techniques_of_its_later_claims() -> None:
    techniques = [c.technique_id for c in read_claim_blocks(REVISION).claims]
    assert techniques[:3] == ["T1218.011", "T1027.007", "T1027.005"]
    assert "T1070" in techniques and "T1620" in techniques
    # The DISPUTES section after the last claim is not read as a claim.
    assert not any("DISPUTED" in c.claim for c in read_claim_blocks(REVISION).claims)


def test_the_base_analyst_path_reads_every_claim_and_records_nothing() -> None:
    analyst = _analyst()
    isr = analyst._text_to_isr(REVISION, revision_round=2)
    assert len(isr.claims) == 13
    assert analyst.truncation_ledger.claims_unread == []


def test_a_malformed_block_is_a_recorded_shortfall(caplog: pytest.LogCaptureFixture) -> None:
    read = read_claim_blocks(MALFORMED)
    assert (read.begun, len(read.claims), read.unread) == (2, 1, 1)

    analyst = _analyst()
    with caplog.at_level(logging.WARNING, logger="test.claims"):
        isr = analyst._text_to_isr(MALFORMED, revision_round=1)
    assert len(isr.claims) == 1
    (sentence,) = analyst.truncation_ledger.claims_unread
    assert "reverser" in sentence and "round 1" in sentence
    assert "began 2 claim(s)" in sentence and "1 were read" in sentence
    assert sentence in caplog.text


def test_the_stricter_reading_records_a_claim_it_turns_away() -> None:
    text = (
        "CLAIM: cited\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.9\n---\n"
        "CLAIM: not cited\nCONFIDENCE: 0.7\n---\n"
    )
    analyst = _analyst()
    claims = analyst._read_claims(text)
    assert [c.claim for c in claims] == ["cited"]
    (sentence,) = analyst.truncation_ledger.claims_unread
    assert "began 2 claim(s) and 1 were read" in sentence


def test_a_stricter_reading_that_reads_nothing_leaves_the_record_to_the_fallback() -> None:
    analyst = _analyst()
    assert analyst._read_claims("CLAIM: not cited\nCONFIDENCE: 0.7\n") == []
    assert analyst.truncation_ledger.claims_unread == []


def test_blocks_without_confidence_are_asked_about_not_recorded_as_unread() -> None:
    text = "CLAIM: one\nEVIDENCE: e\nCONFIDENCE: 0.5\n---\nCLAIM: two\nEVIDENCE: e\n"
    read = read_claim_blocks(text)
    assert (read.begun, len(read.claims), read.without_confidence, read.unread) == (2, 1, 1, 0)


def test_the_sentence_names_the_agent_and_both_numbers() -> None:
    read = ClaimRead(claims=[], without_confidence=1, begun=5)
    sentence = claims_unread_sentence("triage", read, 2)
    assert sentence == (
        "The triage analyst's answer (round 2) began 5 claim(s) and 0 were read, "
        "1 stated no confidence; 4 could not be read as a claim and are not in its findings."
    )


def test_the_cut_answer_question_counts_claims_by_the_same_heading_rule() -> None:
    text = "CLAIM 1: a\nEVIDENCE: e\nCONFIDENCE: 0.5\n\n**CLAIM 2 —** b\nEVIDENCE: e"
    assert count_claims_begun(text) == 2
    assert "began 2 CLAIM block(s)" in analyst_cut_violation(100, text).message


def test_a_claim_quoted_under_disputes_is_not_counted() -> None:
    text = "CLAIM: own\nEVIDENCE: e\nCONFIDENCE: 0.9\n\nDISPUTES:\nCLAIM 3: a peer's\n"
    assert count_claims_begun(text) == 1
