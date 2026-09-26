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

# The second claim is written where the first has no CONFIDENCE line yet.
UNCLOSED = (
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
    claims = read_claim_blocks(REVISION).claims
    techniques = [c.technique_id for c in claims]
    assert techniques[:3] == ["T1218.011", "T1027.007", "T1027.005"]
    assert "T1070" in techniques and "T1620" in techniques
    # "TECHNIQUE: T1055, T1106" claims two: neither is read, the line is kept whole.
    (both,) = [c for c in claims if c.technique_line]
    assert (both.technique_id, both.technique_line) == (None, "T1055, T1106")
    # The DISPUTES section after the last claim is not read as a claim.
    assert not any("DISPUTED" in c.claim for c in read_claim_blocks(REVISION).claims)


def test_the_base_analyst_path_reads_every_claim_and_records_nothing() -> None:
    analyst = _analyst()
    isr = analyst._text_to_isr(REVISION, revision_round=2)
    assert len(isr.claims) == 13
    assert analyst.truncation_ledger.claims_unread == []


# A block whose heading was written and whose claim was not: an answer cut there.
MALFORMED = (
    "CLAIM 1: The loader resolves its imports by hash.\n"
    "EVIDENCE: [ev_0002]\n"
    "CONFIDENCE: 0.7\n"
    "TECHNIQUE: NONE\n"
    "\n"
    "**CLAIM 2:**\n"
)


def test_a_claim_never_carries_the_next_claim_s_fields() -> None:
    read = read_claim_blocks(UNCLOSED)
    (claim,) = read.claims
    assert claim.claim == "The beacon sleeps 180 seconds before its first request."
    assert (claim.confidence, claim.evidence_ref) == (0.8, "[ev_0003]")
    # The first stated no confidence: counted and asked about, not given the next one's.
    assert (read.begun, read.without_confidence, read.unread) == (2, 1, 0)


def test_a_malformed_block_is_a_recorded_shortfall(caplog: pytest.LogCaptureFixture) -> None:
    read = read_claim_blocks(MALFORMED)
    assert (read.begun, len(read.claims), read.unread) == (2, 1, 1)
    assert read.claims[0].confidence == 0.7

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


def test_a_claim_after_disputes_and_a_separator_is_not_read_as_the_analyst_s() -> None:
    text = (
        "CLAIM: own\nEVIDENCE: e\nCONFIDENCE: 0.9\n\nDISPUTES:\n---\n"
        "CLAIM: the peer says x\nEVIDENCE: e\nCONFIDENCE: 0.8\n"
    )
    read = read_claim_blocks(text)
    assert [c.claim for c in read.claims] == ["own"]
    assert read.begun == 1


@pytest.mark.parametrize("marker", ["- ", "+ ", "1. ", "2) ", "* "])
def test_list_marker_headings_are_read_and_counted(marker: str) -> None:
    text = "".join(
        f"{marker}CLAIM: finding {n}\n{marker}EVIDENCE: [ev_000{n}]\n{marker}CONFIDENCE: 0.6\n\n"
        for n in (1, 2)
    )
    read = read_claim_blocks(text)
    assert [c.claim for c in read.claims] == ["finding 1", "finding 2"]
    assert [c.evidence_ref for c in read.claims] == ["[ev_0001]", "[ev_0002]"]
    assert (read.begun, read.unread) == (2, 0)
    assert len(_parse_claim_blocks(text)) == 2


def test_a_numbered_only_answer_is_a_report() -> None:
    from maljan.agents.base_agent import answer_is_isr

    text = "CLAIM 1: one\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.5\n\n**CLAIM 2 (REVISED):** two"
    assert "CLAIM:" not in text
    assert answer_is_isr(text)


def test_a_technique_the_analyst_rejects_is_not_read_as_claimed() -> None:
    claims = read_claim_blocks(FINAL_ISR).claims
    packing = claims[2]
    assert packing.claim.startswith("Producer/build")
    assert packing.technique_id is None
    assert packing.technique_line == "T1027.002 not supported"
    # Every other qualified or several-id line is kept as written, none cut to its first id.
    lines = [c.technique_line for c in claims if c.technique_line]
    assert "T1027.005 (rule-asserted); T1140" in lines
    assert all(c.technique_id is None for c in claims if c.technique_line)


@pytest.mark.parametrize(
    ("line", "technique", "kept"),
    [
        ("T1055", "T1055", None),
        ("t1055.012", "T1055.012", None),
        ("**T1105**", "T1105", None),
        ("NONE", None, None),
        ("—", None, None),
        ("-", None, None),
        ("T1027.002 not supported", None, "T1027.002 not supported"),
        ("T1055 (unproven)", None, "T1055 (unproven)"),
        ("T1055, T1106", None, "T1055, T1106"),
        ("T1105; T1620 (candidate)", None, "T1105; T1620 (candidate)"),
    ],
)
def test_a_technique_line_is_one_id_none_or_kept_whole(
    line: str, technique: str | None, kept: str | None
) -> None:
    (claim,) = read_claim_blocks(
        f"CLAIM: x\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.5\nTECHNIQUE: {line}\n"
    ).claims
    assert (claim.technique_id, claim.technique_line) == (technique, kept)


def test_a_kept_technique_line_is_asked_about_once() -> None:
    from maljan.pipeline.validation import TECHNIQUE_LINE_UNREAD_CODE, parse_violations

    isr = _analyst()._text_to_isr(
        "CLAIM: x\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.5\nTECHNIQUE: T1055, T1106\n", 0
    )
    (question,) = [v for v in parse_violations(isr) if v.code == TECHNIQUE_LINE_UNREAD_CODE]
    assert '"T1055, T1106"' in question.message
    assert "one claim per technique" in question.message


def test_only_the_answer_in_force_carries_its_unread_claims_reason() -> None:
    from maljan.pipeline.nodes import claims_unread_in_force
    from maljan.schemas.isr_models import AgentISR

    analyst = _analyst()
    analyst._text_to_isr(MALFORMED, revision_round=0)
    analyst._text_to_isr(REVISION, revision_round=2)
    recorded = analyst.truncation_ledger.claims_unread_by
    assert [(agent, rnd) for agent, rnd, _ in recorded] == [("reverser", 0)]

    later = {"reverser": AgentISR(agent_id="reverser", domain="static", revision_round=2)}
    assert claims_unread_in_force(recorded, later) == []
    # Still in the run's record of every read, and in the log.
    assert len(analyst.truncation_ledger.claims_unread) == 1

    same = {"reverser": AgentISR(agent_id="reverser", domain="static", revision_round=0)}
    assert claims_unread_in_force(recorded, same) == [recorded[0][2]]
    assert claims_unread_in_force(recorded, {}) == [recorded[0][2]]
