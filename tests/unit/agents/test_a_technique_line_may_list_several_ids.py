"""A TECHNIQUE line that lists several ids is read as the analyst's own claims.

Models write the techniques a claim holds as one list ("T1027, T1140"), and
the reader used to read no id from such a line and ask for one claim per
technique: in a paid run that question was most of the validation turns. A
list of ids, each one an id and nothing else, separated by commas or "and",
is read as one claim per id, each carrying the claim's own sentence, evidence
and confidence, so every check a technique gets after the read is asked of
each one. A line with words beside an id is still kept whole and asked about.
"""

from __future__ import annotations

import pytest

from maljan.agents.base_agent import claims_unread_sentence, read_claim_blocks
from maljan.pipeline.validation import (
    CLAIM_DOES_NOT_DESCRIBE_CODE,
    TECHNIQUE_LINE_UNREAD_CODE,
    parse_violations,
    validate_isr,
)
from maljan.schemas.isr_models import AgentISR
from maljan.tools import knowledge


def _block(line: str) -> str:
    return (
        "CLAIM: The loader decodes its strings at run time.\n"
        "EVIDENCE: [ev_0004] decoder routine\n"
        "CONFIDENCE: 0.8\n"
        f"TECHNIQUE: {line}\n"
    )


@pytest.mark.parametrize(
    ("line", "ids"),
    [
        ("T1027, T1140", ["T1027", "T1140"]),
        ("T1027,T1140", ["T1027", "T1140"]),
        ("T1027 and T1140", ["T1027", "T1140"]),
        ("T1027, T1140, and T1106", ["T1027", "T1140", "T1106"]),
        ("T1027, T1140 and T1106", ["T1027", "T1140", "T1106"]),
        ("t1027.007, **T1106**", ["T1027.007", "T1106"]),
        ("`T1071.001`, `T1573.001`.", ["T1071.001", "T1573.001"]),
        # One id written twice is one technique.
        ("T1027, T1027", ["T1027"]),
        # The block separator written after the line, the next claim on the same line.
        ("T1027 · ---", ["T1027"]),
        ("T1027, T1140 ---", ["T1027", "T1140"]),
    ],
)
def test_a_list_of_ids_is_one_claim_per_id(line: str, ids: list[str]) -> None:
    claims = read_claim_blocks(_block(line)).claims

    assert [c.technique_id for c in claims] == ids
    # Each is the analyst's claim as written: sentence, evidence and confidence.
    assert {(c.claim, c.evidence_ref, c.confidence) for c in claims} == {
        ("The loader decodes its strings at run time.", "[ev_0004] decoder routine", 0.8)
    }
    assert all(c.technique_line is None for c in claims)


@pytest.mark.parametrize(
    "line",
    [
        # Words beside an id: a qualifier, a negation, a candidate.
        "T1027, T1140 (candidate)",
        "T1027.005, T1027 (rule-asserted)",
        "T1027 and not T1140",
        "T1105; T1620 (candidate)",
        # A separator the reader does not read as a list.
        "T1027 / T1140",
        "T1027 or T1140",
        # Something that is not an id.
        "T1027, T99",
        "T1027, ",
    ],
)
def test_a_line_with_anything_but_ids_is_kept_whole_and_asked_about(line: str) -> None:
    (claim,) = read_claim_blocks(_block(line)).claims

    assert claim.technique_id is None
    assert claim.technique_line == line.strip()
    isr = AgentISR(agent_id="static", domain="static", claims=[claim])
    (question,) = [v for v in parse_violations(isr) if v.code == TECHNIQUE_LINE_UNREAD_CODE]
    assert line.strip() in question.message


def test_a_separator_closing_the_technique_line_is_not_part_of_it() -> None:
    text = (
        "CLAIM: The loader decodes its strings.\nEVIDENCE: [ev_0004]\nCONFIDENCE: 0.8\n"
        "TECHNIQUE: T1140 · ---\nCLAIM: The loader resolves imports by hash.\n"
        "EVIDENCE: [ev_0005]\nCONFIDENCE: 0.7\nTECHNIQUE: NONE · ---\n"
    )
    claims = read_claim_blocks(text).claims

    assert [(c.technique_id, c.technique_line) for c in claims] == [("T1140", None), (None, None)]


def test_the_claim_format_asks_for_ids_alone() -> None:
    from maljan.agents.prompt_fragments import CLAIM_FORMAT_FRAGMENT

    assert "TECHNIQUE: <T-ID, several separated by commas, or NONE>" in CLAIM_FORMAT_FRAGMENT


def test_a_list_read_as_ids_is_not_asked_about() -> None:
    claims = read_claim_blocks(_block("T1027, T1140")).claims
    isr = AgentISR(agent_id="static", domain="static", claims=claims)

    assert TECHNIQUE_LINE_UNREAD_CODE not in [v.code for v in parse_violations(isr)]


def test_the_question_says_a_list_of_ids_is_read() -> None:
    (claim,) = read_claim_blocks(_block("T1027 (candidate)")).claims
    isr = AgentISR(agent_id="static", domain="static", claims=[claim])
    (question,) = [v for v in parse_violations(isr) if v.code == TECHNIQUE_LINE_UNREAD_CODE]

    assert "separated by commas" in question.message
    assert "one claim per technique" not in question.message


def test_every_id_of_a_list_gets_the_checks_a_technique_gets() -> None:
    """An id the claim's sentence does not describe is asked about on its own claim."""
    text = (
        "CLAIM: The loader obfuscates its strings.\nEVIDENCE: [ev_0004]\n"
        "CONFIDENCE: 0.8\nTECHNIQUE: T1027, T1003\n"
    )
    claims = read_claim_blocks(text).claims
    isr = AgentISR(agent_id="static", domain="static", claims=claims)
    found = validate_isr(isr, attck=knowledge, sample={"platform": "windows", "file_type": "pe"})

    asked = [v for v in found if v.code == CLAIM_DOES_NOT_DESCRIBE_CODE]
    assert [(v.subject, v.path.rsplit(".", 1)[-1]) for v in asked] == [("T1003", "claims[1]")]


def test_a_split_claim_is_counted_once_against_the_claims_begun() -> None:
    text = _block("T1027, T1140") + "\nCLAIM: a second\nEVIDENCE: [ev_0002]\n"
    read = read_claim_blocks(text)

    # Two claims begun: one read (as two techniques), one stated no confidence.
    assert (read.begun, len(read.claims), read.without_confidence, read.unread) == (2, 2, 1, 0)


def test_a_split_claim_does_not_hide_a_block_left_unread() -> None:
    text = _block("T1027, T1140") + "\n**CLAIM 2:**\n"
    read = read_claim_blocks(text)

    assert (read.begun, len(read.claims), read.unread) == (2, 2, 1)
    sentence = claims_unread_sentence("static", read)
    assert "began 2 claim(s), and 1 were read" in sentence
