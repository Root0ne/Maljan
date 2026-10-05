"""Every answer one run's analysts wrote reads to every claim that states a confidence.

The fixture holds each analyst's answer from one benchmark run as the models
wrote them: the final answer of every analyst, and each revision round's
answer as the run's events carried it, cut at the event bound. The analysts
write their fields three ways: one per line; EVIDENCE, CONFIDENCE and
TECHNIQUE on one line (the network analyst's shape, which a reader that only
looked at line starts read as nine claims with no confidence); and under list
or emphasis marks. A block that states a CONFIDENCE value is read as a claim,
through both readings, in every one of them.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from maljan.agents.base_agent import _BLOCK_SPLIT_RE, read_claim_blocks
from maljan.agents.claim_headings import claims_headed

ANSWERS: dict[str, str] = json.loads(
    (
        Path(__file__).resolve().parents[2] / "fixtures" / "claims" / "every_answer_of_one_run.json"
    ).read_text(encoding="utf-8")
)
# A block that writes a confidence value, however its fields are laid out.
_STATES_A_CONFIDENCE = re.compile(r"CONFIDENCE:\s*\**\s*\d")


def _blocks(text: str) -> list[str]:
    return [b for b in _BLOCK_SPLIT_RE.split(claims_headed(text)) if "CLAIM:" in b]


@pytest.mark.parametrize("name", sorted(ANSWERS))
def test_every_block_with_a_confidence_is_read_through_both_readings(name: str) -> None:
    text = ANSWERS[name]
    stated = sum(1 for block in _blocks(text) if _STATES_A_CONFIDENCE.search(block))
    lenient = read_claim_blocks(text)
    strict = read_claim_blocks(text, require_evidence=True)
    assert len(lenient.claims) == stated
    assert len(strict.claims) == stated
    assert lenient.unread == 0


@pytest.mark.parametrize("name", sorted(n for n in ANSWERS if n.endswith("final answer")))
def test_a_whole_answer_reads_every_claim_it_began(name: str) -> None:
    read = read_claim_blocks(ANSWERS[name])
    assert len(read.claims) == read.begun
    assert read.without_confidence == 0


@pytest.mark.parametrize("name", sorted(n for n in ANSWERS if "cut at the event bound" in n))
def test_an_answer_cut_at_the_event_bound_loses_at_most_the_claim_it_was_cut_in(name: str) -> None:
    text = ANSWERS[name]
    read = read_claim_blocks(text)
    assert read.begun - len(read.claims) <= 1
    if read.begun > len(read.claims):
        # The one not read is the last, cut before its CONFIDENCE line.
        assert not _STATES_A_CONFIDENCE.search(_blocks(text)[-1])
        assert read.without_confidence == 1


def test_the_inline_field_shape_is_among_them() -> None:
    network = ANSWERS["network final answer"]
    assert re.search(r"EVIDENCE:[^\n]*\sCONFIDENCE:", network)
    read = read_claim_blocks(network)
    assert len(read.claims) == 9 and all(c.confidence > 0 for c in read.claims)


def test_three_fields_on_one_line_are_all_read() -> None:
    (claim,) = read_claim_blocks(
        "CLAIM: The capture holds no C2 session.\n"
        "EVIDENCE: [ev_0309] (conversation table). CONFIDENCE: 0.65 TECHNIQUE: T1071.001\n"
    ).claims
    assert claim.evidence_ref == "[ev_0309] (conversation table)."
    assert (claim.confidence, claim.technique_id) == (0.65, "T1071.001")
