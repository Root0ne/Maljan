"""A sub-technique is not described by what every sub-technique of its parent shares.

The does-not-describe question passes a claim that shares any term with the
technique: its capability terms, its tactic, its catalogue name and its
parent's. For a sub-technique those are mostly the parent's, so a sentence
that names a sibling sub-technique outright passed under another one on a
tactic word alone. When the sentence writes none of the sub-technique's own
distinctive words (its vendored name's words that are not its parent's) and
writes the whole name of a sibling, it is asked once, naming the sibling.
Every other sentence is read as before.
"""

from __future__ import annotations

import pytest

from maljan.pipeline.validation import (
    CLAIM_DOES_NOT_DESCRIBE_CODE,
    claim_does_not_describe_violation,
    sibling_named_instead,
    validate_isr,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.tools import knowledge

PE = {"platform": "windows", "file_type": "pe"}
SIBLING_SENTENCE = "The loader persists by registering its own accessibility features handler."


def _claim(text: str, technique: str) -> ClaimEvidence:
    return ClaimEvidence(
        claim=text, evidence_ref="[ev_0008] registry write", confidence=0.8, technique_id=technique
    )


def test_a_sentence_naming_a_sibling_on_a_tactic_word_is_asked() -> None:
    found = claim_does_not_describe_violation(
        _claim(SIBLING_SENTENCE, "T1546.001"), "T1546.001", knowledge
    )

    assert found is not None
    assert found.code == CLAIM_DOES_NOT_DESCRIBE_CODE
    assert found.subject == "T1546.001"
    assert "T1546.008 Accessibility Features" in found.message
    assert "another sub-technique of T1546" in found.message


def test_the_question_is_asked_through_the_validator_once() -> None:
    isr = AgentISR(
        agent_id="static", domain="static", claims=[_claim(SIBLING_SENTENCE, "T1546.001")]
    )
    codes = [v.code for v in validate_isr(isr, attck=knowledge, sample=PE)]

    assert codes == [CLAIM_DOES_NOT_DESCRIBE_CODE]


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        # The sibling's own id: its name is its own word.
        (SIBLING_SENTENCE, "T1546.008"),
        # One of the sub-technique's own words is written.
        (
            "The loader persists by changing the default association of a file "
            "type to its accessibility features handler.",
            "T1546.001",
        ),
        # A tactic word and no sibling named: read as before.
        ("The loader persists across reboots.", "T1546.001"),
        # A sibling named by one word only is not a whole name of more than one.
        ("The beacon speaks HTTP to its C2 and makes no DNS query.", "T1071.001"),
        # A parent id has no sibling.
        (SIBLING_SENTENCE, "T1546"),
    ],
)
def test_every_other_sentence_is_read_as_before(text: str, technique: str) -> None:
    assert claim_does_not_describe_violation(_claim(text, technique), technique, knowledge) is None


def test_an_id_outside_the_catalogue_names_no_sibling() -> None:
    assert sibling_named_instead(SIBLING_SENTENCE, "T1999.001") is None
