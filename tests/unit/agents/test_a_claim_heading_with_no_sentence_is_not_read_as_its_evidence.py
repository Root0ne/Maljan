"""A claim heading with no sentence is a claim with no sentence, not one whose sentence is a field.

A kept validation retry wrote CLAIM headings with nothing after them and the
EVIDENCE line next. The reader took that EVIDENCE line as the claim's sentence,
so a technique and its ids entered the findings with "EVIDENCE: [ev_…]" as
their statement, and the does-not-describe question was asked of it. Such a
block is begun and not read, as a block with no sentence always was, and is
counted as unread so the run records it.

Every value here is made up for the test.
"""

from __future__ import annotations

import pytest

from maljan.agents.base_agent import read_claim_blocks

GOOD = (
    "CLAIM: Routine 0x4100 decodes its strings at run time.\n"
    "EVIDENCE: [ev_0002]\nCONFIDENCE: 0.8\nTECHNIQUE: T1140\n"
)


@pytest.mark.parametrize(
    "heading",
    ["CLAIM:\n", "CLAIM: \n\n", "**CLAIM:**\n", "CLAIM 3:\n"],
)
@pytest.mark.parametrize("require_evidence", [True, False])
def test_a_heading_with_no_sentence_is_begun_and_not_read(
    heading: str, require_evidence: bool
) -> None:
    text = f"{heading}EVIDENCE: [ev_0001]\nCONFIDENCE: 0.9\nTECHNIQUE: T1027\n---\n{GOOD}"
    read = read_claim_blocks(text, require_evidence=require_evidence)
    assert [claim.claim for claim in read.claims] == [
        "Routine 0x4100 decodes its strings at run time."
    ]
    assert read.begun == 2
    assert read.unread == 1
    assert not any("EVIDENCE" in claim.claim for claim in read.claims)


@pytest.mark.parametrize("field", ["CONFIDENCE: 0.9", "TECHNIQUE: T1027", "- EVIDENCE: [ev_0001]"])
def test_no_field_line_is_taken_as_a_sentence(field: str) -> None:
    read = read_claim_blocks(f"CLAIM:\n{field}\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.9\n")
    assert read.claims == []
    assert read.begun == 1


def test_a_sentence_on_the_line_after_its_heading_is_still_read() -> None:
    read = read_claim_blocks(
        "CLAIM:\nRoutine 0x4100 decodes its strings at run time.\n"
        "EVIDENCE: [ev_0002]\nCONFIDENCE: 0.8\n",
        require_evidence=True,
    )
    assert [claim.claim for claim in read.claims] == [
        "Routine 0x4100 decodes its strings at run time."
    ]
    assert read.unread == 0


def test_a_sentence_that_mentions_a_field_word_is_still_read() -> None:
    read = read_claim_blocks(
        "CLAIM: Evidence of a decode loop sits in routine 0x4100.\n"
        "EVIDENCE: [ev_0002]\nCONFIDENCE: 0.8\n"
    )
    assert [claim.claim for claim in read.claims] == [
        "Evidence of a decode loop sits in routine 0x4100."
    ]
