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

from malspark.agents.base_agent import read_claim_blocks

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


@pytest.mark.parametrize(
    ("sentence", "claim"),
    [
        (
            "Evidence: the routine at 0x10 decodes strings.",
            "Evidence: the routine at 0x10 decodes strings.",
        ),
        (
            "evidence: the routine at 0x10 decodes strings.",
            "evidence: the routine at 0x10 decodes strings.",
        ),
        (
            "Confidence: the routine at 0x10 decodes strings.",
            "Confidence: the routine at 0x10 decodes strings.",
        ),
        (
            "**Evidence:** the routine at 0x10 decodes strings.",
            "Evidence:** the routine at 0x10 decodes strings.",
        ),
    ],
)
def test_a_sentence_that_opens_with_a_label_in_another_casing_is_read(
    sentence: str, claim: str
) -> None:
    read = read_claim_blocks(
        f"CLAIM: {sentence}\nEVIDENCE: [ev_0002]\nCONFIDENCE: 0.8\n", require_evidence=True
    )
    assert [found.claim for found in read.claims] == [claim]
    assert read.begun == 1
    assert read.unread == 0


@pytest.mark.parametrize(
    "field",
    [
        "EVIDENCE: the routine at 0x10 decodes strings.",
        "Technique: T1027",
        "technique: the routine at 0x10 decodes strings.",
        "Evidence: [ev_0001], [ev_0002].",
        "confidence: 0.9",
        "Confidence: 90%",
        "Technique: T1027, T1140.",
        "Evidence: NONE",
        "Dissent: none",
        "- **Evidence**: _ev_0001_",
        "Evidence: [ev_0001] (strings output)",
        "Evidence: [ev_0001], see above",
        "Evidence: [ev_0001] \u2014 strings",
        "Evidence: [ev_0001] and [ev_0002]",
        "Confidence: high",
        "Confidence: high because the loop is clear",
        "Evidence: N/A",
        "Dissent: the peer is wrong",
        "Evidence: \u2022 [ev_0001]",
        'Evidence: "ev_0001"',
        "Evidence: see [ev_0001]",
        "Confidence: ~0.8",
        "Confidence: .9",
        "Confidence: TBD",
        "Confidence: n.a.",
        "Confidence: very high",
        "Evidence: ledger ev_0001",
        "Evidence: ID ev_0001",
        "Evidence: (from strings) [ev_0001]",
        "Confidence: ledger ev_0001",
        "Confidence: (from strings) [ev_0001]",
        "Technique: see ev_0001",
        "Dissent: the peer misread ev_0001",
        "DISSENT: the peer's packer claim is wrong [ev_0001]",
        "Evidence: [ev_0001] strings\nConfidence: high\nTechnique: T1027",
    ],
)
@pytest.mark.parametrize("heading", ["CLAIM: ", "CLAIM:\n"])
@pytest.mark.parametrize("require_evidence", [True, False])
def test_a_label_the_tail_reads_or_a_field_value_is_still_no_sentence(
    field: str, heading: str, require_evidence: bool
) -> None:
    read = read_claim_blocks(
        f"{heading}{field}\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.9\n",
        require_evidence=require_evidence,
    )
    assert read.claims == []
    assert read.begun == 1
    assert read.unread == 1


def test_a_title_case_block_with_no_sentence_stores_no_technique() -> None:
    read = read_claim_blocks(
        "CLAIM:\nEvidence: [ev_0001] strings\nTechnique: T1027\nCONFIDENCE: 0.8\n"
    )
    assert read.claims == []
    assert read.begun == 1
    assert read.unread == 1


@pytest.mark.parametrize("field", ["Evidence: capa output", "Confidence: probable"])
def test_a_label_line_below_a_bare_heading_is_no_sentence(field: str) -> None:
    read = read_claim_blocks(
        f"CLAIM:\n{field}\nCONFIDENCE: 0.8\nTECHNIQUE: T1027\n", require_evidence=False
    )
    assert read.claims == []
    assert read.begun == 1
    assert read.unread == 1


@pytest.mark.parametrize("field", ["Evidence: capa output", "Confidence: probable"])
def test_the_same_label_on_the_heading_line_is_the_sentence(field: str) -> None:
    read = read_claim_blocks(
        f"CLAIM: {field}\nCONFIDENCE: 0.8\nTECHNIQUE: T1027\n", require_evidence=False
    )
    assert [claim.claim for claim in read.claims] == [field]
    assert read.unread == 0


@pytest.mark.parametrize("label", ["Technique", "technique", "**Technique", "- Technique"])
def test_a_technique_line_in_any_casing_ends_the_sentence_it_is_read_for(label: str) -> None:
    read = read_claim_blocks(
        f"CLAIM: Routine 0x4100 decodes its strings at run time.\n{label}: T1140\n"
        "EVIDENCE: [ev_0002]\nCONFIDENCE: 0.8\n",
        require_evidence=True,
    )
    assert [(claim.claim, claim.technique_id) for claim in read.claims] == [
        ("Routine 0x4100 decodes its strings at run time.", "T1140")
    ]


def test_a_technique_label_inside_the_sentence_stays_in_the_sentence() -> None:
    read = read_claim_blocks(
        "CLAIM: The sample uses the technique: XOR [ev_1].\nTECHNIQUE: T1140\nCONFIDENCE: 0.8\n"
    )
    assert [(claim.claim, claim.technique_id) for claim in read.claims] == [
        ("The sample uses the technique: XOR [ev_1].", "T1140")
    ]
