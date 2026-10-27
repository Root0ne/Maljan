"""A sentence that says a behaviour was not seen qualifies its own words, not the claim's.

A procedure word or a description word in a sentence that says the behaviour
was not seen, run or used ("imported but never referenced") names a capability
only, and the does-not-describe question is asked as before. The rule read
the whole claim as that one sentence, so a static claim that names the
technique's call in one sentence and adds "This is a code path only and was
not observed." in the next was asked whether it describes its technique: a
paid run asked twelve such claims, and every analyst kept its id. The
not-seen reading now reaches the sentence it stands in; a sentence that says
so of its own words is asked as before.

Every sentence here is made up for the test.
"""

from __future__ import annotations

import pytest

from maljan.pipeline.validation import (
    CLAIM_DOES_NOT_DESCRIBE_CODE,
    claim_does_not_describe_violation,
    described_by_its_words,
    validate_isr,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.tools import knowledge

PE = {"platform": "windows", "file_type": "pe"}


def _claim(text: str, technique: str) -> ClaimEvidence:
    return ClaimEvidence(
        claim=text, evidence_ref="[ev_0024] routine", confidence=0.7, technique_id=technique
    )


def _asked(text: str, technique: str) -> bool:
    isr = AgentISR(agent_id="static", domain="static", claims=[_claim(text, technique)])
    codes = [v.code for v in validate_isr(isr, attck=knowledge, sample=PE)]
    return CLAIM_DOES_NOT_DESCRIBE_CODE in codes


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        # A procedure word, and the observation said of the run in a sentence of its own.
        (
            "Routine 0x4a10 calls HttpSendRequestA through a resolved slot. "
            "This is a code path only and was not observed.",
            "T1071.001",
        ),
        (
            "Routine 0x6b20 resolves GetComputerNameExA and formats the result. "
            "Its use in a live run is not observed.",
            "T1082",
        ),
        # Description words, and a later sentence about other strings.
        (
            "Strings are encoded and decoded at run time from their blobs. "
            "Three further decodings are not referenced by code.",
            "T1027",
        ),
    ],
)
def test_a_not_seen_sentence_leaves_the_sentence_before_it_read(text: str, technique: str) -> None:
    assert claim_does_not_describe_violation(_claim(text, technique), technique, knowledge) is None
    assert not _asked(text, technique)


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        # The not-seen reading said of the word in its own sentence.
        ("Routine 0x4a10 calls HttpSendRequestA, but no request was observed.", "T1071.001"),
        ("OpenProcess is imported but never referenced.", "T1055"),
        ("The routine passes the cmd.exe path to a child process; the spawn is not observed.",
         "T1059.003"),
        # Every sentence of the claim says so.
        (
            "GetComputerNameExA is resolved but never called. "
            "No host query was observed either.",
            "T1082",
        ),
    ],
)  # fmt: skip
def test_a_sentence_that_says_its_own_behaviour_was_not_seen_is_asked(
    text: str, technique: str
) -> None:
    assert _asked(text, technique)


def test_the_description_words_read_each_sentence_on_its_own() -> None:
    read = "Strings are encoded and decoded at run time from their blobs."
    unseen = "Strings encoded and decoded at run time from their blobs were not observed."

    assert described_by_its_words(read + " Three further decodings are not referenced.", "T1027")
    assert not described_by_its_words(unseen, "T1027")
    assert not described_by_its_words(unseen + " The routine has one caller.", "T1027")
