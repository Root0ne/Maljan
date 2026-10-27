"""An acronym written in the plural shares a term with a catalogue name that writes it once.

The does-not-describe question compares each word of a claim with the name's
words, their common endings off while four letters stay. An acronym of three
letters and its plural ("API", "APIs") were two words, so "Windows APIs are
resolved at run time from name hashes" was asked whether it describes Dynamic
API Resolution while "the API is resolved" was not. A word written as capitals
and a closing small "s" is the plural of the acronym; any other word keeps its
own ending ("uses" is no "use").

Every sentence here is made up for the test.
"""

from __future__ import annotations

import pytest

from maljan.pipeline.validation import claim_does_not_describe_violation
from maljan.schemas.isr_models import ClaimEvidence
from maljan.tools import knowledge


def _claim(text: str, technique: str) -> ClaimEvidence:
    return ClaimEvidence(
        claim=text, evidence_ref="[ev_0019] hash rows", confidence=0.7, technique_id=technique
    )


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        ("Windows APIs are found at run time from name hashes.", "T1027.007"),
        ("The loader calls its APIs through a table of slots.", "T1106"),
    ],
)
def test_an_acronym_s_plural_is_a_shared_term(text: str, technique: str) -> None:
    assert claim_does_not_describe_violation(_claim(text, technique), technique, knowledge) is None


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        # A word of small letters keeps its ending.
        ("The sample uses a mutex named after its build.", "T1550"),
        # A plural acronym that is no word of the name.
        ("The config lists two URLs and a port.", "T1027.007"),
    ],
)
def test_any_other_plural_is_still_asked(text: str, technique: str) -> None:
    assert claim_does_not_describe_violation(_claim(text, technique), technique, knowledge)
