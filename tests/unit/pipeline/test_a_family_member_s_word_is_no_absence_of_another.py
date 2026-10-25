"""A behaviour word that only another member of a technique's family names is no absence of it.

The absence question is asked of a claim that names its technique's behaviour
only to say it is absent. The words it reads come from the capability terms of
a whole technique family, so "not packed" read as the absence of Obfuscated
Files or Information and of Dynamic API Resolution on a claim that also says
the strings are XOR-encoded: packing is Software Packing's word, a sibling's
or a child's, not theirs. A mention whose every catalogued word is in the name
of another member of the family and in none of the technique's own names is
not read for a sub-technique (a sibling's word). For a parent a child's word
may be its absence ("The DLL is not packed."), so it is set aside only when the
claim also names the family's behaviour without negating it ("its strings are
XOR-encoded"), by a word of a family member's name that the parent's own
vendored data writes and that no more families' names hold than the child's
word does. The rule is built from the catalogue's names alone, for every
parent and child; the member that owns the word is asked as before.

Every sentence here is made up for the test.
"""

from __future__ import annotations

import pytest

from maljan.pipeline.validation import ABSENCE_CLAIM_CODE, absence_claim_violation
from maljan.schemas.isr_models import ClaimEvidence
from maljan.tools import knowledge


def _claim(text: str, technique: str) -> ClaimEvidence:
    return ClaimEvidence(
        claim=text, evidence_ref="[ev_0004] pe", confidence=0.8, technique_id=technique
    )


NOT_PACKED = "The DLL is not packed; its strings are XOR-encoded in one data section."


@pytest.mark.parametrize("technique", ["T1027", "T1027.007"])
def test_a_child_s_or_sibling_s_word_is_not_read_as_absence(technique: str) -> None:
    assert absence_claim_violation(_claim(NOT_PACKED, technique), technique, knowledge) is None


def test_a_parent_s_own_rarer_word_sets_a_child_s_word_aside() -> None:
    text = "The strings are not encrypted; they are encoded in base64."
    assert absence_claim_violation(_claim(text, "T1027"), "T1027", knowledge) is None


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        # The member whose name holds the word is asked as before.
        ("The DLL is not packed.", "T1027.002"),
        # A parent with a child's word and nothing of the family affirmed.
        ("The DLL is not packed.", "T1027"),
        ("No string is encrypted or packed.", "T1027"),
        ("Packing is absent.", "T1027"),
        # A word that is no word of the parent's own data, or names more families
        # than the child's word, or is negated in its clause, affirms nothing.
        ("No string is encrypted or packed. The payload is a DLL.", "T1027"),
        ("The sample is not packed; it runs after delivery.", "T1027"),
        ("Not packed. The indicator list is empty.", "T1027"),
        ("No packer; an icon resource is present.", "T1027"),
        ("Not packed; the HTML report is attached.", "T1027"),
        ("Not packed, and nothing is encoded.", "T1027"),
        # A word of the technique's own name.
        ("The beacon channel is not encrypted.", "T1573"),
        ("The sample has no anti-debugging check.", "T1622"),
    ],
)
def test_the_technique_s_own_word_is_still_asked(text: str, technique: str) -> None:
    found = absence_claim_violation(_claim(text, technique), technique, knowledge)
    assert found is not None and found.code == ABSENCE_CLAIM_CODE
