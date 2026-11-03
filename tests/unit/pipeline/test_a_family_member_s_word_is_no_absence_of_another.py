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
word does, or that is the rarest word of the parent's own name ("strings are
obfuscated"). The rule is built from the catalogue's names alone, for every
parent and child; the member that owns the word is asked as before.

Every sentence here is made up for the test.
"""

from __future__ import annotations

import pytest

from maljan.memory.attck_loader import sub_technique_entries, technique_names
from maljan.pipeline.validation import (
    ABSENCE_CLAIM_CODE,
    _another_member_s_word,
    _family_name_stems,
    absence_claim_violation,
    name_stem_families,
)
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
    "text",
    [
        "Not packed; strings are obfuscated.",
        "Not packed; strings are obfuscated/encrypted.",
    ],
)
def test_the_rarest_word_of_the_parent_s_own_name_sets_a_child_s_word_aside(text: str) -> None:
    # "obfusc" is in more families' names than "pack", yet it is the rarest
    # word of Obfuscated Files or Information itself.
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
        # The commoner words of the parent's own name affirm nothing by themselves.
        ("Not packed; the file is a DLL.", "T1027"),
        ("Not packed; information is collected.", "T1027"),
        # The parent's rarest own word, negated, affirms nothing.
        ("Not packed; nothing is obfuscated.", "T1027"),
        ("Not packed; free of obfuscation.", "T1027"),
        ("Not packed; obfuscation-free.", "T1027"),
        ("Not packed; obfuscation is unlikely.", "T1027"),
        ("Not packed; obfuscated strings: none.", "T1027"),
        # The parent's rarest own word written bare names a thing, not the act.
        ("No keylogging; the input box is shown.", "T1056"),
        ("No keylogging; the input file is read.", "T1056"),
        ("No keylogging is present; the sample takes input from its command line.", "T1056"),
        ("No keylogging; the input buffer is 256 bytes.", "T1056"),
        ("No keylogging hooks are installed; user input is not read.", "T1056"),
        ("No clear Windows event logs; the indicator list is empty.", "T1070"),
        # A word of the technique's own name.
        ("The beacon channel is not encrypted.", "T1573"),
        ("The sample has no anti-debugging check.", "T1622"),
    ],
)
def test_the_technique_s_own_word_is_still_asked(text: str, technique: str) -> None:
    found = absence_claim_violation(_claim(text, technique), technique, knowledge)
    assert found is not None and found.code == ABSENCE_CLAIM_CODE


def test_no_parent_s_rarest_own_word_written_bare_sets_a_child_s_word_aside() -> None:
    # Over every shipped parent where only the rarest-own-word rule could set
    # the child's rarest word aside: the bare stem or its plural names a thing
    # and never does.
    families = name_stem_families()
    read = 0
    for technique in sorted(technique_names()):
        if "." in technique or not sub_technique_entries(technique):
            continue
        own, others = _family_name_stems(technique)
        if not own or not others:
            continue
        rarest = min(families.get(stem, 0) for stem in own)
        child = min(others, key=lambda stem: (families.get(stem, 0), stem))
        if families.get(child, 0) >= rarest or not child.isalpha():
            continue
        for stem in sorted(own):
            if families.get(stem, 0) == rarest and stem.isalpha():
                read += 1
                # The bare stem, and its plural ("images", "resources").
                for text in (f"The {stem}.", f"The {stem}s."):
                    assert not _another_member_s_word(technique, text)(child), (
                        technique,
                        text,
                        child,
                    )
    assert read


@pytest.mark.parametrize(
    ("technique", "word"),
    [
        ("T1543", "created"),
        ("T1136", "created"),
        ("T1560", "archived"),
        ("T1608", "staged"),
        ("T1683", "generated"),
    ],
)
def test_a_silent_e_verb_s_inflection_of_the_rarest_own_word_affirms(
    technique: str, word: str
) -> None:
    # "created" is Create's act, though its stem ("creat") is not the name's.
    families = name_stem_families()
    own, others = _family_name_stems(technique)
    child = min(others, key=lambda stem: (families.get(stem, 0), stem))
    assert _another_member_s_word(technique, f"It was {word}.")(child)
    if families.get(child, 0) < min(families.get(stem, 0) for stem in own):
        # Where only the rarest-own-word rule could set it aside, the bare verb does not.
        assert not _another_member_s_word(technique, f"The {word[:-1]} step.")(child)
