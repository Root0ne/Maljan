"""A claim that writes the catalogue name's own words, inflected, describes the technique.

The does-not-describe question compares a claim's words with the words of
the technique's catalogue name, each with its common endings taken off. A
name word that ends in a silent "e" kept it, so "Deobfuscate" and "Decode"
never met "deobfuscates", "decoded" or "decoder", and a paid run asked eleven
correct T1140 claims whether they described Deobfuscate/Decode Files or
Information. The regular inflections of the name's own words are its terms
too; a word that is no inflection of them is still no term.
"""

from __future__ import annotations

import pytest

from maljan.pipeline.validation import (
    CLAIM_DOES_NOT_DESCRIBE_CODE,
    claim_does_not_describe_violation,
    validate_isr,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.tools import knowledge

PE = {"platform": "windows", "file_type": "pe"}


def _claim(text: str, technique: str) -> ClaimEvidence:
    return ClaimEvidence(
        claim=text, evidence_ref="[ev_0008] decoder", confidence=0.8, technique_id=technique
    )


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        ("The sample deobfuscates its own strings at run time.", "T1140"),
        ("Its strings are decoded only at run time by one routine.", "T1140"),
        ("A full enumeration of the config decodings agrees in total.", "T1140"),
        ("The routine is decoding every blob before its caller reads it.", "T1140"),
        # A name word ending in -ion, written as its verb.
        ("The sample deletes its own executable when the handle closes.", "T1070.004"),
        ("It injected a thread into the host process.", "T1055"),
    ],
)
def test_an_inflected_name_word_is_a_shared_term(text: str, technique: str) -> None:
    assert claim_does_not_describe_violation(_claim(text, technique), technique, knowledge) is None


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        # Unrelated words stay unrelated, however close they look.
        ("The sample decorates its window title.", "T1140"),
        ("The sample opens a window.", "T1140"),
        ("The sample profiles the host before beaconing.", "T1070.004"),
        ("The loader projects a window onto the desktop.", "T1055"),
        ("The malware accesses the PEB to bypass sandboxing.", "T1003"),
    ],
)
def test_a_word_that_is_no_inflection_is_still_asked(text: str, technique: str) -> None:
    isr = AgentISR(agent_id="static", domain="static", claims=[_claim(text, technique)])
    codes = [v.code for v in validate_isr(isr, attck=knowledge, sample=PE)]

    assert codes == [CLAIM_DOES_NOT_DESCRIBE_CODE]


# Words of their own that look like the inflections of a catalogue name word.
UNRELATED = (
    "stated",
    "station",
    "stats",
    "computer",
    "past",
    "officer",
    "temples",
    "privy",
    "privation",
    "coder",
)


def _every_technique() -> list[str]:
    from maljan.memory.attck_loader import valid_ids

    return sorted(valid_ids())


def test_no_catalogue_name_shares_a_term_with_a_word_of_its_own() -> None:
    from maljan.pipeline.validation import _name_terms, _stem

    shared = []
    for tid in _every_technique():
        name, stems, forms = _name_terms(tid, knowledge)
        for word in UNRELATED:
            if _stem(word) in stems or word in forms:
                shared.append((tid, name, word))
    assert shared == []


def test_the_inflections_come_from_the_leading_verb_only() -> None:
    from maljan.pipeline.validation import _inflected_forms

    assert _inflected_forms("Deobfuscate/Decode Files or Information") == {
        "deobfuscates",
        "deobfuscated",
        "deobfuscating",
        "deobfuscatings",
        "decodes",
        "decoded",
        "decoding",
        "decodings",
    }
    assert _inflected_forms("Monitor Process State") == set()
    assert _inflected_forms("Malicious Copy and Paste") == set()
    # A leading word shorter than five letters keeps no forms ("use" and "user").
    assert _inflected_forms("Use Alternate Authentication Material") == set()


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        ("The sample collects the computer name.", "T1578"),
        ("The analyst stated the sample reads its own image.", "T0801"),
    ],
)
def test_a_word_of_its_own_is_no_inflection_of_a_name_word(text: str, technique: str) -> None:
    assert claim_does_not_describe_violation(_claim(text, technique), technique, knowledge)
