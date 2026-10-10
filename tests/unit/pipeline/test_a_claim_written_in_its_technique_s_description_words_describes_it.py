"""A claim written in the words one phrase of its technique's card describes it with describes it.

The does-not-describe question asked most of the claims it was asked of in
five stored runs about claims that were right: API names found "by a walk of
each loaded module's export table" under Obfuscated Files or Information, "a
decode loop over each embedded blob" under Deobfuscate/Decode Files or
Information. None of them wrote the catalogue name; each wrote words one
phrase of the technique's card (or the API catalogue's rule) writes together.
Those words now count: two or more of one phrase, each weighed by how few
technique families' texts write it, a parent reading its sub-techniques'
phrases too.

Read as a procedure word is read: nothing counts in a sentence that says the
behaviour was not seen, nor a word the sentence names as absent or writes after
a negating word of its own clause. Generic English words (``very``, ``few``,
``made``) never count. A claim of another behaviour is asked as before: the
change only adds what a sentence may share with its technique.

Every sentence here is made up for the test.
"""

from __future__ import annotations

import gc
import time
from fractions import Fraction

import pytest

from maljan.pipeline import validation
from maljan.pipeline.validation import (
    CLAIM_DOES_NOT_DESCRIBE_CODE,
    DESCRIPTION_MAX_FAMILIES,
    DESCRIPTION_STEMS_NEEDED,
    described_by_its_words,
    description_phrases,
    description_stem_families,
    description_weights,
    validate_isr,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.tools import knowledge

PE = {"platform": "windows", "file_type": "pe"}


def _asked(text: str, technique: str) -> bool:
    claim = ClaimEvidence(
        claim=text, evidence_ref="[ev_0004] listing", confidence=0.8, technique_id=technique
    )
    isr = AgentISR(agent_id="static", domain="static", claims=[claim])
    codes = [v.code for v in validate_isr(isr, attck=knowledge, sample=PE)]
    return CLAIM_DOES_NOT_DESCRIBE_CODE in codes


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        ("Most API names are found by a walk of each loaded module's export table.", "T1027"),
        ("Routine 0x4400 runs a decode loop over each embedded blob.", "T1140"),
        ("Routine 0x4500 queries the adapters and interfaces of the machine.", "T1016"),
        ("Routine 0x4100 removes its dropped files after use.", "T1070.004"),
        # A plural and its singular are one word.
        ("The beacon sends its URLs and a user agent string from the configuration.",
         "T1071.001"),
        ("The beacon sends its URL and a user agent string from the configuration.",
         "T1071.001"),
    ],
)  # fmt: skip
def test_a_claim_in_one_phrase_s_words_is_not_asked(text: str, technique: str) -> None:
    assert described_by_its_words(text, technique)
    assert not _asked(text, technique)


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        # Another technique's behaviour, under a technique it does not describe.
        ("The binary resolves Windows API functions at run time from CRC32 hashes to evade "
         "static signature detection.", "T1036.005"),
        ("The sample runs reconnaissance commands to enumerate network configuration, domain "
         "trusts and user groups.", "T1012"),
        ("The sample runs reconnaissance commands to enumerate network configuration, domain "
         "trusts and user groups.", "T1078"),
        ("Module bases are found by walking the loader's module list from the PEB and hashing "
         "each module name.", "T1622"),
        ("The file is a 64-bit DLL of five sections whose four exports all point at one routine.",
         "T1218.011"),
        ("Both domains carry malicious verdicts from 16 and 20 engines in existing intelligence.",
         "T1071.001"),
        ("The hash constants match published values and an RC4 routine is present; no key was "
         "recovered.", "T1027"),
        ("Strings sit behind a rolling XOR with a short header, and API names are resolved from "
         "hashes.", "T1036"),
        ("EVIDENCE: [ev_0019] [ev_0021] [ev_0008]", "T1027"),
        # Generic English words describe nothing.
        ("Very few processes ran in the sandbox, and the capture is small.", "T1027"),
        ("It is hard to say more; the sample made few network requests.", "T1027"),
        ("Very few names are given, and it is hard to tell more.", "T1036"),
        # A sentence that denies the behaviour, or says it was not seen.
        ("No string in the image is encoded and nothing is decoded at run time from a blob.",
         "T1027"),
        ("The strings are plain text; no decode loop and no export walk were found.", "T1027"),
        ("No URL was requested and no transfer over the network was observed.", "T1071.001"),
        ("No executable memory is allocated and nothing is mapped.", "T1620"),
        ("A walk of each loaded module's export table was not observed in this run.", "T1027"),
        # A program or a call is a procedure word, read only as one.
        ("The string table holds `cmd.exe` and `reg.exe` among the names it skips.", "T1059.003"),
        ("The routine passes the cmd.exe path to a child process; the spawn is not observed.",
         "T1059.003"),
    ],
)  # fmt: skip
def test_a_claim_of_another_behaviour_is_still_asked(text: str, technique: str) -> None:
    assert not described_by_its_words(text, technique)
    assert _asked(text, technique)


class TestTheWeights:
    def test_a_stem_weighs_one_over_the_families_that_write_it(self) -> None:
        families = description_stem_families()
        phrases = description_phrases("T1140")
        assert phrases
        for phrase in phrases:
            assert len(phrase) >= DESCRIPTION_STEMS_NEEDED
            for stem, weight in phrase.items():
                assert weight == Fraction(1, families[stem])

    def test_a_stem_more_families_write_than_the_cap_weighs_nothing(self) -> None:
        families = description_stem_families()
        common = [stem for stem, count in families.items() if count > DESCRIPTION_MAX_FAMILIES]
        assert {"file", "command", "process"} <= set(common)
        for technique in ("T1027", "T1140", "T1059.003", "T1071.001"):
            assert not set(common) & set(description_weights(technique))

    def test_two_words_of_two_phrases_are_not_one_phrase(self) -> None:
        phrases = description_phrases("T1140")
        assert any("embedd" in phrase for phrase in phrases)
        assert any("byte" in phrase for phrase in phrases)
        assert not any({"embedd", "byte"} <= set(phrase) for phrase in phrases)
        assert not described_by_its_words("The embedded bytes sit in the resource.", "T1140")

    def test_a_parent_reads_its_sub_techniques_phrases(self) -> None:
        # The export-table walk is the dynamic resolution sub-technique's card.
        assert "export" in description_weights("T1027")
        assert "export" in description_weights("T1027.007")

    def test_a_sub_technique_reads_its_parent_s_phrases(self) -> None:
        parent = {frozenset(p) for p in description_phrases("T1027") if "decod" in p}
        assert parent
        assert parent <= {frozenset(p) for p in description_phrases("T1027.007")}

    def test_one_word_alone_is_not_enough(self) -> None:
        weights = description_weights("T1140")
        own = next(stem for stem, weight in weights.items() if weight == 1)
        assert DESCRIPTION_STEMS_NEEDED == 2
        assert not described_by_its_words(f"The routine holds {own}.", "T1140")

    def test_a_silent_e_an_inflection_and_a_plural_meet(self) -> None:
        stem = validation._description_stem
        assert stem("decode") == stem("decodes") == stem("decoded") == stem("decoding")
        assert stem("delete") == stem("deleted") == stem("deletion")
        assert stem("url") == stem("urls") and stem("api") == stem("apis")
        assert stem("header") != stem("head")
        assert stem("process") == stem("processes")

    def test_a_program_or_a_call_is_no_description_word(self) -> None:
        stems = validation._description_stems("cmd.exe runs GetComputerNameA through ntdll")
        assert not {"cmd", "getcomputernamea", "ntdll"} & stems

    def test_generic_english_words_are_no_description_words(self) -> None:
        assert not {"very", "few", "made", "more"} & validation._description_stems(
            "very few made more"
        )

    def test_an_unknown_id_has_no_words(self) -> None:
        assert description_phrases("T9999") == ()
        assert not described_by_its_words("strings encoded and decoded from blobs", "T9999")


def _timed(claims: int, *, long: int = 4) -> float:
    sentence = (
        "Routine 0x4100 writes a value to a buffer and returns its length to the caller, "
        "and nothing checks the bounds of the region, after a decode loop. "
    )
    isr = AgentISR(
        agent_id="static",
        domain="static",
        claims=[
            ClaimEvidence(
                claim=f"{sentence * long}{n}",
                evidence_ref="[ev_0004]",
                confidence=0.5,
                technique_id="T1027",
            )
            for n in range(claims)
        ],
    )
    gc.collect()
    began = time.perf_counter()
    found = validate_isr(isr, attck=knowledge, sample=PE)
    seconds = time.perf_counter() - began
    assert sum(v.code == CLAIM_DOES_NOT_DESCRIBE_CODE for v in found) == claims
    return seconds


class TestTheCheckStaysLinear:
    def test_ten_times_the_claims_take_about_ten_times_as_long(self) -> None:
        _timed(20)
        low = min(_timed(40) for _ in range(2))
        high = min(_timed(400) for _ in range(2))
        print("description words, 40 and 400 claims:", round(low, 3), round(high, 3))
        assert high < low * 20

    @pytest.mark.parametrize(
        "unit",
        [
            "a decode loop, and nothing over the stored data. ",
            # One clause with no break: every word is in it.
            "the decode loop over the stored data and the blob section ",
            "no decode loop over the stored data ",
        ],
    )
    def test_a_ten_times_longer_claim_takes_about_ten_times_as_long(self, unit: str) -> None:
        words = validation.described_by_its_words
        words("warm", "T1027")

        def timed(text: str) -> float:
            gc.collect()
            start = time.perf_counter()
            words(text, "T1027")
            return time.perf_counter() - start

        low = min(timed(unit * 400) for _ in range(2))
        high = min(timed(unit * 4000) for _ in range(2))
        print("description words, a claim and ten times its length:", low, high)
        assert high < low * 20 + 0.01
