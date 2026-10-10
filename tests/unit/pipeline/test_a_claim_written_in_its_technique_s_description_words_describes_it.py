"""A claim written in the words its technique's card describes it with describes the technique.

The does-not-describe question asked most of the claims it was asked of in
five stored runs about claims that were right: strings "XOR-encoded and
decoded at run time" under Obfuscated Files or Information, API names
"resolved by walking the export table" under the same parent, "cmd.exe"
passed to a pipe-captured child under Windows Command Shell. None of them
wrote the catalogue name, and each wrote the words the technique's card (and
the API catalogue's rule) describes it with. Those words now count, each
weighed by how few technique families' texts write it, a parent reading its
sub-techniques' words too, and only two or more of them together: one word
alone is an object a card acts on as often as it is the behaviour.

A claim of another behaviour is asked as before: the change only adds what a
sentence may share with its technique.

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
    DESCRIPTION_WEIGHT_NEEDED,
    described_by_its_words,
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
        ("Every configuration string is stored XOR-encoded and decoded at run time from its blob.",
         "T1027"),
        ("Most API names are resolved at run time by walking each loaded module's export table, "
         "so the import table lists five functions.", "T1027"),
        ("Routine 0x4500 lists the adapters, their addresses and the routes of the machine.",
         "T1016"),
        ("Routine 0x4100 renames its dropped copy and deletes it after the last task.",
         "T1070.004"),
        ("The decoder at 0x4400 restores each embedded blob into memory before use.", "T1140"),
    ],
)  # fmt: skip
def test_a_claim_in_its_technique_s_description_words_is_not_asked(
    text: str, technique: str
) -> None:
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
        # One word a sub-technique's card writes is not enough.
        ("Strings sit behind a rolling XOR with a short header, and API names are resolved from "
         "hashes.", "T1036"),
        ("EVIDENCE: [ev_0019] [ev_0021] [ev_0008]", "T1027"),
        # A program or a call is a procedure word, read only as one: named as an
        # object, or in a sentence that says it was not seen, it describes nothing.
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
        weights = description_weights("T1140")
        assert weights
        for stem, weight in weights.items():
            assert weight == Fraction(1, families[stem])
            assert families[stem] <= DESCRIPTION_MAX_FAMILIES

    def test_the_words_every_family_writes_weigh_nothing(self) -> None:
        families = description_stem_families()
        for stem in ("file", "command", "process"):
            assert families[stem] > DESCRIPTION_MAX_FAMILIES
            assert stem not in description_weights("T1027")

    def test_a_parent_reads_its_sub_techniques_words(self) -> None:
        # The export-table walk is the dynamic resolution sub-technique's card.
        assert "export" in description_weights("T1027")
        assert "export" in description_weights("T1027.007")

    def test_a_sub_technique_reads_its_parent_s_words(self) -> None:
        stems_by_id, families = validation._description_stems_by_id()
        parent_own = {
            stem for stem in stems_by_id["T1027"] if families[stem] <= DESCRIPTION_MAX_FAMILIES
        }
        assert parent_own
        assert parent_own <= set(description_weights("T1027.007"))

    def test_one_word_alone_is_not_enough(self) -> None:
        weights = description_weights("T1059.003")
        own = next(stem for stem, weight in weights.items() if weight == 1)
        assert DESCRIPTION_STEMS_NEEDED == 2
        assert not described_by_its_words(f"The routine holds {own}.", "T1059.003")

    def test_the_cuts_are_where_they_were_measured(self) -> None:
        assert DESCRIPTION_MAX_FAMILIES == 6
        assert DESCRIPTION_WEIGHT_NEEDED == 1

    def test_a_silent_e_and_an_inflection_meet(self) -> None:
        stem = validation._description_stem
        assert stem("decode") == stem("decodes") == stem("decoded") == stem("decoding")
        assert stem("delete") == stem("deleted") == stem("deletion")
        assert stem("header") != stem("head")
        assert stem("process") == stem("processes")

    def test_a_program_or_a_call_is_no_description_word(self) -> None:
        stems = validation._description_stems("cmd.exe runs GetComputerNameA through ntdll")
        assert not {"cmd", "getcomputernamea", "ntdll"} & stems

    def test_an_unknown_id_has_no_words(self) -> None:
        assert description_weights("T9999") == {}
        assert not described_by_its_words("strings encoded and decoded from blobs", "T9999")


def _timed(claims: int) -> float:
    sentence = (
        "Routine 0x4100 writes a value to a buffer and returns its length to the caller, "
        "after checking the bounds of the region it was given. "
    )
    isr = AgentISR(
        agent_id="static",
        domain="static",
        claims=[
            ClaimEvidence(
                claim=f"{sentence * 4}{n}",
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
