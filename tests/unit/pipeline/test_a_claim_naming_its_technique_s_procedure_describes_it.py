"""A claim that names its technique's own procedure words describes the technique.

The does-not-describe question compares a claim's sentence with the words of
the technique it carries. A claim written at the level of the mechanism names
the command, the call or the artefact the technique is done with, not its
catalogue name: "runs wmic" under Windows Management Instrumentation, "queries
SecurityCenter2" under Security Software Discovery. Those words come from the
vendored data that ties an id to its procedures (the technique cards and the
API catalogue's rules), in the shape a procedure's name has, and only where few
techniques share them. An identifier written as joined words names each of its
words. A claim that names none of them is still asked, once, as before.

Every sentence here is made up for the test.
"""

from __future__ import annotations

import pytest

from maljan.pipeline import validation
from maljan.pipeline.validation import (
    CLAIM_DOES_NOT_DESCRIBE_CODE,
    PROCEDURE_WORD_MAX_TECHNIQUES,
    claim_does_not_describe_violation,
    procedure_word_counts,
    procedure_words,
    validate_isr,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.tools import knowledge

PE = {"platform": "windows", "file_type": "pe"}


def _claim(text: str, technique: str) -> ClaimEvidence:
    return ClaimEvidence(
        claim=text, evidence_ref="[ev_0004] listing", confidence=0.8, technique_id=technique
    )


def _asked(text: str, technique: str) -> list[str]:
    isr = AgentISR(agent_id="static", domain="static", claims=[_claim(text, technique)])
    return [
        v.code
        for v in validate_isr(isr, attck=knowledge, sample=PE)
        if v.code == CLAIM_DOES_NOT_DESCRIBE_CODE
    ]


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        # A program the card writes as one.
        ("Routine 0x4100 runs `wmic` with an inventory query and keeps the output.", "T1047"),
        ("The loader registers itself through schtasks /create at logon.", "T1053.005"),
        # An identifier the card writes.
        ("The command list queries root\\SecurityCenter2 for the product names.", "T1518.001"),
        ("Helper 0x2c40 reads the adapter table through GetAdaptersAddresses.", "T1016"),
        # Its call spellings: ANSI, wide and extended.
        ("0x5e40 posts the body with HttpSendRequestA and reads the reply.", "T1071.001"),
        # The API catalogue's rule for the id.
        ("The beacon loop goes out through the WinINet helper at 0x4d00.", "T1071.001"),
        # A module the card names, and that module's exported calls.
        ("The resolver fills its table from a block of ntdll names.", "T1106"),
        ("0x4600 queries its own process with NtQueryInformationProcess.", "T1106"),
        # A parent's word under its sub-technique.
        ("The loader registers itself through the ITaskService interface.", "T1053.005"),
        # An identifier of joined words writing a word of the name few names share.
        ("The gate 0x3800 reads the BeingDebugged byte and aborts when it is set.", "T1622"),
    ],
)
def test_a_procedure_word_is_a_shared_term(text: str, technique: str) -> None:
    assert claim_does_not_describe_violation(_claim(text, technique), technique, knowledge) is None
    assert _asked(text, technique) == []


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        # A word several techniques' data write names none of them.
        ("The sample sends its report in HTTP POST requests to a remote server.", "T1071"),
        ("The malware resolves Windows API functions at runtime by hashing.", "T1102"),
        ("The file is an unsigned 64-bit DLL submitted under another name.", "T1218.011"),
        # An ordinary word the cards write in running text is no procedure word.
        ("The routine reads the services listed under one key and their version.", "T1505"),
        # Another technique's procedure, not this one's.
        ("Module bases are found by walking the PEB loader list and hashing names.", "T1622"),
        ("The sample uses Volume Shadow Copy APIs and WMI providers.", "T1003"),
        # The API catalogue's import lists are not read: resolved imports name
        # no claim's technique.
        ("Resolved but not observed: DeleteFileW and NtDeleteFile are in the table.", "T1070.004"),
        # Joined words whose parts many techniques' names share.
        ("The helper reads its own image with ReadProcessMemory and GetFileSize.", "T1070.004"),
    ],
)
def test_a_word_that_names_no_procedure_of_the_technique_is_still_asked(
    text: str, technique: str
) -> None:
    assert _asked(text, technique) == [CLAIM_DOES_NOT_DESCRIBE_CODE]


class TestTheWordsAreTheCatalogueData:
    def test_a_word_many_techniques_share_is_counted_above_the_bound(self) -> None:
        counts = procedure_word_counts()

        for shared in ("api", "http", "dns", "com", "dll"):
            assert counts[shared] > PROCEDURE_WORD_MAX_TECHNIQUES, shared
        for own in ("wininet", "securitycenter2", "wmic", "ntdll", "schtasks"):
            assert 1 <= counts[own] <= PROCEDURE_WORD_MAX_TECHNIQUES, own

    def test_a_shared_word_is_no_technique_s_procedure_word(self) -> None:
        words = procedure_words("T1071.001")

        assert "HTTP" not in words.acronyms
        assert "httpsendrequesta" in words.lowered
        assert "wininet" in words.lowered

    def test_an_ordinary_word_in_running_text_is_no_procedure_word(self) -> None:
        counts = procedure_word_counts()

        assert "services" not in counts
        assert "version" not in counts

    def test_an_id_with_no_card_and_no_rule_has_no_procedure_words(self) -> None:
        words = procedure_words("T1078")

        assert not words.acronyms and not words.lowered and not words.exports
        assert not words.named_in(["anything", "wmic"])


def test_the_words_are_built_once_per_technique() -> None:
    procedure_words.cache_clear()
    claims = [
        _claim(f"Helper 0x{0x1000 + n:x} formats a record and stores it.", technique)
        for n in range(200)
        for technique in ("T1082", "T1033")
    ]
    isr = AgentISR(agent_id="static", domain="static", claims=claims)

    validate_isr(isr, attck=knowledge, sample=PE)

    assert procedure_words.cache_info().misses == 2
    assert validation._procedure_words_by_id.cache_info().currsize == 1
