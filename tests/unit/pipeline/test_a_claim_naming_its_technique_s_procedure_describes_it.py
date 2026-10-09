"""A claim that names its technique's own procedure words describes the technique.

The does-not-describe question compares a claim's sentence with the words of
the technique it carries. A claim written at the level of the mechanism names
the command, the call or the artefact the technique is done with, not its
catalogue name: "runs wmic" under Windows Management Instrumentation, "queries
SecurityCenter2" under Security Software Discovery. Those words come from the
vendored data that ties an id to its procedures (the technique cards and the
API catalogue's rules), only where they name a call, a class or an artefact,
and only where one technique family's data writes them; a sentence's word
counts in the same shape. An identifier written as joined words names each of
its words. A sentence that names such a word only to say it is absent is asked
the absence question, and one that says the behaviour was not seen is asked as
before: the words widen what a claim of behaviour shares, nothing else.

Every sentence here is made up for the test.
"""

from __future__ import annotations

import pytest

from maljan.pipeline import validation
from maljan.pipeline.validation import (
    ABSENCE_CLAIM_CODE,
    CLAIM_DOES_NOT_DESCRIBE_CODE,
    NAME_STEM_MAX_FAMILIES,
    PROCEDURE_WORD_MAX_FAMILIES,
    claim_does_not_describe_violation,
    name_stem_families,
    procedure_word_families,
    procedure_words,
    validate_isr,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.tools import knowledge

PE = {"platform": "windows", "file_type": "pe"}
ASKED = {CLAIM_DOES_NOT_DESCRIBE_CODE, ABSENCE_CLAIM_CODE}


def _claim(text: str, technique: str) -> ClaimEvidence:
    return ClaimEvidence(
        claim=text, evidence_ref="[ev_0004] listing", confidence=0.8, technique_id=technique
    )


def _asked(text: str, technique: str) -> list[str]:
    isr = AgentISR(agent_id="static", domain="static", claims=[_claim(text, technique)])
    return [v.code for v in validate_isr(isr, attck=knowledge, sample=PE) if v.code in ASKED]


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        # A program the card writes as one, written as one.
        ("Routine 0x4100 runs `wmic` with an inventory query and keeps the output.", "T1047"),
        ("The loader registers itself through schtasks /create at logon.", "T1053.005"),
        # An identifier the card writes.
        ("The command list queries root\\SecurityCenter2 for the product names.", "T1518.001"),
        ("Helper 0x2c40 reads the adapter table through GetAdaptersAddresses.", "T1016"),
        # Its call spellings: ANSI, wide and extended.
        ("0x5e40 posts the body with HttpSendRequestA and reads the reply.", "T1071.001"),
        # The API catalogue's rule for the id.
        ("The beacon loop goes out through the WinINet helper at 0x4d00.", "T1071.001"),
        # A call of a module the card writes as what is called ("ntdll's").
        ("0x4600 queries its own process with NtQueryInformationProcess.", "T1106"),
        # A parent's word under its sub-technique.
        ("The loader registers itself through the ITaskService interface.", "T1053.005"),
        # An identifier of joined words writing a word of one family's names.
        ("The gate 0x3800 reads the BeingDebugged byte and aborts when it is set.", "T1622"),
    ],
)
def test_a_procedure_word_is_a_shared_term(text: str, technique: str) -> None:
    assert claim_does_not_describe_violation(_claim(text, technique), technique, knowledge) is None
    assert _asked(text, technique) == []


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        # Named only to say it is absent: the absence question.
        ("The sample does not invoke wmic.", "T1047"),
        ("No wmic process was observed in the sandbox.", "T1047"),
        ("tasklist is absent from the decoded strings.", "T1057"),
        ("The PEB BeingDebugged field is never read.", "T1622"),
        # Named as a capability the run did not see.
        ("OpenProcess is imported but never referenced.", "T1055"),
        ("A WinINet string is present in the rdata section but no request was seen.", "T1071.001"),
        ("regsvr32 is not used by the sample.", "T1218"),
        ("No CPUID instruction appears in the code.", "T1082"),
        # A qualifier, a format or a platform word names no procedure.
        ("The installer writes the Run reg key for persistence.", "T1012"),
        ("The file is a Win32 GUI executable built with MSVC.", "T1106"),
        ("The configuration blob is parsed as XML at start-up.", "T1053.005"),
        ("The sample reads the adapter MAC address to build its bot id.", "T1497"),
        ("The config holds a URL list.", "T1071"),
        ("The sample sends its report in HTTP POST requests to a remote server.", "T1071"),
        ("The malware resolves Windows API functions at runtime by hashing.", "T1102"),
        ("The file is an unsigned 64-bit DLL submitted under another name.", "T1218.011"),
        # A module's name in running text, and a call of a module the card does
        # not write as what is called.
        ("ntdll is loaded in every process; the sample reads its base from the PEB.", "T1106"),
        ("InternetGetConnectedState is called to check whether the host is online.", "T1071.001"),
        # An ordinary word the cards write in running text is no procedure word.
        ("The routine reads the services listed under one key and their version.", "T1505"),
        # Another technique's procedure, not this one's.
        ("Module bases are found by walking the PEB loader list and hashing names.", "T1622"),
        ("The sample uses Volume Shadow Copy APIs and WMI providers.", "T1003"),
        # The API catalogue's import lists are not read.
        ("Resolved but not observed: DeleteFileW and NtDeleteFile are in the table.", "T1070.004"),
        # Joined words whose parts the names of many families share.
        ("The helper reads its own image with ReadProcessMemory and GetFileSize.", "T1070.004"),
    ],
)
def test_a_sentence_that_names_no_procedure_of_the_technique_is_still_asked(
    text: str, technique: str
) -> None:
    assert _asked(text, technique) != []


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        ("The sample does not invoke wmic.", "T1047"),
        ("tasklist is absent from the decoded strings.", "T1057"),
        ("The code holds no BeingDebugged check.", "T1622"),
    ],
)
def test_a_procedure_word_named_to_say_it_is_absent_is_asked_the_absence_question(
    text: str, technique: str
) -> None:
    assert _asked(text, technique) == [ABSENCE_CLAIM_CODE]


def test_a_procedure_word_named_as_present_is_no_absence() -> None:
    assert _asked("Routine 0x4100 runs `wmic` and stores what it prints.", "T1047") == []


class TestTheWordsAreTheCatalogueData:
    def test_a_word_is_kept_only_where_one_technique_family_owns_it(self) -> None:
        families = procedure_word_families()

        # Measured: every word the cards and rules write is one family's, but for
        # four calls of a module another family's data names (WinINet, ntdll).
        shared = {word for word, count in families.items() if count > 1}
        assert shared == {
            "internetreadfile",
            "ldrgetprocedureaddress",
            "ntloaddriver",
            "rtlgetversion",
        }
        assert PROCEDURE_WORD_MAX_FAMILIES == 1
        assert "internetreadfile" not in procedure_words("T1105").identifiers
        assert "ntloaddriver" not in procedure_words("T1106").exports

    def test_the_name_stem_cut_falls_between_one_family_and_several(self) -> None:
        families = name_stem_families()

        assert NAME_STEM_MAX_FAMILIES == 1
        assert families[validation._stem("Debugger")] == NAME_STEM_MAX_FAMILIES
        for shared in ("File", "Process", "System", "Discovery", "Injection"):
            assert families[validation._stem(shared)] > NAME_STEM_MAX_FAMILIES, shared

    def test_acronyms_formats_and_platform_words_are_no_procedure_words(self) -> None:
        families = procedure_word_families()

        for word in ("http", "https", "dns", "api", "dll", "com", "wmi", "xml", "url", "mac"):
            assert word not in families, word
        assert "win32" not in families
        assert "win32_" in families

    def test_a_shared_word_is_no_technique_s_procedure_word(self) -> None:
        words = procedure_words("T1071.001")

        assert "httpsendrequesta" in words.identifiers
        assert "wininet" in words.identifiers
        assert words.exports == frozenset()

    def test_a_module_the_card_writes_as_called_brings_its_calls(self) -> None:
        words = procedure_words("T1106")

        assert "ntdll" in words.programs
        assert "ntqueryinformationprocess" in words.exports

    def test_an_ordinary_word_in_running_text_is_no_procedure_word(self) -> None:
        families = procedure_word_families()

        assert "services" not in families
        assert "version" not in families

    def test_a_word_inside_a_phrase_the_card_negates_is_left_out(self) -> None:
        families = procedure_word_families()

        # "... without going through LoadLibrary": the opposite of the technique.
        assert "loadlibrary" not in families
        assert not validation._NEGATED_PHRASE_RE.sub("", "copied without LoadLibrary").count(
            "LoadLibrary"
        )

    def test_an_id_with_no_card_and_no_rule_has_no_procedure_words(self) -> None:
        words = procedure_words("T1078")

        assert not words.identifiers and not words.programs and not words.exports
        assert words.places("It runs `wmic` and calls GetUserNameW.") == []


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
