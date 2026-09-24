"""A claim whose sentence shares no term with its technique is asked about, once.

A reference run published ten techniques from one analyst's claims, and five
of them were not what their own sentences described: OS Credential Dumping on
"accesses the PEB to determine its own process characteristics or to bypass
sandboxing", Valid Accounts on "is a Trojan/Backdoor that performs system
reconnaissance". Only the narrow case is decidable without a model: the
sentence shares no term of the technique's vocabulary — the capability terms
that list the id, its catalogue name word by word, its tactics as a category
phrase. That sentence is asked about once; what the analyst answers stands, and
a technique kept after the question is published as the analyst stated it.
"""

from __future__ import annotations

import pytest

from maljan.pipeline.validation import (
    ABSENCE_CLAIM_CODE,
    CLAIM_DOES_NOT_DESCRIBE_CODE,
    PLATFORM_MISMATCH_CODE,
    claim_does_not_describe_violation,
    mark_invalid_technique_ids,
    validate_isr,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.tools import knowledge

PE = {"platform": "windows", "file_type": "pe"}


def _claim(text: str, technique: str) -> ClaimEvidence:
    return ClaimEvidence(
        claim=text, evidence_ref="[ev_0008] capa", confidence=0.8, technique_id=technique
    )


def _codes(claim: ClaimEvidence) -> list[str]:
    isr = AgentISR(agent_id="static", domain="static", claims=[claim])
    return [v.code for v in validate_isr(isr, attck=knowledge, sample=PE)]


class TestTheNarrowCaseIsAsked:
    @pytest.mark.parametrize(
        ("text", "technique"),
        [
            (
                "The malware accesses the PEB (Process Environment Block) to determine its own "
                "process characteristics or to bypass sandboxing.",
                "T1003",
            ),
            (
                "The binary is a Trojan/Backdoor that performs system reconnaissance and sends "
                "data to a remote server.",
                "T1078",
            ),
            ("The binary contains 0 imports from 0 libraries.", "T1027"),
        ],
    )
    def test_a_sentence_sharing_no_term_is_asked(self, text: str, technique: str) -> None:
        assert _codes(_claim(text, technique)) == [CLAIM_DOES_NOT_DESCRIBE_CODE]

    def test_the_question_names_the_technique_and_asks_to_keep_it_only_if_true(self) -> None:
        violation = claim_does_not_describe_violation(
            _claim("The sample opens a window.", "T1003"), "T1003", knowledge, path="claims[0]"
        )

        assert violation is not None
        assert "T1003 OS Credential Dumping" in violation.message
        assert "Keep T1003 only if the sample does it" in violation.message
        assert violation.path == "claims[0]"


class TestASentenceThatSharesATermIsNotAsked:
    @pytest.mark.parametrize(
        ("text", "technique"),
        [
            # A word of the catalogue name, its ending aside.
            ("The sample uses obfuscation to hide its strings.", "T1027"),
            ("It dumps the credentials of logged-on users.", "T1003"),
            # A capability term that lists the id.
            ("It injects code into a remote process.", "T1055"),
            # The tactic as a category phrase.
            ("It carries discovery techniques for the local host.", "T1082"),
        ],
    )
    def test_it_is_left_alone(self, text: str, technique: str) -> None:
        assert _codes(_claim(text, technique)) == []


class TestOneQuestionPerClaim:
    def test_an_absence_claim_is_asked_the_absence_question_only(self) -> None:
        claim = _claim("The binary does not contain any persistence mechanisms.", "T1547")

        assert _codes(claim) == [ABSENCE_CLAIM_CODE]

    def test_a_platform_mismatch_is_asked_about_the_platform_only(self) -> None:
        claim = _claim("The sample opens a window.", "T1633")

        assert _codes(claim) == [PLATFORM_MISMATCH_CODE]

    def test_without_the_catalogue_nothing_is_decided(self) -> None:
        claim = _claim("The sample opens a window.", "T1003")

        assert claim_does_not_describe_violation(claim, "T1003", None) is None


class TestTheAnswerStands:
    def test_a_kept_technique_is_published_as_stated(self) -> None:
        """The question notes nothing on the claim: no validity flag, no absence note."""
        claim = _claim("The sample opens a window.", "T1003")
        isr = AgentISR(agent_id="static", domain="static", claims=[claim])
        violations = validate_isr(isr, attck=knowledge, sample=PE)

        mark_invalid_technique_ids(isr, violations)

        assert isr.claims[0].technique_id == "T1003"
        assert isr.claims[0].technique_id_valid is True
        assert isr.claims[0].kept_after_absence_question is False
