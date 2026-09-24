"""A claim that says a behaviour is absent asserts no technique.

A benign control run published thirteen ATT&CK techniques — Rootkit, Credentials
from Password Stores, Exfiltration Over Alternative Protocol among them — from
analyst claims such as "The binary does not contain any obvious persistence
mechanisms in its static analysis.", each carrying a technique id. A technique
id on a claim is read everywhere downstream as something the sample does.

Such a claim is asked about once, in its analyst's own loop, with the reader the
report's capability check already uses. The claim and its id are never edited.
What still reads as absence after the question is flagged on the claim, the
publish rule counts no assertion from it, and the run records why.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.agents.base_agent import BaseAnalyst
from maljan.extractors.capability_matrix import ABSENCE_REASON, build_capability_matrix
from maljan.pipeline.evidence_summary import collect
from maljan.pipeline.validation import (
    ABSENCE_CLAIM_CODE,
    absence_claim_violation,
    mark_invalid_technique_ids,
    validate_isr,
)
from maljan.schemas.isr_models import ABSENCE_TECHNIQUE_MARKER, AgentISR, ClaimEvidence
from maljan.tools import knowledge

# The benign control run's claims that stated absence, with the ids they carried.
PUTTY_ABSENCE_CLAIMS: tuple[tuple[str, str], ...] = (
    (
        "The binary does not contain any obvious persistence mechanisms in its static analysis.",
        "T1547",
    ),
    (
        "The binary does not exhibit any obvious anti-analysis or anti-debugging techniques "
        "beyond what is expected for a complex application.",
        "T1014",
    ),
    (
        "The binary does not contain any obvious defense evasion mechanisms in its static "
        "analysis.",
        "T1070",
    ),
    (
        "The binary does not contain any obvious credential access mechanisms in its static "
        "analysis.",
        "T1555",
    ),
    (
        "The binary does not contain any obvious discovery mechanisms in its static analysis.",
        "T1082",
    ),
    (
        "The binary does not contain any obvious lateral movement mechanisms in its static "
        "analysis.",
        "T1021",
    ),
    (
        "The binary does not contain any obvious collection mechanisms in its static analysis.",
        "T1005",
    ),
    (
        "The binary does not contain any obvious data exfiltration mechanisms in its static "
        "analysis.",
        "T1048",
    ),
    (
        "The binary does not contain any obvious command and control (C2) communication patterns "
        "in its static analysis.",
        "T1071",
    ),
    ("The binary does not exhibit obvious persistence mechanisms in its static imports.", "T1547"),
)

# Claims that assert, and must go on asserting: the same run's hedged positive
# claims, and positive claims that carry a negation about something else.
POSITIVE_CLAIMS: tuple[tuple[str, str], ...] = (
    (
        "The binary contains obfuscated or encoded strings, likely for configuration or internal "
        "data structures, which is common in complex applications but can be mimicked by malware.",
        "T1027",
    ),
    (
        "The binary imports APIs related to process and memory manipulation, which are standard "
        "for system utilities but also used in malware for injection or evasion.",
        "T1055",
    ),
    (
        "The binary contains network-related strings and imports, consistent with its function "
        "as an SSH client, but also potentially useful for C2 communication.",
        "T1071",
    ),
    ("The sample injects code into explorer.exe with CreateRemoteThread.", "T1055"),
    ("No persistence was observed; the sample injects code into explorer.exe.", "T1055"),
    ("The sample resolves its imports at run time without an import table entry.", "T1106"),
    ("Persistence is established through a Run key, and no service is created.", "T1547.001"),
    ("It does not persist through a service, and it writes a Run key for persistence.", "T1547"),
    (
        "The sample exfiltrates the collected archive over HTTPS; no other channel was seen.",
        "T1048",
    ),
)


def _claim(text: str, technique_id: str | None, confidence: float = 0.9) -> ClaimEvidence:
    return ClaimEvidence(
        claim=text,
        evidence_ref="[ev_0006] strings; [ev_0009] API catalogue",
        confidence=confidence,
        technique_id=technique_id,
    )


def _isr(*claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id="static", domain="static", claims=list(claims))


class TestTheQuestion:
    @pytest.mark.parametrize(("text", "technique_id"), PUTTY_ABSENCE_CLAIMS)
    def test_every_absence_claim_of_the_benign_run_is_asked_about(
        self, text: str, technique_id: str
    ) -> None:
        found = validate_isr(
            _isr(_claim(text, technique_id)), attck=knowledge, ledger_ids=["ev_0006"]
        )

        assert [v.code for v in found] == [ABSENCE_CLAIM_CODE]
        assert technique_id in found[0].message
        assert text in found[0].message
        assert "TECHNIQUE: NONE" in found[0].message
        assert found[0].path == "static.claims[0]"

    @pytest.mark.parametrize(("text", "technique_id"), POSITIVE_CLAIMS)
    def test_a_claim_that_asserts_is_not_asked(self, text: str, technique_id: str) -> None:
        found = validate_isr(
            _isr(_claim(text, technique_id)), attck=knowledge, ledger_ids=["ev_0006"]
        )

        assert ABSENCE_CLAIM_CODE not in [v.code for v in found]

    def test_a_claim_without_a_technique_id_is_not_asked(self) -> None:
        found = validate_isr(
            _isr(_claim(PUTTY_ABSENCE_CLAIMS[0][0], None)), attck=knowledge, ledger_ids=["ev_0006"]
        )

        assert found == []

    def test_without_the_catalogue_the_capability_words_still_decide(self) -> None:
        text, tid = PUTTY_ABSENCE_CLAIMS[0]

        assert absence_claim_violation(_claim(text, tid), tid, None) is not None
        # "discovery" is a tactic name only the catalogue supplies.
        text, tid = PUTTY_ABSENCE_CLAIMS[4]
        assert absence_claim_violation(_claim(text, tid), tid, None) is None

    def test_a_claim_that_never_names_the_behaviour_states_nothing_about_it(self) -> None:
        claim = _claim("The binary does not import any .NET runtime library.", "T1547")

        assert absence_claim_violation(claim, "T1547", knowledge) is None


class _Analyst(BaseAnalyst):
    def __init__(self, first: AgentISR, replies: list[str]) -> None:
        super().__init__(llm=MagicMock(), name="static")
        self._first = first
        self._replies = list(replies)
        self.seen_turns: list[list[Any]] = []

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def analyze_isr(self, data: str) -> AgentISR:
        return self._first

    def _invoke_llm_with_timeout(self, messages: list, timeout: int) -> str:
        self.seen_turns.append(list(messages))
        return self._replies.pop(0)


_PERSISTENCE, _PERSISTENCE_ID = PUTTY_ABSENCE_CLAIMS[0]


def _answer(technique: str) -> str:
    return (
        f"CLAIM: {_PERSISTENCE}\n"
        "EVIDENCE: [ev_0006] strings; [ev_0009] API catalogue\n"
        "CONFIDENCE: 0.9\n"
        f"TECHNIQUE: {technique}\n"
    )


class TestTheAnalystsLoop:
    def test_an_absence_claim_kept_after_the_question_is_flagged_and_unchanged(self) -> None:
        analyst = _Analyst(_isr(_claim(_PERSISTENCE, _PERSISTENCE_ID)), [_answer("T1547")])

        result = analyst.safe_analyze_isr("raw data")

        feedback = str(analyst.seen_turns[0][-1].content)
        assert ABSENCE_CLAIM_CODE in feedback
        (claim,) = result.claims
        assert (claim.claim, claim.technique_id) == (_PERSISTENCE, "T1547")
        assert claim.states_absence is True
        assert [v.code for v in analyst.validation_findings] == [ABSENCE_CLAIM_CODE]

    def test_an_analyst_that_drops_the_id_leaves_nothing_to_record(self) -> None:
        analyst = _Analyst(_isr(_claim(_PERSISTENCE, _PERSISTENCE_ID)), [_answer("NONE")])

        result = analyst.safe_analyze_isr("raw data")

        (claim,) = result.claims
        assert claim.technique_id is None
        assert claim.states_absence is False
        assert analyst.validation_findings == []


def _flagged(text: str, technique_id: str, confidence: float = 0.9) -> ClaimEvidence:
    claim = _claim(text, technique_id, confidence)
    isr = _isr(claim)
    mark_invalid_technique_ids(isr, validate_isr(isr, attck=knowledge, ledger_ids=["ev_0006"]))
    assert claim.states_absence is True
    return claim


class TestThePublishRule:
    def test_a_technique_only_absence_claims_name_is_kept_marked_and_not_published(self) -> None:
        isr = _isr(*(_flagged(text, tid) for text, tid in PUTTY_ABSENCE_CLAIMS))

        cells, mappings = build_capability_matrix(stix_output=None, isr_reports={"static": isr})

        assert mappings == []
        ids = {cell.technique_id for cell in cells}
        assert ids == {tid for _text, tid in PUTTY_ABSENCE_CLAIMS}
        assert {cell.not_published for cell in cells} == {ABSENCE_REASON}
        (persistence,) = [cell for cell in cells if cell.technique_id == "T1547"]
        assert _PERSISTENCE in persistence.evidence

    def test_a_technique_a_claim_asserts_is_published_from_that_claim_alone(self) -> None:
        absent_text, tid = PUTTY_ABSENCE_CLAIMS[8]
        positive_text, _ = POSITIVE_CLAIMS[2]
        isr = _isr(_flagged(absent_text, tid, 0.9), _claim(positive_text, tid, 0.8))

        _cells, mappings = build_capability_matrix(stix_output=None, isr_reports={"static": isr})

        (mapping,) = mappings
        assert mapping.technique_id == "T1071"
        assert mapping.confidence == 0.8
        assert mapping.evidence_quotes == [positive_text]

    def test_the_evidence_summary_counts_no_absence_claim_as_a_source(self) -> None:
        isr = _isr(_flagged(*PUTTY_ABSENCE_CLAIMS[0]), _claim(*POSITIVE_CLAIMS[3]))

        assert set(collect({"static": isr})) == {"T1055"}

    def test_the_judge_reads_the_id_with_what_the_claim_said(self) -> None:
        summary = _isr(_flagged(*PUTTY_ABSENCE_CLAIMS[0])).to_text_summary()

        assert f"(T1547 — {ABSENCE_TECHNIQUE_MARKER})" in summary
        assert _PERSISTENCE in summary
