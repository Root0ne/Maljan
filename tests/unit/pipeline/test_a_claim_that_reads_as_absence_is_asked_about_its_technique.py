"""A claim that reads as absence is asked about its technique id, and the analyst decides.

A benign control run published thirteen ATT&CK techniques — Rootkit, Credentials
from Password Stores, Exfiltration Over Alternative Protocol among them — from
analyst claims such as "The binary does not contain any obvious persistence
mechanisms in its static analysis.", each carrying a technique id. A technique
id on a claim is read everywhere downstream as something the sample does.

Such a claim is asked once, in its analyst's own loop, with the reader the
report's capability check already uses, held to a stricter reading of which
negation governs the behaviour: a misread only costs a question, but a
question sent to a positive claim is still one the analyst should not have to
answer. The claim and its id are never edited, and the platform withholds
nothing: an analyst that drops the id has removed it; an id kept after the
question is published as usual, with a note in the report's ATT&CK table and in
the judge's summary; a question never sent notes nothing.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from maljan.agents.base_agent import BaseAnalyst, TurnPace
from maljan.agents.judge_agent import JudgeAgent
from maljan.analysis.chunk_merger import merge_chunk_isrs
from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.memory.long_term_memory import build_stored_case
from maljan.pipeline.evidence_summary import collect
from maljan.pipeline.validation import (
    ABSENCE_CLAIM_CODE,
    absence_claim_violation,
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

# A review's two shapes of absence the stricter reading first missed: a negated
# noun list ending at its head noun, and the behaviour as the subject of "is
# absent", "is not present" or "was not observed".
_LIST = "The binary does not contain persistence, lateral movement, or exfiltration mechanisms."
REVIEW_ABSENCE_CLAIMS: tuple[tuple[str, str], ...] = (
    (_LIST, "T1547"),
    (_LIST, "T1021"),
    (_LIST, "T1048"),
    ("The binary shows no persistence, credential theft and exfiltration capabilities.", "T1555"),
    ("Persistence is absent from the static artifacts.", "T1547"),
    ("Lateral movement is not present in the imports.", "T1021"),
    ("Persistence mechanisms were not observed.", "T1547"),
    ("Exfiltration was not observed in any string.", "T1048"),
)

# Claims that assert, and must go on asserting: the same run's hedged positive
# claims, positive claims that carry a negation about something else, and every
# sentence a review found the first reading asked wrongly.
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
    ("It no longer checks for a debugger before injecting into explorer.exe.", "T1055"),
    ("It no longer checks for a debugger before process injection.", "T1055"),
    ("The sample does not merely read files, it encrypts them for impact.", "T1486"),
    ("The sample does not merely read files; it encrypts them for impact.", "T1486"),
    ("No persistence mechanism exists and process injection into explorer.exe is used.", "T1055"),
    ("It lacks persistence and instead uses process injection into explorer.exe.", "T1055"),
    ("It performs no persistence, only process injection into explorer.exe.", "T1055"),
    ("There is no persistence, the sample exfiltrates data over HTTPS.", "T1048"),
    ("Without encryption, the sample exfiltrates data over HTTP.", "T1048"),
    ("Without writing files, it achieves persistence through a scheduled task.", "T1053"),
    ("The sample does not use a packer, and performs credential dumping from LSASS.", "T1003"),
    ("It cannot run without admin rights, and establishes persistence as a service.", "T1543"),
    ("The implant never stops beaconing to its command and control server.", "T1071"),
    ("No AV flagged its defense evasion.", "T1070"),
    (
        "The sample resolves native APIs at run time, without any execution of child processes.",
        "T1106",
    ),
    ("The sample avoids detection by injecting into explorer.exe.", "T1055"),
    ("Without user interaction it creates a Run key for persistence.", "T1547.001"),
    ("No persistence was found, but the sample uses process injection into explorer.exe.", "T1055"),
)


def _claim(
    text: str, technique_id: str | None, confidence: float = 0.9, *, kept: bool = False
) -> ClaimEvidence:
    return ClaimEvidence(
        claim=text,
        evidence_ref="[ev_0006] strings; [ev_0009] API catalogue",
        confidence=confidence,
        technique_id=technique_id,
        kept_after_absence_question=kept,
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

    @pytest.mark.parametrize(("text", "technique_id"), REVIEW_ABSENCE_CLAIMS)
    def test_a_negated_noun_list_and_an_absent_subject_are_asked_about(
        self, text: str, technique_id: str
    ) -> None:
        found = validate_isr(
            _isr(_claim(text, technique_id)), attck=knowledge, ledger_ids=["ev_0006"]
        )

        assert [v.code for v in found] == [ABSENCE_CLAIM_CODE]

    @pytest.mark.parametrize(("text", "technique_id"), POSITIVE_CLAIMS)
    def test_a_claim_that_asserts_is_not_asked(self, text: str, technique_id: str) -> None:
        found = validate_isr(
            _isr(_claim(text, technique_id)), attck=knowledge, ledger_ids=["ev_0006"]
        )

        assert ABSENCE_CLAIM_CODE not in [v.code for v in found]

    def test_the_question_asks_and_does_not_decide(self) -> None:
        text, tid = PUTTY_ABSENCE_CLAIMS[0]
        (found,) = validate_isr(_isr(_claim(text, tid)), attck=knowledge, ledger_ids=["ev_0006"])

        assert "keep the technique" in found.message
        assert "reads as saying the behaviour is absent" in found.message

    def test_a_claim_without_a_technique_id_is_not_asked(self) -> None:
        found = validate_isr(
            _isr(_claim(PUTTY_ABSENCE_CLAIMS[0][0], None)), attck=knowledge, ledger_ids=["ev_0006"]
        )

        assert found == []

    def test_without_the_catalogue_the_capability_words_still_decide(self) -> None:
        text, tid = PUTTY_ABSENCE_CLAIMS[0]

        assert absence_claim_violation(_claim(text, tid), tid, None) is not None
        # "discovery mechanisms" is a tactic phrase only the catalogue supplies.
        text, tid = PUTTY_ABSENCE_CLAIMS[3]
        assert absence_claim_violation(_claim(text, tid), tid, None) is None

    def test_a_tactic_name_alone_names_no_behaviour(self) -> None:
        claim = _claim("There is no collection of the results by the operator.", "T1005")

        assert absence_claim_violation(claim, "T1005", knowledge) is None

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

    def _invoke_llm_with_timeout(self, messages: list, timeout: int, **_: Any) -> str:
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
    def test_an_id_kept_after_the_question_is_noted_and_unchanged(self) -> None:
        analyst = _Analyst(_isr(_claim(_PERSISTENCE, _PERSISTENCE_ID)), [_answer("T1547")])

        result = analyst.safe_analyze_isr("raw data")

        assert ABSENCE_CLAIM_CODE in str(analyst.seen_turns[0][-1].content)
        (claim,) = result.claims
        assert (claim.claim, claim.technique_id) == (_PERSISTENCE, "T1547")
        assert claim.kept_after_absence_question is True
        assert [v.code for v in analyst.validation_findings] == [ABSENCE_CLAIM_CODE]

    def test_an_analyst_that_drops_the_id_has_removed_it(self) -> None:
        analyst = _Analyst(_isr(_claim(_PERSISTENCE, _PERSISTENCE_ID)), [_answer("NONE")])

        result = analyst.safe_analyze_isr("raw data")

        (claim,) = result.claims
        assert claim.technique_id is None
        assert claim.kept_after_absence_question is False
        assert analyst.validation_findings == []

    def test_a_question_never_sent_notes_nothing_and_says_it_was_not_asked(self) -> None:
        """A loop that ended at its time cap leaves no time for the question."""
        analyst = _Analyst(_isr(_claim(_PERSISTENCE, _PERSISTENCE_ID)), [])
        pace = TurnPace()
        pace.current = "qwen"
        pace.turns["qwen"] = [140.0]
        analyst._last_pace = pace
        analyst._note_budget({"stage": "analysis", "cap": "time"})
        analyst._last_loop_deadline = time.monotonic() + 100.0

        with patch("maljan.agents.base_agent.validity_check_available", return_value=True):
            result = analyst._validate_isr(analyst._first, "evidence")

        assert analyst.seen_turns == []
        (claim,) = result.claims
        assert claim.technique_id == "T1547"
        assert claim.kept_after_absence_question is False
        (finding,) = analyst.validation_findings
        assert finding.code == ABSENCE_CLAIM_CODE
        assert "Not asked: " in finding.message
        _cells, mappings = build_capability_matrix(stix_output=None, isr_reports={"static": result})
        assert [m.technique_id for m in mappings] == ["T1547"]


def _kept(text: str, technique_id: str, confidence: float = 0.9) -> ClaimEvidence:
    return _claim(text, technique_id, confidence, kept=True)


class TestNothingIsWithheld:
    def test_a_kept_technique_is_published_with_its_note(self) -> None:
        isr = _isr(*(_kept(text, tid) for text, tid in PUTTY_ABSENCE_CLAIMS))

        cells, mappings = build_capability_matrix(stix_output=None, isr_reports={"static": isr})

        assert {m.technique_id for m in mappings} == {tid for _t, tid in PUTTY_ABSENCE_CLAIMS}
        assert {cell.not_published for cell in cells} == {""}
        assert {cell.note for cell in cells} == {ABSENCE_TECHNIQUE_MARKER}

    def test_a_technique_a_positive_claim_also_names_carries_no_note(self) -> None:
        absent_text, tid = PUTTY_ABSENCE_CLAIMS[7]
        positive_text, _ = POSITIVE_CLAIMS[2]
        isr = _isr(_kept(absent_text, tid), _claim(positive_text, tid, 0.8))

        cells, mappings = build_capability_matrix(stix_output=None, isr_reports={"static": isr})

        assert [m.technique_id for m in mappings] == ["T1071"]
        assert [cell.note for cell in cells] == [""]

    def test_the_evidence_summary_counts_the_claim_as_stated(self) -> None:
        isr = _isr(_kept(*PUTTY_ABSENCE_CLAIMS[0]), _claim(*POSITIVE_CLAIMS[3]))

        assert set(collect({"static": isr})) == {"T1547", "T1055"}

    def test_a_bundle_built_from_the_claims_keeps_the_technique(self) -> None:
        isrs = {"static": _isr(_kept(*PUTTY_ABSENCE_CLAIMS[0]))}
        bundle = JudgeAgent(llm=MagicMock())._fallback_bundle_from_text(
            "Verdict: Benign.", {}, isrs
        )

        named = {
            ref.get("external_id")
            for obj in bundle.model_dump(mode="json")["objects"]
            if obj.get("type") == "attack-pattern"
            for ref in obj.get("external_references") or []
        }
        assert "T1547" in named

    def test_the_judge_reads_the_id_with_the_note(self) -> None:
        summary = _isr(_kept(*PUTTY_ABSENCE_CLAIMS[0])).to_text_summary()

        assert f"(T1547 — {ABSENCE_TECHNIQUE_MARKER})" in summary
        assert _PERSISTENCE in summary


class TestWhatAPastCaseTeaches:
    def test_long_term_memory_stores_no_noted_or_unknown_id_as_the_cases_technique(
        self,
    ) -> None:
        unknown = _claim("The binary may raise its privileges.", "T1058")
        unknown.technique_id_valid = False
        isr = _isr(_kept(*PUTTY_ABSENCE_CLAIMS[0]), unknown, _claim(*POSITIVE_CLAIMS[3]))

        case = build_stored_case("sample", {"static": isr})

        assert case.technique_ids == ["T1055"]
        assert "T1547" not in case.summary_text.split()


class TestTheChunkMerge:
    def test_a_noted_claim_never_displaces_a_positive_one(self) -> None:
        text, tid = PUTTY_ABSENCE_CLAIMS[7]
        positive = _claim(POSITIVE_CLAIMS[2][0], tid, 0.7)

        merged = merge_chunk_isrs([_isr(positive), _isr(_kept(text, tid, 0.95))])

        (claim,) = [c for c in merged.claims if c.technique_id == tid]
        assert claim is positive or claim.claim == positive.claim

    def test_between_two_positive_claims_the_higher_number_still_wins(self) -> None:
        low = _claim(POSITIVE_CLAIMS[3][0], "T1055", 0.5)
        high = _claim(POSITIVE_CLAIMS[1][0], "T1055", 0.8)

        merged = merge_chunk_isrs([_isr(low), _isr(high)])

        assert [c.confidence for c in merged.claims if c.technique_id == "T1055"] == [0.8]
