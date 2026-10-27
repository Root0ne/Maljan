"""A revision's report is the answer in force, not the one its validation turn replaced.

A stored run showed the mediator, the verdict and the technique question an
analyst's first revision answer (12 claims citing the round's new entries) as
its report while its ISR held the retry the validation turn kept (27 claims,
no text shared): the report was the answer the revision wrote, whatever the
turn did to it. The revision notes the answer in force on its ISR now when
the turn changed it: the claims in force rendered as a first answer's are,
numbered as the ISR summaries number them, the findings in force, and what
the revision wrote besides its claims (its disputes and rebuttals), never its
replaced claims. The written answer still comes back as written, for the
record, with the kept retry's own words beside it.

Every value is synthetic.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from maljan.agents.base_agent import (
    NO_STRUCTURED_REPORT_STATUS,
    WRITTEN_BESIDES_CLAIMS,
    BaseAnalyst,
    report_rendered_again,
)
from maljan.agents.claim_headings import besides_claims
from maljan.agents.judge_agent import mediation_reports_text
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, Finding

WRITTEN = "CLAIM 1: The loader decodes its strings.\nCONFIDENCE: 0.7\nEVIDENCE: [ev_0138]"


def _claim(text: str, ev: str = "[ev_0138]") -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ev, confidence=0.7)


FIRST = _claim("The loader decodes its strings.")
RETRY = [_claim("The loader decodes 81 strings at 0xae78.", "[ev_0021]"), FIRST]


def _written() -> AgentISR:
    isr = AgentISR(agent_id="static", domain="static", claims=[FIRST], revision_round=2)
    isr.note_answer_text(WRITTEN)
    return isr


class _Analyst(BaseAnalyst):
    """Revises with ``written`` and lets ``turn`` stand for the validation turn."""

    def __init__(self, written: tuple[str, AgentISR], turn: Any) -> None:
        super().__init__(llm=MagicMock(), name="static")
        self.written = written
        self.turn = turn

    def analyze(self, data: str) -> str:  # pragma: no cover
        return ""

    def revise(self, *a: Any, **k: Any) -> str:  # pragma: no cover
        return ""

    def revise_isr(self, data: str, own: str, peers: dict, feedback: str, rnd: int = 1) -> Any:
        return self.written

    def _apply_consistency_gate(self, isr: AgentISR, evidence: str) -> AgentISR:
        return isr

    def _validate_isr(self, isr: AgentISR, evidence: str) -> AgentISR:
        return self.turn(isr)


def _returned(turn: Any, written: tuple[str, AgentISR] | None = None) -> tuple[str, AgentISR]:
    analyst = _Analyst(written or (WRITTEN, _written()), turn)
    return analyst.safe_revise_isr("raw data", "own", {"peer": "peer"}, "feedback", 2)


def _revise(turn: Any, written: tuple[str, AgentISR] | None = None) -> tuple[str, AgentISR]:
    """The report the prompts read, as the revision node takes it, and the ISR in force."""
    text, isr = _returned(turn, written)
    return isr.report_in_force or text, isr


def _retry(isr: AgentISR) -> AgentISR:
    kept = AgentISR(agent_id="static", domain="static", claims=list(RETRY), revision_round=2)
    kept.note_answer_text("the retry's own words")
    return kept


class TestTheReportIsTheAnswerInForce:
    def test_an_answer_the_turn_left_as_written_is_reported_as_written(self) -> None:
        text, isr = _revise(lambda isr: isr)

        assert text == WRITTEN
        assert isr.claims == [FIRST]

    def test_a_turn_that_returns_a_copy_stating_the_same_keeps_the_words(self) -> None:
        text, _isr = _revise(lambda isr: isr.model_copy(deep=True))

        assert text == WRITTEN

    def test_a_kept_retry_is_reported_as_its_claims_in_force(self) -> None:
        text, isr = _revise(_retry)

        assert text == isr.to_text_summary()
        assert "Claim 1: The loader decodes 81 strings at 0xae78." in text
        assert "Claim 2: The loader decodes its strings." in text
        assert WRITTEN not in text

    def test_a_withdrawal_from_the_written_answer_is_reported_as_what_stands(self) -> None:
        written = _written()
        written.claims = [FIRST, RETRY[0]]

        text, isr = _revise(
            lambda isr: isr.model_copy(update={"claims": [RETRY[0]]}), (WRITTEN, written)
        )

        assert text == isr.to_text_summary()
        assert FIRST.claim not in text

    def test_every_claim_withdrawn_is_reported_as_none_in_force(self) -> None:
        text, isr = _revise(lambda isr: isr.model_copy(update={"claims": []}))

        assert text == isr.to_text_summary()
        assert FIRST.claim not in text

    def test_a_finding_settled_back_in_is_an_answer_changed(self) -> None:
        def _settled(isr: AgentISR) -> AgentISR:
            return isr.model_copy(update={"findings": [Finding(title="Install path")]})

        text, isr = _revise(_settled)

        assert text.startswith(isr.to_text_summary())
        assert text.count("Install path") == 1

    def test_a_kept_retry_s_findings_are_in_the_report_each_once(self) -> None:
        findings = [
            Finding(
                title="Mutex runnung guards a single instance",
                detail="CreateMutexW is called with the decoded name at 0x3935.",
                category="anti-analysis",
                technique_ids=["T1480"],
                confidence=0.6,
                evidence_ids=["ev_0021", "ev_0025"],
            ),
            Finding(title="Beacon path /live/", detail="Decoded at 0x6a1f."),
        ]

        def _retry_with_findings(isr: AgentISR) -> AgentISR:
            return _retry(isr).model_copy(update={"findings": findings})

        text, isr = _revise(_retry_with_findings)

        assert text.startswith(isr.to_text_summary())
        for finding in findings:
            assert text.count(finding.title) == 1
            assert text.count(finding.detail) == 1
        assert (
            "    - Mutex runnung guards a single instance: CreateMutexW is called with the decoded "
            "name at 0x3935. (technique T1480; evidence ev_0021, ev_0025; confidence 0.60; "
            "category anti-analysis)"
        ) in text

    def test_a_claimless_kept_retry_keeps_its_findings_after_its_words(self) -> None:
        def _prose(isr: AgentISR) -> AgentISR:
            kept = AgentISR(
                agent_id="static", domain="static", claims=[], findings=[Finding(title="Packer")]
            )
            kept.note_answer_text("prose the retry wrote")
            return kept

        text, _isr = _revise(_prose)

        assert text == "prose the retry wrote\n  Findings:\n    - Packer"

    def test_a_changed_confidence_is_an_answer_changed(self) -> None:
        def _sure(isr: AgentISR) -> AgentISR:
            claim = isr.claims[0].model_copy(update={"confidence": 0.9})
            return isr.model_copy(update={"claims": [claim]})

        text, _isr = _revise(_sure)

        assert "Confidence: 0.90" in text

    def test_a_kept_answer_with_no_claim_is_its_own_words(self) -> None:
        def _prose(isr: AgentISR) -> AgentISR:
            kept = AgentISR(agent_id="static", domain="static", claims=[])
            kept.note_answer_text("prose the retry wrote")
            return kept

        text, _isr = _revise(_prose)

        assert text == "prose the retry wrote"

    def test_a_revision_that_wrote_no_claim_keeps_what_it_wrote(self) -> None:
        empty = AgentISR(
            agent_id="static", domain="static", claims=[], status=NO_STRUCTURED_REPORT_STATUS
        )

        text, isr = _revise(_retry, ("prose with no claim line", empty))

        assert text == "prose with no claim line"
        assert isr.revision_wrote_no_claim

    def test_a_revision_that_wrote_nothing_stays_nothing(self) -> None:
        text, _isr = _revise(_retry, ("", _written()))

        assert text == ""


DISPUTED = (
    "CLAIM 1: The loader decodes its strings.\nCONFIDENCE: 0.7\nEVIDENCE: [ev_0138]\n\n"
    "ACCEPTED FROM PEERS: the network analyst's C2 path, now cited to ev_0019.\n\n"
    "DISPUTES:\n- Network claim 4 says 0x6a1f is unused; ev_0025 lists its caller 0x6a10."
)


class TestTheRecordKeepsWhatWasWritten:
    def test_the_written_answer_comes_back_as_written_and_the_retry_s_words_are_noted(
        self,
    ) -> None:
        text, isr = _returned(_retry)

        assert text == WRITTEN
        assert isr.report_in_force == isr.to_text_summary()
        assert isr.retry_words == "the retry's own words"

    def test_an_answer_left_as_written_notes_nothing(self) -> None:
        text, isr = _returned(lambda isr: isr)

        assert text == WRITTEN
        assert isr.report_in_force == "" and isr.retry_words == ""

    def test_a_withdrawal_notes_no_retry_words(self) -> None:
        _text, isr = _returned(lambda isr: isr.model_copy(update={"claims": []}))

        assert isr.report_in_force and isr.retry_words == ""


class TestTheReportKeepsWhatTheRevisionWroteBesidesItsClaims:
    def test_its_rebuttals_and_what_it_accepted_follow_the_claims_in_force(self) -> None:
        written = _written()
        written.note_answer_text(DISPUTED)

        report, isr = _revise(_retry, (DISPUTED, written))

        assert report.startswith(isr.to_text_summary())
        besides = report.split(f"\n{WRITTEN_BESIDES_CLAIMS}\n", 1)[1]
        assert "ACCEPTED FROM PEERS: the network analyst's C2 path" in besides
        assert "Network claim 4 says 0x6a1f is unused; ev_0025 lists its caller" in besides
        # Never the replaced claim the revision wrote.
        assert "CLAIM 1" not in besides and "CONFIDENCE: 0.7" not in besides

    def test_an_answer_of_claims_alone_adds_no_heading(self) -> None:
        report, _isr = _revise(_retry)

        assert WRITTEN_BESIDES_CLAIMS not in report


class TestASummaryIsRenderedAgainWithEveryMarkSetSince:
    def test_a_mark_set_after_the_report_was_kept_is_in_the_report_read(self) -> None:
        report, isr = _revise(_retry)
        isr.claims[0].technique_id = "T9999"
        isr.claims[0].technique_id_valid = False

        again = report_rendered_again(report, isr)

        assert again.startswith(isr.to_text_summary())
        assert report != again

    def test_what_follows_the_summary_is_kept(self) -> None:
        written = _written()
        written.note_answer_text(DISPUTED)
        report, isr = _revise(_retry, (DISPUTED, written))
        isr.claims[0].technique_id = "T9999"

        again = report_rendered_again(report, isr)

        assert again.endswith(report[report.index(f"\n{WRITTEN_BESIDES_CLAIMS}\n") :])

    def test_a_written_report_that_echoes_the_summary_heading_is_as_it_was(self) -> None:
        _report, isr = _revise(_retry)
        echoed = (
            "[STATIC ANALYST — round 2]\n"
            "Rebuttal: network's claim 4 misreads the beacon interval; ev_0009 shows 60s.\n"
            "CLAIM 1: The loader decodes its strings.\nEVIDENCE: [ev_0138]\nCONFIDENCE: 0.7"
        )

        assert report_rendered_again(echoed, isr) == echoed
        assert "Rebuttal" in mediation_reports_text({"static": echoed}, {"static": isr})

    def test_a_summary_with_no_record_of_rendering_is_as_it_was(self) -> None:
        isr = _retry(_written())

        assert report_rendered_again(isr.to_text_summary(), isr) == isr.to_text_summary()

    def test_a_written_report_is_as_it_was(self) -> None:
        assert report_rendered_again(WRITTEN, _written()) == WRITTEN
        assert report_rendered_again(WRITTEN, None) == WRITTEN


class TestWhatIsWrittenBesidesTheClaims:
    def test_a_rebuttal_right_under_a_claim_with_no_fields_stays(self) -> None:
        text = (
            "CLAIM 1: RC4 decryption [ev_0002] (confidence 0.8)\n"
            "I accept network's reading of ev_0009 and withdraw my earlier mutex claim."
        )

        assert besides_claims(text) == (
            "I accept network's reading of ev_0009 and withdraw my earlier mutex claim."
        )

    def test_a_claim_s_sentence_lines_and_fields_go_and_the_prose_after_them_stays(self) -> None:
        text = (
            "CLAIM 2: The beacon\nsleeps 450 to 599 seconds.\nEVIDENCE: [ev_0063]\n"
            "CONFIDENCE: 0.7\nI accept the dynamic analyst's interval."
        )

        assert besides_claims(text) == "I accept the dynamic analyst's interval."

    def test_the_disputes_section_stays_whole(self) -> None:
        text = (
            "CLAIM 1: x\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.6\n\nDISPUTES:\n"
            "- network's claim 3: a sinkhole.\nCLAIM 3: quoted peer claim\nEVIDENCE: [ev_0009]"
        )

        assert besides_claims(text) == (
            "DISPUTES:\n- network's claim 3: a sinkhole.\nCLAIM 3: quoted peer claim\n"
            "EVIDENCE: [ev_0009]"
        )
