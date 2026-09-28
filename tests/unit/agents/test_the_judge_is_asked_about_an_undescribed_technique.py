"""A technique no claim naming it describes, by the check, goes to the judge with that finding.

Local runs raised ``attck.claim_does_not_describe`` 95 and 34 times, and the
judge kept wrong ids it had never been told about: OS Credential Dumping on
"accesses the PEB to bypass sandboxing". The analysts were asked and kept
their ids, which is their answer. What the judge had not been shown is that no
claim naming the technique describes it. It now is, once, in the question it
is already asked after its verdict: keep or drop, with a reason, and the report
shows the answer, the reason and the check's finding beside the row.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

from maljan.agents.judge_agent import (
    TECHNIQUE_QUESTION_SYSTEM,
    JudgeAgent,
    technique_question_text,
)
from maljan.extractors.capability_matrix import (
    build_capability_matrix,
    judge_questions,
    techniques_for_the_judge,
)
from maljan.pipeline.validation import undescribed_technique_finding
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.stix_models import Bundle, TechniqueReview
from maljan.tools import knowledge

UNDESCRIBED = "T1003"  # OS Credential Dumping, carried by the bundle
DESCRIBED = "T1112"  # Modify Registry, carried and described
MIXED = "T1055"  # Process Injection: one claim describes it, one does not
LEFT_OUT = "T1078"  # Valid Accounts: claimed, not in the bundle, undescribed

PEB = "The malware accesses the PEB to bypass sandboxing"


def _pattern(tid: str, name: str, n: int) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--0f1e2d3c-4b5a-4968-8776-65544333221{n}",
        "name": name,
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
    }


def _bundle() -> Bundle:
    return Bundle.model_validate(
        {
            "objects": [
                _pattern(UNDESCRIBED, "OS Credential Dumping", 1),
                _pattern(DESCRIBED, "Modify Registry", 2),
                _pattern(MIXED, "Process Injection", 3),
            ]
        }
    )


def _claim(text: str, tid: str, ref: str = "[ev_0004]") -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ref, confidence=0.6, technique_id=tid)


def _isrs() -> dict[str, AgentISR]:
    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                _claim(PEB, UNDESCRIBED),
                _claim("The sample writes a registry value", DESCRIBED),
                _claim("The sample writes code into a remote process", MIXED),
                _claim("The binary is a trojan that reports to a remote server", LEFT_OUT),
            ],
        ),
        "dynamic": AgentISR(
            agent_id="dynamic",
            domain="dynamic",
            claims=[
                _claim("The sample reads the PEB of its own process", UNDESCRIBED, "[ev_0009]"),
                _claim("The sample opens a window", MIXED),
            ],
        ),
    }


class _Llm:
    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> Any:
        self.calls.append(list(messages))
        return MagicMock(content=self.answer)


def _ask(answer: str) -> tuple[TechniqueReview | None, _Llm]:
    llm = _Llm(answer)
    judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
    review = asyncio.run(
        judge.decide_techniques(_bundle(), _isrs(), reports={"static": "r"}, evidence_texts={})
    )
    return review, llm


def _cells(review: TechniqueReview | None) -> tuple[dict[str, Any], set[str]]:
    bundle = _bundle()
    bundle.x_maljan_technique_review = review
    cells, mappings = build_capability_matrix(stix_output=bundle.model_dump(), isr_reports=_isrs())
    return {c.technique_id: c for c in cells}, {m.technique_id for m in mappings}


class TestWhatIsAsked:
    def test_only_a_technique_no_claim_of_which_describes_it_is_asked_with_the_finding(
        self,
    ) -> None:
        questions, _not_asked = judge_questions(_bundle().model_dump(), _isrs(), attck=knowledge)
        by_id = {q.technique_id: q for q in questions}

        assert set(by_id) == {UNDESCRIBED, LEFT_OUT}
        carried = by_id[UNDESCRIBED]
        assert carried.kind == "undescribed"
        assert [agent for agent, _text, _ids in carried.mentions] == ["static", "dynamic"]
        assert carried.check == undescribed_technique_finding(UNDESCRIBED, knowledge, 2)
        assert "T1003 OS Credential Dumping" in carried.check

    def test_a_left_out_technique_is_asked_once_and_carries_the_finding_too(self) -> None:
        questions, _ = judge_questions(_bundle().model_dump(), _isrs(), attck=knowledge)
        left_out = [q for q in questions if q.technique_id == LEFT_OUT]

        assert len(left_out) == 1
        assert left_out[0].kind == "claimed"
        assert "T1078 Valid Accounts" in left_out[0].check

    def test_without_the_catalogue_nothing_new_is_asked(self) -> None:
        questions, _ = judge_questions(_bundle().model_dump(), _isrs())

        assert [q.technique_id for q in questions] == [LEFT_OUT]
        assert questions[0].check == ""

    def test_the_question_shows_the_finding_under_the_technique(self) -> None:
        questions, _ = judge_questions(_bundle().model_dump(), _isrs(), attck=knowledge)
        text = technique_question_text(questions)

        finding = undescribed_technique_finding(UNDESCRIBED, knowledge, 2)
        assert f"   check: {finding}" in text
        assert "in your bundle; the ATT&CK check found no claim naming it uses" in text
        assert "uses the catalogue's terms" in TECHNIQUE_QUESTION_SYSTEM

    def test_the_judge_is_asked_once_through_its_technique_question(self) -> None:
        review, llm = _ask(f"{UNDESCRIBED}: drop: nothing reads credentials\n{LEFT_OUT}: drop: no")

        assert len(llm.calls) == 1
        assert review is not None
        assert UNDESCRIBED in review.asked
        assert review.undescribed[UNDESCRIBED] == undescribed_technique_finding(
            UNDESCRIBED, knowledge, 2
        )


class TestTheReportShowsTheAnswer:
    def test_a_dropped_technique_is_not_published_and_says_the_judge_s_reason(self) -> None:
        review, _ = _ask(f"{UNDESCRIBED}: drop: nothing reads credentials\n{LEFT_OUT}: drop: no")

        cells, published = _cells(review)

        assert UNDESCRIBED not in published
        assert DESCRIBED in published and MIXED in published
        assert (
            "the judge dropped it (nothing reads credentials)" in cells[UNDESCRIBED].not_published
        )
        finding = "no claim naming it uses the catalogue's terms for it"
        assert finding in cells[UNDESCRIBED].not_published

    def test_a_kept_technique_is_published_with_the_finding_and_the_reason(self) -> None:
        review, _ = _ask(f"{UNDESCRIBED}: keep: the PEB walk reads LSASS\n{LEFT_OUT}: keep: yes")

        cells, published = _cells(review)

        assert UNDESCRIBED in published
        note = cells[UNDESCRIBED].note
        assert "no claim naming it uses the catalogue's terms for it" in note
        assert "kept by the judge when asked (the PEB walk reads LSASS)" in note

    def test_the_markdown_carries_both(self) -> None:
        review, _ = _ask(f"{UNDESCRIBED}: drop: nothing reads credentials\n{LEFT_OUT}: drop: no")
        bundle = _bundle()
        bundle.x_maljan_technique_review = review
        cells, mappings = build_capability_matrix(
            stix_output=bundle.model_dump(), isr_reports=_isrs()
        )
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_name="s.exe"),
            capability_matrix=cells,
            ttp_mappings=mappings,
        )

        markdown = MarkdownRenderer().render(report)

        assert "the judge dropped it (nothing reads credentials)" in markdown


class TestTheAnalystsExemptionsHold:
    def test_a_technique_with_a_claim_that_reads_as_absence_carries_no_finding(self) -> None:
        isrs = _isrs()
        isrs["dynamic"].claims[0] = _claim(
            "The sample does not dump credentials from LSASS", UNDESCRIBED
        )

        questions, _ = judge_questions(_bundle().model_dump(), isrs, attck=knowledge)

        assert UNDESCRIBED not in {q.technique_id for q in questions}

    def test_a_technique_the_sample_cannot_host_carries_no_finding(self) -> None:
        questions, _ = judge_questions(
            _bundle().model_dump(),
            _isrs(),
            {"platform": "android", "file_type": "apk"},
            attck=knowledge,
        )

        assert not any(q.check and q.technique_id == UNDESCRIBED for q in questions)


def test_the_listing_names_what_the_judge_is_asked_given_the_catalogue() -> None:
    listed = techniques_for_the_judge(_bundle().model_dump(), _isrs(), attck=knowledge)

    assert {q.technique_id for q in listed} == {UNDESCRIBED, LEFT_OUT}
