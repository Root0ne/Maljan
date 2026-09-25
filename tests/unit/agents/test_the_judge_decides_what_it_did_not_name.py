"""The judge decides the techniques the analysts named and its bundle does not carry.

A paid run published a technique one analyst claimed at 0.30 that the judge's
bundle left out, and listed three techniques that appeared only on findings,
which no check had ever asked about. After the verdict the judge is asked
once, in one question, about both kinds — keep or drop, with a reason — and the
report publishes per its answer. A dropped technique says so in the judge's
words; with no answer nothing is withheld, and the row says the judge did not
confirm it.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.agents.judge_agent import (
    TECHNIQUE_ANSWER_FORM,
    TECHNIQUE_ANSWER_UNREAD,
    TECHNIQUE_QUESTION_NOT_ASKED,
    TECHNIQUE_QUESTION_SYSTEM,
    JudgeAgent,
    read_technique_answer,
)
from maljan.extractors.capability_matrix import (
    FINDING_ONLY_REASON,
    build_capability_matrix,
    techniques_for_the_judge,
)
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.isr_models import (
    JUDGE_UNCONFIRMED_TECHNIQUE_MARKER,
    AgentISR,
    ClaimEvidence,
    Finding,
)
from maljan.schemas.stix_models import Bundle, TechniqueDecision, TechniqueReview

# In the bundle; claimed by one analyst and left out of it; named on a finding only.
IN_BUNDLE = "T1112"
LEFT_OUT = "T1568.002"
FINDING_ONLY = "T1003"


def _bundle() -> Bundle:
    return Bundle.model_validate(
        {
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--0f1e2d3c-4b5a-4968-8776-655443332211",
                    "name": "Modify Registry",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": IN_BUNDLE}
                    ],
                }
            ]
        }
    )


def _isrs() -> dict[str, AgentISR]:
    return {
        "network": AgentISR(
            agent_id="network",
            domain="network",
            claims=[
                ClaimEvidence(
                    claim="The sample generates its server names from the date",
                    evidence_ref="decoded routine [ev_0012] and [ev_0013]",
                    confidence=0.3,
                    technique_id=LEFT_OUT,
                ),
                ClaimEvidence(
                    claim="The sample writes a registry value",
                    evidence_ref="[ev_0002]",
                    confidence=0.8,
                    technique_id=IN_BUNDLE,
                ),
            ],
            findings=[
                Finding(
                    title="Reads credentials from process memory",
                    detail="opens the credential store process",
                    technique_ids=[FINDING_ONLY, IN_BUNDLE],
                    evidence_ids=["ev_0007"],
                )
            ],
        )
    }


class _Llm:
    """Answers each call from a queue, and remembers what it was sent."""

    def __init__(self, *answers: Any) -> None:
        self._answers = list(answers)
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> Any:
        self.calls.append(list(messages))
        answer = self._answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return MagicMock(content=answer)


def _ask(*answers: Any, timed_out: bool = False) -> tuple[TechniqueReview | None, _Llm]:
    llm = _Llm(*answers)
    judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
    review = asyncio.run(
        judge.decide_techniques(
            _bundle(),
            _isrs(),
            facts_block="=== PACK ===\nthe pack",
            run_state="the run state",
            verdict_timed_out=timed_out,
        )
    )
    return review, llm


def _published(review: TechniqueReview | None) -> tuple[dict[str, Any], set[str]]:
    bundle = _bundle()
    bundle.x_maljan_technique_review = review
    cells, mappings = build_capability_matrix(stix_output=bundle.model_dump(), isr_reports=_isrs())
    return {c.technique_id: c for c in cells}, {m.technique_id for m in mappings}


def _markdown(review: TechniqueReview | None) -> str:
    bundle = _bundle()
    bundle.x_maljan_technique_review = review
    cells, mappings = build_capability_matrix(stix_output=bundle.model_dump(), isr_reports=_isrs())
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_name="s.exe"),
        capability_matrix=cells,
        ttp_mappings=mappings,
    )
    return MarkdownRenderer().render(report)


class TestWhatIsAsked:
    def test_a_left_out_claim_and_a_finding_only_technique_are_asked_the_bundle_s_are_not(
        self,
    ) -> None:
        questions = techniques_for_the_judge(_bundle().model_dump(), _isrs())

        assert [(q.technique_id, q.kind) for q in questions] == [
            (LEFT_OUT, "claimed"),
            (FINDING_ONLY, "finding"),
        ]
        assert questions[0].mentions == [
            (
                "network",
                "The sample generates its server names from the date",
                ["ev_0012", "ev_0013"],
            )
        ]
        assert questions[1].mentions == [
            (
                "network",
                "Reads credentials from process memory — opens the credential store process",
                ["ev_0007"],
            )
        ]

    def test_one_tool_free_question_with_the_run_state_and_the_pack(self) -> None:
        _review, llm = _ask(f"{LEFT_OUT}: keep: the routine is shown\n{FINDING_ONLY}: drop: no")

        assert len(llm.calls) == 1
        system, human = llm.calls[0]
        assert system.content == TECHNIQUE_QUESTION_SYSTEM
        assert human.type == "human"
        text = str(human.content)
        assert text.index("the run state") < text.index("the pack") < text.index(LEFT_OUT)
        assert "ev_0012, ev_0013" in text and "ev_0007" in text
        assert text.endswith(TECHNIQUE_ANSWER_FORM)

    def test_nothing_to_ask_asks_nothing(self) -> None:
        llm = _Llm()
        judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]

        review = asyncio.run(judge.decide_techniques(_bundle(), {}))

        assert review is None
        assert llm.calls == []


class TestTheAnswerIsRead:
    def test_keep_and_drop_with_their_reasons_whole(self) -> None:
        reason = "the decoded routine at [ev_0012] builds the names; " + "and more " * 60
        answer = (
            f"Here you go.\n- **{LEFT_OUT}**: KEEP — {reason}\n2. {FINDING_ONLY}: drop: no call"
        )

        decisions = read_technique_answer(answer, [LEFT_OUT, FINDING_ONLY])

        assert decisions == [
            TechniqueDecision(technique_id=LEFT_OUT, decision="keep", reason=reason.strip()),
            TechniqueDecision(technique_id=FINDING_ONLY, decision="drop", reason="no call"),
        ]

    def test_a_line_about_a_technique_not_asked_is_not_read(self) -> None:
        assert read_technique_answer("T1999: drop: not asked", [LEFT_OUT]) == []


class TestKeep:
    def test_both_are_published_and_the_rows_say_the_judge_kept_them(self) -> None:
        review, _llm = _ask(
            f"{LEFT_OUT}: keep: the routine is shown\n{FINDING_ONLY}: keep: the call is there"
        )

        cells, published = _published(review)

        assert {LEFT_OUT, FINDING_ONLY, IN_BUNDLE} <= published
        assert cells[LEFT_OUT].note == "kept by the judge when asked (the routine is shown)"
        assert cells[FINDING_ONLY].not_published == ""


class TestDrop:
    def test_a_dropped_technique_is_not_published_and_says_why(self) -> None:
        review, _llm = _ask(
            f"{LEFT_OUT}: drop: one analyst at 0.30 and no routine in the evidence\n"
            f"{FINDING_ONLY}: drop: nothing opens that process"
        )

        cells, published = _published(review)

        assert LEFT_OUT not in published and FINDING_ONLY not in published
        assert IN_BUNDLE in published
        assert cells[LEFT_OUT].not_published == (
            "the judge dropped it (one analyst at 0.30 and no routine in the evidence)"
        )

    def test_the_report_says_the_judge_dropped_it(self) -> None:
        review, _llm = _ask(f"{LEFT_OUT}: drop: no routine in the evidence")

        markdown = _markdown(review)

        assert "not published: the judge dropped it (no routine in the evidence)" in markdown


class TestNoAnswer:
    @pytest.mark.parametrize(
        ("answers", "timed_out", "unanswered"),
        [
            ((TimeoutError(),), False, "the question timed out after"),
            ((RuntimeError("down"),), False, "the question failed (RuntimeError)"),
            (("I cannot tell.",), False, TECHNIQUE_ANSWER_UNREAD),
            ((), True, TECHNIQUE_QUESTION_NOT_ASKED),
        ],
    )
    def test_nothing_is_withheld_and_the_claim_is_marked_unconfirmed(
        self, answers: tuple[Any, ...], timed_out: bool, unanswered: str
    ) -> None:
        review, _llm = _ask(*answers, timed_out=timed_out)

        assert review is not None
        assert str(review.unanswered).startswith(unanswered)
        cells, published = _published(review)
        assert LEFT_OUT in published
        assert cells[LEFT_OUT].note == JUDGE_UNCONFIRMED_TECHNIQUE_MARKER
        # A finding-only technique is what it was without the question.
        assert cells[FINDING_ONLY].not_published == FINDING_ONLY_REASON

    def test_a_technique_the_answer_skipped_is_marked_unconfirmed(self) -> None:
        review, _llm = _ask(f"{FINDING_ONLY}: keep: the call is there")

        cells, published = _published(review)

        assert LEFT_OUT in published
        assert cells[LEFT_OUT].note == JUDGE_UNCONFIRMED_TECHNIQUE_MARKER
        assert "not confirmed by the judge" in _markdown(review)

    def test_a_bundle_asked_nothing_publishes_as_before(self) -> None:
        cells, published = _published(None)

        assert LEFT_OUT in published
        assert cells[LEFT_OUT].note == ""
        assert cells[FINDING_ONLY].not_published == FINDING_ONLY_REASON


class TestTheJudgeNodeKeepsTheAnswer:
    def test_the_answer_is_on_the_judge_s_bundle(self) -> None:
        from maljan.agents.judge_agent import JudgeVerdict
        from maljan.pipeline.nodes import make_judge_node
        from maljan.schemas.evidence import EvidenceCounter
        from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import _Container, _state

        container = _Container(EvidenceCounter())
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(bundle=_bundle(), violations=[], retries=0, fed_back={})
        )
        review = TechniqueReview(
            asked=["T1055"],
            decisions=[TechniqueDecision(technique_id="T1055", decision="drop", reason="r")],
        )
        judge.decide_techniques = AsyncMock(return_value=review)

        update = asyncio.run(make_judge_node(container)(_state([])))

        assert update["stix_output"]["x_maljan_technique_review"] == review.model_dump()
        kwargs = judge.decide_techniques.await_args.kwargs
        assert kwargs["verdict_timed_out"] is False
        assert kwargs["run_state"]
