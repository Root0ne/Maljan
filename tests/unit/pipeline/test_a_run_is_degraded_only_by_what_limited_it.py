"""A run is degraded only by what limited it.

A technique claim an analyst kept citing no evidence is a fact about that
claim, not about what the run could examine. It is the judge's input, stated
in the RUN QUALITY paragraph the judge reads, and a validation finding the
report lists. It never makes the run degraded on its own, and a technique the
judge then drops never puts a "verdict tentative" banner on a run where every
stage ran.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

from maljan.agents.judge_agent import JudgeVerdict
from maljan.pipeline.nodes import make_judge_node, run_quality_note
from maljan.pipeline.validation import UNGROUNDED_TECHNIQUE_CODE, ungrounded_technique_note
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import EvidenceCounter
from maljan.schemas.isr_models import ClaimEvidence
from maljan.schemas.stix_models import Bundle, TechniqueDecision, TechniqueReview
from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import _Container
from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import _state as _corroborated_state
from tests.unit.reporting.test_renderers_markdown import _build

_FINDINGS = {
    "static": [
        {
            "code": UNGROUNDED_TECHNIQUE_CODE,
            "message": "TECHNIQUE T1048 cites no evidence id from this run.",
            "path": "static.claims[0]",
        }
    ]
}
_NOTE = "technique claims citing no evidence from this run: T1048"


def _state(signatures: list[dict[str, str]] | None = None) -> dict[str, Any]:
    """A run whose only other technique is corroborated, so nothing else degrades it."""
    state = _corroborated_state([])
    state["isr_reports"]["static"].claims.append(
        ClaimEvidence(
            claim="No alternative-protocol channel is observed",
            evidence_ref="none",
            confidence=0.7,
            technique_id="T1048",
        )
    )
    state["validation_findings"] = _FINDINGS
    state["sandbox_report"] = {"signatures": signatures or []}
    return state


def _judged(state: dict[str, Any]) -> tuple[dict[str, Any], Any]:
    container = _Container(EvidenceCounter())
    judge = container.get_judge_agent(role="judge")
    judge.give_verdict = AsyncMock(
        return_value=JudgeVerdict(bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={})
    )
    judge.decide_techniques = AsyncMock(
        return_value=TechniqueReview(
            asked=["T1048"],
            decisions=[
                TechniqueDecision(technique_id="T1048", decision="drop", reason="an absence")
            ],
        )
    )
    return asyncio.run(make_judge_node(container)(state)), judge


def _banner(update: dict[str, Any]) -> bool:
    report = _build()
    report.degraded_mode = bool(update["degraded_mode"])
    report.degradation_reasons = list(update["degradation_reasons"])
    return "[DEGRADED RUN]" in MarkdownRenderer().render(report)


class TestATechniqueTheJudgeDropsDoesNotDegradeTheRun:
    def test_the_run_is_not_degraded_and_prints_no_banner(self) -> None:
        update, _judge = _judged(_state())

        assert update["degraded_mode"] is False
        assert _NOTE not in update["degradation_reasons"]
        assert update["run_summary"]["degraded_mode"] is False
        assert _NOTE not in update["run_summary"]["degradation_reasons"]
        assert not _banner(update)

    def test_the_note_still_reaches_the_judge_in_both_questions(self) -> None:
        _update, judge = _judged(_state())

        verdict_note = judge.give_verdict.await_args.kwargs["degradation_note"]
        technique_note = judge.decide_techniques.await_args.kwargs["degradation_note"]

        assert _NOTE in verdict_note
        assert verdict_note == technique_note
        assert "degraded" not in verdict_note

    def test_the_validation_finding_is_kept_for_the_reader(self) -> None:
        update, _judge = _judged(_state())

        codes = [row["code"] for row in update["run_summary"]["validation"]["unresolved"]]
        assert UNGROUNDED_TECHNIQUE_CODE in codes


class TestAnotherReasonStillDegradesTheRun:
    def test_only_that_reason_is_listed(self) -> None:
        update, judge = _judged(_state([{"name": "antivm_generic", "description": "anti-vm"}]))

        assert update["degraded_mode"] is True
        assert update["degradation_reasons"] == [
            "sandbox detected anti-emulation behaviour: antivm_generic"
        ]
        assert _banner(update)
        note = judge.give_verdict.await_args.kwargs["degradation_note"]
        assert note.startswith("RUN QUALITY — this analysis is degraded because sandbox detected")
        assert note.endswith(f"not about the run: {_NOTE}.")


class TestTheRunQualityParagraph:
    def test_a_run_with_only_claim_notes_states_them_alone(self) -> None:
        assert run_quality_note([], degraded=False, notes=[_NOTE]) == f"RUN QUALITY — {_NOTE}."

    def test_a_run_with_no_notes_reads_as_before(self) -> None:
        assert run_quality_note([], degraded=False) == ""
        assert run_quality_note(["a reason"], degraded=True) == run_quality_note(
            ["a reason"], degraded=True, notes=()
        )
        assert run_quality_note(["a reason"], degraded=True).endswith("not only in its prose.")

    def test_the_note_wording_is_the_validation_module_s(self) -> None:
        assert ungrounded_technique_note(_FINDINGS) == _NOTE
