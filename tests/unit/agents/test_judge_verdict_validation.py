"""The judge's verdict: what it is shown, and what it is asked to fix.

Three properties, each replacing something that used to happen behind the
judge's back. The evidence summary and the degradation note reach the prompt,
so the judge weighs them instead of having a number capped afterwards. A
severity outside the enum comes back as feedback. And an indicator naming a
value no tool saw is only dropped after the judge has had its turn — and then
it is recorded, because an ungrounded IOC in a STIX bundle is a false positive
somebody downstream will act on.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.agents.judge_agent import JudgeAgent
from maljan.pipeline.validation import FEEDBACK_PREAMBLE
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _bundle_json(
    *,
    severity: str = "High",
    indicators: list[str] | None = None,
    family: dict[str, Any] | None = None,
) -> str:
    objects: list[dict[str, Any]] = [
        {
            "type": "malware",
            "id": "malware--0f1e2d3c-4b5a-4968-8776-655443332211",
            "name": "sample",
            "is_family": False,
        }
    ]
    objects.extend(
        {
            "type": "indicator",
            "id": f"indicator--0f1e2d3c-4b5a-4968-8776-6554433322{n:02d}",
            "pattern": f"[domain-name:value = '{value}']",
            "pattern_type": "stix",
        }
        for n, value in enumerate(indicators or [])
    )
    assessment: dict[str, Any] = {
        "severity": {"rating": severity, "rationale": "it does harm"},
        "malware_category": "loader",
    }
    if family is not None:
        assessment["family"] = family
    return json.dumps(
        {
            "type": "bundle",
            "id": "bundle--0f1e2d3c-4b5a-4968-8776-655443332200",
            "objects": objects,
            "x_maljan_assessment": assessment,
        }
    )


class _Llm:
    """Answers each verdict call from a queue, and remembers what it was sent."""

    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> Any:
        self.calls.append(list(messages))
        return MagicMock(content=self._answers.pop(0))


def _judge(*answers: str) -> tuple[JudgeAgent, _Llm]:
    llm = _Llm(*answers)
    judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
    return judge, llm


def _prompt_text(llm: _Llm, call: int = 0) -> str:
    return "\n".join(str(getattr(turn, "content", turn)) for turn in llm.calls[call])


REPORTS = {"static": "It loads a payload."}


class TestWhatReachesThePrompt:
    @pytest.mark.asyncio
    async def test_the_evidence_summary_block_is_in_the_prompt(self) -> None:
        judge, llm = _judge(_bundle_json())

        await judge.give_verdict(
            reports=REPORTS,
            history=[],
            evidence_summary="EVIDENCE SUMMARY — T1055: 2 source(s) — static (0.90)",
        )

        assert "T1055: 2 source(s)" in _prompt_text(llm)

    @pytest.mark.asyncio
    async def test_the_degradation_is_stated_rather_than_capped_afterwards(self) -> None:
        judge, llm = _judge(_bundle_json())

        await judge.give_verdict(
            reports=REPORTS,
            history=[],
            degradation_note=(
                "RUN QUALITY — this analysis is degraded because no sandbox report. "
                "Weigh your confidence accordingly."
            ),
        )

        prompt = _prompt_text(llm)
        assert "this analysis is degraded because no sandbox report" in prompt
        assert "Weigh your confidence accordingly" in prompt

    @pytest.mark.asyncio
    async def test_the_prompt_asks_for_severity_category_and_family(self) -> None:
        judge, llm = _judge(_bundle_json())

        await judge.give_verdict(reports=REPORTS, history=[])

        prompt = _prompt_text(llm)
        assert "x_maljan_assessment" in prompt
        assert "malware_category" in prompt
        assert "evidence_ids" in prompt


class TestSeverityIsValidatedNotCorrected:
    @pytest.mark.asyncio
    async def test_a_rating_outside_the_enum_earns_one_retry(self) -> None:
        judge, llm = _judge(_bundle_json(severity="Catastrophic"), _bundle_json(severity="High"))

        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        assert verdict.retries == 1
        assert verdict.violations == []
        assert verdict.bundle.x_maljan_assessment is not None
        assert verdict.bundle.x_maljan_assessment.severity is not None
        assert verdict.bundle.x_maljan_assessment.severity.rating == "High"

    @pytest.mark.asyncio
    async def test_the_feedback_names_the_allowed_ratings(self) -> None:
        judge, llm = _judge(_bundle_json(severity="Catastrophic"), _bundle_json())

        await judge.give_verdict(reports=REPORTS, history=[])

        feedback = str(llm.calls[1][-1].content)
        assert feedback.startswith(FEEDBACK_PREAMBLE)
        assert "verdict.severity_enum" in feedback
        assert "Critical, High, Medium, Low, Informational" in feedback

    @pytest.mark.asyncio
    async def test_a_valid_rating_costs_no_retry(self) -> None:
        judge, llm = _judge(_bundle_json(severity="Medium"))

        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        assert (verdict.retries, len(llm.calls)) == (0, 1)


class TestUngroundedIndicators:
    @pytest.mark.asyncio
    async def test_the_judge_is_asked_first_and_a_fixed_answer_is_kept(self) -> None:
        judge, llm = _judge(
            _bundle_json(indicators=["invented.example"]),
            _bundle_json(indicators=["real.example"]),
        )

        verdict = await judge.give_verdict(
            reports=REPORTS, history=[], evidence_corpus={"real.example"}
        )

        assert verdict.retries == 1
        assert verdict.violations == []
        patterns = [getattr(o, "pattern", "") for o in verdict.bundle.objects]
        assert any("real.example" in p for p in patterns)
        assert not any("invented.example" in p for p in patterns)

    @pytest.mark.asyncio
    async def test_one_that_survives_the_retry_is_dropped_and_reported(self) -> None:
        stubborn = _bundle_json(indicators=["invented.example"])
        judge, _llm = _judge(stubborn, stubborn)

        verdict = await judge.give_verdict(
            reports=REPORTS, history=[], evidence_corpus={"real.example"}
        )

        # Dropped, because a STIX consumer has no way to read a caveat...
        assert not any(
            "invented.example" in str(getattr(o, "pattern", "")) for o in verdict.bundle.objects
        )
        # ...and recorded, because the false positive is a fact about the run.
        assert [v.code for v in verdict.violations] == ["stix.ungrounded_indicator"]
        assert "invented.example" in verdict.violations[0].message

    @pytest.mark.asyncio
    async def test_without_a_corpus_no_indicator_is_questioned(self) -> None:
        judge, llm = _judge(_bundle_json(indicators=["anything.example"]))

        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        assert (verdict.retries, verdict.violations, len(llm.calls)) == (0, [], 1)


class TestFamilyAttribution:
    @pytest.mark.asyncio
    async def test_a_family_with_no_evidence_ids_is_questioned_then_kept(self) -> None:
        naked = _bundle_json(family={"name": "AsyncRAT", "confidence": 0.6})
        judge, _llm = _judge(naked, naked)

        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        assert [v.code for v in verdict.violations] == ["attribution.ungrounded_family"]
        assert verdict.bundle.x_maljan_assessment is not None
        family = verdict.bundle.x_maljan_assessment.family
        assert family is not None and family.name == "AsyncRAT"

    @pytest.mark.asyncio
    async def test_a_family_that_cites_evidence_passes(self) -> None:
        judge, _llm = _judge(_bundle_json(family={"name": "AsyncRAT", "evidence_ids": ["ev_0004"]}))

        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        assert verdict.violations == []


class TestTheAnswerStillDegradesGracefully:
    @pytest.mark.asyncio
    async def test_a_non_json_answer_falls_back_to_a_text_bundle(self) -> None:
        judge, _llm = _judge("The sample is malware. No JSON for you.")

        verdict = await judge.give_verdict(
            reports=REPORTS,
            history=[],
            isr_reports={
                "static": AgentISR(
                    agent_id="static",
                    domain="static",
                    claims=[ClaimEvidence(claim="c", evidence_ref="e", confidence=0.5)],
                )
            },
        )

        assert verdict.bundle.objects
