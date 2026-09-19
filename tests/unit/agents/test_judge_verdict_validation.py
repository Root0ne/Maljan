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

from maljan.agents.judge_agent import (
    VERDICT_FALLBACK_CODE,
    VERDICT_FALLBACK_REASON,
    VERDICT_TIMEOUT_CODE,
    VERDICT_TIMEOUT_REASON,
    JudgeAgent,
)
from maljan.pipeline.validation import FEEDBACK_PREAMBLE
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _bundle_json(
    *,
    severity: str = "High",
    verdict: str | None = "Malware",
    indicators: list[str] | None = None,
    family: dict[str, Any] | None = None,
    attack_patterns: list[dict[str, Any]] | None = None,
) -> str:
    objects: list[dict[str, Any]] = [
        {
            "type": "malware",
            "id": "malware--0f1e2d3c-4b5a-4968-8776-655443332211",
            "name": "sample",
            "is_family": False,
        }
    ]
    objects.extend(attack_patterns or [])
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
    if verdict is not None:
        assessment["verdict"] = verdict
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
    async def test_the_prompt_asks_for_the_verdict_severity_category_and_family(self) -> None:
        judge, llm = _judge(_bundle_json())

        await judge.give_verdict(reports=REPORTS, history=[])

        prompt = _prompt_text(llm)
        assert "x_maljan_assessment" in prompt
        assert '"verdict": "Malware" | "Suspicious" | "Benign"' in prompt
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
    async def test_with_nothing_to_search_the_judge_is_told_and_keeps_its_object(self) -> None:
        """A run with no evidence at all searched nothing, and says so.

        The check used to be skipped outright when there was no corpus, which
        is mock mode, a static-only team, a failed submission and any sample
        that made no network call — and an invented indicator reached the
        exported bundle with nothing said about it. Searching nothing is not a
        licence to conclude nothing: the judge is asked once, as it is for any
        finding, and if it keeps the value the row is advisory and the object
        stays, because an absence measured over no evidence is not a reason to
        remove anything.
        """
        stubborn = _bundle_json(indicators=["anything.example"])
        judge, llm = _judge(stubborn, stubborn)

        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        assert (verdict.retries, len(llm.calls)) == (1, 2)
        assert [v.code for v in verdict.violations] == ["stix.ungrounded_indicator"]
        assert verdict.violations[0].advisory is True
        assert "no evidence was searched" in verdict.violations[0].message
        # Kept: nothing was searched, so nothing was established about it.
        assert any(
            "anything.example" in str(getattr(o, "pattern", "")) for o in verdict.bundle.objects
        )


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
        """After the one retry: the judge is asked again for a bundle first."""
        judge, _llm = _judge(
            "The sample is malware. No JSON for you.",
            "Still malware, still no JSON.",
        )

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


def _attack_pattern(external_id: str, source_name: str = "mitre-attack") -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": "attack-pattern--0f1e2d3c-4b5a-4968-8776-655443332299",
        "name": "Process Injection",
        "external_references": [{"source_name": source_name, "external_id": external_id}],
    }


class TestUnknownTechniqueIds:
    """The case the violation exists for: well-formed, and imaginary.

    It was unreachable while ``_filter_invalid_technique_ids`` dropped the
    object before the validator ran — the judge never learned it had invented
    an id, and the report simply showed one fewer attack-pattern.
    """

    @pytest.mark.asyncio
    async def test_a_plausible_but_unknown_id_earns_one_retry(self) -> None:
        judge, llm = _judge(
            _bundle_json(attack_patterns=[_attack_pattern("T7777")]),
            _bundle_json(attack_patterns=[_attack_pattern("T1055")]),
        )

        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        assert verdict.retries == 1
        assert verdict.violations == []
        feedback = str(llm.calls[1][-1].content)
        assert "stix.unknown_technique" in feedback
        assert "T7777" in feedback

    @pytest.mark.asyncio
    async def test_a_real_id_costs_no_retry(self) -> None:
        judge, llm = _judge(_bundle_json(attack_patterns=[_attack_pattern("T1055")]))

        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        assert (verdict.retries, len(llm.calls)) == (0, 1)

    @pytest.mark.asyncio
    async def test_a_sigma_reference_is_not_read_as_a_technique_id(self) -> None:
        """It is not asked about the catalogue — there is no ATT&CK id to look
        up — it is asked for one, once, and the answer it gives stands."""
        answer = _bundle_json(
            attack_patterns=[_attack_pattern("5f1c6b0d-1e1a", source_name="sigma")]
        )
        judge, llm = _judge(answer, answer)

        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        assert [v.code for v in verdict.violations] == ["attck.missing_id"]
        assert (verdict.retries, len(llm.calls)) == (1, 2)

    @pytest.mark.asyncio
    async def test_the_object_is_reported_rather_than_dropped_before_the_judge_sees_it(
        self,
    ) -> None:
        stubborn = _bundle_json(attack_patterns=[_attack_pattern("T7777")])
        judge, _llm = _judge(stubborn, stubborn)

        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        assert [v.code for v in verdict.violations] == ["stix.unknown_technique"]
        assert any(getattr(o, "type", "") == "attack-pattern" for o in verdict.bundle.objects)


class TestAnAnswerThatIsNotABundle:
    """The live run's judge answered "<tool_call>begin_of_header>" and the
    fallback extraction accepted it silently: the run summary said no retries
    and no unresolved findings while the malware object carried no severity at
    all."""

    @pytest.mark.asyncio
    async def test_garbage_is_asked_again_and_the_second_answer_is_kept(self) -> None:
        judge, llm = _judge("<tool_call>begin_of_header>", _bundle_json(severity="High"))

        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        assert verdict.retries == 1
        assert verdict.violations == []
        assert verdict.bundle.x_maljan_assessment is not None
        assert verdict.bundle.x_maljan_assessment.severity is not None
        assert verdict.bundle.x_maljan_assessment.severity.rating == "High"

    @pytest.mark.asyncio
    async def test_the_feedback_asks_for_the_bundle_alone(self) -> None:
        judge, llm = _judge("<tool_call>begin_of_header>", _bundle_json())

        await judge.give_verdict(reports=REPORTS, history=[])

        feedback = str(llm.calls[1][-1].content)
        assert "verdict.not_json" in feedback
        assert "Return the JSON bundle only, no tool calls, no prose." in feedback

    @pytest.mark.asyncio
    async def test_garbage_twice_falls_back_and_says_so(self) -> None:
        judge, llm = _judge("<tool_call>begin_of_header>", "still not a bundle")

        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        assert verdict.retries == 1
        assert len(llm.calls) == 2
        # Both: the answer that was not a bundle, which the model was shown and
        # did not fix, and what this pipeline did about it. The conversation
        # published the first as survived, so a summary without it would
        # disagree with the feed.
        assert [v.code for v in verdict.violations] == ["verdict.not_json", VERDICT_FALLBACK_CODE]
        assert verdict.violations[-1].message == VERDICT_FALLBACK_REASON
        assert verdict.bundle.objects, "the fallback bundle is still built"

    @pytest.mark.asyncio
    async def test_an_empty_answer_carrying_tool_calls_is_not_an_answer(self) -> None:
        """The judge binds no tools on this path, so a tool call is the local
        model emitting control tokens rather than saying anything."""
        llm = _Llm(_bundle_json())
        judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
        empty = MagicMock(content="", tool_calls=[{"name": "identify_file", "args": {}}])

        async def _first_then_queue(messages: list[Any]) -> Any:
            llm.calls.append(list(messages))
            if len(llm.calls) == 1:
                return empty
            return MagicMock(content=llm._answers.pop(0))

        llm.ainvoke = _first_then_queue  # type: ignore[method-assign]

        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        assert verdict.retries == 1
        assert verdict.violations == []

    @pytest.mark.asyncio
    async def test_the_unresolved_fallback_reaches_the_run_summary(self) -> None:
        from maljan.pipeline.validation import validation_metrics

        judge, _llm = _judge("not json", "not json either")
        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        metrics = validation_metrics(verdict.retries, [("judge", v) for v in verdict.violations])

        assert metrics["retries"] == 1
        assert [row["code"] for row in metrics["unresolved"]] == [
            "verdict.not_json",
            VERDICT_FALLBACK_CODE,
        ]


class TestAJudgeThatNeverAnswered:
    """A timeout produces the same fallback bundle as garbage does, and asking
    again would cost a second full judge timeout for the same answer. So it is
    not asked again — but the verdict in the report is the analysts' text, not
    the judge's, and the run summary used to show a clean validation block
    beside it."""

    @pytest.mark.asyncio
    async def test_the_timeout_is_recorded_unresolved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import judge_agent as module

        async def _timeout(coro: Any, *args: Any, **kwargs: Any) -> Any:
            coro.close()
            raise TimeoutError("the judge did not answer")

        monkeypatch.setattr(module, "run_on_agent_loop", _timeout)

        judge, llm = _judge()
        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        assert [v.code for v in verdict.violations] == [VERDICT_TIMEOUT_CODE]
        assert verdict.violations[0].message == VERDICT_TIMEOUT_REASON
        assert verdict.retries == 0, "a second full judge timeout buys nothing"

    @pytest.mark.asyncio
    async def test_it_reaches_the_run_summary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from maljan.agents import judge_agent as module
        from maljan.pipeline.validation import validation_metrics

        async def _timeout(coro: Any, *args: Any, **kwargs: Any) -> Any:
            coro.close()
            raise TimeoutError("the judge did not answer")

        monkeypatch.setattr(module, "run_on_agent_loop", _timeout)

        judge, _llm = _judge()
        verdict = await judge.give_verdict(reports=REPORTS, history=[])

        metrics = validation_metrics(
            verdict.retries, [("judge", v) for v in verdict.violations], verdict.fed_back
        )

        assert [row["code"] for row in metrics["unresolved"]] == [VERDICT_TIMEOUT_CODE]
