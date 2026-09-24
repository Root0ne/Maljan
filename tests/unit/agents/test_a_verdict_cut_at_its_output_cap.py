"""A verdict the output cap cut off is told so, and what it stated whole is kept.

The large model's judge answered one sample twice with about 25,000 characters
that were not a JSON bundle. Both answers had generated exactly the 8,192
tokens ``judge_max_tokens`` allows (the server log says so, and the run
summary counts two ``judge_token_cap_hits``), and the text the fallback kept
begins ``{ "type": "bundle", ... "x_maljan_assessment": {"verdict":
"Malware", "confidence": 0.85, ... "family": {"name": "Filisto", ...}}``. The
cause was a bundle larger than the output budget, and the correction the
model was given — "not a JSON STIX bundle" — named a different one, so it
wrote the same bundle again. The fallback then published Malware with no
confidence, no severity and no family.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from langchain_core.messages import AIMessage

from maljan.agents.judge_agent import (
    VERDICT_CUT_CODE,
    VERDICT_FALLBACK_CODE,
    JudgeAgent,
    JudgeVerdict,
    stated_assessment_in,
    verdict_cut_violation,
)
from maljan.core.config import get_settings
from maljan.pipeline.outcome import decide_from_bundle, stated_confidence, verdict_reading
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

ASSESSMENT = {
    "verdict": "Malware",
    "confidence": 0.85,
    "severity": {"rating": "High", "rationale": "A packed loader; VT names Filisto."},
    "malware_category": "Trojan Loader",
    "family": {"name": "Filisto", "confidence": 0.75, "evidence_ids": ["ev_0010"]},
}


def _cut_bundle(chars: int = 25_000) -> str:
    """A bundle written assessment first and stopped mid-object, the way the cap stops it."""
    whole = json.dumps(
        {
            "type": "bundle",
            "id": "bundle--1",
            "x_maljan_assessment": ASSESSMENT,
            "objects": [
                {
                    "type": "indicator",
                    "id": f"indicator--{i}",
                    "name": f"File Hash MD5 {i:032x}",
                    "pattern": f"[file:hashes.'MD5' = '{i:032x}']",
                }
                for i in range(400)
            ],
        },
        indent=2,
    )
    return whole[:chars]


def _cap() -> int:
    return int(get_settings().llm.judge_max_tokens)


def _answer(text: str, *, tokens: int) -> AIMessage:
    return AIMessage(
        content=text,
        usage_metadata={
            "input_tokens": 3751,
            "output_tokens": tokens,
            "total_tokens": 3751 + tokens,
        },
    )


class _Llm:
    def __init__(self, *answers: AIMessage) -> None:
        self.answers = list(answers)
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> AIMessage:
        self.calls.append(list(messages))
        return self.answers.pop(0)


CLAIMED = {
    "static": AgentISR(
        agent_id="static",
        domain="static",
        claims=[ClaimEvidence(claim="packed", evidence_ref="[ev_0004]", confidence=0.9)],
    )
}


async def _verdict(llm: _Llm) -> JudgeVerdict:
    judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
    return await judge.give_verdict(
        reports={"static": "packed"},
        history=[],
        isr_reports=CLAIMED,
        ledger_ids=["ev_0004", "ev_0010"],
    )


class TestTheAssessmentAnAnswerStatedWhole:
    def test_it_is_read_from_the_cut_bundle(self) -> None:
        assessment = stated_assessment_in(_cut_bundle())

        assert assessment is not None
        assert assessment.verdict == "Malware"
        assert assessment.confidence == 0.85
        assert assessment.family is not None and assessment.family.name == "Filisto"
        assert assessment.severity is not None and assessment.severity.rating == "High"

    def test_one_the_cap_cut_inside_states_nothing(self) -> None:
        text = _cut_bundle()
        inside = text[: text.index('"Filisto"')]

        assert stated_assessment_in(inside) is None

    def test_prose_and_an_unreadable_verdict_state_nothing(self) -> None:
        assert stated_assessment_in("The verdict is Malware with confidence 0.85.") is None
        unreadable = json.dumps({"x_maljan_assessment": {**ASSESSMENT, "verdict": "Malicious?"}})
        assert stated_assessment_in(unreadable) is None


class TestWhichAssessmentIsRead:
    def test_the_last_whole_one_is_the_bundle_s(self) -> None:
        draft = {**ASSESSMENT, "verdict": "Suspicious", "confidence": 0.4}
        text = (
            "Thinking: maybe "
            + json.dumps({"x_maljan_assessment": draft})
            + " but the evidence says otherwise.\n"
            + _cut_bundle()
        )

        assessment = stated_assessment_in(text)

        assert assessment is not None
        assert (assessment.verdict, assessment.confidence) == ("Malware", 0.85)

    def test_a_value_is_read_as_written_before_any_repair(self) -> None:
        rationale = "see https://example.test/a//b and 'quoted' words"
        written = {
            **ASSESSMENT,
            "severity": {"rating": "High", "rationale": rationale},
        }
        text = json.dumps({"type": "bundle", "x_maljan_assessment": written})[:-1]

        assessment = stated_assessment_in(text)

        assert assessment is not None
        assert assessment.severity is not None
        assert assessment.severity.rationale == rationale


class TestTheRound:
    @pytest.mark.asyncio
    async def test_the_prompt_states_the_output_budget(self) -> None:
        llm = _Llm(_answer(_cut_bundle(), tokens=_cap()), _answer(_cut_bundle(), tokens=_cap()))

        await _verdict(llm)

        assert f"It must close within {_cap()} output tokens" in str(llm.calls[0][-1].content)

    @pytest.mark.asyncio
    async def test_a_cut_answer_is_told_it_was_cut_not_that_it_was_not_json(self) -> None:
        llm = _Llm(_answer(_cut_bundle(), tokens=_cap()), _answer(_cut_bundle(), tokens=_cap()))

        verdict = await _verdict(llm)

        assert verdict.fed_back == {VERDICT_CUT_CODE: 1}
        feedback = str(llm.calls[1][-1].content)
        assert f"output limit of {_cap()} tokens" in feedback
        assert "25,000 characters" in feedback

    @pytest.mark.asyncio
    async def test_the_retry_carries_the_question_and_not_the_cut_answer(self) -> None:
        """At temperature 0 a retry that carried the cut answer was answered with it again.

        The benign control's retry prompt was its first prompt plus the whole
        8,192-token cut answer plus the question, and the model wrote a
        response one byte shorter than the first. The retry is the first prompt
        and the question, which describes the answer instead of repeating it.
        """
        cut = _cut_bundle()
        llm = _Llm(_answer(cut, tokens=_cap()), _answer(cut, tokens=_cap()))

        await _verdict(llm)

        first, retry = llm.calls
        assert len(retry) == len(first) + 1
        assert [str(t.content) for t in retry[:-1]] == [str(t.content) for t in first]
        assert cut[:2_000] not in "\n".join(str(t.content) for t in retry)
        assert "It is not shown to you again." in str(retry[-1].content)

    def test_the_question_names_the_bound_and_where_the_room_went(self) -> None:
        message = verdict_cut_violation(_cap(), _cut_bundle()).message

        assert "shorter than those 25,000 characters" in message
        assert "Most of that room went on" in message
        assert "118 indicator object(s): write one only where the evidence" in message

    @pytest.mark.asyncio
    async def test_after_the_retry_the_stated_assessment_is_kept_and_the_fallback_recorded(
        self,
    ) -> None:
        llm = _Llm(_answer(_cut_bundle(), tokens=_cap()), _answer(_cut_bundle(), tokens=_cap()))

        verdict = await _verdict(llm)

        bundle = verdict.bundle
        assert verdict_reading(bundle) == "fallback"
        assert VERDICT_FALLBACK_CODE in {v.code for v in verdict.violations}
        assert decide_from_bundle(bundle) == "Malware"
        assert stated_confidence(bundle) == 0.85
        assert bundle.x_maljan_assessment is not None
        assert bundle.x_maljan_assessment.family is not None
        assert bundle.x_maljan_assessment.family.name == "Filisto"

    @pytest.mark.asyncio
    async def test_a_retry_that_fits_is_the_verdict(self) -> None:
        fits = json.dumps(
            {"type": "bundle", "id": "bundle--1", "x_maljan_assessment": ASSESSMENT, "objects": []}
        )
        llm = _Llm(_answer(_cut_bundle(), tokens=_cap()), _answer(fits, tokens=400))

        verdict = await _verdict(llm)

        assert verdict_reading(verdict.bundle) == "stated"
        assert stated_confidence(verdict.bundle) == 0.85

    @pytest.mark.asyncio
    async def test_an_answer_that_was_not_cut_keeps_the_not_json_question(self) -> None:
        llm = _Llm(_answer("I think this is malware.", tokens=12), _answer("Malware.", tokens=3))

        verdict = await _verdict(llm)

        assert verdict.fed_back == {"verdict.not_json": 1}
        assert verdict.bundle.x_maljan_assessment is None
        assert stated_confidence(verdict.bundle) is None


class TestTheReportPublishesTheStatedNumber:
    def test_a_fallback_whose_answer_stated_its_assessment_carries_its_number(self) -> None:
        from maljan.pipeline.nodes import _overall_confidence, the_judge_stated_the_verdict
        from maljan.schemas.judgement import JudgeAssessment

        assessment = JudgeAssessment.model_validate(ASSESSMENT)
        stated = {"decision": "Malware", "failure": VERDICT_FALLBACK_CODE, "stated": True}
        extracted = {"decision": "Malware", "failure": VERDICT_FALLBACK_CODE, "stated": False}

        assert the_judge_stated_the_verdict(None)
        assert _overall_confidence(assessment, judged=the_judge_stated_the_verdict(stated)) == 0.85
        assert (
            _overall_confidence(assessment, judged=the_judge_stated_the_verdict(extracted)) is None
        )
