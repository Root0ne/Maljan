"""A failed verdict retry keeps the judge's first bundle; the text fallback reads statements only.

JA-1: the async ``retry_with_feedback`` had no ``keep`` rule, unlike the
analysts' synchronous loop, so when the judge's one retry answered prose, timed
out or answered JSON that was not a bundle, a valid first bundle was replaced
by the text fallback or by a ``verdict.timeout`` the first call never earned:
a Malware/High/loader bundle was published as Benign. The first bundle is now
kept, with what is still wrong with it, and the retry's failure is its own
``verdict.retry_failed`` row. The retry's wait is sized from its own prompt.

JA-2: ``_verdict_from_text`` read "isn't malware", "no evidence of malware" and
"anti-malware" as Malware and looked for Malware first. Only an explicit
verdict statement is read now; anything else is the inconclusive verdict.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import AIMessage

from maljan.agents import judge_agent as module
from maljan.agents.judge_agent import (
    VERDICT_FALLBACK_CODE,
    VERDICT_RETRY_FAILED_CODE,
    VERDICT_TIMEOUT_CODE,
    JudgeAgent,
    JudgeVerdict,
)
from maljan.pipeline.outcome import INCONCLUSIVE_VERDICT, decide_from_bundle
from maljan.pipeline.validation import Violation, retry_with_feedback

# The audit probe's first answer: a whole bundle whose one indicator no
# evidence grounds, so the judge is asked once about it.
FIRST = {
    "type": "bundle",
    "id": "bundle--1",
    "x_maljan_assessment": {
        "verdict": "Malware",
        "confidence": 0.9,
        "severity": {"rating": "High", "rationale": "injects"},
        "malware_category": "loader",
    },
    "objects": [
        {
            "type": "malware",
            "id": "malware--1",
            "name": "x",
            "is_family": False,
            "malware_types": ["dropper"],
        },
        {
            "type": "indicator",
            "id": "indicator--1",
            "pattern": "[domain-name:value='evil.example']",
            "pattern_type": "stix",
            "indicator_types": ["malicious-activity"],
        },
        {
            "type": "relationship",
            "id": "relationship--1",
            "relationship_type": "indicates",
            "source_ref": "indicator--1",
            "target_ref": "malware--1",
        },
    ],
}
PROSE_RETRY = (
    "I apologise; I cannot verify that domain, so I leave it out. "
    "There is no evidence of benign behaviour."
)


class _Llm:
    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any], **_: Any) -> Any:
        self.calls.append(list(messages))
        return AIMessage(content=self._answers.pop(0) if self._answers else "")


async def _verdict(judge: JudgeAgent) -> JudgeVerdict:
    return await judge.give_verdict(
        {"static": "loader injecting"}, [], evidence_corpus={"nothing"}, ledger_ids=["ev_0001"]
    )


def _codes(verdict: JudgeVerdict) -> list[str]:
    return [v.code for v in verdict.violations]


def _assert_first_kept(verdict: JudgeVerdict) -> None:
    assessment = verdict.bundle.x_maljan_assessment
    assert assessment is not None
    assert assessment.verdict == "Malware"
    assert assessment.severity is not None and assessment.severity.rating == "High"
    assert assessment.malware_category == "loader"
    assert verdict.bundle.x_maljan_fallback_verdict is None
    assert decide_from_bundle(verdict.bundle) == "Malware"
    assert _codes(verdict).count(VERDICT_RETRY_FAILED_CODE) == 1
    assert VERDICT_FALLBACK_CODE not in _codes(verdict)
    assert VERDICT_TIMEOUT_CODE not in _codes(verdict)
    # The first bundle's own finding is still recorded, and its ungrounded
    # indicator is dropped as one that survived a retry.
    assert "stix.ungrounded_indicator" in _codes(verdict)
    assert not [o for o in verdict.bundle.objects if o.type == "indicator"]


class TestAFailedRetryKeepsTheFirstBundle:
    @pytest.mark.asyncio
    async def test_a_prose_retry_the_audit_probe(self) -> None:
        llm = _Llm(json.dumps(FIRST), PROSE_RETRY)
        verdict = await _verdict(JudgeAgent(llm))  # type: ignore[arg-type]

        assert len(llm.calls) == 2
        assert verdict.retries == 1
        _assert_first_kept(verdict)
        assert "verdict.retry_failed" in _codes(verdict)
        row = next(v for v in verdict.violations if v.code == VERDICT_RETRY_FAILED_CODE)
        assert "not a JSON bundle" in row.message

    @pytest.mark.asyncio
    async def test_a_retry_that_timed_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sent = 0

        async def _second_times_out(coro: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal sent
            sent += 1
            if sent > 1:
                coro.close()
                raise TimeoutError("the retry did not answer")
            return await coro

        monkeypatch.setattr(module, "run_on_agent_loop", _second_times_out)
        verdict = await _verdict(JudgeAgent(_Llm(json.dumps(FIRST), "")))  # type: ignore[arg-type]

        _assert_first_kept(verdict)
        row = next(v for v in verdict.violations if v.code == VERDICT_RETRY_FAILED_CODE)
        assert "budget" in row.message

    @pytest.mark.asyncio
    async def test_a_retry_that_is_json_but_not_a_bundle(self) -> None:
        not_a_bundle = json.dumps({"objects": {"verdict": "benign, nothing found"}})
        verdict = await _verdict(JudgeAgent(_Llm(json.dumps(FIRST), not_a_bundle)))  # type: ignore[arg-type]

        _assert_first_kept(verdict)

    @pytest.mark.asyncio
    async def test_the_row_is_published_to_the_conversation(self) -> None:
        published: list[tuple[str, dict[str, Any]]] = []
        judge = JudgeAgent(_Llm(json.dumps(FIRST), PROSE_RETRY))  # type: ignore[arg-type]
        judge._container = MagicMock(event_sink=lambda kind, data: published.append((kind, data)))
        await _verdict(judge)

        rows = [d for k, d in published if k == "validation_feedback"]
        assert [r["state"] for r in rows if r["code"] == VERDICT_RETRY_FAILED_CODE] == ["survived"]


class TestARetryThatStatedItsAssessmentIsKept:
    """Its correction is read however it ended: cut, or as JSON that was not a bundle."""

    @staticmethod
    def _corrected() -> dict[str, Any]:
        fixed = json.loads(json.dumps(FIRST))
        fixed["x_maljan_assessment"]["verdict"] = "Suspicious"
        fixed["x_maljan_assessment"]["malware_category"] = None
        fixed["objects"] = [o for o in fixed["objects"] if o["type"] == "malware"]
        return fixed

    @pytest.mark.asyncio
    async def test_a_cut_retry_that_stated_its_assessment(self) -> None:
        cut = json.dumps(self._corrected())[:200]
        verdict = await _verdict(JudgeAgent(_Llm(json.dumps(FIRST), cut)))  # type: ignore[arg-type]

        assert decide_from_bundle(verdict.bundle) == "Suspicious"
        assessment = verdict.bundle.x_maljan_assessment
        assert assessment is not None and assessment.verdict == "Suspicious"
        assert VERDICT_RETRY_FAILED_CODE not in _codes(verdict)
        assert "verdict.unsupported_malware" not in _codes(verdict)

    @pytest.mark.asyncio
    async def test_a_retry_with_an_object_the_bundle_cannot_hold(self) -> None:
        bad = self._corrected()
        bad["objects"].append(
            {"type": "relationship", "id": "relationship--9", "relationship_type": "uses"}
        )
        verdict = await _verdict(JudgeAgent(_Llm(json.dumps(FIRST), json.dumps(bad))))  # type: ignore[arg-type]

        assert decide_from_bundle(verdict.bundle) == "Suspicious"
        assert VERDICT_RETRY_FAILED_CODE not in _codes(verdict)


class TestAGoodRetryOrABadFirstAnswerIsUnchanged:
    @pytest.mark.asyncio
    async def test_a_retry_that_answered_a_bundle_is_kept(self) -> None:
        fixed = json.loads(json.dumps(FIRST))
        fixed["objects"] = [fixed["objects"][0]]
        fixed["x_maljan_assessment"]["malware_category"] = "dropper"
        verdict = await _verdict(JudgeAgent(_Llm(json.dumps(FIRST), json.dumps(fixed))))  # type: ignore[arg-type]

        assert verdict.bundle.x_maljan_assessment is not None
        assert verdict.bundle.x_maljan_assessment.malware_category == "dropper"
        assert VERDICT_RETRY_FAILED_CODE not in _codes(verdict)

    @pytest.mark.asyncio
    async def test_prose_twice_still_falls_back(self) -> None:
        verdict = await _verdict(JudgeAgent(_Llm("Verdict: Malware.", "Verdict: Malware.")))  # type: ignore[arg-type]

        assert verdict.bundle.x_maljan_fallback_verdict is not None
        assert VERDICT_FALLBACK_CODE in _codes(verdict)
        assert VERDICT_RETRY_FAILED_CODE not in _codes(verdict)


class TestTheRetryIsSizedFromItsOwnPrompt:
    @pytest.mark.asyncio
    async def test_the_retry_s_wait_comes_from_the_retry_prompt(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        judge = JudgeAgent(_Llm(json.dumps(FIRST), PROSE_RETRY))  # type: ignore[arg-type]
        sized: list[tuple[int, str]] = []

        def _timeout(configured: Any, prompt_chars: int = 0, call: str = "judge:verdict") -> float:
            sized.append((prompt_chars, call))
            return float(prompt_chars)

        waits: list[float] = []

        async def _loop(coro: Any, timeout: float, **_: Any) -> Any:
            waits.append(timeout)
            return await coro

        monkeypatch.setattr(judge, "_verdict_timeout", _timeout)
        monkeypatch.setattr(module, "run_on_agent_loop", _loop)
        await _verdict(judge)

        assert [call for _, call in sized] == ["judge:verdict", "judge:verdict_retry"]
        assert sized[1][0] > sized[0][0]
        assert waits == [float(sized[0][0]), float(sized[1][0])]


class TestTheAsyncLoopHasTheSyncLoopsKeep:
    @pytest.mark.asyncio
    async def test_the_kept_answer_is_validated_again(self) -> None:
        answers = iter(["first", "second"])

        async def _run(_: list[Any]) -> str:
            return next(answers)

        def _check(answer: str) -> list[Violation]:
            return [Violation(code=f"x.{answer}", message=answer)]

        parsed, left, retries = await retry_with_feedback(
            _run, [], [_check], parse=str, keep=lambda first, last: first
        )

        assert (parsed, [v.code for v in left], retries) == ("first", ["x.first"], 1)

    @pytest.mark.asyncio
    async def test_without_keep_the_last_answer_stands(self) -> None:
        answers = iter(["first", "second"])

        async def _run(_: list[Any]) -> str:
            return next(answers)

        parsed, left, _ = await retry_with_feedback(
            _run, [], [lambda a: [Violation(code=f"x.{a}", message=a)]], parse=str
        )

        assert (parsed, [v.code for v in left]) == ("second", ["x.second"])


class TestOnlyAnExplicitVerdictStatementIsRead:
    @pytest.mark.parametrize(
        "text",
        [
            # The audit probe's three negated sentences.
            "This sample isn't malware; it is a signed installer.",
            "Benign. There is no evidence of malware in any layer.",
            "The file is benign: a legitimate anti-malware updater.",
            "This is malware.",
            "The verdict is not malware.",
            "Verdict: malware-free.",
            "No verdict could be reached.",
            "",
        ],
    )
    def test_anything_but_a_statement_is_inconclusive(self, text: str) -> None:
        assert JudgeAgent._verdict_from_text(text) == INCONCLUSIVE_VERDICT

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("Verdict: Benign. It is not a malware sample.", "Benign"),
            ("**Verdict**: Malware (loader)", "Malware"),
            ("Final verdict - benign", "Benign"),
            ("The verdict is Malware.", "Malware"),
            ('{"verdict": "Suspicious"}', "Suspicious"),
            ("**Verdict:** Malware", "Malware"),
            ("Verdict:\nMalware", "Malware"),
            ("Verdict: Malware.\nVerdict: malware, a loader.", "Malware"),
            ("Previous verdict was Benign; my verdict is Malware", "Malware"),
        ],
    )
    def test_a_statement_is_read(self, text: str, expected: str) -> None:
        assert JudgeAgent._verdict_from_text(text) == expected

    @pytest.mark.parametrize(
        "text",
        [
            'Verdict: Malware\nThe dropped note reads: "Verdict: Benign"',
            "Verdict: Malware. The sample's README says verdict: benign, which is a lure.",
            "Verdict: Malware.\nOn reflection...\nVerdict: Benign.",
            "The analysts' verdict - benign - is wrong.",
            "Final Verdict: **Likely Malware**",
        ],
    )
    def test_statements_that_disagree_or_do_not_end_are_inconclusive(self, text: str) -> None:
        assert JudgeAgent._verdict_from_text(text) == INCONCLUSIVE_VERDICT
