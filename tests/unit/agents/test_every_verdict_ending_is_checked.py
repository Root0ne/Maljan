"""Whatever way the verdict round ends, the verdict is asked what it rests on.

Two questions, one per direction: a Benign verdict over a run in which no
analyst claimed anything is asked for the entry that establishes it, and a
Malware verdict over the same run is asked for the entries that establish it.
They were asked on the path where the judge answered a bundle and nowhere else,
so the two paths that manufacture a verdict out of text — the prose the model
answered twice, and the timeout that left no text at all — reached a report
unasked.

The endings a verdict round has are enumerated here and driven one at a time:
a bundle, a malformed answer the retry fixed, prose, JSON that is not a bundle,
and no answer at all. The judge's body raising is the sixth, and it never
reaches this agent — the node writes that verdict, and its own tests cover it.

Nothing here changes a verdict. A judge that says "this is malware" in prose
has said it, and it keeps it; what changes is that the run records what the
verdict was asked and could not answer.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.agents.judge_agent import (
    VERDICT_FALLBACK_CODE,
    VERDICT_TIMEOUT_CODE,
    JudgeAgent,
    JudgeVerdict,
)
from maljan.pipeline.outcome import decide_from_bundle
from maljan.pipeline.validation import UNSUPPORTED_BENIGN_CODE, UNSUPPORTED_MALWARE_CODE
from maljan.schemas.isr_models import AgentISR

# A run in which the tools recorded something and no analyst claimed anything,
# which is the only run these two checks have an opinion about.
LEDGER = ["ev_0001", "ev_0002"]
SILENT = {"static": AgentISR(agent_id="static", domain="static", claims=[])}
REPORTS = {"static": "Nothing was established about this sample."}


def _bundle_json(*, malware: bool) -> str:
    objects: list[dict[str, Any]] = []
    if malware:
        objects.append(
            {
                "type": "malware",
                "id": "malware--0f1e2d3c-4b5a-4968-8776-655443332211",
                "name": "sample",
                "is_family": False,
            }
        )
    return json.dumps(
        {
            "type": "bundle",
            "id": "bundle--0f1e2d3c-4b5a-4968-8776-655443332200",
            "objects": objects,
            "x_maljan_assessment": {
                "severity": {"rating": "High" if malware else "Informational", "rationale": "x"},
                "malware_category": "loader" if malware else None,
            },
        }
    )


class _Llm:
    def __init__(self, *answers: str) -> None:
        self._answers = list(answers)
        self.calls: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any]) -> Any:
        self.calls.append(list(messages))
        return MagicMock(content=self._answers.pop(0) if self._answers else "")


async def _verdict(*answers: str, time_out: bool = False, monkeypatch: Any = None) -> JudgeVerdict:
    judge = JudgeAgent(llm=_Llm(*answers))  # type: ignore[arg-type]
    if time_out:
        from maljan.agents import judge_agent as module

        async def _timeout(coro: Any, *args: Any, **kwargs: Any) -> Any:
            coro.close()
            raise TimeoutError("the judge did not answer")

        monkeypatch.setattr(module, "run_on_agent_loop", _timeout)
    return await judge.give_verdict(
        reports=REPORTS, history=[], isr_reports=SILENT, ledger_ids=LEDGER
    )


def _codes(verdict: JudgeVerdict) -> list[str]:
    return [v.code for v in verdict.violations]


class TestTheMalwareDirection:
    """A verdict of Malware over zero analyst claims, reached five ways."""

    @pytest.mark.asyncio
    async def test_a_bundle_the_judge_stood_by(self) -> None:
        answer = _bundle_json(malware=True)
        verdict = await _verdict(answer, answer)

        assert decide_from_bundle(verdict.bundle) == "Malware"
        assert UNSUPPORTED_MALWARE_CODE in _codes(verdict)
        assert _codes(verdict).count(UNSUPPORTED_MALWARE_CODE) == 1, "asked once, recorded once"

    @pytest.mark.asyncio
    async def test_a_malformed_answer_the_retry_fixed(self) -> None:
        verdict = await _verdict("{not json at all", _bundle_json(malware=True))

        assert decide_from_bundle(verdict.bundle) == "Malware"
        assert UNSUPPORTED_MALWARE_CODE in _codes(verdict)

    @pytest.mark.asyncio
    async def test_prose_the_model_answered_twice(self) -> None:
        verdict = await _verdict("This is malware.", "It is malware, a loader.")

        # The model said it, so the model keeps it.
        assert decide_from_bundle(verdict.bundle) == "Malware"
        assert VERDICT_FALLBACK_CODE in _codes(verdict)
        assert UNSUPPORTED_MALWARE_CODE in _codes(verdict)

    @pytest.mark.asyncio
    async def test_json_that_is_not_a_bundle(self) -> None:
        answer = json.dumps({"objects": {"malware": "yes, this is malware"}})
        verdict = await _verdict(answer, answer)

        assert verdict.bundle.x_maljan_fallback_verdict is not None
        assert VERDICT_FALLBACK_CODE in _codes(verdict)
        assert UNSUPPORTED_MALWARE_CODE in _codes(verdict)

    @pytest.mark.asyncio
    async def test_no_answer_at_all(self, monkeypatch: pytest.MonkeyPatch) -> None:
        verdict = await _verdict(time_out=True, monkeypatch=monkeypatch)

        # The pipeline's own verdict, which is not Malware and is not Benign.
        assert decide_from_bundle(verdict.bundle) == "Suspicious"
        assert VERDICT_TIMEOUT_CODE in _codes(verdict)
        assert UNSUPPORTED_MALWARE_CODE not in _codes(verdict)
        assert UNSUPPORTED_BENIGN_CODE not in _codes(verdict)


class TestTheBenignDirection:
    """The mirror: a clean verdict over a run that examined nothing."""

    @pytest.mark.asyncio
    async def test_a_bundle_the_judge_stood_by(self) -> None:
        answer = _bundle_json(malware=False)
        verdict = await _verdict(answer, answer)

        assert decide_from_bundle(verdict.bundle) == "Benign"
        assert UNSUPPORTED_BENIGN_CODE in _codes(verdict)

    @pytest.mark.asyncio
    async def test_prose_the_model_answered_twice(self) -> None:
        verdict = await _verdict("The sample is benign.", "Still benign; nothing to report.")

        assert decide_from_bundle(verdict.bundle) == "Benign"
        assert VERDICT_FALLBACK_CODE in _codes(verdict)
        assert UNSUPPORTED_BENIGN_CODE in _codes(verdict)

    @pytest.mark.asyncio
    async def test_json_that_is_not_a_bundle(self) -> None:
        answer = json.dumps({"objects": {"verdict": "benign, nothing found"}})
        verdict = await _verdict(answer, answer)

        assert VERDICT_FALLBACK_CODE in _codes(verdict)
        assert UNSUPPORTED_BENIGN_CODE in _codes(verdict)


class TestWhatTheConversationIsTold:
    """A finding nobody was shown is still a finding a reader should see."""

    @pytest.mark.asyncio
    async def test_the_endings_publish_what_they_recorded(self) -> None:
        published: list[tuple[str, dict[str, Any]]] = []
        judge = JudgeAgent(llm=_Llm("This is malware.", "It is malware."))  # type: ignore[arg-type]
        container = SimpleNamespace(event_sink=lambda kind, data: published.append((kind, data)))
        judge._container = container

        await judge.give_verdict(reports=REPORTS, history=[], isr_reports=SILENT, ledger_ids=LEDGER)

        rows = [data for kind, data in published if kind == "validation_feedback"]
        assert [row["state"] for row in rows if row["code"] == UNSUPPORTED_MALWARE_CODE] == [
            "survived"
        ]
        assert any(row["code"] == VERDICT_FALLBACK_CODE for row in rows)


class TestTheFeedAndTheSummaryAgree:
    """Every state the conversation published is a row the summary records."""

    @pytest.mark.asyncio
    async def test_no_state_is_published_for_a_code_the_summary_drops(self) -> None:
        published: list[tuple[str, dict[str, Any]]] = []
        judge = JudgeAgent(llm=_Llm("not a bundle", "still not a bundle"))  # type: ignore[arg-type]
        judge._container = SimpleNamespace(
            event_sink=lambda kind, data: published.append((kind, data))
        )

        verdict = await judge.give_verdict(
            reports=REPORTS, history=[], isr_reports=SILENT, ledger_ids=LEDGER
        )

        feed = {
            data["code"]
            for kind, data in published
            if kind == "validation_feedback" and data["state"] != "retried"
        }
        assert feed <= set(_codes(verdict)), "a state was published for a code nothing records"
        assert "verdict.not_json" in feed


class TestARunWithClaimsBehindItIsAskedNothing:
    """The checks have an opinion only about a run in which nothing was said."""

    @pytest.mark.asyncio
    async def test_prose_over_a_run_with_claims(self) -> None:
        from maljan.schemas.isr_models import ClaimEvidence

        judge = JudgeAgent(llm=_Llm("This is malware.", "It is malware."))  # type: ignore[arg-type]
        verdict = await judge.give_verdict(
            reports=REPORTS,
            history=[],
            isr_reports={
                "static": AgentISR(
                    agent_id="static",
                    domain="static",
                    claims=[
                        ClaimEvidence(
                            claim="it injects into another process",
                            evidence_ref="[ev_0001] capa",
                            confidence=0.8,
                            technique_id="T1055",
                        )
                    ],
                )
            },
            ledger_ids=LEDGER,
        )

        assert _codes(verdict) == ["verdict.not_json", VERDICT_FALLBACK_CODE]
