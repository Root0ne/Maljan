"""The judge node's own arguments, driven with a run whose sandbox report is empty.

The grounding check once read ``evidence_corpus is not None``, and the node
handed it ``evidence_corpus or None``: a run with no sandbox network block (mock
mode, a static-only team, a sample that made no call) reached the check with
nothing, the check was skipped outright, and an invented indicator was exported
with no finding row. Tests of ``give_verdict`` with a hand-passed corpus could
not see that, because the node builds those arguments. This one drives
``make_judge_node`` itself.
"""

from __future__ import annotations

import asyncio
from typing import Any

from maljan.agents.judge_agent import JudgeAgent
from maljan.pipeline.nodes import make_judge_node
from maljan.schemas.evidence import EvidenceCounter
from tests.unit.agents.test_judge_verdict_validation import _bundle_json, _Llm
from tests.unit.pipeline.test_a_fallback_verdict_assesses_nothing import _Container, _state


def _drive(sandbox_report: Any) -> tuple[dict[str, Any], list[dict[str, Any]], list[Any]]:
    """Run the node with a judge that keeps an invented indicator through its retry."""
    invented = _bundle_json(indicators=["invented.example"])
    llm = _Llm(invented, invented)
    judge = JudgeAgent(llm=llm)  # type: ignore[arg-type]
    container = _Container(EvidenceCounter())
    container._judge_agent_cache["judge"] = judge
    asked: list[dict[str, Any]] = []
    verdicts: list[Any] = []
    give_verdict = judge.give_verdict

    async def _watched(**kwargs: Any) -> Any:
        asked.append(kwargs)
        verdict = await give_verdict(**kwargs)
        verdicts.append(verdict)
        return verdict

    judge.give_verdict = _watched  # type: ignore[method-assign]
    state = _state()
    state["sandbox_report"] = sandbox_report
    update = asyncio.run(make_judge_node(container)(state))
    return update, asked, verdicts


def test_an_indicator_no_tool_saw_is_asked_about_when_the_sandbox_report_is_empty() -> None:
    _update, asked, verdicts = _drive({})

    (kwargs,) = asked
    assert not kwargs["evidence_corpus"], "the node had no corpus to hand over"
    (verdict,) = verdicts
    assert [v.code for v in verdict.violations] == ["stix.ungrounded_indicator"]
    assert "invented.example" in verdict.violations[0].message


def test_with_nothing_searched_the_row_is_advisory_and_the_object_stays() -> None:
    _update, _asked, verdicts = _drive({"signatures": []})

    (verdict,) = verdicts
    patterns = [str(getattr(o, "pattern", "")) for o in verdict.bundle.objects]
    assert any("invented.example" in p for p in patterns)
    assert "no evidence was searched" in verdict.violations[0].message
