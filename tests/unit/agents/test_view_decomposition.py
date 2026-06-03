"""Unit tests for the view-decomposition mechanism (findings-log §3.6).

No live LLM: a tiny BaseAnalyst subclass with a stubbed ``_invoke_view`` exercises
the view-spec generation, equal-budget split, merge wiring, and fault isolation.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.agents.base_agent import BaseAnalyst, _view_specs
from maljan.core.exceptions import AnalystError


class _StubAnalyst(BaseAnalyst):
    """Minimal concrete analyst. ``_invoke_view`` is stubbed per-test."""

    def analyze(self, data: str) -> str:
        return "CLAIM: monolithic path used.\nTECHNIQUE: T1055\n---"

    def revise(self, original_data, own_report, peer_reports, mediator_feedback) -> str:
        return "revised"


def _agent(name: str = "static_analyst") -> _StubAnalyst:
    return _StubAnalyst(llm=MagicMock(), name=name)


class TestViewSpecs:
    def test_two_views_static(self) -> None:
        specs = _view_specs("static", 2)
        assert [k for k, _ in specs] == ["code", "artifacts"]

    def test_four_views_dynamic(self) -> None:
        specs = _view_specs("dynamic", 4)
        assert [k for k, _ in specs] == ["behaviour", "artifacts", "persistence", "network"]

    def test_pads_beyond_table(self) -> None:
        specs = _view_specs("network", 6)
        assert len(specs) == 6
        # First four are the curated network facets; the rest are generic.
        assert specs[0][0] == "dns"
        assert specs[5][0].startswith("facet")

    def test_unknown_domain_falls_back_to_static(self) -> None:
        specs = _view_specs("mystery", 2)
        assert [k for k, _ in specs] == ["code", "artifacts"]


class TestAnalyzeIsrViews:
    def test_runs_one_call_per_view_and_merges(self) -> None:
        agent = _agent()
        calls: list[tuple[str, int | None]] = []

        def _stub(instruction: str, data: str, max_tokens: int | None) -> str:
            calls.append((instruction, max_tokens))
            # Distinct technique per view so the merge keeps both (the two static
            # facets are "code" and "artifacts").
            tid = "T1071" if "artifacts" in instruction else "T1055"
            return f"CLAIM: focused finding about the sample under test.\nTECHNIQUE: {tid}\n---"

        agent._invoke_view = _stub  # type: ignore[method-assign]
        isr = agent.analyze_isr_views("evidence text", 2)
        assert len(calls) == 2
        tids = {c.technique_id for c in isr.claims}
        assert tids == {"T1055", "T1071"}

    def test_equal_budget_split(self) -> None:
        agent = _agent()
        budgets: list[int | None] = []

        def _stub(instruction: str, data: str, max_tokens: int | None) -> str:
            budgets.append(max_tokens)
            return "CLAIM: a sufficiently long finding sentence here.\nTECHNIQUE: T1055\n---"

        agent._invoke_view = _stub  # type: ignore[method-assign]
        agent.analyze_isr_views("evidence", 4, total_max_tokens=1000)
        # 1000 // 4 == 250 per view.
        assert budgets == [250, 250, 250, 250]

    def test_fault_isolation_drops_failed_view(self) -> None:
        agent = _agent()

        def _stub(instruction: str, data: str, max_tokens: int | None) -> str:
            if "artifacts" in instruction:
                raise RuntimeError("view derailed")
            return "CLAIM: surviving finding about behaviour.\nTECHNIQUE: T1055\n---"

        agent._invoke_view = _stub  # type: ignore[method-assign]
        isr = agent.analyze_isr_views("evidence", 2)
        # One view failed; the other survived and was merged.
        assert any(c.technique_id == "T1055" for c in isr.claims)

    def test_all_views_failing_raises(self) -> None:
        agent = _agent()

        def _stub(instruction: str, data: str, max_tokens: int | None) -> str:
            raise RuntimeError("boom")

        agent._invoke_view = _stub  # type: ignore[method-assign]
        # safe_ wrapper translates to AnalystError; the raw method raises it too.
        with pytest.raises(AnalystError):
            agent.analyze_isr_views("evidence", 2)

    def test_n_below_two_uses_monolithic(self) -> None:
        agent = _agent()
        called = {"invoke_view": 0}

        def _stub(*a: Any, **k: Any) -> str:
            called["invoke_view"] += 1
            return ""

        agent._invoke_view = _stub  # type: ignore[method-assign]
        isr = agent.analyze_isr_views("evidence", 1)
        # Falls through to analyze_isr (the monolithic path); no view calls.
        assert called["invoke_view"] == 0
        assert any(c.technique_id == "T1055" for c in isr.claims)
