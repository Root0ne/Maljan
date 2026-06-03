"""Unit tests for the view-decomposition mechanism (findings-log §3.6).

No live LLM: a tiny BaseAnalyst subclass with a stubbed ``_invoke_view`` exercises
the view-spec generation, equal-budget split, merge wiring, and fault isolation.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.agents.base_agent import BaseAnalyst, _tier_specs, _view_specs
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


# ---------------------------------------------------------------------------
# Tier-wise (vertical) reasoning — findings-log §4 Item 3 (LAMD)
# ---------------------------------------------------------------------------


class TestTierSpecs:
    def test_three_tiers_is_the_facts_behaviour_semantics_ladder(self) -> None:
        specs = _tier_specs(3)
        assert [k for k, _ in specs] == ["facts", "behaviour", "semantics"]

    def test_two_tiers_drops_the_semantics_tier(self) -> None:
        specs = _tier_specs(2)
        assert [k for k, _ in specs] == ["facts", "behaviour"]

    def test_pads_beyond_the_ladder(self) -> None:
        specs = _tier_specs(5)
        assert len(specs) == 5
        assert specs[0][0] == "facts"
        assert specs[4][0].startswith("tier")


def _tier_stub_factory(calls: list[dict[str, Any]]):
    """A stub _invoke_view that emits a distinct, tier-keyed finding so the
    sequential context-passing and the merge can be asserted."""

    def _stub(instruction: str, data: str, max_tokens: int | None) -> str:
        calls.append({"instruction": instruction, "data": data, "budget": max_tokens})
        if "tier 1" in instruction:
            return "CLAIM: foundational artifact VirtualAllocEx observed.\nTECHNIQUE: T1055\n---"
        if "tier 2" in instruction:
            return "CLAIM: behaviour process injection synthesized.\nTECHNIQUE: T1055\n---"
        return "CLAIM: semantics maps to credential access.\nTECHNIQUE: T1056\n---"

    return _stub


class TestAnalyzeIsrTiered:
    def test_runs_one_call_per_tier_sequentially(self) -> None:
        agent = _agent()
        calls: list[dict[str, Any]] = []
        agent._invoke_view = _tier_stub_factory(calls)  # type: ignore[method-assign]
        agent.analyze_isr_tiered("evidence text", 3)
        assert len(calls) == 3

    def test_each_tier_receives_the_previous_tier_output(self) -> None:
        agent = _agent()
        calls: list[dict[str, Any]] = []
        agent._invoke_view = _tier_stub_factory(calls)  # type: ignore[method-assign]
        agent.analyze_isr_tiered("evidence text", 3)
        # Tier 1 sees only the raw evidence.
        assert calls[0]["data"] == "evidence text"
        # Tier 2 sees tier 1's finding; tier 3 sees tier 2's finding.
        assert "foundational artifact VirtualAllocEx" in calls[1]["data"]
        assert "behaviour process injection" in calls[2]["data"]
        # The original evidence is still carried into every tier.
        assert "evidence text" in calls[2]["data"]

    def test_merge_dedups_repeated_techniques_keeps_distinct(self) -> None:
        agent = _agent()
        calls: list[dict[str, Any]] = []
        agent._invoke_view = _tier_stub_factory(calls)  # type: ignore[method-assign]
        isr = agent.analyze_isr_tiered("evidence text", 3)
        # T1055 repeated across tiers 1+2 dedups; T1056 from tier 3 survives.
        tids = {c.technique_id for c in isr.claims}
        assert tids == {"T1055", "T1056"}

    def test_equal_budget_split(self) -> None:
        agent = _agent()
        calls: list[dict[str, Any]] = []
        agent._invoke_view = _tier_stub_factory(calls)  # type: ignore[method-assign]
        agent.analyze_isr_tiered("evidence", 3, total_max_tokens=999)
        assert [c["budget"] for c in calls] == [333, 333, 333]

    def test_fault_isolation_skips_failed_tier_and_chains_last_good(self) -> None:
        agent = _agent()
        calls: list[dict[str, Any]] = []

        def _stub(instruction: str, data: str, max_tokens: int | None) -> str:
            calls.append({"instruction": instruction, "data": data})
            if "tier 2" in instruction:
                raise RuntimeError("tier derailed")
            if "tier 1" in instruction:
                return "CLAIM: foundational CreateRemoteThread seen.\nTECHNIQUE: T1055\n---"
            return "CLAIM: semantics conclusion drawn here.\nTECHNIQUE: T1056\n---"

        agent._invoke_view = _stub  # type: ignore[method-assign]
        isr = agent.analyze_isr_tiered("evidence text", 3)
        # Tier 3 still ran; since tier 2 failed it chains tier 1's output.
        assert "foundational CreateRemoteThread" in calls[2]["data"]
        tids = {c.technique_id for c in isr.claims}
        assert tids == {"T1055", "T1056"}

    def test_all_tiers_failing_raises(self) -> None:
        agent = _agent()

        def _stub(instruction: str, data: str, max_tokens: int | None) -> str:
            raise RuntimeError("boom")

        agent._invoke_view = _stub  # type: ignore[method-assign]
        with pytest.raises(AnalystError):
            agent.analyze_isr_tiered("evidence", 3)

    def test_n_below_two_uses_monolithic(self) -> None:
        agent = _agent()
        called = {"invoke_view": 0}

        def _stub(*a: Any, **k: Any) -> str:
            called["invoke_view"] += 1
            return ""

        agent._invoke_view = _stub  # type: ignore[method-assign]
        isr = agent.analyze_isr_tiered("evidence", 1)
        # Falls through to analyze_isr (monolithic); no tier calls.
        assert called["invoke_view"] == 0
        assert any(c.technique_id == "T1055" for c in isr.claims)
