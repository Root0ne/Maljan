"""Unit tests for the RunSummary observability layer.

Tests:
  - RunSummaryBuilder — all setter methods, graceful fallbacks
  - NegotiationMetrics — termination reason inference, converged_early
  - ISRAgentStats — claim extraction, technique deduplication
  - ValidationMetrics / CascadeMetrics — data extraction
  - RunSummary.to_markdown() — section presence
  - RunSummary.to_dict() — JSON serializability
  - _rolling_std helper
"""

from __future__ import annotations

import json
import time

import pytest

from maljan.analysis.run_summary import (
    NegotiationMetrics,
    RunSummary,
    RunSummaryBuilder,
    _rolling_std,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_isr(
    agent_id: str,
    domain: str,
    claims: list[ClaimEvidence],
    revision_round: int = 1,
    dissent_items: list[str] | None = None,
) -> AgentISR:
    return AgentISR(
        agent_id=agent_id,
        domain=domain,  # type: ignore[arg-type]
        claims=claims,
        dissent_items=dissent_items or [],
        revision_round=revision_round,
    )


def _claim(technique_id: str | None, confidence: float) -> ClaimEvidence:
    return ClaimEvidence(
        claim=f"claim for {technique_id}",
        evidence_ref="ref",
        confidence=confidence,
        technique_id=technique_id,
    )


def _make_state(
    rounds: int = 2,
    is_consensus: bool = True,
    confidence_history: list[float] | None = None,
    sycophancy_detected: bool = False,
    max_iterations: int = 5,
) -> dict:
    return {
        "file_hash": "abc123",
        "file_name": "evil.exe",
        "iteration_count": rounds,
        "is_consensus": is_consensus,
        "confidence_history": confidence_history or [0.7, 0.85, 0.91],
        "sycophancy_detected": sycophancy_detected,
        "discussion_history": [],
        "_max_iterations": max_iterations,
    }


def _make_builder(start_time: float | None = None) -> RunSummaryBuilder:
    return RunSummaryBuilder(start_time=start_time or time.time() - 1.0)


# ---------------------------------------------------------------------------
# _rolling_std
# ---------------------------------------------------------------------------


class TestRollingStd:
    def test_single_value_returns_inf(self) -> None:
        assert _rolling_std([0.5]) == float("inf")

    def test_identical_values_returns_zero(self) -> None:
        assert _rolling_std([0.8, 0.8, 0.8]) == pytest.approx(0.0)

    def test_known_std(self) -> None:
        # values: 0, 2, 4 → mean=2, variance=8/3, std=sqrt(8/3)≈1.633
        result = _rolling_std([0.0, 2.0, 4.0])
        assert result == pytest.approx((8 / 3) ** 0.5, abs=1e-6)

    def test_empty_returns_inf(self) -> None:
        assert _rolling_std([]) == float("inf")


# ---------------------------------------------------------------------------
# NegotiationMetrics
# ---------------------------------------------------------------------------


class TestNegotiationMetrics:
    def _make(self, termination_reason: str) -> NegotiationMetrics:
        return NegotiationMetrics(
            rounds_completed=2,
            max_rounds=5,
            termination_reason=termination_reason,
            sycophancy_events=0,
            confidence_history=[0.7, 0.85],
            final_confidence=0.85,
        )

    def test_converged_early_true_for_consensus(self) -> None:
        assert self._make("consensus").converged_early is True

    def test_converged_early_true_for_convergence(self) -> None:
        assert self._make("convergence").converged_early is True

    def test_converged_early_false_for_hard_limit(self) -> None:
        assert self._make("hard_limit").converged_early is False


# ---------------------------------------------------------------------------
# RunSummaryBuilder — set_negotiation
# ---------------------------------------------------------------------------


class TestBuilderSetNegotiation:
    def test_consensus_termination_reason(self) -> None:
        builder = _make_builder()
        builder.set_negotiation(_make_state(is_consensus=True))
        summary = builder.build()
        assert summary.negotiation.termination_reason == "consensus"

    def test_hard_limit_when_not_consensus(self) -> None:
        builder = _make_builder()
        builder.set_negotiation(
            _make_state(
                is_consensus=False,
                confidence_history=[0.6, 0.8],  # only 2 rounds, no std check
            )
        )
        summary = builder.build()
        assert summary.negotiation.termination_reason == "hard_limit"

    def test_convergence_when_stable_confidence(self) -> None:
        builder = _make_builder()
        # std of [0.85, 0.85, 0.85] = 0.0 < 0.02
        builder.set_negotiation(
            _make_state(
                is_consensus=False,
                confidence_history=[0.85, 0.85, 0.85],
            )
        )
        summary = builder.build()
        assert summary.negotiation.termination_reason == "convergence"

    def test_confidence_history_preserved(self) -> None:
        builder = _make_builder()
        history = [0.7, 0.85, 0.91]
        builder.set_negotiation(_make_state(confidence_history=history))
        assert builder.build().negotiation.confidence_history == history

    def test_final_confidence_is_last_value(self) -> None:
        builder = _make_builder()
        builder.set_negotiation(_make_state(confidence_history=[0.7, 0.85, 0.92]))
        assert builder.build().negotiation.final_confidence == pytest.approx(0.92)


# ---------------------------------------------------------------------------
# RunSummaryBuilder — set_isr_stats
# ---------------------------------------------------------------------------


class TestBuilderSetISRStats:
    def test_empty_isr_reports(self) -> None:
        builder = _make_builder()
        builder.set_isr_stats({})
        summary = builder.build()
        assert summary.agent_stats == []

    def test_agent_stats_extracted(self) -> None:
        isr = _make_isr(
            "static",
            "static",
            [_claim("T1055", 0.8), _claim("T1547", 0.7)],
        )
        builder = _make_builder()
        builder.set_isr_stats({"static": isr})
        summary = builder.build()
        assert len(summary.agent_stats) == 1
        s = summary.agent_stats[0]
        assert s.agent_id == "static"
        assert s.claim_count == 2
        assert s.mean_confidence == pytest.approx(0.75)

    def test_technique_ids_deduplicated(self) -> None:
        isr = _make_isr(
            "dynamic",
            "dynamic",
            [_claim("T1055", 0.9), _claim("T1055", 0.8)],  # duplicate T1055
        )
        builder = _make_builder()
        builder.set_isr_stats({"dynamic": isr})
        s = builder.build().agent_stats[0]
        assert s.technique_ids == ["T1055"]  # deduplicated

    def test_has_dissent_true(self) -> None:
        isr = _make_isr("static", "static", [], dissent_items=["dispute A"])
        builder = _make_builder()
        builder.set_isr_stats({"static": isr})
        assert builder.build().agent_stats[0].has_dissent is True

    def test_has_dissent_false(self) -> None:
        isr = _make_isr("static", "static", [], dissent_items=[])
        builder = _make_builder()
        builder.set_isr_stats({"static": isr})
        assert builder.build().agent_stats[0].has_dissent is False

    def test_none_technique_ids_excluded(self) -> None:
        isr = _make_isr("static", "static", [_claim(None, 0.8)])
        builder = _make_builder()
        builder.set_isr_stats({"static": isr})
        assert builder.build().agent_stats[0].technique_ids == []


# ---------------------------------------------------------------------------
# RunSummaryBuilder — set_validation / set_corroboration
# ---------------------------------------------------------------------------


class TestBuilderOptionalSummaries:
    def test_validation_none_if_not_set(self) -> None:
        assert _make_builder().build().validation is None

    def test_corroboration_is_empty_if_not_set(self) -> None:
        assert _make_builder().build().corroboration == {}

    def test_the_validation_tally_is_recorded_verbatim(self) -> None:
        builder = _make_builder()
        builder.set_validation(
            {
                "retries": 2,
                "by_code": {"attck.unknown_id": 1},
                "unresolved": [{"agent": "static", "code": "attck.unknown_id", "message": "no"}],
            }
        )

        v = builder.build().validation
        assert v is not None
        assert v.retries == 2
        assert v.by_code == {"attck.unknown_id": 1}
        assert v.unresolved[0]["agent"] == "static"

    def test_corroboration_counts_per_source_without_combining_anything(self) -> None:
        builder = _make_builder()
        builder.set_corroboration({"T1055": ["static", "dynamic"], "T1071": ["static"]})

        summary = builder.build()
        assert summary.corroboration == {"T1055": ["static", "dynamic"], "T1071": ["static"]}
        assert summary.techniques_by_layer == {"static": 2, "dynamic": 1}

    def test_an_empty_tally_leaves_validation_unset(self) -> None:
        builder = _make_builder()
        builder.set_validation(None)
        assert builder.build().validation is None


# ---------------------------------------------------------------------------
# RunSummary.to_markdown()
# ---------------------------------------------------------------------------


class TestRunSummaryToMarkdown:
    def _make_summary(self) -> RunSummary:
        builder = _make_builder()
        builder.set_sample("abc123", "evil.exe")
        builder.set_verdict("Malware", 12)
        builder.set_negotiation(_make_state(is_consensus=True))
        builder.set_isr_stats(
            {
                "s": _make_isr("static", "static", [_claim("T1055", 0.8)]),
            }
        )
        return builder.build()

    def test_contains_verdict(self) -> None:
        md = self._make_summary().to_markdown()
        assert "Malware" in md

    def test_contains_file_name(self) -> None:
        md = self._make_summary().to_markdown()
        assert "evil.exe" in md

    def test_contains_negotiation_section(self) -> None:
        md = self._make_summary().to_markdown()
        assert "## Negotiation" in md

    def test_contains_agent_section(self) -> None:
        md = self._make_summary().to_markdown()
        assert "## Agent ISR" in md
        assert "static" in md

    def test_contains_corroboration_section(self) -> None:
        md = self._make_summary().to_markdown()
        assert "## Corroboration" in md

    def test_contains_validation_section(self) -> None:
        md = self._make_summary().to_markdown()
        assert "## Validation" in md

    def test_confidence_history_shown(self) -> None:
        md = self._make_summary().to_markdown()
        assert "Confidence history" in md


# ---------------------------------------------------------------------------
# RunSummary.to_dict() — JSON serializability
# ---------------------------------------------------------------------------


class TestRunSummaryToDict:
    def _make_summary(self) -> RunSummary:
        builder = _make_builder()
        builder.set_sample("hash1", "file.exe")
        builder.set_verdict("Suspicious", 5)
        builder.set_negotiation(_make_state())
        return builder.build()

    def test_dict_is_json_serializable(self) -> None:
        d = self._make_summary().to_dict()
        dumped = json.dumps(d)
        assert "hash1" in dumped

    def test_dict_contains_expected_keys(self) -> None:
        d = self._make_summary().to_dict()
        assert "file_hash" in d
        assert "negotiation" in d
        assert "agent_stats" in d
        assert "corroboration" in d
        assert "validation" in d

    def test_elapsed_seconds_present(self) -> None:
        d = self._make_summary().to_dict()
        assert d["elapsed_seconds"] > 0

    def test_corroboration_is_empty_when_not_set(self) -> None:
        d = self._make_summary().to_dict()
        assert d["corroboration"] == {}

    def test_validation_none_when_not_set(self) -> None:
        d = self._make_summary().to_dict()
        assert d["validation"] is None
