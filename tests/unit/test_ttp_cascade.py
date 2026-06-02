"""Unit tests for Phase 4.3: Three-Layer TTP Mapping Cascade.

Tests:
  - TTPCascadeEngine.compute() — grouping, weighting, multipliers
  - CascadeResult model properties
  - CascadeSummary.top_techniques() and to_prompt_block()
  - JudgeAgent._build_cascade_block() graceful degradation
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from maljan.agents.judge_agent import JudgeAgent
from maljan.analysis.ttp_cascade import (
    CROSS_LAYER_MULTIPLIERS,
    CascadeResult,
    CascadeSummary,
    LayerContribution,
    TTPCascadeEngine,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_isr(
    agent_id: str,
    domain: str,
    claims: list[ClaimEvidence],
    revision_round: int = 0,
) -> AgentISR:
    return AgentISR(
        agent_id=agent_id,
        domain=domain,  # type: ignore[arg-type]
        claims=claims,
        dissent_items=[],
        revision_round=revision_round,
    )


def _claim(technique_id: str | None, confidence: float, evidence: str = "ref") -> ClaimEvidence:
    return ClaimEvidence(
        claim=f"Claim for {technique_id}",
        evidence_ref=evidence,
        confidence=confidence,
        technique_id=technique_id,
    )


@pytest.fixture
def engine() -> TTPCascadeEngine:
    return TTPCascadeEngine()


# ---------------------------------------------------------------------------
# TTPCascadeEngine — basic grouping
# ---------------------------------------------------------------------------


class TestCascadeEngineGrouping:
    def test_empty_isr_reports(self, engine: TTPCascadeEngine) -> None:
        summary = engine.compute({})
        assert summary.total_techniques == 0
        assert summary.results == []

    def test_no_technique_ids_in_claims(self, engine: TTPCascadeEngine) -> None:
        isr = _make_isr("static", "static", [_claim(None, 0.9)])
        summary = engine.compute({"static": isr})
        assert summary.total_techniques == 0

    def test_single_layer_single_technique(self, engine: TTPCascadeEngine) -> None:
        isr = _make_isr("static", "static", [_claim("T1055", 0.8)])
        summary = engine.compute({"static": isr})
        assert summary.total_techniques == 1
        result = summary.results[0]
        assert result.technique_id == "T1055"
        assert result.contributing_layers == ["static"]
        assert result.total_evidence_count == 1

    def test_multiple_techniques_same_layer(self, engine: TTPCascadeEngine) -> None:
        isr = _make_isr(
            "static",
            "static",
            [
                _claim("T1055", 0.8),
                _claim("T1547", 0.7),
            ],
        )
        summary = engine.compute({"static": isr})
        assert summary.total_techniques == 2
        tids = {r.technique_id for r in summary.results}
        assert tids == {"T1055", "T1547"}

    def test_same_technique_across_two_layers(self, engine: TTPCascadeEngine) -> None:
        isr_static = _make_isr("static", "static", [_claim("T1055", 0.8)])
        isr_dynamic = _make_isr("dynamic", "dynamic", [_claim("T1055", 0.9)])
        summary = engine.compute({"static": isr_static, "dynamic": isr_dynamic})
        assert summary.total_techniques == 1
        result = summary.results[0]
        assert set(result.contributing_layers) == {"static", "dynamic"}
        assert result.total_evidence_count == 2

    def test_technique_from_all_three_layers(self, engine: TTPCascadeEngine) -> None:
        isrs = {
            "s": _make_isr("s", "static", [_claim("T1071", 0.7)]),
            "d": _make_isr("d", "dynamic", [_claim("T1071", 0.85)]),
            "n": _make_isr("n", "network", [_claim("T1071", 0.9)]),
        }
        summary = engine.compute(isrs)
        result = summary.results[0]
        assert set(result.contributing_layers) == {"static", "dynamic", "network"}
        assert result.is_consensus is True


# ---------------------------------------------------------------------------
# TTPCascadeEngine — confidence calculation
# ---------------------------------------------------------------------------


class TestCascadeConfidenceCalculation:
    def test_single_layer_confidence_equals_claim(self, engine: TTPCascadeEngine) -> None:
        """Single claim → mean == claim confidence; no multiplier bonus."""
        isr = _make_isr("static", "static", [_claim("T1055", 0.80)])
        result = engine.compute({"static": isr}).results[0]
        # raw_weighted = 0.80 (only static contributes)
        # multiplier = 1.0
        assert result.raw_weighted_confidence == pytest.approx(0.80, abs=1e-6)
        assert result.cross_layer_multiplier == CROSS_LAYER_MULTIPLIERS[1]
        assert result.weighted_confidence == pytest.approx(0.80, abs=1e-6)

    def test_mean_confidence_per_layer_multiple_claims(self, engine: TTPCascadeEngine) -> None:
        """Multiple claims in same layer → layer confidence = mean."""
        isr = _make_isr(
            "dynamic",
            "dynamic",
            [
                _claim("T1055", 0.60),
                _claim("T1055", 0.80),
            ],
        )
        result = engine.compute({"dynamic": isr}).results[0]
        # mean = (0.60 + 0.80) / 2 = 0.70
        assert result.layer_confidences["dynamic"] == pytest.approx(0.70, abs=1e-6)

    def test_two_layer_multiplier_applied(self, engine: TTPCascadeEngine) -> None:
        isr_s = _make_isr("s", "static", [_claim("T1055", 0.80)])
        isr_d = _make_isr("d", "dynamic", [_claim("T1055", 0.80)])
        result = engine.compute({"s": isr_s, "d": isr_d}).results[0]
        assert result.cross_layer_multiplier == CROSS_LAYER_MULTIPLIERS[2]  # 1.25
        assert result.weighted_confidence > result.raw_weighted_confidence

    def test_three_layer_multiplier_applied(self, engine: TTPCascadeEngine) -> None:
        isrs = {
            "s": _make_isr("s", "static", [_claim("T1055", 0.70)]),
            "d": _make_isr("d", "dynamic", [_claim("T1055", 0.70)]),
            "n": _make_isr("n", "network", [_claim("T1055", 0.70)]),
        }
        result = engine.compute(isrs).results[0]
        assert result.cross_layer_multiplier == CROSS_LAYER_MULTIPLIERS[3]  # 1.50

    def test_confidence_capped_at_1_0(self, engine: TTPCascadeEngine) -> None:
        """Even with 1.5x multiplier, weighted_confidence must not exceed 1.0."""
        isrs = {
            "s": _make_isr("s", "static", [_claim("T1055", 1.0)]),
            "d": _make_isr("d", "dynamic", [_claim("T1055", 1.0)]),
            "n": _make_isr("n", "network", [_claim("T1055", 1.0)]),
        }
        result = engine.compute(isrs).results[0]
        assert result.weighted_confidence <= 1.0

    def test_weighted_average_uses_domain_weights(self, engine: TTPCascadeEngine) -> None:
        """Dynamic weight (0.45) > static weight (0.35) — dynamic dominates."""
        isr_s = _make_isr("s", "static", [_claim("T1055", 0.50)])
        isr_d = _make_isr("d", "dynamic", [_claim("T1055", 1.00)])
        result = engine.compute({"s": isr_s, "d": isr_d}).results[0]
        # raw = (0.45 * 1.0 + 0.35 * 0.5) / (0.45 + 0.35) = 0.625 / 0.80 = 0.78125
        expected_raw = (0.45 * 1.0 + 0.35 * 0.5) / (0.45 + 0.35)
        assert result.raw_weighted_confidence == pytest.approx(expected_raw, abs=1e-4)

    def test_unknown_domain_uses_default_weight(self, engine: TTPCascadeEngine) -> None:
        """A domain not in LAYER_WEIGHTS should use DEFAULT_LAYER_WEIGHT."""
        isr = _make_isr("custom", "static", [_claim("T1055", 0.90)])
        # Override: pass custom weights that don't include "static"
        result = engine.compute({"custom": isr}, layer_weights={}).results[0]
        # With empty weights dict, all domains use DEFAULT_LAYER_WEIGHT
        assert result.layer_confidences["static"] == pytest.approx(0.90, abs=1e-6)


# ---------------------------------------------------------------------------
# CascadeResult model
# ---------------------------------------------------------------------------


class TestCascadeResultModel:
    def _make_result(self, layers: list[str]) -> CascadeResult:
        contribs = [
            LayerContribution(
                domain=d, agent_id=d, claim_count=1, mean_confidence=0.8, evidence_refs=["ref"]
            )
            for d in layers
        ]
        return CascadeResult(
            technique_id="T1055",
            contributing_layers=layers,
            layer_contributions=contribs,
            layer_confidences={d: 0.8 for d in layers},
            raw_weighted_confidence=0.8,
            cross_layer_multiplier=CROSS_LAYER_MULTIPLIERS.get(len(layers), 1.0),
            weighted_confidence=min(0.8 * CROSS_LAYER_MULTIPLIERS.get(len(layers), 1.0), 1.0),
            total_evidence_count=len(layers),
        )

    def test_is_corroborated_two_layers(self) -> None:
        assert self._make_result(["static", "dynamic"]).is_corroborated is True

    def test_is_corroborated_false_one_layer(self) -> None:
        assert self._make_result(["static"]).is_corroborated is False

    def test_is_consensus_three_layers(self) -> None:
        assert self._make_result(["static", "dynamic", "network"]).is_consensus is True

    def test_is_consensus_false_two_layers(self) -> None:
        assert self._make_result(["static", "dynamic"]).is_consensus is False

    def test_corroboration_label_single(self) -> None:
        assert self._make_result(["static"]).corroboration_label() == "SINGLE-LAYER"

    def test_corroboration_label_two(self) -> None:
        assert self._make_result(["static", "dynamic"]).corroboration_label() == "CORROBORATED"

    def test_corroboration_label_three(self) -> None:
        assert (
            self._make_result(["static", "dynamic", "network"]).corroboration_label() == "CONSENSUS"
        )

    def test_layer_summary_contains_domains(self) -> None:
        result = self._make_result(["static", "dynamic"])
        summary = result.layer_summary()
        assert "static" in summary
        assert "dynamic" in summary


# ---------------------------------------------------------------------------
# CascadeSummary
# ---------------------------------------------------------------------------


class TestCascadeSummary:
    def _make_summary(self, corroborated: int, consensus: int, total: int) -> CascadeSummary:
        return CascadeSummary(
            results=[],
            total_techniques=total,
            corroborated_count=corroborated,
            consensus_count=consensus,
        )

    def test_top_techniques_empty(self) -> None:
        s = CascadeSummary(results=[], total_techniques=0, corroborated_count=0, consensus_count=0)
        assert s.top_techniques(n=5) == []

    def test_top_techniques_sorted_by_confidence(self, engine: TTPCascadeEngine) -> None:
        isrs = {
            "s": _make_isr(
                "s",
                "static",
                [
                    _claim("T1055", 0.90),  # high
                    _claim("T1071", 0.40),  # low
                ],
            ),
        }
        summary = engine.compute(isrs)
        top = summary.top_techniques(n=2)
        assert top[0].weighted_confidence >= top[1].weighted_confidence

    def test_to_prompt_block_empty(self) -> None:
        s = CascadeSummary(results=[], total_techniques=0, corroborated_count=0, consensus_count=0)
        block = s.to_prompt_block()
        assert "No structured TTP claims" in block

    def test_to_prompt_block_contains_header(self, engine: TTPCascadeEngine) -> None:
        isrs = {"s": _make_isr("s", "static", [_claim("T1055", 0.8)])}
        summary = engine.compute(isrs)
        block = summary.to_prompt_block()
        assert "THREE-LAYER TTP CASCADE" in block
        assert "T1055" in block

    def test_to_prompt_block_shows_corroboration_label(self, engine: TTPCascadeEngine) -> None:
        isrs = {
            "s": _make_isr("s", "static", [_claim("T1055", 0.8)]),
            "d": _make_isr("d", "dynamic", [_claim("T1055", 0.9)]),
        }
        summary = engine.compute(isrs)
        block = summary.to_prompt_block()
        assert "CORROBORATED" in block

    def test_to_prompt_block_instruction_present(self, engine: TTPCascadeEngine) -> None:
        isrs = {"s": _make_isr("s", "static", [_claim("T1055", 0.8)])}
        summary = engine.compute(isrs)
        block = summary.to_prompt_block()
        assert "INSTRUCTION" in block

    def test_aggregate_counts_correct(self, engine: TTPCascadeEngine) -> None:
        isrs = {
            "s": _make_isr("s", "static", [_claim("T1055", 0.8), _claim("T1071", 0.7)]),
            "d": _make_isr("d", "dynamic", [_claim("T1055", 0.9)]),
            "n": _make_isr("n", "network", [_claim("T1055", 0.85)]),
        }
        summary = engine.compute(isrs)
        assert summary.total_techniques == 2
        # T1055 is in all 3 layers → consensus (also corroborated)
        # T1071 is only in static → single layer
        assert summary.consensus_count == 1
        assert summary.corroborated_count == 1


# ---------------------------------------------------------------------------
# JudgeAgent._build_cascade_block() — graceful degradation
# ---------------------------------------------------------------------------


class TestJudgeCascadeBlock:
    @pytest.fixture
    def judge(self) -> JudgeAgent:
        return JudgeAgent(llm=MagicMock())

    def test_returns_empty_string_for_none(self, judge: JudgeAgent) -> None:
        assert judge._build_cascade_block(None) == ""

    def test_returns_empty_for_object_without_method(self, judge: JudgeAgent) -> None:
        assert judge._build_cascade_block(object()) == ""

    def test_returns_empty_when_no_techniques(self, judge: JudgeAgent) -> None:
        mock_summary = MagicMock()
        mock_summary.total_techniques = 0
        assert judge._build_cascade_block(mock_summary) == ""

    def test_returns_block_when_summary_has_techniques(self, judge: JudgeAgent) -> None:
        mock_summary = MagicMock()
        mock_summary.total_techniques = 2
        mock_summary.corroborated_count = 1
        mock_summary.consensus_count = 0
        mock_summary.to_prompt_block.return_value = "=== CASCADE BLOCK ==="
        result = judge._build_cascade_block(mock_summary)
        assert "CASCADE BLOCK" in result

    def test_graceful_on_to_prompt_block_error(self, judge: JudgeAgent) -> None:
        mock_summary = MagicMock()
        mock_summary.total_techniques = 1
        mock_summary.to_prompt_block.side_effect = RuntimeError("render error")
        result = judge._build_cascade_block(mock_summary)
        assert result == ""

    def test_real_cascade_summary_integration(
        self, judge: JudgeAgent, engine: TTPCascadeEngine
    ) -> None:
        isrs = {
            "s": _make_isr("s", "static", [_claim("T1055", 0.8)]),
            "d": _make_isr("d", "dynamic", [_claim("T1055", 0.9)]),
        }
        summary = engine.compute(isrs)
        block = judge._build_cascade_block(summary)
        assert "THREE-LAYER TTP CASCADE" in block
        assert "T1055" in block


# ---------------------------------------------------------------------------
# Wave 4 — Platform-aware cascade filtering
# ---------------------------------------------------------------------------


def _claim_with_platforms(
    technique_id: str,
    confidence: float,
    rule_platforms: list[str] | None,
) -> ClaimEvidence:
    return ClaimEvidence(
        claim=f"Claim for {technique_id}",
        evidence_ref="ref",
        confidence=confidence,
        technique_id=technique_id,
        rule_platforms=rule_platforms,
    )


class TestPlatformAwareCascade:
    """Wave 4: cascade must drop platform-mismatched claims and keep the rest."""

    def test_legacy_no_platform_kept(self, engine: TTPCascadeEngine) -> None:
        # sample_platform=None preserves the v3 behaviour.
        isrs = {"s": _make_isr("sigma", "sigma", [_claim("T1059.001", 0.8)])}
        summary = engine.compute(isrs, sample_platform=None)
        assert summary.total_techniques == 1
        assert summary.dropped_by_platform == []

    def test_drops_windows_sigma_claim_for_linux(self, engine: TTPCascadeEngine) -> None:
        # Foreign-OS rule dropped: a Sigma Windows PowerShell claim on a Linux sample.
        isrs = {
            "sig": _make_isr(
                "sigma",
                "sigma",
                [_claim_with_platforms("T1059.001", 0.8, ["windows"])],
            ),
        }
        summary = engine.compute(isrs, sample_platform="linux")
        assert summary.total_techniques == 0
        assert len(summary.dropped_by_platform) == 1
        dropped = summary.dropped_by_platform[0]
        assert dropped.technique_id == "T1059.001"
        assert dropped.source_layer == "sigma"
        assert dropped.rule_platforms == ["windows"]
        assert dropped.sample_platform == "linux"

    def test_keeps_any_platform_yara_claim_on_linux(self, engine: TTPCascadeEngine) -> None:
        # Source layer says "any" → keep regardless of MITRE catalog platforms.
        isrs = {
            "yara": _make_isr(
                "yara",
                "yara",
                [_claim_with_platforms("T1497", 0.85, ["any"])],
            ),
        }
        summary = engine.compute(isrs, sample_platform="linux")
        assert summary.total_techniques == 1
        assert summary.results[0].technique_id == "T1497"
        assert summary.dropped_by_platform == []

    def test_keeps_windows_claim_for_windows_sample(self, engine: TTPCascadeEngine) -> None:
        isrs = {
            "sig": _make_isr(
                "sigma",
                "sigma",
                [_claim_with_platforms("T1059.001", 0.8, ["windows"])],
            ),
        }
        summary = engine.compute(isrs, sample_platform="windows")
        assert summary.total_techniques == 1
        assert summary.dropped_by_platform == []

    def test_unknown_sample_falls_open(self, engine: TTPCascadeEngine) -> None:
        # Platform inference failed → don't drop anything (defensive default).
        isrs = {
            "sig": _make_isr(
                "sigma",
                "sigma",
                [_claim_with_platforms("T1059.001", 0.8, ["windows"])],
            ),
        }
        summary = engine.compute(isrs, sample_platform="unknown")
        assert summary.total_techniques == 1
