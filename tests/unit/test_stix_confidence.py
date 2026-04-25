"""Unit tests for STIX Confidence Intervals (Phase 7.2).

Tests:
  - ConfidenceAnnotatedRelationship: field validation, property helpers
  - EvidenceBasis controlled vocabulary
  - Bundle: union type resolution, helper methods
  - JudgeAgent._build_confidence_instruction(): cascade hint table generation,
    graceful degradation
  - Backward compatibility: plain Relationship still accepted in Bundle
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from maljan.schemas.stix_models import (
    AttackPattern,
    Bundle,
    ConfidenceAnnotatedRelationship,
    Indicator,
    Malware,
    Relationship,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_annotated(
    rel_type: str = "uses",
    source_ref: str = "malware--aaa",
    target_ref: str = "attack-pattern--bbb",
    confidence: float = 0.85,
    evidence_basis: str = "static+dynamic",
    contributing_agents: list[str] | None = None,
    technique_id: str | None = "T1055",
) -> ConfidenceAnnotatedRelationship:
    return ConfidenceAnnotatedRelationship(
        relationship_type=rel_type,
        source_ref=source_ref,
        target_ref=target_ref,
        x_maljan_confidence=confidence,
        x_maljan_evidence_basis=evidence_basis,  # type: ignore[arg-type]
        x_maljan_contributing_agents=contributing_agents or ["static", "dynamic"],
        x_maljan_technique_id=technique_id,
    )


def _make_plain(
    rel_type: str = "uses",
    source_ref: str = "malware--aaa",
    target_ref: str = "attack-pattern--bbb",
) -> Relationship:
    return Relationship(
        relationship_type=rel_type,
        source_ref=source_ref,
        target_ref=target_ref,
    )


# ---------------------------------------------------------------------------
# ConfidenceAnnotatedRelationship: field validation
# ---------------------------------------------------------------------------


class TestConfidenceAnnotatedRelationship:
    def test_type_is_relationship(self) -> None:
        r = _make_annotated()
        assert r.type == "relationship"

    def test_id_starts_with_relationship_prefix(self) -> None:
        r = _make_annotated()
        assert r.id.startswith("relationship--")

    def test_confidence_stored_correctly(self) -> None:
        r = _make_annotated(confidence=0.75)
        assert r.x_maljan_confidence == pytest.approx(0.75)

    def test_evidence_basis_stored(self) -> None:
        r = _make_annotated(evidence_basis="all")
        assert r.x_maljan_evidence_basis == "all"

    def test_contributing_agents_stored(self) -> None:
        r = _make_annotated(contributing_agents=["static", "network"])
        assert "static" in r.x_maljan_contributing_agents
        assert "network" in r.x_maljan_contributing_agents

    def test_technique_id_stored(self) -> None:
        r = _make_annotated(technique_id="T1547.001")
        assert r.x_maljan_technique_id == "T1547.001"

    def test_technique_id_can_be_none(self) -> None:
        r = _make_annotated(technique_id=None)
        assert r.x_maljan_technique_id is None

    def test_confidence_default_is_half(self) -> None:
        r = ConfidenceAnnotatedRelationship(
            relationship_type="uses",
            source_ref="a",
            target_ref="b",
        )
        assert r.x_maljan_confidence == pytest.approx(0.5)

    def test_evidence_basis_default_is_unknown(self) -> None:
        r = ConfidenceAnnotatedRelationship(
            relationship_type="uses",
            source_ref="a",
            target_ref="b",
        )
        assert r.x_maljan_evidence_basis == "unknown"

    def test_contributing_agents_default_is_empty(self) -> None:
        r = ConfidenceAnnotatedRelationship(
            relationship_type="uses",
            source_ref="a",
            target_ref="b",
        )
        assert r.x_maljan_contributing_agents == []

    def test_confidence_below_zero_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _make_annotated(confidence=-0.1)

    def test_confidence_above_one_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _make_annotated(confidence=1.1)

    def test_confidence_zero_accepted(self) -> None:
        r = _make_annotated(confidence=0.0)
        assert r.x_maljan_confidence == pytest.approx(0.0)

    def test_confidence_one_accepted(self) -> None:
        r = _make_annotated(confidence=1.0)
        assert r.x_maljan_confidence == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Property helpers
# ---------------------------------------------------------------------------


class TestConfidenceAnnotatedProperties:
    def test_is_high_confidence_true_at_080(self) -> None:
        assert _make_annotated(confidence=0.80).is_high_confidence is True

    def test_is_high_confidence_true_above_080(self) -> None:
        assert _make_annotated(confidence=0.95).is_high_confidence is True

    def test_is_high_confidence_false_below_080(self) -> None:
        assert _make_annotated(confidence=0.79).is_high_confidence is False

    def test_is_multi_domain_all(self) -> None:
        assert _make_annotated(evidence_basis="all").is_multi_domain is True

    def test_is_multi_domain_combined(self) -> None:
        assert _make_annotated(evidence_basis="static+dynamic").is_multi_domain is True

    def test_is_multi_domain_single(self) -> None:
        assert _make_annotated(evidence_basis="static").is_multi_domain is False

    def test_is_multi_domain_unknown(self) -> None:
        assert _make_annotated(evidence_basis="unknown").is_multi_domain is False

    def test_confidence_label_high(self) -> None:
        assert _make_annotated(confidence=0.92).confidence_label() == "HIGH"

    def test_confidence_label_medium(self) -> None:
        assert _make_annotated(confidence=0.75).confidence_label() == "MEDIUM"

    def test_confidence_label_low(self) -> None:
        assert _make_annotated(confidence=0.55).confidence_label() == "LOW"

    def test_confidence_label_speculative(self) -> None:
        assert _make_annotated(confidence=0.30).confidence_label() == "SPECULATIVE"

    def test_confidence_label_boundary_070(self) -> None:
        assert _make_annotated(confidence=0.70).confidence_label() == "MEDIUM"

    def test_confidence_label_boundary_090(self) -> None:
        assert _make_annotated(confidence=0.90).confidence_label() == "HIGH"


# ---------------------------------------------------------------------------
# EvidenceBasis controlled vocabulary
# ---------------------------------------------------------------------------


class TestEvidenceBasisVocab:
    @pytest.mark.parametrize(
        "basis",
        [
            "static",
            "dynamic",
            "network",
            "static+dynamic",
            "dynamic+network",
            "static+network",
            "all",
            "unknown",
        ],
    )
    def test_all_valid_basis_values_accepted(self, basis: str) -> None:
        r = ConfidenceAnnotatedRelationship(
            relationship_type="uses",
            source_ref="a",
            target_ref="b",
            x_maljan_evidence_basis=basis,  # type: ignore[arg-type]
        )
        assert r.x_maljan_evidence_basis == basis

    def test_invalid_basis_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ConfidenceAnnotatedRelationship(
                relationship_type="uses",
                source_ref="a",
                target_ref="b",
                x_maljan_evidence_basis="memory",  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# Bundle: union type resolution and helpers
# ---------------------------------------------------------------------------


class TestBundle:
    def test_bundle_accepts_annotated_relationship(self) -> None:
        bundle = Bundle(objects=[_make_annotated()])
        assert len(bundle.objects) == 1
        assert isinstance(bundle.objects[0], ConfidenceAnnotatedRelationship)

    def test_bundle_accepts_plain_relationship(self) -> None:
        bundle = Bundle(objects=[_make_plain()])
        assert len(bundle.objects) == 1

    def test_bundle_accepts_mixed_objects(self) -> None:
        malware = Malware(name="TestMalware")
        ap = AttackPattern(name="T1055")
        annotated = _make_annotated()
        plain = _make_plain()
        indicator = Indicator(pattern="[file:name = 'evil.exe']")
        bundle = Bundle(objects=[malware, ap, annotated, plain, indicator])
        assert len(bundle.objects) == 5

    def test_confidence_annotated_relationships_filter(self) -> None:
        bundle = Bundle(
            objects=[
                _make_annotated(confidence=0.9),
                _make_plain(),
                Malware(name="TestMalware"),
                _make_annotated(confidence=0.6),
            ]
        )
        annotated = bundle.confidence_annotated_relationships()
        assert len(annotated) == 2

    def test_mean_relationship_confidence_computed(self) -> None:
        bundle = Bundle(
            objects=[
                _make_annotated(confidence=0.8),
                _make_annotated(confidence=0.6),
            ]
        )
        mean = bundle.mean_relationship_confidence()
        assert mean == pytest.approx(0.70)

    def test_mean_relationship_confidence_none_when_no_annotated(self) -> None:
        bundle = Bundle(
            objects=[
                _make_plain(),
                Malware(name="TestMalware"),
            ]
        )
        assert bundle.mean_relationship_confidence() is None

    def test_mean_relationship_confidence_none_on_empty_bundle(self) -> None:
        bundle = Bundle(objects=[])
        assert bundle.mean_relationship_confidence() is None

    def test_bundle_type_is_bundle(self) -> None:
        assert Bundle().type == "bundle"

    def test_bundle_id_starts_with_prefix(self) -> None:
        assert Bundle().id.startswith("bundle--")

    def test_annotated_relationship_preserved_after_roundtrp(self) -> None:
        """ConfidenceAnnotatedRelationship survives serialization/deserialization."""
        r = _make_annotated(confidence=0.88, evidence_basis="all")
        bundle = Bundle(objects=[r])
        data = bundle.model_dump()
        restored = Bundle.model_validate(data)
        obj = restored.objects[0]
        assert isinstance(obj, ConfidenceAnnotatedRelationship)
        assert obj.x_maljan_confidence == pytest.approx(0.88)
        assert obj.x_maljan_evidence_basis == "all"


# ---------------------------------------------------------------------------
# JudgeAgent._build_confidence_instruction()
# ---------------------------------------------------------------------------


class TestBuildConfidenceInstruction:
    """Tests for the cascade-derived confidence hint table in the verdict prompt."""

    def _make_judge(self) -> object:
        """Create a JudgeAgent with a mock LLM."""
        from maljan.agents.judge_agent import JudgeAgent

        return JudgeAgent(llm=MagicMock())

    def _make_cascade_result(
        self,
        technique_id: str,
        weighted_confidence: float,
        layers: list[str],
    ) -> MagicMock:
        r = MagicMock()
        r.technique_id = technique_id
        r.weighted_confidence = weighted_confidence
        r.contributing_layers = layers
        return r

    def _make_cascade_summary(self, results: list) -> MagicMock:
        summary = MagicMock()
        summary.top_techniques.return_value = results
        return summary

    def test_returns_empty_string_when_no_cascade(self) -> None:
        judge = self._make_judge()
        result = judge._build_confidence_instruction(None)  # type: ignore[union-attr]
        assert result == ""

    def test_returns_empty_string_when_no_top_techniques(self) -> None:
        judge = self._make_judge()
        summary = self._make_cascade_summary([])
        result = judge._build_confidence_instruction(summary)  # type: ignore[union-attr]
        assert result == ""

    def test_returns_table_header(self) -> None:
        judge = self._make_judge()
        results = [self._make_cascade_result("T1055", 0.85, ["static", "dynamic"])]
        summary = self._make_cascade_summary(results)
        output = judge._build_confidence_instruction(summary)  # type: ignore[union-attr]
        assert "CONFIDENCE REFERENCE TABLE" in output

    def test_single_layer_basis_maps_correctly(self) -> None:
        judge = self._make_judge()
        results = [self._make_cascade_result("T1055", 0.7, ["network"])]
        summary = self._make_cascade_summary(results)
        output = judge._build_confidence_instruction(summary)  # type: ignore[union-attr]
        assert "network" in output
        # Basis for single layer should be just "network" not "unknown"
        assert "unknown" not in output

    def test_two_layer_basis_joined_with_plus(self) -> None:
        judge = self._make_judge()
        results = [
            self._make_cascade_result("T1055", 0.8, ["dynamic", "network"]),
        ]
        summary = self._make_cascade_summary(results)
        output = judge._build_confidence_instruction(summary)  # type: ignore[union-attr]
        assert "dynamic+network" in output

    def test_three_layer_basis_maps_to_all(self) -> None:
        judge = self._make_judge()
        results = [
            self._make_cascade_result("T1055", 0.95, ["static", "dynamic", "network"]),
        ]
        summary = self._make_cascade_summary(results)
        output = judge._build_confidence_instruction(summary)  # type: ignore[union-attr]
        assert "all" in output

    def test_technique_id_in_output(self) -> None:
        judge = self._make_judge()
        results = [self._make_cascade_result("T1547", 0.72, ["static"])]
        summary = self._make_cascade_summary(results)
        output = judge._build_confidence_instruction(summary)  # type: ignore[union-attr]
        assert "T1547" in output

    def test_graceful_degradation_on_cascade_error(self) -> None:
        judge = self._make_judge()
        broken_summary = MagicMock()
        broken_summary.top_techniques.side_effect = RuntimeError("cascade broken")
        result = judge._build_confidence_instruction(broken_summary)  # type: ignore[union-attr]
        assert result == ""
