"""Unit tests for the evaluation benchmark framework (Phase 8.2).

Tests:
  NegotiationMetrics:
    - efficiency_ratio, converged_early, confidence_gain, confidence_std
    - edge cases: empty history, single item, max_iterations=0
    - to_dict() serialization

  TTPAccuracyMetrics:
    - perfect match, partial match, no overlap
    - hallucination_rate with and without attck_valid_ids
    - case normalization
    - empty predicted / empty ground truth edge cases
    - to_dict() serialization

  STIXQualityMetrics:
    - entity_coverage: full, partial, empty expected
    - confidence_coverage: all annotated, none annotated, mixed
    - mean_confidence from bundle
    - relationship_type_f1: full match, partial, empty expected
    - to_dict() serialization

  GroundTruth:
    - from_dict() deserialization
    - from_json() loading from fixture files

  BenchmarkReport:
    - to_dict() completeness
    - to_markdown() renders all sections
    - to_json() round-trip

  BenchmarkRunner:
    - run() produces BenchmarkReport
    - from_dict() factory
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.evaluation.benchmark_runner import (
    BenchmarkReport,
    BenchmarkRunner,
    GroundTruth,
)
from tests.evaluation.metrics import (
    NegotiationMetrics,
    STIXQualityMetrics,
    TTPAccuracyMetrics,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _make_bundle(
    has_malware: bool = True,
    has_attack_pattern: bool = True,
    has_annotated_rel: bool = True,
    has_plain_rel: bool = False,
    confidence: float = 0.85,
) -> object:
    """Build a minimal STIX Bundle for testing."""
    from maljan.schemas.stix_models import (
        AttackPattern,
        Bundle,
        ConfidenceAnnotatedRelationship,
        Malware,
        Relationship,
    )

    objects = []
    malware_id = "malware--test-0000"
    ap_id = "attack-pattern--test-0000"

    if has_malware:
        objects.append(Malware(id=malware_id, name="TestMalware"))
    if has_attack_pattern:
        objects.append(AttackPattern(id=ap_id, name="T1486 Encryption"))
    if has_annotated_rel:
        objects.append(
            ConfidenceAnnotatedRelationship(
                relationship_type="uses",
                source_ref=malware_id,
                target_ref=ap_id,
                x_maljan_confidence=confidence,
                x_maljan_evidence_basis="all",
            )
        )
    if has_plain_rel:
        objects.append(
            Relationship(
                relationship_type="indicates",
                source_ref="indicator--test-0000",
                target_ref=malware_id,
            )
        )
    return Bundle(objects=objects)


def _make_ground_truth(
    technique_ids: set[str] | None = None,
    attck_valid_ids: set[str] | None = None,
) -> GroundTruth:
    return GroundTruth(
        sample_id="test_sample",
        technique_ids=technique_ids or {"T1486", "T1490"},
        attck_valid_ids=attck_valid_ids,
    )


# ---------------------------------------------------------------------------
# NegotiationMetrics
# ---------------------------------------------------------------------------


class TestNegotiationMetrics:
    def test_efficiency_ratio_partial(self) -> None:
        m = NegotiationMetrics(
            rounds_to_consensus=2,
            max_iterations=4,
            sycophancy_detected=False,
        )
        assert m.efficiency_ratio == pytest.approx(0.5)

    def test_efficiency_ratio_full(self) -> None:
        m = NegotiationMetrics(
            rounds_to_consensus=3,
            max_iterations=3,
            sycophancy_detected=False,
        )
        assert m.efficiency_ratio == pytest.approx(1.0)

    def test_efficiency_ratio_zero_max(self) -> None:
        m = NegotiationMetrics(
            rounds_to_consensus=0,
            max_iterations=0,
            sycophancy_detected=False,
        )
        assert m.efficiency_ratio == pytest.approx(1.0)

    def test_converged_early_true(self) -> None:
        m = NegotiationMetrics(
            rounds_to_consensus=1,
            max_iterations=3,
            sycophancy_detected=False,
        )
        assert m.converged_early is True

    def test_converged_early_false(self) -> None:
        m = NegotiationMetrics(
            rounds_to_consensus=3,
            max_iterations=3,
            sycophancy_detected=False,
        )
        assert m.converged_early is False

    def test_confidence_gain_positive(self) -> None:
        m = NegotiationMetrics(
            rounds_to_consensus=2,
            max_iterations=3,
            sycophancy_detected=False,
            confidence_history=[0.60, 0.80],
        )
        assert m.confidence_gain == pytest.approx(0.20)

    def test_confidence_gain_empty(self) -> None:
        m = NegotiationMetrics(
            rounds_to_consensus=1,
            max_iterations=3,
            sycophancy_detected=False,
        )
        assert m.confidence_gain == pytest.approx(0.0)

    def test_confidence_gain_single(self) -> None:
        m = NegotiationMetrics(
            rounds_to_consensus=1,
            max_iterations=3,
            sycophancy_detected=False,
            confidence_history=[0.70],
        )
        assert m.confidence_gain == pytest.approx(0.0)

    def test_confidence_std_zero_for_constant(self) -> None:
        m = NegotiationMetrics(
            rounds_to_consensus=2,
            max_iterations=3,
            sycophancy_detected=False,
            confidence_history=[0.80, 0.80, 0.80],
        )
        assert m.confidence_std == pytest.approx(0.0)

    def test_confidence_std_non_zero(self) -> None:
        m = NegotiationMetrics(
            rounds_to_consensus=3,
            max_iterations=3,
            sycophancy_detected=False,
            confidence_history=[0.60, 0.75, 0.90],
        )
        assert m.confidence_std > 0.0

    def test_to_dict_keys(self) -> None:
        m = NegotiationMetrics(
            rounds_to_consensus=2,
            max_iterations=3,
            sycophancy_detected=True,
            confidence_history=[0.6, 0.85],
        )
        d = m.to_dict()
        assert "rounds_to_consensus" in d
        assert "efficiency_ratio" in d
        assert "converged_early" in d
        assert "sycophancy_detected" in d
        assert d["sycophancy_detected"] is True


# ---------------------------------------------------------------------------
# TTPAccuracyMetrics
# ---------------------------------------------------------------------------


class TestTTPAccuracyMetrics:
    def test_perfect_match(self) -> None:
        m = TTPAccuracyMetrics(
            predicted_ttps={"T1486", "T1490"},
            ground_truth_ttps={"T1486", "T1490"},
        )
        assert m.precision == pytest.approx(1.0)
        assert m.recall == pytest.approx(1.0)
        assert m.f1 == pytest.approx(1.0)

    def test_no_overlap(self) -> None:
        m = TTPAccuracyMetrics(
            predicted_ttps={"T1055"},
            ground_truth_ttps={"T1486"},
        )
        assert m.precision == pytest.approx(0.0)
        assert m.recall == pytest.approx(0.0)
        assert m.f1 == pytest.approx(0.0)

    def test_partial_overlap(self) -> None:
        m = TTPAccuracyMetrics(
            predicted_ttps={"T1486", "T1490", "T1055"},  # T1055 is FP
            ground_truth_ttps={"T1486", "T1490", "T1489"},  # T1489 is FN
        )
        assert m.precision == pytest.approx(2 / 3)
        assert m.recall == pytest.approx(2 / 3)

    def test_empty_predicted_zero_precision(self) -> None:
        m = TTPAccuracyMetrics(
            predicted_ttps=set(),
            ground_truth_ttps={"T1486"},
        )
        assert m.precision == pytest.approx(0.0)
        assert m.recall == pytest.approx(0.0)

    def test_empty_ground_truth_recall_one(self) -> None:
        m = TTPAccuracyMetrics(
            predicted_ttps={"T1486"},
            ground_truth_ttps=set(),
        )
        assert m.recall == pytest.approx(1.0)

    def test_case_normalization(self) -> None:
        m = TTPAccuracyMetrics(
            predicted_ttps={"t1486"},
            ground_truth_ttps={"T1486"},
        )
        assert m.f1 == pytest.approx(1.0)

    def test_hallucination_rate_zero(self) -> None:
        m = TTPAccuracyMetrics(
            predicted_ttps={"T1486", "T1490"},
            ground_truth_ttps={"T1486"},
            attck_valid_ttps={"T1486", "T1490", "T1055"},
        )
        assert m.hallucination_rate == pytest.approx(0.0)

    def test_hallucination_rate_partial(self) -> None:
        m = TTPAccuracyMetrics(
            predicted_ttps={"T1486", "T9999"},  # T9999 is not in ATT&CK
            ground_truth_ttps={"T1486"},
            attck_valid_ttps={"T1486", "T1490"},
        )
        assert m.hallucination_rate == pytest.approx(0.5)

    def test_hallucination_rate_none_when_no_valid_set(self) -> None:
        m = TTPAccuracyMetrics(
            predicted_ttps={"T1486"},
            ground_truth_ttps={"T1486"},
        )
        assert m.hallucination_rate is None

    def test_to_dict_keys(self) -> None:
        m = TTPAccuracyMetrics(
            predicted_ttps={"T1486"},
            ground_truth_ttps={"T1486", "T1490"},
        )
        d = m.to_dict()
        assert "precision" in d
        assert "recall" in d
        assert "f1" in d
        assert "true_positives" in d
        assert "false_positives" in d
        assert "false_negatives" in d


# ---------------------------------------------------------------------------
# STIXQualityMetrics
# ---------------------------------------------------------------------------


class TestSTIXQualityMetrics:
    def test_full_entity_coverage(self) -> None:
        bundle = _make_bundle(has_malware=True, has_attack_pattern=True, has_annotated_rel=True)
        m = STIXQualityMetrics(
            bundle=bundle,
            expected_entity_types={"malware", "attack-pattern", "relationship"},
        )
        assert m.entity_coverage == pytest.approx(1.0)

    def test_partial_entity_coverage(self) -> None:
        bundle = _make_bundle(has_malware=True, has_attack_pattern=False, has_annotated_rel=False)
        m = STIXQualityMetrics(
            bundle=bundle,
            expected_entity_types={"malware", "attack-pattern"},
        )
        assert m.entity_coverage == pytest.approx(0.5)

    def test_empty_expected_entity_types_returns_one(self) -> None:
        bundle = _make_bundle()
        m = STIXQualityMetrics(bundle=bundle, expected_entity_types=set())
        assert m.entity_coverage == pytest.approx(1.0)

    def test_confidence_coverage_all_annotated(self) -> None:
        bundle = _make_bundle(has_annotated_rel=True, has_plain_rel=False)
        m = STIXQualityMetrics(bundle=bundle)
        assert m.confidence_coverage == pytest.approx(1.0)

    def test_confidence_coverage_mixed(self) -> None:
        bundle = _make_bundle(has_annotated_rel=True, has_plain_rel=True)
        m = STIXQualityMetrics(bundle=bundle)
        # 1 annotated + 1 plain = 50%
        assert m.confidence_coverage == pytest.approx(0.5)

    def test_confidence_coverage_no_rels(self) -> None:
        bundle = _make_bundle(has_annotated_rel=False, has_plain_rel=False)
        m = STIXQualityMetrics(bundle=bundle)
        assert m.confidence_coverage == pytest.approx(1.0)

    def test_mean_confidence(self) -> None:
        bundle = _make_bundle(has_annotated_rel=True, confidence=0.9)
        m = STIXQualityMetrics(bundle=bundle)
        assert m.mean_confidence == pytest.approx(0.9)

    def test_mean_confidence_none_when_no_annotated(self) -> None:
        bundle = _make_bundle(has_annotated_rel=False, has_plain_rel=True)
        m = STIXQualityMetrics(bundle=bundle)
        assert m.mean_confidence is None

    def test_relationship_type_f1_perfect(self) -> None:
        bundle = _make_bundle(has_annotated_rel=True)
        m = STIXQualityMetrics(
            bundle=bundle,
            expected_relationship_types={"uses"},
        )
        assert m.relationship_type_f1 == pytest.approx(1.0)

    def test_relationship_type_f1_empty_expected(self) -> None:
        bundle = _make_bundle(has_annotated_rel=True)
        m = STIXQualityMetrics(bundle=bundle, expected_relationship_types=set())
        assert m.relationship_type_f1 == pytest.approx(1.0)

    def test_relationship_type_f1_no_overlap(self) -> None:
        bundle = _make_bundle(has_annotated_rel=True)  # has "uses"
        m = STIXQualityMetrics(
            bundle=bundle,
            expected_relationship_types={"attributed-to"},
        )
        assert m.relationship_type_f1 == pytest.approx(0.0)

    def test_to_dict_keys(self) -> None:
        bundle = _make_bundle()
        m = STIXQualityMetrics(bundle=bundle)
        d = m.to_dict()
        assert "entity_coverage" in d
        assert "confidence_coverage" in d
        assert "mean_confidence" in d
        assert "relationship_type_f1" in d


# ---------------------------------------------------------------------------
# GroundTruth
# ---------------------------------------------------------------------------


class TestGroundTruth:
    def test_from_dict_basic(self) -> None:
        gt = GroundTruth.from_dict(
            {
                "sample_id": "test_1",
                "technique_ids": ["T1486", "T1490"],
            }
        )
        assert gt.sample_id == "test_1"
        assert "T1486" in gt.technique_ids
        assert "T1490" in gt.technique_ids

    def test_from_dict_defaults(self) -> None:
        gt = GroundTruth.from_dict({"sample_id": "test_1", "technique_ids": []})
        assert "malware" in gt.expected_stix_types
        assert gt.attck_valid_ids is None

    def test_from_dict_with_attck_valid_ids(self) -> None:
        gt = GroundTruth.from_dict(
            {
                "sample_id": "test_1",
                "technique_ids": ["T1486"],
                "attck_valid_ids": ["T1486", "T1055"],
            }
        )
        assert gt.attck_valid_ids == {"T1486", "T1055"}

    def test_from_json_ransomware_fixture(self) -> None:
        fixture = FIXTURES_DIR / "ransomware_sample_1.json"
        gt = GroundTruth.from_json(fixture)
        assert gt.sample_id == "ransomware_sample_1"
        assert "T1486" in gt.technique_ids
        assert gt.attck_valid_ids is not None

    def test_from_json_rat_fixture(self) -> None:
        fixture = FIXTURES_DIR / "rat_sample_1.json"
        gt = GroundTruth.from_json(fixture)
        assert gt.sample_id == "rat_sample_1"
        assert "T1095" in gt.technique_ids


# ---------------------------------------------------------------------------
# BenchmarkReport
# ---------------------------------------------------------------------------


class TestBenchmarkReport:
    def _make_report(self) -> BenchmarkReport:
        bundle = _make_bundle(has_annotated_rel=True, confidence=0.85)
        gt = _make_ground_truth(
            technique_ids={"T1486", "T1490"},
            attck_valid_ids={"T1486", "T1490", "T1055"},
        )
        runner = BenchmarkRunner(
            sample_id="test_sample",
            ground_truth=gt,
            stix_bundle=bundle,
            predicted_ttps={"T1486", "T1490"},
            negotiation_rounds=2,
            max_iterations=3,
            sycophancy_detected=False,
            confidence_history=[0.70, 0.85],
        )
        return runner.run()

    def test_to_dict_has_all_sections(self) -> None:
        report = self._make_report()
        d = report.to_dict()
        assert "sample_id" in d
        assert "negotiation" in d
        assert "ttp_accuracy" in d
        assert "stix_quality" in d

    def test_to_json_round_trip(self) -> None:
        report = self._make_report()
        serialized = json.loads(report.to_json())
        assert serialized["sample_id"] == "test_sample"

    def test_to_markdown_contains_sections(self) -> None:
        report = self._make_report()
        md = report.to_markdown()
        assert "## Negotiation" in md
        assert "## TTP Accuracy" in md
        assert "## STIX Quality" in md

    def test_to_markdown_contains_f1(self) -> None:
        report = self._make_report()
        md = report.to_markdown()
        assert "F1" in md

    def test_perfect_ttp_f1_in_report(self) -> None:
        report = self._make_report()
        assert report.ttp_accuracy.f1 == pytest.approx(1.0)

    def test_zero_hallucination_in_report(self) -> None:
        report = self._make_report()
        assert report.ttp_accuracy.hallucination_rate == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# BenchmarkRunner
# ---------------------------------------------------------------------------


class TestBenchmarkRunner:
    def test_run_returns_report(self) -> None:
        bundle = _make_bundle()
        gt = _make_ground_truth()
        runner = BenchmarkRunner(
            sample_id="s1",
            ground_truth=gt,
            stix_bundle=bundle,
            predicted_ttps={"T1486"},
            negotiation_rounds=1,
            max_iterations=3,
        )
        report = runner.run()
        assert isinstance(report, BenchmarkReport)
        assert report.sample_id == "s1"

    def test_from_dict_factory(self) -> None:
        bundle = _make_bundle()
        gt = _make_ground_truth()
        pipeline_output = {
            "sample_id": "s2",
            "negotiation_rounds": 2,
            "max_iterations": 3,
            "sycophancy_detected": True,
            "confidence_history": [0.6, 0.8],
            "predicted_ttps": ["T1486", "T1490"],
        }
        runner = BenchmarkRunner.from_dict(pipeline_output, gt, bundle)
        report = runner.run()
        assert report.sample_id == "s2"
        assert report.negotiation.sycophancy_detected is True
        assert report.negotiation.rounds_to_consensus == 2

    def test_no_confidence_history_defaults_empty(self) -> None:
        bundle = _make_bundle()
        gt = _make_ground_truth()
        runner = BenchmarkRunner(
            sample_id="s3",
            ground_truth=gt,
            stix_bundle=bundle,
            predicted_ttps=set(),
            negotiation_rounds=1,
            max_iterations=1,
        )
        report = runner.run()
        assert report.negotiation.confidence_history == []
        assert report.negotiation.confidence_gain == pytest.approx(0.0)
