"""Tests for the Phase 8.2 BenchmarkSuite and supporting utilities.

Tests:
  from_run_summary():
    - Extracts technique IDs from cascade results
    - Falls back to ISR agent stats when cascade is empty
    - Maps negotiation fields correctly (rounds, sycophancy, confidence_history)

  load_fixture_suite():
    - Loads all 5 *.json fixtures from the fixtures directory
    - Returns GroundTruth objects with correct sample_ids

  SuiteResult:
    - mean_ttp_f1, mean_negotiation_efficiency, sycophancy_rate,
      mean_hallucination_rate, mean_confidence_coverage
    - to_dict() completeness
    - to_markdown() contains all required sections
    - Empty suite edge case

  BenchmarkSuite:
    - run() produces SuiteResult with correct sample count
    - Failed runners are captured, not re-raised

  run_fixture_benchmark():
    - Produces SuiteResult with one report per fixture
    - Reports have non-zero TTP F1 (synthetic perfect-precision baseline)
    - All reports carry confidence annotations (synthetic bundle)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tests.evaluation.benchmark_runner import BenchmarkRunner, GroundTruth
from tests.evaluation.benchmark_suite import (
    BenchmarkSuite,
    SuiteResult,
    _make_synthetic_bundle,
    _make_synthetic_run_summary,
    from_run_summary,
    load_fixture_suite,
    run_fixture_benchmark,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_run_summary(
    technique_ids: list[str] | None = None,
    rounds: int = 2,
    sycophancy_events: int = 0,
) -> dict:
    return _make_synthetic_run_summary(
        sample_id="test_sample",
        technique_ids=technique_ids or ["T1486", "T1490"],
        rounds=rounds,
        max_rounds=3,
        sycophancy_events=sycophancy_events,
    )


def _minimal_gt(technique_ids: set[str] | None = None) -> GroundTruth:
    return GroundTruth(
        sample_id="test_sample",
        technique_ids=technique_ids or {"T1486", "T1490"},
    )


def _minimal_bundle(technique_ids: list[str] | None = None):
    return _make_synthetic_bundle(technique_ids or ["T1486", "T1490"])


# ---------------------------------------------------------------------------
# from_run_summary
# ---------------------------------------------------------------------------


class TestFromRunSummary:
    def test_extracts_technique_ids_from_cascade(self) -> None:
        run_summary = _minimal_run_summary(["T1486", "T1490"])
        bundle = _minimal_bundle(["T1486", "T1490"])
        gt = _minimal_gt({"T1486", "T1490"})

        runner = from_run_summary(run_summary, bundle, gt)
        report = runner.run()

        assert report.ttp_accuracy.f1 == pytest.approx(1.0)

    def test_fallback_to_isr_agent_stats(self) -> None:
        run_summary = {
            "sample_id": "test_sample",
            "negotiation": {
                "rounds_completed": 1,
                "max_rounds": 3,
                "sycophancy_events": 0,
                "confidence_history": [0.80],
            },
            # cascade is absent / empty
            "cascade": {"results": []},
            "isr_agents": [
                {"technique_ids": ["T1486", "T1490"], "agent_id": "static", "domain": "static"},
            ],
        }
        bundle = _minimal_bundle(["T1486", "T1490"])
        gt = _minimal_gt({"T1486", "T1490"})

        runner = from_run_summary(run_summary, bundle, gt)
        report = runner.run()

        assert report.ttp_accuracy.f1 == pytest.approx(1.0)

    def test_maps_negotiation_rounds(self) -> None:
        run_summary = _minimal_run_summary(rounds=2)
        runner = from_run_summary(run_summary, _minimal_bundle(), _minimal_gt())
        report = runner.run()

        assert report.negotiation.rounds_to_consensus == 2
        assert report.negotiation.max_iterations == 3

    def test_sycophancy_detected_when_events_gt_zero(self) -> None:
        run_summary = _minimal_run_summary(sycophancy_events=1)
        runner = from_run_summary(run_summary, _minimal_bundle(), _minimal_gt())
        report = runner.run()

        assert report.negotiation.sycophancy_detected is True

    def test_sycophancy_not_detected_when_zero_events(self) -> None:
        run_summary = _minimal_run_summary(sycophancy_events=0)
        runner = from_run_summary(run_summary, _minimal_bundle(), _minimal_gt())
        report = runner.run()

        assert report.negotiation.sycophancy_detected is False

    def test_confidence_history_passed_through(self) -> None:
        run_summary = _make_synthetic_run_summary(
            "test_sample",
            ["T1486"],
            confidence_history=[0.60, 0.75, 0.88],
        )
        runner = from_run_summary(run_summary, _minimal_bundle(), _minimal_gt())
        report = runner.run()

        assert report.negotiation.confidence_history == pytest.approx([0.60, 0.75, 0.88])

    def test_normalizes_technique_ids_to_uppercase(self) -> None:
        run_summary = _minimal_run_summary(["t1486", "t1490"])
        bundle = _minimal_bundle(["T1486", "T1490"])
        gt = _minimal_gt({"T1486", "T1490"})

        runner = from_run_summary(run_summary, bundle, gt)
        report = runner.run()

        assert report.ttp_accuracy.f1 == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# load_fixture_suite
# ---------------------------------------------------------------------------


class TestLoadFixtureSuite:
    def test_loads_all_five_fixtures(self) -> None:
        fixtures = load_fixture_suite(FIXTURES_DIR)
        sample_ids = {gt.sample_id for gt in fixtures}
        assert "ransomware_sample_1" in sample_ids
        assert "rat_sample_1" in sample_ids
        assert "dropper_sample_1" in sample_ids
        assert "worm_sample_1" in sample_ids
        assert "infostealer_sample_1" in sample_ids

    def test_fixture_count_matches_file_count(self) -> None:
        file_count = len(list(FIXTURES_DIR.glob("*.json")))
        fixture_count = len(load_fixture_suite(FIXTURES_DIR))
        assert fixture_count == file_count

    def test_all_fixtures_have_technique_ids(self) -> None:
        for gt in load_fixture_suite(FIXTURES_DIR):
            assert len(gt.technique_ids) >= 3, (
                f"{gt.sample_id} should have at least 3 technique IDs"
            )

    def test_all_fixtures_have_attck_valid_ids(self) -> None:
        for gt in load_fixture_suite(FIXTURES_DIR):
            assert gt.attck_valid_ids is not None, (
                f"{gt.sample_id} should provide attck_valid_ids for hallucination rate"
            )

    def test_empty_dir_returns_empty_list(self, tmp_path) -> None:
        fixtures = load_fixture_suite(tmp_path)
        assert fixtures == []

    def test_malformed_fixture_skipped(self, tmp_path) -> None:
        (tmp_path / "bad.json").write_text("{not valid json", encoding="utf-8")
        (tmp_path / "good.json").write_text(
            json.dumps({"sample_id": "good", "technique_ids": ["T1486"]}),
            encoding="utf-8",
        )
        fixtures = load_fixture_suite(tmp_path)
        assert len(fixtures) == 1
        assert fixtures[0].sample_id == "good"


# ---------------------------------------------------------------------------
# SuiteResult
# ---------------------------------------------------------------------------


def _make_suite_result_with_two_reports() -> SuiteResult:
    """Build a SuiteResult with two synthetic reports."""

    bundle1 = _make_synthetic_bundle(["T1486", "T1490"])
    bundle2 = _make_synthetic_bundle(["T1095", "T1071"])
    gt1 = GroundTruth("s1", {"T1486", "T1490"}, attck_valid_ids={"T1486", "T1490", "T1055"})
    gt2 = GroundTruth("s2", {"T1095", "T1071"}, attck_valid_ids={"T1095", "T1071", "T1003"})

    r1 = BenchmarkRunner("s1", gt1, bundle1, {"T1486", "T1490"}, 2, 3, False, [0.65, 0.85]).run()
    r2 = BenchmarkRunner(
        "s2", gt2, bundle2, {"T1095", "T1071"}, 3, 3, True, [0.60, 0.70, 0.80]
    ).run()

    result = SuiteResult()
    result.reports = [r1, r2]
    return result


class TestSuiteResult:
    def test_sample_count(self) -> None:
        result = _make_suite_result_with_two_reports()
        assert result.sample_count == 2

    def test_mean_ttp_f1_perfect(self) -> None:
        result = _make_suite_result_with_two_reports()
        # Both reports have perfect F1 (predicted == ground truth)
        assert result.mean_ttp_f1 == pytest.approx(1.0)

    def test_mean_negotiation_efficiency(self) -> None:
        result = _make_suite_result_with_two_reports()
        # s1: 2/3 = 0.667, s2: 3/3 = 1.0 -> mean = 0.833
        assert result.mean_negotiation_efficiency == pytest.approx((2 / 3 + 1.0) / 2, rel=1e-3)

    def test_sycophancy_rate(self) -> None:
        result = _make_suite_result_with_two_reports()
        # s1: False, s2: True -> 1/2 = 0.5
        assert result.sycophancy_rate == pytest.approx(0.5)

    def test_mean_hallucination_rate_zero(self) -> None:
        result = _make_suite_result_with_two_reports()
        # All predicted TTPs are in attck_valid_ids -> 0.0
        assert result.mean_hallucination_rate == pytest.approx(0.0)

    def test_mean_confidence_coverage_full(self) -> None:
        result = _make_suite_result_with_two_reports()
        # Synthetic bundles have only annotated relationships -> 1.0
        assert result.mean_confidence_coverage == pytest.approx(1.0)

    def test_empty_suite_returns_none_for_aggregates(self) -> None:
        result = SuiteResult()
        assert result.mean_ttp_f1 is None
        assert result.mean_negotiation_efficiency is None
        assert result.sycophancy_rate is None

    def test_to_dict_has_required_keys(self) -> None:
        result = _make_suite_result_with_two_reports()
        d = result.to_dict()
        assert "sample_count" in d
        assert "aggregate" in d
        assert "samples" in d
        assert d["sample_count"] == 2

    def test_to_dict_aggregate_keys(self) -> None:
        result = _make_suite_result_with_two_reports()
        agg = result.to_dict()["aggregate"]
        assert "mean_ttp_f1" in agg
        assert "mean_negotiation_efficiency" in agg
        assert "sycophancy_rate" in agg
        assert "mean_hallucination_rate" in agg
        assert "mean_confidence_coverage" in agg

    def test_to_json_round_trip(self) -> None:
        result = _make_suite_result_with_two_reports()
        parsed = json.loads(result.to_json())
        assert parsed["sample_count"] == 2

    def test_to_markdown_contains_required_sections(self) -> None:
        result = _make_suite_result_with_two_reports()
        md = result.to_markdown()
        assert "Maljan Evaluation Benchmark Suite" in md
        assert "Aggregate Results" in md
        assert "Per-Sample Results" in md
        assert "Mean TTP F1" in md

    def test_to_markdown_contains_sample_ids(self) -> None:
        result = _make_suite_result_with_two_reports()
        md = result.to_markdown()
        assert "s1" in md
        assert "s2" in md

    def test_failed_samples_included_in_dict(self) -> None:
        result = SuiteResult()
        result.failed = ["s3: ValueError"]
        d = result.to_dict()
        assert d["failed_count"] == 1
        assert "s3: ValueError" in d["failed_sample_ids"]

    def test_failed_samples_in_markdown(self) -> None:
        result = SuiteResult()
        result.failed = ["bad_sample: RuntimeError"]
        md = result.to_markdown()
        assert "Failed Samples" in md
        assert "bad_sample" in md


# ---------------------------------------------------------------------------
# BenchmarkSuite
# ---------------------------------------------------------------------------


class TestBenchmarkSuite:
    def test_run_produces_suite_result(self) -> None:
        suite = BenchmarkSuite()
        gt = _minimal_gt()
        bundle = _minimal_bundle()
        runner = BenchmarkRunner("s1", gt, bundle, {"T1486", "T1490"}, 2, 3)
        suite.add(runner)
        result = suite.run()
        assert result.sample_count == 1

    def test_run_multiple_runners(self) -> None:
        suite = BenchmarkSuite()
        for i in range(3):
            gt = GroundTruth(f"s{i}", {"T1486"})
            bundle = _minimal_bundle(["T1486"])
            suite.add(BenchmarkRunner(f"s{i}", gt, bundle, {"T1486"}, 1, 3))
        result = suite.run()
        assert result.sample_count == 3

    def test_failed_runner_captured_not_raised(self) -> None:
        suite = BenchmarkSuite()
        bad_runner = MagicMock()
        bad_runner._sample_id = "failing_sample"
        bad_runner.run.side_effect = RuntimeError("Synthetic failure")
        suite._runners.append(bad_runner)

        result = suite.run()
        assert result.sample_count == 0
        assert len(result.failed) == 1
        assert "failing_sample" in result.failed[0]

    def test_from_fixture_dir_skips_unknown_sample_ids(self) -> None:
        suite = BenchmarkSuite.from_fixture_dir(
            pipeline_outputs={"unknown_sample": ({}, None)},
            fixtures_dir=FIXTURES_DIR,
        )
        # unknown_sample has no fixture -> skipped silently
        assert len(suite._runners) == 0


# ---------------------------------------------------------------------------
# run_fixture_benchmark
# ---------------------------------------------------------------------------


class TestRunFixtureBenchmark:
    def test_produces_one_report_per_fixture(self) -> None:
        result = run_fixture_benchmark(FIXTURES_DIR)
        fixture_count = len(list(FIXTURES_DIR.glob("*.json")))
        assert result.sample_count == fixture_count

    def test_perfect_ttp_f1_on_synthetic_outputs(self) -> None:
        result = run_fixture_benchmark(FIXTURES_DIR)
        for report in result.reports:
            assert report.ttp_accuracy.f1 == pytest.approx(1.0), (
                f"{report.sample_id}: expected F1=1.0 on synthetic perfect-prediction baseline"
            )

    def test_zero_hallucination_on_synthetic_outputs(self) -> None:
        result = run_fixture_benchmark(FIXTURES_DIR)
        for report in result.reports:
            hr = report.ttp_accuracy.hallucination_rate
            if hr is not None:
                assert hr == pytest.approx(0.0), (
                    f"{report.sample_id}: expected 0.0 hallucination rate on synthetic baseline"
                )

    def test_full_confidence_coverage_on_synthetic_bundles(self) -> None:
        result = run_fixture_benchmark(FIXTURES_DIR)
        for report in result.reports:
            assert report.stix_quality.confidence_coverage == pytest.approx(1.0), (
                f"{report.sample_id}: all synthetic relationships should be annotated"
            )

    def test_output_written_to_file_markdown(self, tmp_path) -> None:
        output = tmp_path / "report.md"
        run_fixture_benchmark(FIXTURES_DIR, output_path=output, output_format="markdown")
        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "Maljan Evaluation Benchmark Suite" in content

    def test_output_written_to_file_json(self, tmp_path) -> None:
        output = tmp_path / "report.json"
        run_fixture_benchmark(FIXTURES_DIR, output_path=output, output_format="json")
        assert output.exists()
        data = json.loads(output.read_text(encoding="utf-8"))
        assert "sample_count" in data

    def test_no_failed_samples_on_clean_fixtures(self) -> None:
        result = run_fixture_benchmark(FIXTURES_DIR)
        assert result.failed == []
