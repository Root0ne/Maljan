"""test_tram_ground_truth.py — Integration tests for TRAM2 ground truth fixtures.

Verifies that:
  1. The TRAM2 fixture directory contains the expected number of fixtures.
  2. Every fixture deserializes correctly into a GroundTruth object.
  3. Key fixture properties are well-formed (non-empty IDs, valid T-numbers, etc.)
  4. The benchmark suite runs without errors on the full TRAM fixture set and
     produces non-trivial aggregate results in synthetic (perfect-prediction) mode.

These tests run offline — no LLM, no network, no heavy dependencies.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.evaluation.benchmark_runner import GroundTruth
from tests.evaluation.benchmark_suite import load_fixture_suite, run_fixture_benchmark

TRAM_FIXTURES_DIR = Path(__file__).parent / "ground_truth" / "tram"

# Minimum fixture count that should always be present after prepare_tram_dataset.py runs.
_MIN_EXPECTED_FIXTURES = 100

# ATT&CK technique ID pattern (base and sub-technique).
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


@pytest.fixture(scope="module")
def tram_fixtures() -> list[GroundTruth]:
    """Load all TRAM fixtures once for the module."""
    if not TRAM_FIXTURES_DIR.exists():
        pytest.skip(
            "TRAM fixture directory not found. Run: uv run python scripts/prepare_tram_dataset.py"
        )
    fixtures = load_fixture_suite(TRAM_FIXTURES_DIR)
    if not fixtures:
        pytest.skip("No TRAM fixtures found. Run: uv run python scripts/prepare_tram_dataset.py")
    return fixtures


class TestTramFixtureCount:
    def test_minimum_fixture_count(self, tram_fixtures: list[GroundTruth]) -> None:
        assert len(tram_fixtures) >= _MIN_EXPECTED_FIXTURES, (
            f"Expected at least {_MIN_EXPECTED_FIXTURES} fixtures, "
            f"found {len(tram_fixtures)}. "
            "Re-run scripts/prepare_tram_dataset.py."
        )


class TestTramFixtureSchema:
    def test_all_fixtures_have_sample_id(self, tram_fixtures: list[GroundTruth]) -> None:
        for gt in tram_fixtures:
            assert gt.sample_id, f"Empty sample_id in fixture: {gt}"

    def test_all_fixtures_have_technique_ids(self, tram_fixtures: list[GroundTruth]) -> None:
        for gt in tram_fixtures:
            assert gt.technique_ids, f"fixture '{gt.sample_id}' has no technique_ids"

    def test_technique_ids_are_valid_attck_format(self, tram_fixtures: list[GroundTruth]) -> None:
        for gt in tram_fixtures:
            for tid in gt.technique_ids:
                assert _TECHNIQUE_RE.match(tid), (
                    f"'{tid}' in fixture '{gt.sample_id}' is not a valid "
                    "ATT&CK technique ID (expected format: T1234 or T1234.001)."
                )

    def test_attck_valid_ids_superset_of_technique_ids(
        self, tram_fixtures: list[GroundTruth]
    ) -> None:
        for gt in tram_fixtures:
            if gt.attck_valid_ids is not None:
                missing = gt.technique_ids - gt.attck_valid_ids
                assert not missing, (
                    f"fixture '{gt.sample_id}': technique_ids not a subset of "
                    f"attck_valid_ids. Missing: {missing}"
                )

    def test_expected_stix_types_non_empty(self, tram_fixtures: list[GroundTruth]) -> None:
        for gt in tram_fixtures:
            assert gt.expected_stix_types, f"fixture '{gt.sample_id}' has empty expected_stix_types"

    def test_notes_contain_source_attribution(self, tram_fixtures: list[GroundTruth]) -> None:
        for gt in tram_fixtures:
            assert "TRAM2" in gt.notes, (
                f"fixture '{gt.sample_id}' notes do not contain source attribution"
            )


class TestTramBenchmarkIntegration:
    def test_benchmark_runs_without_errors(self) -> None:
        """Full synthetic-mode benchmark run on the TRAM fixture set."""
        if not TRAM_FIXTURES_DIR.exists():
            pytest.skip("TRAM fixtures not present.")
        result = run_fixture_benchmark(fixtures_dir=TRAM_FIXTURES_DIR)
        assert result.sample_count > 0
        assert len(result.failed) == 0, f"Failed samples: {result.failed}"

    def test_benchmark_perfect_prediction_f1(self) -> None:
        """In synthetic mode the predicted TTPs equal the ground truth, so F1 must be 1.0."""
        if not TRAM_FIXTURES_DIR.exists():
            pytest.skip("TRAM fixtures not present.")
        result = run_fixture_benchmark(fixtures_dir=TRAM_FIXTURES_DIR)
        assert result.mean_ttp_f1 is not None
        assert abs(result.mean_ttp_f1 - 1.0) < 1e-9, (
            f"Expected F1=1.0 in synthetic mode, got {result.mean_ttp_f1}"
        )

    def test_benchmark_zero_hallucination_in_synthetic_mode(self) -> None:
        """Predicted TTPs come from ground truth, so hallucination rate must be 0."""
        if not TRAM_FIXTURES_DIR.exists():
            pytest.skip("TRAM fixtures not present.")
        result = run_fixture_benchmark(fixtures_dir=TRAM_FIXTURES_DIR)
        assert result.mean_hallucination_rate is not None
        assert result.mean_hallucination_rate == 0.0, (
            f"Expected 0.0 hallucination rate in synthetic mode, "
            f"got {result.mean_hallucination_rate}"
        )
