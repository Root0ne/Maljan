"""benchmark_suite.py — Phase 8.2 Maljan Evaluation Benchmark Suite.

Provides:

    BenchmarkSuite
        Runs BenchmarkRunner against a list of (pipeline_state, ground_truth)
        pairs, aggregates results, and produces a Markdown/JSON summary report.
        Designed to run offline (no LLM, no network) against saved pipeline
        outputs or mock states.

    from_run_summary(run_summary, ground_truth)
        Bridge function that converts a RunSummary dict (as stored in
        AnalysisState["run_summary"]) into a BenchmarkRunner, so benchmark
        evaluation can be performed immediately after any pipeline run.

    load_fixture_suite(fixtures_dir)
        Loads all *.json ground truth fixtures from a directory and returns a
        list of GroundTruth objects ready for batch evaluation.

CLI usage (via `maljan benchmark` or `python -m tests.evaluation.benchmark_suite`):
    Runs the built-in fixture suite with synthetic pipeline outputs and prints
    a Markdown summary to stdout.

All metric computation is deterministic and dependency-free (no sklearn, no
sentence-transformers, no LLM). The suite runs in < 1 second on any machine
and is safe to include in the CI test matrix.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tests.evaluation.benchmark_runner import (
    BenchmarkReport,
    BenchmarkRunner,
    GroundTruth,
)

# Default fixtures directory relative to this file.
_DEFAULT_FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# RunSummary bridge
# ---------------------------------------------------------------------------


def from_run_summary(
    run_summary: dict[str, Any],
    stix_bundle: Any,
    ground_truth: GroundTruth,
) -> BenchmarkRunner:
    """Build a BenchmarkRunner from a RunSummary dict.

    The RunSummary dict is the value stored in AnalysisState["run_summary"]
    after a completed pipeline run. This bridge extracts the fields needed by
    BenchmarkRunner so evaluation can happen immediately after any analysis.

    Args:
        run_summary:   The dict from AnalysisState["run_summary"].
        stix_bundle:   The STIX Bundle object from AnalysisState["stix_output"]
                       parsed into a maljan.schemas.stix_models.Bundle.
        ground_truth:  Pre-loaded GroundTruth for this sample.

    Returns:
        A configured BenchmarkRunner ready for .run().
    """
    neg = run_summary.get("negotiation", {})
    cascade = run_summary.get("cascade", {})

    # Collect predicted TTP IDs from the cascade summary (most complete source).
    predicted_ttps: set[str] = set()
    for result in cascade.get("results", []):
        tid = result.get("technique_id")
        if tid:
            predicted_ttps.add(str(tid).strip().upper())

    # Fall back to ISR agent stats if cascade is empty (pre-cascade pipeline).
    if not predicted_ttps:
        for agent_stat in run_summary.get("isr_agents", []):
            for tid in agent_stat.get("technique_ids", []):
                if tid:
                    predicted_ttps.add(str(tid).strip().upper())

    confidence_history: list[float] = neg.get("confidence_history", [])
    rounds_completed: int = int(neg.get("rounds_completed", 0))
    max_rounds: int = int(neg.get("max_rounds", 1))
    sycophancy_events: int = int(neg.get("sycophancy_events", 0))

    return BenchmarkRunner(
        sample_id=run_summary.get("sample_id", ground_truth.sample_id),
        ground_truth=ground_truth,
        stix_bundle=stix_bundle,
        predicted_ttps=predicted_ttps,
        negotiation_rounds=rounds_completed,
        max_iterations=max_rounds,
        sycophancy_detected=sycophancy_events > 0,
        confidence_history=confidence_history,
    )


# ---------------------------------------------------------------------------
# Fixture loader
# ---------------------------------------------------------------------------


def load_fixture_suite(fixtures_dir: str | Path | None = None) -> list[GroundTruth]:
    """Load all *.json ground truth fixtures from a directory.

    Args:
        fixtures_dir: Directory path. Defaults to tests/evaluation/fixtures/.

    Returns:
        List of GroundTruth objects sorted by sample_id.
    """
    directory = Path(fixtures_dir) if fixtures_dir else _DEFAULT_FIXTURES_DIR
    fixtures: list[GroundTruth] = []
    for path in sorted(directory.glob("*.json")):
        try:
            fixtures.append(GroundTruth.from_json(path))
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            print(f"[WARNING] Skipping malformed fixture {path.name}: {exc}", file=sys.stderr)
    return fixtures


# ---------------------------------------------------------------------------
# Suite result container
# ---------------------------------------------------------------------------


@dataclass
class SuiteResult:
    """Aggregated results for a multi-sample benchmark run.

    Attributes:
        reports:       Individual BenchmarkReport per sample.
        failed:        Sample IDs that raised exceptions during evaluation.
    """

    reports: list[BenchmarkReport] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Aggregate statistics
    # ------------------------------------------------------------------

    @property
    def sample_count(self) -> int:
        return len(self.reports)

    @property
    def mean_ttp_f1(self) -> float | None:
        """Mean TTP F1 across all successful samples."""
        if not self.reports:
            return None
        return sum(r.ttp_accuracy.f1 for r in self.reports) / len(self.reports)

    @property
    def mean_negotiation_efficiency(self) -> float | None:
        """Mean efficiency_ratio (rounds_used / max_rounds) across samples."""
        if not self.reports:
            return None
        return sum(r.negotiation.efficiency_ratio for r in self.reports) / len(self.reports)

    @property
    def mean_confidence_coverage(self) -> float | None:
        """Mean fraction of relationships that carry confidence annotations."""
        if not self.reports:
            return None
        return sum(r.stix_quality.confidence_coverage for r in self.reports) / len(self.reports)

    @property
    def sycophancy_rate(self) -> float | None:
        """Fraction of samples in which sycophancy was detected."""
        if not self.reports:
            return None
        count = sum(1 for r in self.reports if r.negotiation.sycophancy_detected)
        return count / len(self.reports)

    @property
    def mean_hallucination_rate(self) -> float | None:
        """Mean hallucination rate across samples that provide attck_valid_ids."""
        rates = [
            r.ttp_accuracy.hallucination_rate
            for r in self.reports
            if r.ttp_accuracy.hallucination_rate is not None
        ]
        if not rates:
            return None
        return sum(rates) / len(rates)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_count": self.sample_count,
            "failed_count": len(self.failed),
            "failed_sample_ids": self.failed,
            "aggregate": {
                "mean_ttp_f1": round(self.mean_ttp_f1, 4) if self.mean_ttp_f1 is not None else None,
                "mean_negotiation_efficiency": (
                    round(self.mean_negotiation_efficiency, 4)
                    if self.mean_negotiation_efficiency is not None
                    else None
                ),
                "mean_confidence_coverage": (
                    round(self.mean_confidence_coverage, 4)
                    if self.mean_confidence_coverage is not None
                    else None
                ),
                "sycophancy_rate": (
                    round(self.sycophancy_rate, 4) if self.sycophancy_rate is not None else None
                ),
                "mean_hallucination_rate": (
                    round(self.mean_hallucination_rate, 4)
                    if self.mean_hallucination_rate is not None
                    else None
                ),
            },
            "samples": [r.to_dict() for r in self.reports],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        """Render a Markdown summary report for the full suite."""
        lines: list[str] = ["# Maljan Evaluation Benchmark Suite", ""]

        # Aggregate table
        lines += [
            "## Aggregate Results",
            "",
            f"- Samples evaluated: **{self.sample_count}**",
            f"- Samples failed: **{len(self.failed)}**",
            "",
            "| Metric | Value |",
            "|---|---|",
        ]

        def _fmt(val: float | None, pct: bool = False) -> str:
            if val is None:
                return "N/A"
            return f"{val:.2%}" if pct else f"{val:.4f}"

        lines += [
            f"| Mean TTP F1 | {_fmt(self.mean_ttp_f1)} |",
            f"| Mean negotiation efficiency | {_fmt(self.mean_negotiation_efficiency, pct=True)} |",
            f"| Mean confidence coverage | {_fmt(self.mean_confidence_coverage, pct=True)} |",
            f"| Sycophancy rate | {_fmt(self.sycophancy_rate, pct=True)} |",
            f"| Mean hallucination rate | {_fmt(self.mean_hallucination_rate, pct=True)} |",
            "",
        ]

        # Per-sample table
        lines += [
            "## Per-Sample Results",
            "",
            "| Sample | TTP F1 | Hallucination Rate | Rounds | Conf. Coverage |",
            "|---|---|---|---|---|",
        ]
        for r in self.reports:
            hr = r.ttp_accuracy.hallucination_rate
            hr_str = f"{hr:.2%}" if hr is not None else "N/A"
            lines.append(
                f"| {r.sample_id} "
                f"| {r.ttp_accuracy.f1:.2%} "
                f"| {hr_str} "
                f"| {r.negotiation.rounds_to_consensus}/{r.negotiation.max_iterations} "
                f"| {r.stix_quality.confidence_coverage:.2%} |"
            )
        lines.append("")

        if self.failed:
            lines += ["## Failed Samples", ""]
            for s in self.failed:
                lines.append(f"- {s}")
            lines.append("")

        return "\n".join(lines)

    def save_json(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    def save_markdown(self, path: str | Path) -> None:
        Path(path).write_text(self.to_markdown(), encoding="utf-8")


# ---------------------------------------------------------------------------
# BenchmarkSuite
# ---------------------------------------------------------------------------


class BenchmarkSuite:
    """Runs multiple BenchmarkRunners and aggregates results.

    Usage (with synthetic/mock pipeline outputs):
        suite = BenchmarkSuite()
        suite.add(runner_1)
        suite.add(runner_2)
        result = suite.run()
        print(result.to_markdown())

    Usage (from_fixture_dir):
        suite = BenchmarkSuite.from_fixture_dir(
            fixtures_dir="tests/evaluation/fixtures",
            pipeline_outputs={
                "ransomware_sample_1": (pipeline_state_dict, stix_bundle),
                "rat_sample_1":        (pipeline_state_dict, stix_bundle),
            }
        )
        result = suite.run()
    """

    def __init__(self) -> None:
        self._runners: list[BenchmarkRunner] = []

    def add(self, runner: BenchmarkRunner) -> None:
        """Register a runner for batch evaluation."""
        self._runners.append(runner)

    def run(self) -> SuiteResult:
        """Execute all registered runners and return aggregated results."""
        result = SuiteResult()
        for runner in self._runners:
            try:
                report = runner.run()
                result.reports.append(report)
            except Exception as exc:
                result.failed.append(f"{runner._sample_id}: {exc}")
        return result

    @classmethod
    def from_fixture_dir(
        cls,
        pipeline_outputs: dict[str, tuple[dict[str, Any], Any]],
        fixtures_dir: str | Path | None = None,
    ) -> BenchmarkSuite:
        """Build a suite from a fixture directory and corresponding pipeline outputs.

        Args:
            pipeline_outputs: Mapping of sample_id -> (run_summary_dict, stix_bundle).
            fixtures_dir:     Path to the fixtures directory. Uses default if None.

        Returns:
            Configured BenchmarkSuite ready for .run().
        """
        suite = cls()
        ground_truths = {gt.sample_id: gt for gt in load_fixture_suite(fixtures_dir)}

        for sample_id, (run_summary, stix_bundle) in pipeline_outputs.items():
            if sample_id not in ground_truths:
                print(
                    f"[WARNING] No ground truth fixture found for '{sample_id}'. Skipping.",
                    file=sys.stderr,
                )
                continue
            runner = from_run_summary(run_summary, stix_bundle, ground_truths[sample_id])
            suite.add(runner)

        return suite


# ---------------------------------------------------------------------------
# Fixture-based standalone runner (used by `maljan benchmark` CLI and CI)
# ---------------------------------------------------------------------------


def _make_synthetic_bundle(technique_ids: list[str]) -> Any:
    """Build a minimal STIX Bundle from a list of technique IDs.

    This is used by the fixture-based benchmark runner to produce synthetic
    pipeline outputs for smoke-testing the evaluation framework without
    requiring a real LLM run.
    """
    from maljan.schemas.stix_models import (
        AttackPattern,
        Bundle,
        ConfidenceAnnotatedRelationship,
        Malware,
    )

    malware_id = "malware--benchmark-0001"
    objects: list[Any] = [Malware(id=malware_id, name="BenchmarkSample")]

    for i, tid in enumerate(technique_ids):
        ap_id = f"attack-pattern--benchmark-{i:04d}"
        objects.append(AttackPattern(id=ap_id, name=tid))
        objects.append(
            ConfidenceAnnotatedRelationship(
                relationship_type="uses",
                source_ref=malware_id,
                target_ref=ap_id,
                x_maljan_confidence=0.75,
                x_maljan_evidence_basis="all",
            )
        )

    return Bundle(objects=objects)


def _make_synthetic_run_summary(
    sample_id: str,
    technique_ids: list[str],
    rounds: int = 2,
    max_rounds: int = 3,
    sycophancy_events: int = 0,
    confidence_history: list[float] | None = None,
) -> dict[str, Any]:
    """Build a minimal RunSummary dict for fixture-based benchmark runs."""
    return {
        "sample_id": sample_id,
        "negotiation": {
            "rounds_completed": rounds,
            "max_rounds": max_rounds,
            "termination_reason": "convergence",
            "sycophancy_events": sycophancy_events,
            "confidence_history": confidence_history or [0.65, 0.80, 0.88],
            "final_confidence": (confidence_history or [0.88])[-1],
        },
        "cascade": {
            "results": [{"technique_id": tid, "final_confidence": 0.75} for tid in technique_ids],
        },
        "isr_agents": [],
    }


def run_fixture_benchmark(
    fixtures_dir: str | Path | None = None,
    output_path: str | Path | None = None,
    output_format: str = "markdown",
) -> SuiteResult:
    """Run the full fixture-based benchmark suite.

    Loads every *.json file from fixtures_dir, synthesizes pipeline outputs
    from the ground truth technique IDs (simulating a perfect-precision run),
    and evaluates all metric sets.

    This gives a baseline: with perfect TTP prediction, what STIX quality
    and negotiation efficiency does the framework produce?

    Args:
        fixtures_dir:   Path to fixture directory (default: tests/evaluation/fixtures/).
        output_path:    Optional path to write the report (JSON or Markdown).
        output_format:  "markdown" or "json".

    Returns:
        SuiteResult with all reports populated.
    """
    fixtures = load_fixture_suite(fixtures_dir)
    if not fixtures:
        print("[WARNING] No fixtures found. Returning empty suite result.", file=sys.stderr)
        return SuiteResult()

    pipeline_outputs: dict[str, tuple[dict[str, Any], Any]] = {}
    for gt in fixtures:
        technique_ids = sorted(gt.technique_ids)
        run_summary = _make_synthetic_run_summary(gt.sample_id, technique_ids)
        stix_bundle = _make_synthetic_bundle(technique_ids)
        pipeline_outputs[gt.sample_id] = (run_summary, stix_bundle)

    suite = BenchmarkSuite.from_fixture_dir(pipeline_outputs, fixtures_dir)
    result = suite.run()

    if output_path:
        path = Path(output_path)
        if output_format == "json":
            result.save_json(path)
        else:
            result.save_markdown(path)

    return result


# ---------------------------------------------------------------------------
# Entry point (python -m tests.evaluation.benchmark_suite)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Maljan Evaluation Benchmark Suite (Phase 8.2)")
    parser.add_argument(
        "--fixtures-dir",
        default=None,
        help="Path to ground truth fixtures directory (default: tests/evaluation/fixtures/)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional path to write report (e.g., benchmark_report.md)",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format: markdown (default) or json",
    )
    args = parser.parse_args()

    suite_result = run_fixture_benchmark(
        fixtures_dir=args.fixtures_dir,
        output_path=args.output,
        output_format=args.format,
    )
    print(suite_result.to_markdown())
    if args.output:
        print(f"\nReport written to: {args.output}", file=sys.stderr)
