"""BenchmarkRunner — aggregates all metric sets into a single report.

Phase 8.2: Evaluation Benchmark Framework

BenchmarkRunner accepts a pipeline output (GraphState or its equivalent
fields) and a GroundTruth object, runs all three metric computations, and
produces a BenchmarkReport that can be printed as Markdown, serialized to
JSON, or used in pytest assertions.

Designed to work with any ground truth data source:
  - Local fixture files (tests/evaluation/fixtures/)
  - aCTIon dataset (204 STIX bundles) when available
  - Custom evaluation datasets

No LLM calls, no network access, no file I/O in the hot path.
All I/O (load_ground_truth, save_report) is isolated in explicit helpers.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tests.evaluation.metrics import (
    NegotiationMetrics,
    STIXQualityMetrics,
    TTPAccuracyMetrics,
)

# ---------------------------------------------------------------------------
# Ground truth container
# ---------------------------------------------------------------------------


@dataclass
class GroundTruth:
    """Ground truth for a single malware sample.

    Attributes:
        sample_id:           Identifier matching the pipeline run.
        technique_ids:       Authoritative set of ATT&CK technique IDs.
        expected_stix_types: STIX object types expected in the output bundle.
        expected_rel_types:  Relationship type verbs expected in the bundle.
        attck_valid_ids:     Optional full ATT&CK ID set for hallucination
                             rate computation. When None, hallucination_rate
                             is omitted from the report.
        notes:               Free-text annotation for dataset documentation.
    """

    sample_id: str
    technique_ids: set[str]
    expected_stix_types: set[str] = field(
        default_factory=lambda: {"malware", "attack-pattern", "relationship"}
    )
    expected_rel_types: set[str] = field(
        default_factory=lambda: {"uses", "indicates"}
    )
    attck_valid_ids: set[str] | None = None
    notes: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GroundTruth:
        """Deserialize from a plain dict (e.g., loaded from a JSON fixture)."""
        return cls(
            sample_id=data["sample_id"],
            technique_ids=set(data.get("technique_ids", [])),
            expected_stix_types=set(
                data.get("expected_stix_types", ["malware", "attack-pattern", "relationship"])
            ),
            expected_rel_types=set(data.get("expected_rel_types", ["uses", "indicates"])),
            attck_valid_ids=(
                set(data["attck_valid_ids"]) if "attck_valid_ids" in data else None
            ),
            notes=data.get("notes", ""),
        )

    @classmethod
    def from_json(cls, path: str | Path) -> GroundTruth:
        """Load a single GroundTruth from a JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)


# ---------------------------------------------------------------------------
# Benchmark report
# ---------------------------------------------------------------------------


@dataclass
class BenchmarkReport:
    """Aggregated benchmark results for a single pipeline run.

    All metric objects are retained for programmatic access; to_dict()
    and to_markdown() provide serialization for CI output and dashboards.
    """

    sample_id: str
    negotiation: NegotiationMetrics
    ttp_accuracy: TTPAccuracyMetrics
    stix_quality: STIXQualityMetrics

    def to_dict(self) -> dict[str, Any]:
        """Serialize all metrics to a plain dict."""
        return {
            "sample_id": self.sample_id,
            "negotiation": self.negotiation.to_dict(),
            "ttp_accuracy": self.ttp_accuracy.to_dict(),
            "stix_quality": self.stix_quality.to_dict(),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        """Render a human-readable Markdown report."""
        neg = self.negotiation
        ttp = self.ttp_accuracy
        stix = self.stix_quality

        hr_value = ttp.hallucination_rate
        hr_str = f"{hr_value:.2%}" if hr_value is not None else "N/A"

        mc = stix.mean_confidence
        mc_str = f"{mc:.3f}" if mc is not None else "N/A"

        lines = [
            f"# Benchmark Report — `{self.sample_id}`",
            "",
            "## Negotiation",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Rounds to consensus | {neg.rounds_to_consensus} / {neg.max_iterations} |",
            f"| Efficiency ratio | {neg.efficiency_ratio:.2%} |",
            f"| Converged early | {neg.converged_early} |",
            f"| Sycophancy detected | {neg.sycophancy_detected} |",
            f"| Confidence gain | {neg.confidence_gain:+.3f} |",
            f"| Confidence std | {neg.confidence_std:.3f} |",
            "",
            "## TTP Accuracy",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Precision | {ttp.precision:.2%} |",
            f"| Recall | {ttp.recall:.2%} |",
            f"| F1 | {ttp.f1:.2%} |",
            f"| Hallucination rate | {hr_str} |",
            f"| True positives | {sorted(ttp.true_positives)} |",
            f"| False positives | {sorted(ttp.false_positives)} |",
            f"| False negatives | {sorted(ttp.false_negatives)} |",
            "",
            "## STIX Quality",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Entity coverage | {stix.entity_coverage:.2%} |",
            f"| Confidence coverage | {stix.confidence_coverage:.2%} |",
            f"| Mean confidence | {mc_str} |",
            f"| Relationship type F1 | {stix.relationship_type_f1:.2%} |",
            f"| Missing entity types | {sorted(stix.missing_entity_types) or 'none'} |",
        ]
        return "\n".join(lines)

    def save_json(self, path: str | Path) -> None:
        """Write the JSON report to a file."""
        Path(path).write_text(self.to_json(), encoding="utf-8")

    def save_markdown(self, path: str | Path) -> None:
        """Write the Markdown report to a file."""
        Path(path).write_text(self.to_markdown(), encoding="utf-8")


# ---------------------------------------------------------------------------
# BenchmarkRunner
# ---------------------------------------------------------------------------


class BenchmarkRunner:
    """Orchestrates all metric computations for a single pipeline run.

    Usage:
        runner = BenchmarkRunner(
            sample_id="ransomware_1",
            ground_truth=GroundTruth.from_json("fixtures/ransomware_1.json"),
            stix_bundle=bundle,
            predicted_ttps={"T1486", "T1490"},
            negotiation_rounds=2,
            max_iterations=3,
            sycophancy_detected=False,
            confidence_history=[0.60, 0.78, 0.85],
        )
        report = runner.run()
        print(report.to_markdown())
    """

    def __init__(
        self,
        sample_id: str,
        ground_truth: GroundTruth,
        stix_bundle: Any,
        predicted_ttps: set[str],
        negotiation_rounds: int,
        max_iterations: int,
        sycophancy_detected: bool = False,
        confidence_history: list[float] | None = None,
    ) -> None:
        self._sample_id = sample_id
        self._ground_truth = ground_truth
        self._bundle = stix_bundle
        self._predicted_ttps = predicted_ttps
        self._negotiation_rounds = negotiation_rounds
        self._max_iterations = max_iterations
        self._sycophancy_detected = sycophancy_detected
        self._confidence_history = confidence_history or []

    def run(self) -> BenchmarkReport:
        """Compute all metric sets and return a consolidated report."""
        neg_metrics = NegotiationMetrics(
            rounds_to_consensus=self._negotiation_rounds,
            max_iterations=self._max_iterations,
            sycophancy_detected=self._sycophancy_detected,
            confidence_history=self._confidence_history,
        )

        ttp_metrics = TTPAccuracyMetrics(
            predicted_ttps=self._predicted_ttps,
            ground_truth_ttps=self._ground_truth.technique_ids,
            attck_valid_ttps=self._ground_truth.attck_valid_ids,
        )

        stix_metrics = STIXQualityMetrics(
            bundle=self._bundle,
            expected_entity_types=self._ground_truth.expected_stix_types,
            expected_relationship_types=self._ground_truth.expected_rel_types,
        )

        return BenchmarkReport(
            sample_id=self._sample_id,
            negotiation=neg_metrics,
            ttp_accuracy=ttp_metrics,
            stix_quality=stix_metrics,
        )

    @classmethod
    def from_dict(
        cls,
        pipeline_output: dict[str, Any],
        ground_truth: GroundTruth,
        stix_bundle: Any,
    ) -> BenchmarkRunner:
        """Construct a runner from a pipeline output dictionary.

        Extracts standard pipeline fields so callers do not need to
        unpack GraphState manually.

        Expected pipeline_output keys:
            sample_id, negotiation_rounds, max_iterations,
            sycophancy_detected, confidence_history, predicted_ttps
        """
        return cls(
            sample_id=pipeline_output.get("sample_id", ground_truth.sample_id),
            ground_truth=ground_truth,
            stix_bundle=stix_bundle,
            predicted_ttps=set(pipeline_output.get("predicted_ttps", [])),
            negotiation_rounds=pipeline_output.get("negotiation_rounds", 0),
            max_iterations=pipeline_output.get("max_iterations", 1),
            sycophancy_detected=pipeline_output.get("sycophancy_detected", False),
            confidence_history=pipeline_output.get("confidence_history", []),
        )
