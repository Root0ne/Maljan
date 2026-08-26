"""Evaluation metrics for the Maljan multi-agent analysis pipeline.

Phase 8.2: Evaluation Benchmark Framework

Provides three complementary metric sets for systematic quality assessment:

NegotiationMetrics
    Quantifies the efficiency and integrity of the multi-agent negotiation
    loop: how many rounds were needed, whether sycophancy was detected, and
    how confidently/steeply the agents converged.

TTPAccuracyMetrics
    Precision / recall / F1 of MITRE ATT&CK technique IDs relative to a
    ground-truth set. Also tracks the hallucination rate (technique IDs
    that appear in predictions but are absent from the ATT&CK knowledge
    base or the ground truth).

STIXQualityMetrics
    Structural quality of the output STIX 2.1 Bundle: entity type coverage,
    confidence annotation fill rate, relationship F1 against expected
    relationship types, and mean relationship confidence.

All metric classes are pure-Python dataclasses — no LLM, no I/O, no network.
They accept already-resolved Python objects and return numeric results suitable
for CI assertions, dashboard reporting, or dataset-level aggregation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from maljan.schemas.stix_models import Bundle


# ---------------------------------------------------------------------------
# NegotiationMetrics
# ---------------------------------------------------------------------------


@dataclass
class NegotiationMetrics:
    """Quantifies the quality and efficiency of a negotiation run.

    Attributes:
        rounds_to_consensus:    Number of negotiation rounds completed.
                                Lower is better (efficient convergence).
        max_iterations:         Configured hard cap for this run.
        sycophancy_detected:    Whether forced dissent was triggered at any
                                point (True = system detected echo chamber risk).
        confidence_history:     Ordered list of mediator confidence values per
                                round. Used to compute convergence metrics.
    """

    rounds_to_consensus: int
    max_iterations: int
    sycophancy_detected: bool
    confidence_history: list[float] = field(default_factory=list)

    @property
    def efficiency_ratio(self) -> float:
        """Fraction of allowed iterations consumed.

        Lower is better: 0.5 = converged in half the allowed rounds.
        Returns 1.0 when max_iterations is 0 (degenerate guard).
        """
        if self.max_iterations <= 0:
            return 1.0
        return min(1.0, self.rounds_to_consensus / self.max_iterations)

    @property
    def converged_early(self) -> bool:
        """True when negotiation terminated before reaching the hard cap."""
        return self.rounds_to_consensus < self.max_iterations

    @property
    def confidence_gain(self) -> float:
        """Absolute confidence improvement from first to last round.

        Returns 0.0 when fewer than two data points are available.
        Positive = confidence increased; negative = degraded.
        """
        if len(self.confidence_history) < 2:
            return 0.0
        return self.confidence_history[-1] - self.confidence_history[0]

    @property
    def confidence_std(self) -> float:
        """Standard deviation of the confidence history.

        Near-zero std = tight convergence; high std = oscillating confidence.
        Returns 0.0 for fewer than two data points.
        """
        if len(self.confidence_history) < 2:
            return 0.0
        mean = sum(self.confidence_history) / len(self.confidence_history)
        variance = sum((c - mean) ** 2 for c in self.confidence_history) / len(
            self.confidence_history
        )
        return math.sqrt(variance)

    def to_dict(self) -> dict:
        """Serialize to a plain dict for JSON reporting."""
        return {
            "rounds_to_consensus": self.rounds_to_consensus,
            "max_iterations": self.max_iterations,
            "efficiency_ratio": round(self.efficiency_ratio, 4),
            "converged_early": self.converged_early,
            "sycophancy_detected": self.sycophancy_detected,
            "confidence_gain": round(self.confidence_gain, 4),
            "confidence_std": round(self.confidence_std, 4),
            "confidence_history": [round(c, 4) for c in self.confidence_history],
        }


# ---------------------------------------------------------------------------
# TTPAccuracyMetrics
# ---------------------------------------------------------------------------


@dataclass
class TTPAccuracyMetrics:
    """Precision, recall, and F1 of predicted ATT&CK technique IDs.

    Predicted and ground-truth sets are compared via exact string matching
    on normalized (uppercase, stripped) technique IDs (e.g., "T1055").

    Attributes:
        predicted_ttps:      Set of technique IDs output by the pipeline.
        ground_truth_ttps:   Set of correct technique IDs for this sample.
        attck_valid_ttps:    Optional set of all valid ATT&CK IDs. When
                             provided, enables hallucination_rate computation.
    """

    predicted_ttps: set[str]
    ground_truth_ttps: set[str]
    attck_valid_ttps: set[str] | None = None

    def __post_init__(self) -> None:
        # Normalize all IDs to uppercase for case-insensitive comparison
        self.predicted_ttps = {t.strip().upper() for t in self.predicted_ttps}
        self.ground_truth_ttps = {t.strip().upper() for t in self.ground_truth_ttps}
        if self.attck_valid_ttps is not None:
            self.attck_valid_ttps = {t.strip().upper() for t in self.attck_valid_ttps}

    @property
    def true_positives(self) -> set[str]:
        """TTPs present in both predicted and ground truth."""
        return self.predicted_ttps & self.ground_truth_ttps

    @property
    def false_positives(self) -> set[str]:
        """TTPs predicted but absent from ground truth."""
        return self.predicted_ttps - self.ground_truth_ttps

    @property
    def false_negatives(self) -> set[str]:
        """Ground-truth TTPs that were missed by the pipeline."""
        return self.ground_truth_ttps - self.predicted_ttps

    @property
    def precision(self) -> float:
        """TP / (TP + FP). Returns 0.0 when no predictions were made."""
        if not self.predicted_ttps:
            return 0.0
        return len(self.true_positives) / len(self.predicted_ttps)

    @property
    def recall(self) -> float:
        """TP / (TP + FN). Returns 1.0 when ground truth is empty."""
        if not self.ground_truth_ttps:
            return 1.0
        return len(self.true_positives) / len(self.ground_truth_ttps)

    @property
    def f1(self) -> float:
        """Harmonic mean of precision and recall."""
        p, r = self.precision, self.recall
        if p + r == 0.0:
            return 0.0
        return 2 * p * r / (p + r)

    @property
    def hallucination_rate(self) -> float | None:
        """Fraction of predicted TTPs that are not in the ATT&CK knowledge base.

        Returns None when attck_valid_ttps is not provided.
        0.0 = no hallucinations; 1.0 = all predictions are invalid.
        """
        if self.attck_valid_ttps is None:
            return None
        if not self.predicted_ttps:
            return 0.0
        invalid = self.predicted_ttps - self.attck_valid_ttps
        return len(invalid) / len(self.predicted_ttps)

    def to_dict(self) -> dict:
        """Serialize to a plain dict for JSON reporting."""
        result: dict = {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "true_positives": sorted(self.true_positives),
            "false_positives": sorted(self.false_positives),
            "false_negatives": sorted(self.false_negatives),
        }
        hr = self.hallucination_rate
        result["hallucination_rate"] = round(hr, 4) if hr is not None else None
        return result


# ---------------------------------------------------------------------------
# STIXQualityMetrics
# ---------------------------------------------------------------------------


@dataclass
class STIXQualityMetrics:
    """Structural quality metrics for a STIX 2.1 Bundle output.

    Attributes:
        bundle:                   The STIX Bundle produced by the pipeline.
        expected_entity_types:    STIX object types the caller expects the
                                  bundle to contain (e.g., {"malware",
                                  "attack-pattern", "relationship"}).
        expected_relationship_types: Relationship type verbs expected to
                                  appear in the bundle (e.g., {"uses",
                                  "indicates"}).
    """

    bundle: Bundle
    expected_entity_types: set[str] = field(default_factory=set)
    expected_relationship_types: set[str] = field(default_factory=set)

    # ------------------------------------------------------------------
    # Entity coverage
    # ------------------------------------------------------------------

    @property
    def present_entity_types(self) -> set[str]:
        """Set of STIX object types actually present in the bundle."""
        return {obj.type for obj in self.bundle.objects}

    @property
    def entity_coverage(self) -> float:
        """Fraction of expected entity types present in the bundle.

        Returns 1.0 when expected_entity_types is empty (nothing expected
        = nothing missing).
        """
        if not self.expected_entity_types:
            return 1.0
        found = self.expected_entity_types & self.present_entity_types
        return len(found) / len(self.expected_entity_types)

    @property
    def missing_entity_types(self) -> set[str]:
        """Expected entity types absent from the bundle."""
        return self.expected_entity_types - self.present_entity_types

    # ------------------------------------------------------------------
    # Confidence annotation fill rate
    # ------------------------------------------------------------------

    @property
    def total_relationships(self) -> int:
        """Total relationship objects (annotated + plain) in the bundle."""
        from maljan.schemas.stix_models import ConfidenceAnnotatedRelationship, Relationship

        return sum(
            1
            for obj in self.bundle.objects
            if isinstance(obj, Relationship | ConfidenceAnnotatedRelationship)
        )

    @property
    def annotated_relationships(self) -> int:
        """Count of ConfidenceAnnotatedRelationship objects in the bundle."""
        return len(self.bundle.confidence_annotated_relationships())

    @property
    def confidence_coverage(self) -> float:
        """Fraction of relationships that carry confidence annotations.

        0.0 = no annotations; 1.0 = all relationships annotated.
        Returns 1.0 when no relationships exist.
        """
        if self.total_relationships == 0:
            return 1.0
        return self.annotated_relationships / self.total_relationships

    @property
    def mean_confidence(self) -> float | None:
        """Mean x_maljan_confidence across annotated relationships, or None."""
        return self.bundle.mean_relationship_confidence()

    # ------------------------------------------------------------------
    # Relationship type F1
    # ------------------------------------------------------------------

    @property
    def present_relationship_types(self) -> set[str]:
        """Relationship type verbs present in the bundle."""
        from maljan.schemas.stix_models import ConfidenceAnnotatedRelationship, Relationship

        return {
            obj.relationship_type
            for obj in self.bundle.objects
            if isinstance(obj, Relationship | ConfidenceAnnotatedRelationship)
        }

    @property
    def relationship_type_f1(self) -> float:
        """F1 score for relationship type coverage vs. expected types.

        Treats expected_relationship_types as ground truth and
        present_relationship_types as predictions (set-level comparison).
        Returns 1.0 when expected set is empty.
        """
        if not self.expected_relationship_types:
            return 1.0
        predicted = self.present_relationship_types
        expected = self.expected_relationship_types
        tp = len(predicted & expected)
        if tp == 0:
            return 0.0
        precision = tp / len(predicted) if predicted else 0.0
        recall = tp / len(expected)
        if precision + recall == 0.0:
            return 0.0
        return 2 * precision * recall / (precision + recall)

    def to_dict(self) -> dict:
        """Serialize to a plain dict for JSON reporting."""
        return {
            "entity_coverage": round(self.entity_coverage, 4),
            "missing_entity_types": sorted(self.missing_entity_types),
            "present_entity_types": sorted(self.present_entity_types),
            "total_relationships": self.total_relationships,
            "annotated_relationships": self.annotated_relationships,
            "confidence_coverage": round(self.confidence_coverage, 4),
            "mean_confidence": (
                round(self.mean_confidence, 4) if self.mean_confidence is not None else None
            ),
            "relationship_type_f1": round(self.relationship_type_f1, 4),
            "present_relationship_types": sorted(self.present_relationship_types),
        }
