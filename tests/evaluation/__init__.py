"""Evaluation benchmark package for the Maljan pipeline.

Phase 8.2: Evaluation Benchmark Framework

Provides metric computation and reporting without LLM, network, or file I/O
dependencies in the hot path. All classes accept already-resolved Python
objects and return numeric results suitable for CI assertions or dataset
aggregation.

Public API:
    metrics.NegotiationMetrics    -- negotiation efficiency and integrity
    metrics.TTPAccuracyMetrics    -- ATT&CK TTP precision / recall / F1
    metrics.STIXQualityMetrics    -- STIX bundle structural quality

    benchmark_runner.GroundTruth     -- ground truth container with JSON loader
    benchmark_runner.BenchmarkReport -- aggregated results with Markdown/JSON export
    benchmark_runner.BenchmarkRunner -- orchestrator that produces BenchmarkReport
"""

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

__all__ = [
    "BenchmarkReport",
    "BenchmarkRunner",
    "GroundTruth",
    "NegotiationMetrics",
    "STIXQualityMetrics",
    "TTPAccuracyMetrics",
]
