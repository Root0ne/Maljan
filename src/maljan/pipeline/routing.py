"""Routing strategies for the negotiation loop.

Determines whether to continue iterating (revision) or proceed to the judge.

Decision priority (highest to lowest):
  1. Hard iteration limit — unconditional judge.
  2. Sycophancy override — if sycophancy AND consensus, force revision.
  3. Genuine LLM consensus — judge.
  4. Adaptive termination — statistical confidence convergence → judge.
  5. Default → revision.

Convergence criterion:
  - Window: last CONFIDENCE_WINDOW finite values.
  - Sample std (n-1 in denominator) < CONVERGENCE_STD_THRESHOLD.
  - Mean(window) >= MIN_CONVERGENCE_CONFIDENCE.
  - NaN / inf values are filtered out before computation; if the resulting
    window is too short, the loop continues.

Rationale: SELENE (arXiv) showed adaptive stopping reduces token cost ~50%
without sacrificing accuracy. Sample std (Bessel-corrected) is the standard
statistical estimator for small windows.
"""

from __future__ import annotations

import math

from maljan.core.config import Settings
from maljan.core.logger import logger
from maljan.pipeline.state import AnalysisState

CONFIDENCE_WINDOW: int = 3
CONVERGENCE_STD_THRESHOLD: float = 0.04
MIN_CONVERGENCE_CONFIDENCE: float = 0.70


def _sample_std(values: list[float]) -> float:
    """Sample (Bessel-corrected) standard deviation. ``inf`` if n<2."""
    n = len(values)
    if n < 2:
        return float("inf")
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    return math.sqrt(variance)


def _finite(values: list[float]) -> list[float]:
    return [v for v in values if math.isfinite(v)]


def is_confidence_stable(
    confidence_history: list[float],
    window: int = CONFIDENCE_WINDOW,
    std_threshold: float = CONVERGENCE_STD_THRESHOLD,
    min_confidence: float = MIN_CONVERGENCE_CONFIDENCE,
) -> bool:
    """Return True if recent confidence values have statistically stabilized.

    NaN / inf entries are dropped before assessment. Requires at least
    ``window`` finite values.
    """
    finite_history = _finite(confidence_history)
    if len(finite_history) < window:
        return False

    recent = finite_history[-window:]
    std = _sample_std(recent)
    mean = sum(recent) / len(recent)

    stable = std < std_threshold and mean >= min_confidence
    if stable:
        logger.info(
            "Adaptive termination: confidence stable (std=%.4f < %.2f, mean=%.3f >= %.2f).",
            std,
            std_threshold,
            mean,
            min_confidence,
        )
    else:
        logger.debug(
            "Adaptive termination: not yet stable "
            "(std=%.4f, std_threshold=%.2f, mean=%.3f, min=%.2f, n=%d).",
            std,
            std_threshold,
            mean,
            min_confidence,
            len(finite_history),
        )
    return stable


class ConsensusRouter:
    """Routes the workflow based on consensus detection and iteration limits."""

    def __init__(self, config: Settings) -> None:
        self._config = config

    def should_continue(self, state: AnalysisState) -> str:
        """Conditional router for LangGraph.

        Returns:
            "judge" to finalize, "revision" to continue negotiating.
        """
        iteration = state.get("iteration_count", 0)
        consensus = state.get("is_consensus", False)
        syco = state.get("sycophancy_detected", False)
        confidence_history: list[float] = state.get("confidence_history") or []
        max_iter = self._config.negotiation.max_iterations

        # 1. Hard limit always wins.
        if iteration >= max_iter:
            logger.info("Hard iteration limit (%d) reached. Proceeding to judge.", max_iter)
            return "judge"

        # 2. Sycophancy override: a "consensus" that comes with sycophancy
        # is treated as premature → force another revision.
        if syco and consensus:
            logger.info(
                "Sycophancy override: consensus premature at round %d. Forcing revision.",
                iteration,
            )
            return "revision"

        # 3. Genuine consensus (no sycophancy).
        if consensus:
            logger.info("Genuine consensus reached at round %d.", iteration)
            return "judge"

        # 4. Adaptive termination on the confidence series.
        if is_confidence_stable(confidence_history):
            logger.info(
                "Adaptive termination triggered at round %d (stable confidence).", iteration
            )
            return "judge"

        return "revision"
