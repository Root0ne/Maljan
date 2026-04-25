"""Routing strategies for the negotiation loop.

Determines whether to continue iterating (revision) or proceed to the judge.

Phase 1: Sycophancy-aware routing — sycophancy detection overrides premature consensus.
Phase 2: Adaptive termination — replaces a fixed round-count exit with a statistical
         convergence detector based on a rolling standard deviation window over the
         per-round mean-confidence values stored in `state["confidence_history"]`.

Convergence criterion (Phase 2):
  - Window: last CONFIDENCE_WINDOW rounds
  - Condition: std(window) < CONVERGENCE_STD_THRESHOLD AND mean(window) >= MIN_CONFIDENCE
  - Rationale: SELENE (arXiv) showed adaptive stopping reduces token cost ~50% without
    sacrificing accuracy. Rolling std is dependency-free and robust for 3-5 round windows.
"""

from __future__ import annotations

import math

from maljan.core.config import Settings
from maljan.core.logger import logger
from maljan.pipeline.state import AnalysisState

# Number of consecutive rounds to examine for convergence
CONFIDENCE_WINDOW: int = 3

# Std threshold below which confidence is considered stable
CONVERGENCE_STD_THRESHOLD: float = 0.04

# Minimum mean confidence required to declare stable convergence
# (prevents declaring convergence at a stably-low confidence like 0.3)
MIN_CONVERGENCE_CONFIDENCE: float = 0.70


def _rolling_std(values: list[float]) -> float:
    """Pure-Python rolling standard deviation over a list of floats."""
    n = len(values)
    if n < 2:
        return float("inf")
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n
    return math.sqrt(variance)


def is_confidence_stable(
    confidence_history: list[float],
    window: int = CONFIDENCE_WINDOW,
    std_threshold: float = CONVERGENCE_STD_THRESHOLD,
    min_confidence: float = MIN_CONVERGENCE_CONFIDENCE,
) -> bool:
    """Return True if the agent consensus confidence has statistically stabilized.

    Requires at least `window` rounds of history. The confidence must also be
    above `min_confidence` to rule out stable low-confidence deadlocks.

    Args:
        confidence_history: Per-round mean-confidence values (growing list).
        window: How many recent rounds to examine.
        std_threshold: Maximum allowed standard deviation to declare stability.
        min_confidence: Minimum mean confidence to accept stability.

    Returns:
        True if confidence is stable and high enough to finalize.
    """
    if len(confidence_history) < window:
        return False

    recent = confidence_history[-window:]
    std = _rolling_std(recent)
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
            "Adaptive termination: not yet stable (std=%.4f, mean=%.3f, history_len=%d).",
            std,
            mean,
            len(confidence_history),
        )
    return stable


class ConsensusRouter:
    """Routes the workflow based on consensus detection and iteration limits.

    Decision priority (highest to lowest):
      1. Hard iteration limit — always sends to judge regardless of other conditions.
      2. Sycophancy override — if sycophancy detected AND consensus, force revision.
      3. Genuine LLM consensus (no sycophancy) — proceed to judge.
      4. Adaptive termination — confidence history is statistically stable → judge.
      5. Default — continue with revision.
    """

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

        # 1. Hard limit always takes precedence
        if iteration >= max_iter:
            logger.info("Hard iteration limit (%d) reached. Proceeding to judge.", max_iter)
            return "judge"

        # 2. Sycophancy detected: override consensus and force another revision round
        if syco and consensus:
            logger.info(
                "Sycophancy override: consensus premature at round %d. Forcing revision.",
                iteration,
            )
            return "revision"

        # 3. Genuine LLM consensus (no sycophancy)
        if consensus:
            logger.info("Genuine consensus reached at round %d.", iteration)
            return "judge"

        # 4. Adaptive termination: statistical convergence on confidence_history
        if is_confidence_stable(confidence_history):
            logger.info(
                "Adaptive termination triggered at round %d (stable confidence).", iteration
            )
            return "judge"

        return "revision"
