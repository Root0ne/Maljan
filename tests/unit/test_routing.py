"""Unit tests for ConsensusRouter and adaptive termination helpers."""

from __future__ import annotations

from unittest.mock import MagicMock

from maljan.pipeline.routing import (
    MIN_CONVERGENCE_CONFIDENCE,
    ConsensusRouter,
    is_confidence_stable,
)
from maljan.pipeline.state import AnalysisState

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_state(
    iteration: int,
    consensus: bool,
    sycophancy: bool,
    confidence_history: list[float] | None = None,
) -> AnalysisState:
    return {
        "file_hash": "abc123",
        "file_name": None,
        "reports": {},
        "revised_reports": {},
        "isr_reports": {},
        "discussion_history": [],
        "sycophancy_detected": sycophancy,
        "confidence_history": confidence_history or [],
        "iteration_count": iteration,
        "is_consensus": consensus,
        "final_decision": None,
        "judge_report": None,
        "stix_output": None,
    }


def _make_router(max_iterations: int = 5) -> ConsensusRouter:
    config = MagicMock()
    config.negotiation.max_iterations = max_iterations
    return ConsensusRouter(config)


# ---------------------------------------------------------------------------
# is_confidence_stable()
# ---------------------------------------------------------------------------


class TestIsConfidenceStable:
    def test_too_few_values_returns_false(self) -> None:
        assert is_confidence_stable([0.9, 0.91]) is False

    def test_exactly_window_stable_values(self) -> None:
        # std([0.90, 0.91, 0.90]) ≈ 0.004 < 0.04, mean=0.903 > 0.70
        assert is_confidence_stable([0.90, 0.91, 0.90]) is True

    def test_high_variance_not_stable(self) -> None:
        # std([0.5, 0.8, 0.6]) ≈ 0.124 > 0.04
        assert is_confidence_stable([0.5, 0.8, 0.6]) is False

    def test_stable_but_low_confidence(self) -> None:
        # std is small but mean=0.3 < MIN_CONVERGENCE_CONFIDENCE
        assert is_confidence_stable([0.30, 0.30, 0.31]) is False

    def test_only_uses_last_window_values(self) -> None:
        # First 5 values are noisy, last 3 are stable and high
        history = [0.3, 0.6, 0.5, 0.88, 0.89, 0.88]
        assert is_confidence_stable(history) is True

    def test_custom_window(self) -> None:
        # With window=2, need only 2 stable values
        assert is_confidence_stable([0.88, 0.89], window=2) is True

    def test_custom_threshold(self) -> None:
        # std([0.80, 0.85, 0.80]) ≈ 0.023 — passes 0.04 but fails 0.02
        assert is_confidence_stable([0.80, 0.85, 0.80], std_threshold=0.02) is False
        assert is_confidence_stable([0.80, 0.85, 0.80], std_threshold=0.04) is True

    def test_exactly_at_min_confidence_boundary(self) -> None:
        # Use a value just above the boundary to avoid float precision edge cases.
        # The boundary itself (0.70 == 0.70) can fail due to floating point repr.
        val = MIN_CONVERGENCE_CONFIDENCE + 0.01  # 0.71
        assert is_confidence_stable([val, val, val]) is True

    def test_single_value_not_stable(self) -> None:
        assert is_confidence_stable([0.99]) is False

    def test_empty_history_not_stable(self) -> None:
        assert is_confidence_stable([]) is False


# ---------------------------------------------------------------------------
# ConsensusRouter.should_continue()
# ---------------------------------------------------------------------------


class TestConsensusRouter:
    # --- Existing tests (Phase 1 behavior preserved) ---

    def test_proceeds_to_judge_on_consensus_no_syco(self) -> None:
        router = _make_router()
        state = _make_state(iteration=1, consensus=True, sycophancy=False)
        assert router.should_continue(state) == "judge"

    def test_overrides_consensus_when_sycophancy_detected(self) -> None:
        router = _make_router(max_iterations=5)
        state = _make_state(iteration=1, consensus=True, sycophancy=True)
        assert router.should_continue(state) == "revision"

    def test_hard_limit_overrides_sycophancy(self) -> None:
        router = _make_router(max_iterations=3)
        state = _make_state(iteration=3, consensus=True, sycophancy=True)
        assert router.should_continue(state) == "judge"

    def test_continues_without_consensus(self) -> None:
        router = _make_router()
        state = _make_state(iteration=1, consensus=False, sycophancy=False)
        assert router.should_continue(state) == "revision"

    def test_hard_limit_forces_judge(self) -> None:
        router = _make_router(max_iterations=3)
        state = _make_state(iteration=3, consensus=False, sycophancy=False)
        assert router.should_continue(state) == "judge"

    def test_zero_iteration_continues(self) -> None:
        router = _make_router()
        state = _make_state(iteration=0, consensus=False, sycophancy=False)
        assert router.should_continue(state) == "revision"

    # --- Phase 2: Adaptive termination ---

    def test_adaptive_termination_stable_history(self) -> None:
        """Stable confidence history triggers judge even without LLM consensus."""
        router = _make_router(max_iterations=10)
        state = _make_state(
            iteration=4,
            consensus=False,
            sycophancy=False,
            confidence_history=[0.6, 0.7, 0.88, 0.89, 0.88],
        )
        assert router.should_continue(state) == "judge"

    def test_adaptive_termination_unstable_history_continues(self) -> None:
        """Unstable confidence history continues negotiation."""
        router = _make_router(max_iterations=10)
        state = _make_state(
            iteration=3,
            consensus=False,
            sycophancy=False,
            confidence_history=[0.5, 0.75, 0.6],
        )
        assert router.should_continue(state) == "revision"

    def test_adaptive_termination_too_few_rounds_continues(self) -> None:
        """Fewer than CONFIDENCE_WINDOW rounds never triggers adaptive stop."""
        router = _make_router(max_iterations=10)
        state = _make_state(
            iteration=2,
            consensus=False,
            sycophancy=False,
            confidence_history=[0.95, 0.95],  # only 2 values, window=3
        )
        assert router.should_continue(state) == "revision"

    def test_adaptive_termination_low_confidence_stable_continues(self) -> None:
        """Low-but-stable confidence must NOT trigger adaptive stop."""
        router = _make_router(max_iterations=10)
        state = _make_state(
            iteration=4,
            consensus=False,
            sycophancy=False,
            confidence_history=[0.30, 0.30, 0.31, 0.30],
        )
        assert router.should_continue(state) == "revision"

    def test_hard_limit_beats_adaptive_termination(self) -> None:
        """Hard limit is checked BEFORE adaptive termination."""
        router = _make_router(max_iterations=3)
        state = _make_state(
            iteration=3,
            consensus=False,
            sycophancy=False,
            confidence_history=[0.3, 0.5, 0.6],  # unstable — but limit hit
        )
        assert router.should_continue(state) == "judge"

    def test_sycophancy_beats_adaptive_termination(self) -> None:
        """Sycophancy + consensus overrides even a stable confidence history."""
        router = _make_router(max_iterations=10)
        state = _make_state(
            iteration=3,
            consensus=True,
            sycophancy=True,
            confidence_history=[0.88, 0.89, 0.88],  # stable → but sycophancy wins
        )
        assert router.should_continue(state) == "revision"

    def test_empty_confidence_history_no_adaptive(self) -> None:
        """Empty history never triggers adaptive termination."""
        router = _make_router(max_iterations=10)
        state = _make_state(
            iteration=1,
            consensus=False,
            sycophancy=False,
            confidence_history=[],
        )
        assert router.should_continue(state) == "revision"
