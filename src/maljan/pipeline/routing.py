"""Routing strategies for the negotiation loop.

Determines whether to continue iterating (revision) or proceed to the judge.
"""

from maljan.core.config import Settings
from maljan.pipeline.state import AnalysisState


class ConsensusRouter:
    """Routes the workflow based on consensus detection and iteration limits."""

    def __init__(self, config: Settings) -> None:
        self._config = config

    def should_continue(self, state: AnalysisState) -> str:
        """Conditional router for LangGraph.

        Returns:
            "judge" if consensus reached or max iterations exceeded.
            "revision" otherwise.
        """
        iteration = state.get("iteration_count", 0)
        consensus = state.get("is_consensus", False)
        max_iter = self._config.negotiation.max_iterations

        if consensus or iteration >= max_iter:
            return "judge"

        return "revision"
