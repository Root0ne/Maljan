"""Dynamic analysis state for the LangGraph workflow.

The state uses a generic `reports` dict instead of hardcoded per-agent fields.
When a new agent is registered, it writes to reports["agent_name"] automatically
without requiring any state schema changes.
"""

import operator
from typing import Annotated, Any, Literal, TypedDict

from pydantic import BaseModel, Field


class AgentArgument(BaseModel):
    """Represents a single argument/finding thrown by an agent during negotiation."""

    agent_name: str = Field(..., description="Name of the agent submitting the argument")
    finding: str = Field(..., description="The main finding or rebuttal")
    confidence_score: float = Field(
        0.0, description="Confidence of this specific argument (0-1)"
    )


def _merge_dicts(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """LangGraph reducer: merge two dicts (right overwrites left keys)."""
    merged = {**left}
    merged.update(right)
    return merged


class AnalysisState(TypedDict):
    """Main state dictionary passed between all nodes in the LangGraph workflow.

    Key design: `reports` and `revised_reports` are generic dicts keyed by
    agent name. Adding a new agent does NOT require changing this schema.
    """

    # Sample metadata
    file_hash: str
    file_name: str | None

    # Agent reports: {"static": "...", "dynamic": "...", "network": "...", ...}
    reports: Annotated[dict[str, str], _merge_dicts]
    revised_reports: Annotated[dict[str, str], _merge_dicts]

    # Negotiation shared memory
    discussion_history: Annotated[list[AgentArgument], operator.add]

    # Iteration tracking
    iteration_count: int
    is_consensus: bool

    # Final output
    final_decision: Literal["Malware", "Benign", "Suspicious"] | None
    judge_report: str | None
    stix_output: dict | None
