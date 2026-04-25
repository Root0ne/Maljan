"""Dynamic analysis state for the LangGraph workflow.

The state uses a generic `reports` dict instead of hardcoded per-agent fields.
When a new agent is registered, it writes to reports["agent_name"] automatically
without requiring any state schema changes.

Phase 1 additions:
  - `isr_reports`: Structured ISR objects replacing raw text inter-agent passing.
  - `sycophancy_detected`: Flag set when the sycophancy detector fires this round.
  - `confidence_history`: Per-round mean-confidence snapshots for adaptive termination.
"""

import operator
from typing import Annotated, Any, Literal, TypedDict

from pydantic import BaseModel, Field

from maljan.schemas.isr_models import AgentISR


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


def _merge_isr_dicts(
    left: dict[str, AgentISR], right: dict[str, AgentISR]
) -> dict[str, AgentISR]:
    """LangGraph reducer for ISR dicts (right overwrites left keys)."""
    merged = {**left}
    merged.update(right)
    return merged


class AnalysisState(TypedDict):
    """Main state dictionary passed between all nodes in the LangGraph workflow.

    Key design: `reports`, `revised_reports`, `isr_reports` are all generic
    dicts keyed by agent name. Adding a new agent does NOT require changing
    this schema.
    """

    # Sample metadata
    file_hash: str
    file_name: str | None

    # Agent reports: {"static": "...", "dynamic": "...", "network": "...", ...}
    # Legacy text format — kept for backward compatibility and LLM prompts.
    reports: Annotated[dict[str, str], _merge_dicts]
    revised_reports: Annotated[dict[str, str], _merge_dicts]

    # Structured ISR reports: {"static": AgentISR, "dynamic": AgentISR, ...}
    # Phase 1: agents populate this alongside their text reports.
    isr_reports: Annotated[dict[str, AgentISR], _merge_isr_dicts]

    # Negotiation shared memory
    discussion_history: Annotated[list[AgentArgument], operator.add]

    # Sycophancy tracking
    # True if the detector fired in the most recent negotiation round.
    sycophancy_detected: bool

    # Confidence history: list of per-round mean-confidence values across all agents.
    # Used by the adaptive termination router (Phase 2).
    confidence_history: Annotated[list[float], operator.add]

    # Iteration tracking
    iteration_count: int
    is_consensus: bool

    # Final output
    final_decision: Literal["Malware", "Benign", "Suspicious"] | None
    judge_report: str | None
    stix_output: dict | None

    # Observability: serialized RunSummary dict, populated after verdict generation.
    run_summary: dict | None

    # Internal: propagated so RunSummaryBuilder can read configured max iterations.
    _max_iterations: int
