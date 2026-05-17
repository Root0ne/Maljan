"""Analysis state schema for the LangGraph workflow.

The state uses agent-keyed dicts (reports, isr_reports) instead of hardcoded
per-agent fields. Adding a new agent does NOT require any schema change.
"""

import operator
from typing import Annotated, Any, Literal, TypedDict

from pydantic import BaseModel, Field

from maljan.schemas.isr_models import AgentISR


class AgentArgument(BaseModel):
    """A single argument or finding raised by an agent during negotiation."""

    agent_name: str = Field(..., description="Name of the agent submitting the argument")
    finding: str = Field(..., description="The main finding or rebuttal")
    confidence_score: float = Field(0.0, description="Confidence of this specific argument (0-1)")


def _merge_dicts[V](left: dict[str, V], right: dict[str, V]) -> dict[str, V]:
    """LangGraph reducer: shallow merge; right keys overwrite left."""
    merged: dict[str, V] = {**left}
    merged.update(right)
    return merged


class AnalysisState(TypedDict):
    """State dictionary passed between all nodes in the LangGraph workflow."""

    # Sample metadata
    file_hash: str
    file_name: str | None
    sample_path: str | None
    sandbox_report: dict[str, Any] | None

    # Per-agent text reports
    reports: Annotated[dict[str, str], _merge_dicts]
    revised_reports: Annotated[dict[str, str], _merge_dicts]

    # Per-agent structured ISR reports
    isr_reports: Annotated[dict[str, AgentISR], _merge_dicts]

    # Mediator/argument log (append-only)
    discussion_history: Annotated[list[AgentArgument], operator.add]

    # Sycophancy detection flag for the latest negotiation round
    sycophancy_detected: bool

    # Per-round mean-confidence values for adaptive termination
    confidence_history: Annotated[list[float], operator.add]

    # Iteration tracking
    iteration_count: int
    is_consensus: bool

    # Final output
    final_decision: Literal["Malware", "Benign", "Suspicious"] | None
    judge_report: str | None
    stix_output: dict[str, Any] | None

    # Observability: serialized RunSummary dict, populated after verdict generation.
    run_summary: dict[str, Any] | None

    # Comprehensive malware analysis report produced by ``report_node`` after
    # the judge verdict. Stays ``None`` if the reporting feature is disabled
    # (``config.reporting.enabled = False``) — downstream consumers fall back
    # to the legacy ``judge_report`` / ``stix_output`` pair.
    malware_report: dict[str, Any] | None
    malware_report_markdown: str | None
    stix_bundle_extended: dict[str, Any] | None
