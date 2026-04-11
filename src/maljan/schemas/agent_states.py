import operator
from typing import Annotated, Literal, TypedDict

from pydantic import BaseModel, Field


class AgentArgument(BaseModel):
    """Represents a single argument/finding thrown by an agent during the negotiation phase."""

    agent_name: str = Field(..., description="Name of the agent submitting the argument")
    finding: str = Field(..., description="The main finding or rebutal to another agent's point")
    confidence_score: float = Field(0.0, description="Confidence of this specific argument (0-1)")


class MalwareState(TypedDict):
    """Main state dictionary passed between all nodes in the LangGraph workflow."""

    # Metadata
    file_hash: str
    file_name: str | None

    # Independent Layer Outputs (Step 1)
    static_report: str | None
    dynamic_report: str | None
    network_report: str | None

    # Shared Memory for Müzakere Engine (Step 2)
    # The Annotated operator.add means that when a state update yields a new item,
    # LangGraph will append it to the list instead of overriding the previous list.
    discussion_history: Annotated[list[AgentArgument], operator.add]

    # State tracking
    iteration_count: int
    is_consensus: bool  # New field to trigger early exit

    # Final Output (Step 3) - Final classification and reason
    final_decision: Literal["Malware", "Benign", "Suspicious"] | None
    judge_report: str | None
    stix_output: dict | None  # Serialized Bundle dict
