"""Pydantic models for the mediator's structured output during negotiation.

This module belongs to the pipeline layer — MediatorVerdict is exclusively
used by JudgeAgent.mediate() and is an implementation detail of the
negotiation loop, not a general-purpose data schema.

Using structured output instead of regex-based parsing eliminates fragile
string extraction and makes consensus detection deterministic.
"""

from pydantic import BaseModel, Field


class MediatorVerdict(BaseModel):
    """Structured response produced by the mediator after comparing expert reports."""

    contradictions: list[str] = Field(
        default_factory=list,
        description="Explicit contradictions found between expert reports.",
    )
    resolution_summary: str = Field(
        description="Brief summary of findings and any remaining disagreements.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Confidence that all experts are in agreement. "
            "0.0 = major unresolved contradictions, 1.0 = full consensus."
        ),
    )
