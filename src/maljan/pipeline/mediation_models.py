"""Pydantic models for the mediator's structured output during negotiation.

This module belongs to the pipeline layer — MediatorVerdict is exclusively
used by JudgeAgent.mediate() and is an implementation detail of the
negotiation loop, not a general-purpose data schema.

Using structured output instead of regex-based parsing eliminates fragile
string extraction and makes consensus detection deterministic.
"""

from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import BaseModel, Field

# Agreement is a relation between analysts that said something. Below two of
# them there is nothing for it to measure, so no agreement value is recorded.
MIN_ANALYSTS_FOR_CONSENSUS = 2


def analysts_with_claims(names: Iterable[str], isr_reports: Mapping[str, Any] | None) -> list[str]:
    """The debate's participants whose report carries at least one claim.

    An ISR is found under its participant's name or its own ``agent_id``, the
    two keys the pipeline files it under.
    """
    by_id = {
        str(getattr(isr, "agent_id", "") or key): isr for key, isr in (isr_reports or {}).items()
    }
    found: list[str] = []
    for name in names:
        isr = (isr_reports or {}).get(name) or by_id.get(name)
        if isr is not None and list(getattr(isr, "claims", None) or []):
            found.append(name)
    return found


def consensus_applies(names: Iterable[str], isr_reports: Mapping[str, Any] | None) -> bool:
    """Whether enough participants produced claims for agreement to mean anything."""
    return len(analysts_with_claims(names, isr_reports)) >= MIN_ANALYSTS_FOR_CONSENSUS


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
