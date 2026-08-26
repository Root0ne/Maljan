"""Intermediate Structural Representation (ISR) models for inter-agent communication.

Instead of passing raw text between agents in the negotiation loop,
agents exchange structured ISR objects. This prevents context bloat and
forces agents to cite concrete evidence for every claim they make.

Literature basis:
  - MalEval (arXiv:2509.14335): LLMs fail when passing raw code slices between agents.
  - CONSENSAGENT (arXiv): Structured formats reduce sycophancy.
  - Multi-Agent Malware Analysis Framework Research (internal report).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ClaimEvidence(BaseModel):
    """A single verifiable claim with supporting evidence.

    Agents must cite a concrete artifact reference for each claim.
    This prevents hallucinated capabilities and forces grounded reasoning.
    """

    claim: str = Field(..., description="The specific finding or assertion.")
    evidence_ref: str = Field(
        ...,
        description=(
            "Concrete artifact reference, e.g. 'API call: VirtualAllocEx @ 0x401234', "
            "'PCAP frame 42: dst=185.220.101.5:443', 'string at .data+0x10: /api/c2'."
        ),
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Agent self-reported confidence (0-1)."
    )
    technique_id: str | None = Field(
        None,
        description="MITRE ATT&CK technique ID if applicable, e.g. 'T1055.001'.",
        pattern=r"^T\d{4}(\.\d{3})?$",
    )
    # Wave 4 (2026-05-28): the platforms the source rule/layer explicitly
    # declared (e.g. ["windows"] for a Sigma rule with
    # ``logsource.product=windows``, ["any"] for a YARA rule annotated
    # cross-platform). Cascade engine prefers this over the MITRE catalog
    # for the platform-compatibility check — that way a YARA rule
    # explicitly marked cross-platform can still fire on a Linux
    # sample even when MITRE Enterprise says T1497 only targets
    # Windows. ``None`` means the producing layer didn't
    # declare anything (analyst LLM claim or legacy rule); cascade then
    # falls back to MITRE platforms.
    rule_platforms: list[str] | None = Field(
        default=None,
        description=(
            "Platform tags the source rule/layer declared (Sigma "
            "logsource.product, YARA platform metadata). Used by the TTP "
            "cascade as the primary platform-compatibility signal."
        ),
    )


class AgentISR(BaseModel):
    """Full Intermediate Structural Representation from one analyst agent.

    This replaces the raw `str` report in the negotiation loop. The agent
    must enumerate its claims and explicitly list any items from peer reports
    it still disputes after each revision round.
    """

    agent_id: str = Field(..., description="Registry name of the agent, e.g. 'static'.")
    domain: Literal["static", "dynamic", "network", "yara", "sigma"] | str = Field(
        ..., description="Analysis domain this agent covers."
    )
    claims: list[ClaimEvidence] = Field(
        default_factory=list,
        description="Ordered list of evidence-backed claims.",
    )
    dissent_items: list[str] = Field(
        default_factory=list,
        description=(
            "Claims from peer ISRs that this agent still disputes. "
            "An empty list signals active convergence (not passive silence). "
            "Round > 0 with empty dissent is treated as a convergence signal."
        ),
    )
    revision_round: int = Field(
        0, ge=0, description="Which negotiation round produced this ISR (0 = initial)."
    )

    @property
    def mean_confidence(self) -> float:
        """Average confidence across all claims. Returns 0.0 if no claims."""
        if not self.claims:
            return 0.0
        return sum(c.confidence for c in self.claims) / len(self.claims)

    def to_text_summary(self) -> str:
        """Render this ISR as a concise human-readable text block.

        Used when the ISR must be passed to an LLM prompt as context.
        The format is compact to minimise token consumption.
        """
        lines: list[str] = [
            f"[{self.agent_id.upper()} ANALYST — round {self.revision_round}]",
            f"Domain: {self.domain} | Mean confidence: {self.mean_confidence:.2f}",
        ]

        for i, claim in enumerate(self.claims, 1):
            tech = f" ({claim.technique_id})" if claim.technique_id else ""
            lines.append(
                f"  Claim {i}: {claim.claim}{tech}"
                f" | Evidence: {claim.evidence_ref}"
                f" | Confidence: {claim.confidence:.2f}"
            )

        if self.dissent_items:
            lines.append("  Disputes:")
            for item in self.dissent_items:
                lines.append(f"    - {item}")
        else:
            if self.revision_round > 0:
                lines.append("  [CONVERGENCE SIGNAL: no remaining disputes]")

        return "\n".join(lines)
