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
    # Whether that id survived validation. ``pipeline.validation`` sets this
    # ``False`` when the analyst kept an id the ATT&CK catalogue does not have,
    # after being told so and given another turn. The id itself stays exactly
    # as the analyst wrote it — a wrong id that says it is wrong is worth more
    # than a right-looking id somebody else substituted — and the flag is what
    # the report, the FP linter and the STIX minting step read instead.
    technique_id_valid: bool = Field(
        default=True,
        description="False when the technique id is not in the ATT&CK catalogue.",
    )
    # The platforms the source rule/layer explicitly declared (``["windows"]``
    # for a Sigma rule with ``logsource.product=windows``, ``["any"]`` for a
    # YARA rule annotated cross-platform). ``None`` means the producing layer
    # declared nothing, which is every analyst claim.
    rule_platforms: list[str] | None = Field(
        default=None,
        description="Platform tags the source rule declared, when it declared any.",
    )


class Artifact(BaseModel):
    """One concrete thing an analyst established, in the shape it has.

    A hash is a value; an import list is a table; a set of C2 endpoints is a
    table with two columns. The model carries both shapes rather than forcing
    one, because forcing one is how a table becomes a comma-joined string
    nobody can sort.

    ``kind`` groups artifacts across agents into a report section — ``hashes``,
    ``imports``, ``permissions``, ``iocs``, ``processes``, ``persistence``,
    ``endpoints``. It is a free string on purpose: an analyst that found
    something the vocabulary has no word for should say the word, not the
    nearest wrong one.
    """

    kind: str = Field(..., description="What this artifact is, e.g. 'imports' or 'iocs'.")
    label: str = Field("", description="Human name for this artifact.")
    value: str | None = Field(None, description="The value, when the artifact is a single fact.")
    columns: list[str] | None = Field(None, description="Column headings, when it is a table.")
    rows: list[list[str]] | None = Field(None, description="Rows, when it is a table.")
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="Ledger entry ids this artifact was read from, e.g. ['ev_0007'].",
    )
    source: str = Field("", description="Which agent or tool established it.")


class Finding(BaseModel):
    """A conclusion an analyst reached, with what it was drawn from.

    Deliberately not a ``ClaimEvidence``: a claim is what the negotiation
    argues about and carries one prose evidence reference, while a finding is
    what the report prints and carries the ledger ids behind it plus the
    artifacts it established. The two channels coexist; neither replaces the
    other.
    """

    title: str = Field(..., description="One line naming the finding.")
    detail: str = Field("", description="What was observed, in the analyst's own words.")
    category: str = Field("", description="Free-form grouping, e.g. 'persistence'.")
    technique_ids: list[str] = Field(
        default_factory=list, description="MITRE ATT&CK technique ids, e.g. ['T1055']."
    )
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Analyst self-reported confidence.")
    evidence_ids: list[str] = Field(
        default_factory=list, description="Ledger entry ids supporting this finding."
    )
    artifacts: list[Artifact] = Field(
        default_factory=list, description="Artifacts established alongside it."
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
    # The optional structured channel (``agents.findings_block``). Empty for an
    # agent that wrote only prose, which is every agent that ignores the
    # channel — it adds to the ISR contract and replaces nothing in it.
    findings: list[Finding] = Field(
        default_factory=list,
        description="Structured conclusions this agent emitted, with their evidence ids.",
    )
    artifacts: list[Artifact] = Field(
        default_factory=list,
        description="Concrete artifacts this agent established, for the report's sections.",
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
