"""TTP validation result models for ATT&CK-grounded claim validation.

These dataclasses carry the result of running ATTCKValidator against
every ClaimEvidence object extracted from AgentISR reports. The summary
is injected into the JudgeAgent's verdict prompt so the LLM has
authoritative grounding information before generating the STIX Bundle.

Validation logic lives in attck_validator.py.
These models are pure data containers — no business logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TTPClaimValidation:
    """Validation result for a single ClaimEvidence.technique_id field.

    Attributes:
        agent_id:          Name of the agent that made this claim.
        technique_id:      The proposed ATT&CK technique ID.
        claim_text:        The claim text (first 120 chars for brevity).
        evidence_ref:      The cited artifact reference.
        is_valid_id:       True if technique_id exists in the ATT&CK dataset.
        alignment_score:   TF-IDF cosine similarity between evidence and ATT&CK description.
        is_plausible:      True if alignment_score >= HALLUCINATION_SCORE_THRESHOLD.
        suggested_ids:     Top-3 alternative technique IDs (when is_plausible is False).
    """

    agent_id: str
    technique_id: str
    claim_text: str
    evidence_ref: str
    is_valid_id: bool
    alignment_score: float
    is_plausible: bool
    suggested_ids: list[str] = field(default_factory=list)

    @property
    def is_hallucinated(self) -> bool:
        """Return True if the TTP ID is unknown — definitive hallucination signal."""
        return not self.is_valid_id

    @property
    def is_suspicious(self) -> bool:
        """Return True if the ID exists but evidence doesn't match the definition."""
        return self.is_valid_id and not self.is_plausible


@dataclass
class TTPValidationSummary:
    """Aggregate validation results for all TTP claims across all agent ISRs.

    Attributes:
        total_claims:   Total number of TTP claims validated (technique_id != None).
        valid_ids:      Number of claims with a recognized ATT&CK ID.
        invalid_ids:    Number of claims with an unrecognized ID (hallucinations).
        low_alignment:  Number of claims with low evidence-definition alignment.
        results:        Per-claim validation details.
    """

    total_claims: int
    valid_ids: int
    invalid_ids: int
    low_alignment: int
    results: list[TTPClaimValidation] = field(default_factory=list)

    @property
    def hallucination_rate(self) -> float:
        """Fraction of claims with unrecognized TTP IDs."""
        if self.total_claims == 0:
            return 0.0
        return self.invalid_ids / self.total_claims

    def to_prompt_block(self) -> str:
        """Render a compact text block suitable for injection into an LLM prompt.

        The block surfaces only actionable issues (invalid/suspicious TTPs)
        to avoid bloating the context with purely informational noise.
        """
        if self.total_claims == 0:
            return "No structured TTP claims to validate."

        lines: list[str] = [
            f"=== ATT&CK TTP VALIDATION ({self.total_claims} claims) ===",
            f"Valid IDs: {self.valid_ids} | "
            f"Hallucinated IDs: {self.invalid_ids} | "
            f"Low alignment: {self.low_alignment}",
        ]

        issues = [r for r in self.results if r.is_hallucinated or r.is_suspicious]
        if not issues:
            lines.append("All TTP claims passed validation.")
            return "\n".join(lines)

        lines.append("\nFLAGGED CLAIMS (require correction before STIX generation):")
        for r in issues:
            if r.is_hallucinated:
                alts = ", ".join(r.suggested_ids) or "none"
                lines.append(
                    f"  [HALLUCINATED] {r.agent_id}: '{r.technique_id}' not in ATT&CK. "
                    f"Suggested: {alts}"
                )
            else:
                score_str = f"{r.alignment_score:.2f}"
                lines.append(
                    f"  [SUSPICIOUS] {r.agent_id}: '{r.technique_id}'"
                    f" alignment={score_str}."
                    f" Evidence: {r.evidence_ref[:60]}"
                )

        return "\n".join(lines)
