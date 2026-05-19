"""Multi-Layer TTP Mapping Cascade Engine.

Problem: A single analyst (static, dynamic, or network) can hallucinate or
misattribute a TTP ID. A claim corroborated by multiple independent analysis
layers is far more reliable than one seen in a single layer.

Solution — Cascade Scoring:
  For each unique technique_id present in the ISR reports, the engine:
    1. Collects all contributing layers (agents) and their per-claim confidences.
    2. Computes a weighted confidence per layer using domain-specific weights.
    3. Applies a cross-layer corroboration multiplier when the same technique
       appears in 2, 3, or 4 independent domains.
    4. Produces a CascadeResult with a final weighted_confidence in [0.0, 1.0].

Layer weights:
  - yara:    0.90  (deterministic signature — highest trust, Layer 0)
  - sigma:   0.55  (deterministic log-based rules — Sigma Layer 0)
  - dynamic: 0.45  (API calls / sandbox behaviours — hardest to spoof)
  - static:  0.35  (PE headers / strings / decompiled code)
  - network: 0.20  (weakest alone; strong corroborator)
Unknown domains use DEFAULT_LAYER_WEIGHT = 0.25.

Cross-layer multipliers:
  - 1 layer : 1.00 (no bonus — single point of evidence)
  - 2 layers: 1.25 (corroborated — moderate confidence boost)
  - 3 layers: 1.50 (consensus — strong confidence boost)
  - 4 layers: 1.75 (full consensus — YARA + all 3 LLM domains)
  - 5 layers: 1.90 (maximum — YARA + Sigma + all 3 LLM domains)

Usage:
    from maljan.analysis.ttp_cascade import TTPCascadeEngine

    engine = TTPCascadeEngine()
    summary = engine.compute(isr_reports)        # dict[str, AgentISR]
    block = summary.to_prompt_block(top_k=8)     # inject into LLM prompt
    top = summary.top_techniques(n=5)            # ranked CascadeResult list
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from maljan.core.logger import logger

if TYPE_CHECKING:
    from maljan.schemas.isr_models import AgentISR

# ---------------------------------------------------------------------------
# Layer weights — domain -> relative weight in confidence calculation
# ---------------------------------------------------------------------------

LAYER_WEIGHTS: dict[str, float] = {
    "yara": 0.90,  # deterministic signature matching (Layer 0)
    "sigma": 0.55,  # deterministic log-based rules (Sigma Layer 0)
    "dynamic": 0.45,  # sandbox behavioral evidence
    "static": 0.35,  # PE/decompiled code analysis
    "network": 0.20,  # network traffic analysis
}

# Unknown domains fall back to this weight
DEFAULT_LAYER_WEIGHT: float = 0.25

# Cross-layer corroboration multipliers keyed by number of contributing layers
CROSS_LAYER_MULTIPLIERS: dict[int, float] = {
    1: 1.00,
    2: 1.25,
    3: 1.50,
    4: 1.75,  # YARA + Sigma + 2 LLM domains
    5: 1.90,  # YARA + Sigma + all 3 LLM domains
}

# If more layers somehow contribute, cap at the 5-layer multiplier
_MAX_MULTIPLIER: float = max(CROSS_LAYER_MULTIPLIERS.values())


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


@dataclass
class LayerContribution:
    """Evidence contribution from a single analysis layer for one technique.

    Attributes:
        domain:       Analysis domain (e.g. "dynamic").
        agent_id:     Agent identifier (e.g. "dynamic_analyst").
        claim_count:  Number of claims referencing this technique from this layer.
        mean_confidence: Mean of per-claim confidence scores.
        evidence_refs: Cited artifact references (deduplicated, max 3).
    """

    domain: str
    agent_id: str
    claim_count: int
    mean_confidence: float
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class CascadeResult:
    """Aggregated cross-layer cascade result for one ATT&CK technique.

    Attributes:
        technique_id:         MITRE ATT&CK technique ID (e.g. "T1055").
        contributing_layers:  Domains that reported evidence (e.g. ["static", "dynamic"]).
        layer_contributions:  Per-layer breakdown of evidence and confidence.
        layer_confidences:    domain -> mean_confidence mapping (for quick access).
        raw_weighted_confidence: Weighted average BEFORE cross-layer multiplier.
        cross_layer_multiplier:  Applied multiplier (1.0, 1.25, or 1.50).
        weighted_confidence:  Final confidence score in [0.0, 1.0].
        total_evidence_count: Total number of claims across all layers.
    """

    technique_id: str
    contributing_layers: list[str]
    layer_contributions: list[LayerContribution]
    layer_confidences: dict[str, float]
    raw_weighted_confidence: float
    cross_layer_multiplier: float
    weighted_confidence: float
    total_evidence_count: int

    @property
    def is_corroborated(self) -> bool:
        """True if at least 2 independent layers provide evidence."""
        return len(self.contributing_layers) >= 2

    @property
    def is_consensus(self) -> bool:
        """True if all 3 standard layers provide evidence."""
        return all(d in self.contributing_layers for d in ("static", "dynamic", "network"))

    def corroboration_label(self) -> str:
        """Human-readable corroboration level."""
        n = len(self.contributing_layers)
        if n >= 3:
            return "CONSENSUS"
        if n == 2:
            return "CORROBORATED"
        return "SINGLE-LAYER"

    def layer_summary(self) -> str:
        """Compact per-layer confidence summary string."""
        by_confidence = sorted(
            self.layer_contributions,
            key=lambda x: x.mean_confidence,
            reverse=True,
        )
        parts = [f"{lc.domain}={lc.mean_confidence:.2f}({lc.claim_count})" for lc in by_confidence]
        return " | ".join(parts)


@dataclass
class CascadeSummary:
    """Full cascade analysis results across all ISR reports.

    Attributes:
        results:       CascadeResult for every unique technique_id found.
        total_techniques: Count of unique techniques.
        corroborated_count: Count of techniques with 2+ layers.
        consensus_count: Count of techniques with all 3 layers.
    """

    results: list[CascadeResult]
    total_techniques: int
    corroborated_count: int
    consensus_count: int

    def top_techniques(self, n: int = 10) -> list[CascadeResult]:
        """Return the top-n techniques by weighted_confidence (descending)."""
        return sorted(self.results, key=lambda r: r.weighted_confidence, reverse=True)[:n]

    def to_prompt_block(self, top_k: int = 8) -> str:
        """Render a compact, LLM-ready block of the top-k cascade results.

        Highlights corroboration level, final confidence, and contributing layers
        so the Judge LLM can prioritize the most reliable TTP mappings.

        Args:
            top_k: Maximum number of techniques to include in the block.

        Returns:
            Multi-line string for injection into the JudgeAgent's verdict prompt.
            Returns a minimal message if no techniques were found.
        """
        if not self.results:
            return "=== TTP CASCADE: No structured TTP claims found across ISR reports. ==="

        top = self.top_techniques(n=top_k)
        lines: list[str] = [
            f"=== THREE-LAYER TTP CASCADE ANALYSIS ({self.total_techniques} techniques) ===",
            f"Corroborated (2+ layers): {self.corroborated_count} | "
            f"Consensus (3 layers): {self.consensus_count}",
            "",
            "Top techniques by weighted confidence:",
        ]

        for r in top:
            label = r.corroboration_label()
            layers_str = ", ".join(r.contributing_layers)
            lines.append(
                f"  [{label}] {r.technique_id} — "
                f"confidence={r.weighted_confidence:.3f} "
                f"(x{r.cross_layer_multiplier}) | "
                f"layers=[{layers_str}] | evidence={r.total_evidence_count}"
            )
            lines.append(f"    {r.layer_summary()}")

        lines.append("")
        lines.append(
            "INSTRUCTION: Prioritize [CONSENSUS] and [CORROBORATED] techniques in "
            "the STIX Bundle. [SINGLE-LAYER] techniques require additional scrutiny."
        )

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Cascade Engine
# ---------------------------------------------------------------------------


class TTPCascadeEngine:
    """Computes cross-layer TTP evidence scores from a set of AgentISR objects.

    This engine is stateless — call compute() for each analysis run.
    It is designed to be used in the judge node after all ISR reports
    are collected and before JudgeAgent.give_verdict() is invoked.

    Usage:
        engine = TTPCascadeEngine()
        summary = engine.compute(state["isr_reports"])
    """

    def compute(
        self,
        isr_reports: dict[str, AgentISR],
        layer_weights: dict[str, float] | None = None,
    ) -> CascadeSummary:
        """Compute the three-layer TTP cascade for a complete set of ISR reports.

        Args:
            isr_reports: Mapping of agent_id to AgentISR from pipeline state.
            layer_weights: Optional override for domain weights. Defaults to
                           LAYER_WEIGHTS (dynamic=0.45, static=0.35, network=0.20).

        Returns:
            CascadeSummary with per-technique cascade results and aggregate stats.
        """
        weights = layer_weights or LAYER_WEIGHTS

        # Step 1: Group claims by technique_id → domain → claims
        tech_domain_claims: dict[str, dict[str, list]] = {}

        # Pre-filter invalid technique IDs so cascade only works with real TTPs.
        # Audit 2026-05-19 SIG-T0000-01: ``T0000`` matches ``T\d{4}`` and was
        # leaking past this guard. Reject the curated placeholder set
        # explicitly as belt-and-braces.
        _VALID_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
        _CASCADE_DENYLIST = frozenset({"T0000", "T0000.000", "T9999", "T1234"})
        for isr in isr_reports.values():
            for claim in isr.claims:
                if claim.technique_id is None:
                    continue
                tid = claim.technique_id
                if not _VALID_TID_RE.match(tid) or tid in _CASCADE_DENYLIST:
                    logger.debug("Skipping invalid technique_id '%s' from cascade.", tid)
                    continue
                dom: str = isr.domain  # type: ignore[assignment]
                agent = isr.agent_id

                if tid not in tech_domain_claims:
                    tech_domain_claims[tid] = {}
                if dom not in tech_domain_claims[tid]:
                    tech_domain_claims[tid][dom] = []
                tech_domain_claims[tid][dom].append((agent, claim))

        # Step 2: Build CascadeResult for each technique
        results: list[CascadeResult] = []

        for tid, domain_map in tech_domain_claims.items():
            contributions: list[LayerContribution] = []
            layer_confidences: dict[str, float] = {}
            total_claims = 0

            for dom, agent_claims in domain_map.items():
                confidences = [c.confidence for _, c in agent_claims]
                refs = list({c.evidence_ref for _, c in agent_claims})[:3]
                mean_conf = sum(confidences) / len(confidences)

                # Use the agent_id from the first claim
                agent_id = agent_claims[0][0]

                contributions.append(
                    LayerContribution(
                        domain=dom,
                        agent_id=agent_id,
                        claim_count=len(agent_claims),
                        mean_confidence=mean_conf,
                        evidence_refs=refs,
                    )
                )
                layer_confidences[dom] = mean_conf
                total_claims += len(agent_claims)

            # Step 3: Weighted average across contributing layers
            contributing_domains = list(domain_map.keys())
            weight_sum = sum(weights.get(d, DEFAULT_LAYER_WEIGHT) for d in contributing_domains)

            if weight_sum == 0:
                raw_weighted = 0.0
            else:
                raw_weighted = (
                    sum(
                        weights.get(d, DEFAULT_LAYER_WEIGHT) * layer_confidences[d]
                        for d in contributing_domains
                    )
                    / weight_sum
                )

            # Step 4: Cross-layer multiplier
            n_layers = len(contributing_domains)
            multiplier = CROSS_LAYER_MULTIPLIERS.get(n_layers, _MAX_MULTIPLIER)
            final_confidence = min(raw_weighted * multiplier, 1.0)

            results.append(
                CascadeResult(
                    technique_id=tid,
                    contributing_layers=contributing_domains,
                    layer_contributions=contributions,
                    layer_confidences=layer_confidences,
                    raw_weighted_confidence=raw_weighted,
                    cross_layer_multiplier=multiplier,
                    weighted_confidence=final_confidence,
                    total_evidence_count=total_claims,
                )
            )

        corroborated = sum(1 for r in results if r.is_corroborated)
        consensus = sum(1 for r in results if r.is_consensus)

        logger.info(
            "TTP cascade: %d techniques | %d corroborated | %d consensus.",
            len(results),
            corroborated,
            consensus,
        )

        return CascadeSummary(
            results=results,
            total_techniques=len(results),
            corroborated_count=corroborated,
            consensus_count=consensus,
        )
