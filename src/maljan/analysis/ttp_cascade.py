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

# Layer-0 sources whose confidences come from a rule match rather than a model's
# opinion. Pooling for these is max(), not mean() — see the comment at the pooling
# site. Deliberately a name check rather than a domain check: `import_capability`
# shares domain="static" with the LLM static analyst, which is the whole reason
# the distinction is needed.
_DETERMINISTIC_AGENTS: frozenset[str] = frozenset(
    {"import_capability", "lolbin", "network_dga", "tool_artifact", "yara_layer", "sigma_layer"}
)

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
class DroppedTechnique:
    """One technique the cascade rejected for platform-incompatibility.

    Carried forward (Wave 4) under ``CascadeSummary.dropped_by_platform``
    so the UI/FP-linter can render forensic transparency rather than
    silently swallowing claims.
    """

    technique_id: str
    source_layer: str
    rule_platforms: list[str]
    sample_platform: str
    reason: str


@dataclass
class CascadeSummary:
    """Full cascade analysis results across all ISR reports.

    Attributes:
        results:       CascadeResult for every unique technique_id found.
        total_techniques: Count of unique techniques.
        corroborated_count: Count of techniques with 2+ layers.
        consensus_count: Count of techniques with all 3 layers.
        dropped_by_platform: Wave 4 (2026-05-28) audit trail of claims
            rejected because the source rule's platform didn't match the
            sample. Empty for legacy runs that didn't supply a platform.
    """

    results: list[CascadeResult]
    total_techniques: int
    corroborated_count: int
    consensus_count: int
    dropped_by_platform: list[DroppedTechnique] = field(default_factory=list)

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
        sample_platform: str | None = None,
        empty_domains: frozenset[str] | None = None,
    ) -> CascadeSummary:
        """Compute the three-layer TTP cascade for a complete set of ISR reports.

        Args:
            isr_reports: Mapping of agent_id to AgentISR from pipeline state.
            layer_weights: Optional override for domain weights. Defaults to
                           LAYER_WEIGHTS (dynamic=0.45, static=0.35, network=0.20).
            sample_platform: Wave 4 (2026-05-28) — when set, the cascade
                drops claims whose source rule explicitly declared an
                incompatible platform. ``None`` preserves legacy behaviour.
            empty_domains: 2026-07 audit — domains that had NO real input data
                this run (e.g. ``{"dynamic", "network"}`` when the sandbox never
                ran). Claims tagged with an empty domain are dropped so an
                absent layer can't be counted as independent corroboration. This
                is what inflated T1497 to 1.00 "corroborated across 4 layers"
                when dynamic+network were both empty. ``None`` = gate nothing.

        Returns:
            CascadeSummary with per-technique cascade results and aggregate stats.
        """
        weights = layer_weights or LAYER_WEIGHTS
        empty_domains = empty_domains or frozenset()

        # Step 1: Group claims by technique_id → domain → claims
        tech_domain_claims: dict[str, dict[str, list]] = {}
        dropped: list[DroppedTechnique] = []

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

                # Wave 4: platform-compatibility check via source-layer
                # declaration first, then MITRE catalog with a mobile-enterprise
                # overlap allowlist. See plan ``Step 4`` for resolution order.
                if not _is_claim_platform_compatible(
                    claim_platforms=claim.rule_platforms,
                    sample_platform=sample_platform,
                    technique_id=tid,
                ):
                    dropped.append(
                        DroppedTechnique(
                            technique_id=tid,
                            source_layer=isr.domain,  # type: ignore[arg-type]
                            rule_platforms=list(claim.rule_platforms or []),
                            sample_platform=sample_platform or "unknown",
                            reason="platform_mismatch",
                        )
                    )
                    logger.debug(
                        "Cascade dropped %s (layer=%s) — rule_platforms=%s sample=%s",
                        tid,
                        isr.domain,
                        claim.rule_platforms,
                        sample_platform,
                    )
                    continue

                dom: str = isr.domain  # type: ignore[assignment]
                agent = isr.agent_id

                # 2026-07 audit: an absent layer cannot corroborate. A claim
                # tagged to a domain that produced no real data this run (e.g. a
                # "dynamic" sandbox-evasion claim when no sandbox ever ran) is
                # dropped so it neither becomes an independent contributing layer
                # nor feeds the cross-layer multiplier.
                if dom in empty_domains:
                    dropped.append(
                        DroppedTechnique(
                            technique_id=tid,
                            source_layer=dom,  # type: ignore[arg-type]
                            rule_platforms=list(claim.rule_platforms or []),
                            sample_platform=sample_platform or "unknown",
                            reason="empty_domain",
                        )
                    )
                    logger.debug(
                        "Cascade dropped %s — domain '%s' had no input data this run.",
                        tid,
                        dom,
                    )
                    continue

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
                # Averaging is right for several LLM opinions and wrong the
                # moment a deterministic rule is one of the voices. The import
                # layer emits dozens of techniques on domain="static", the same
                # domain the LLM static analyst writes to, so collisions are
                # routine: mean(rule 0.62, LLM 0.90) = 0.76 *lowers* a finding
                # two independent sources agree on, and mean(rule 0.62, LLM
                # 0.30) = 0.46 lets a guess drag a grounded rule down. Take the
                # strongest voice instead when one of them is a rule match.
                if any(agent in _DETERMINISTIC_AGENTS for agent, _ in agent_claims):
                    mean_conf = max(confidences)
                else:
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

        if dropped:
            logger.info(
                "TTP cascade: %d claim(s) dropped for platform=%s (sample-incompatible rules).",
                len(dropped),
                sample_platform,
            )

        return CascadeSummary(
            results=results,
            total_techniques=len(results),
            corroborated_count=corroborated,
            consensus_count=consensus,
            dropped_by_platform=dropped,
        )


# ---------------------------------------------------------------------------
# Wave 4 — platform-aware compatibility resolver
# ---------------------------------------------------------------------------


def _is_claim_platform_compatible(
    claim_platforms: list[str] | None,
    sample_platform: str | None,
    technique_id: str,
) -> bool:
    """Decide whether a single ClaimEvidence survives the platform check.

    Resolution order (matches plan Step 4):
      1. ``sample_platform`` is ``None`` → legacy / no-filter caller.
         Keep everything.
      2. ``sample_platform`` is ``"unknown"`` → bootstrap couldn't
         disambiguate. Fall open (keep everything, log via the parent).
      3. ``claim_platforms`` provided by source rule (Sigma/YARA Wave 4):
         keep iff ``"any" in claim_platforms`` or the sample's platform
         is in the list.
      4. No ``claim_platforms`` (analyst LLM claim or legacy rule):
         consult the MITRE catalog (Windows / Linux).
    """
    if sample_platform is None:
        return True
    sp = sample_platform.strip().lower()
    if sp == "" or sp == "unknown":
        return True  # fall open on inference failure

    # Path 1: source-layer-declared platforms (Sigma/YARA after Wave 4).
    if claim_platforms:
        norm = {p.strip().lower() for p in claim_platforms if p}
        if "any" in norm:
            return True
        return sp in norm

    # Path 2: no rule_platforms → MITRE catalog lookup.
    catalog_platforms = _mitre_platforms_for(technique_id)
    if catalog_platforms is None:
        # Technique not in our catalog — fall open (don't lose unknown signal).
        return True

    mitre_sp = _MITRE_PLATFORM_MAP.get(sp, ())
    if not mitre_sp:
        return True  # Unknown sample type vs. MITRE — fall open.

    if any(p in catalog_platforms for p in mitre_sp):
        return True

    return False


# Map our canonical Platform taxonomy to MITRE's x_mitre_platforms strings.
# OS-support scope (2026-06-02): Windows + Linux only.
_MITRE_PLATFORM_MAP: dict[str, tuple[str, ...]] = {
    "windows": ("Windows",),
    "linux": ("Linux",),
}


def _mitre_platforms_for(technique_id: str) -> tuple[str, ...] | None:
    """Lazy-load and cache the MITRE catalog; return platforms list or None."""
    try:
        catalog = _get_attck_catalog()
    except Exception as exc:  # noqa: BLE001
        logger.debug("ATTCK catalog unavailable (%s); skipping MITRE platform check.", exc)
        return None
    if catalog is None:
        return None
    entry = catalog.get(technique_id)
    if entry is None:
        return None
    return tuple(entry)


_attck_cache: dict[str, tuple[str, ...]] | None = None


def _get_attck_catalog() -> dict[str, tuple[str, ...]] | None:
    """Build ``{technique_id: tuple(platforms)}`` from the loader once."""
    global _attck_cache
    if _attck_cache is not None:
        return _attck_cache
    try:
        from maljan.memory.attck_loader import load_attck_bundle

        techs = load_attck_bundle()
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not load ATT&CK catalog: %s", exc)
        return None
    catalog: dict[str, tuple[str, ...]] = {}
    for t in techs:
        platforms = getattr(t, "platforms", None) or ()
        catalog[t.technique_id] = tuple(platforms)
    _attck_cache = catalog
    return catalog
