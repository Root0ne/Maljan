"""Analysis run observability: structured RunSummary report.

After a complete analysis run, the pipeline has produced:
  - ISR reports (per-agent structured claims)
  - Negotiation history (mediator arguments + confidence evolution)
  - ATT&CK TTP validation results (hallucinated / suspicious IDs)
  - Three-layer TTP cascade results (corroboration scoring)
  - Final STIX 2.1 bundle

RunSummary aggregates all of these into a single inspectable object that
can be rendered as a Markdown report, serialized to JSON, or logged.

This gives security analysts full explainability: they can see exactly
WHY the pipeline reached its verdict, which agents agreed, which TTPs
were cross-corroborated, and which claims were flagged as hallucinations.

Design:
  - RunSummary is built post-verdict in the judge node via RunSummaryBuilder.
  - It is stored in AnalysisState["run_summary"] as a plain dict
    (JSON-serializable; avoids TypedDict + dataclass compatibility issues).
  - MaljanApp.run() returns it alongside the STIX output.
  - The CLI renders it as a Markdown block or writes it to a .md file.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from maljan.core.logger import logger

# ---------------------------------------------------------------------------
# Sub-components
# ---------------------------------------------------------------------------


@dataclass
class NegotiationMetrics:
    """Statistics from the negotiation loop.

    Attributes:
        rounds_completed:    Number of negotiation rounds actually executed.
        max_rounds:          Hard limit configured at startup.
        termination_reason:  Why the loop stopped (consensus / hard_limit /
                             convergence / sycophancy).
        sycophancy_events:   Number of rounds where sycophancy was detected.
        confidence_history:  Per-round mediator confidence scores.
        final_confidence:    Last recorded confidence value.
    """

    rounds_completed: int
    max_rounds: int
    termination_reason: str
    sycophancy_events: int
    confidence_history: list[float]
    final_confidence: float

    @property
    def converged_early(self) -> bool:
        return self.termination_reason != "hard_limit"


@dataclass
class ISRAgentStats:
    """Per-agent ISR statistics extracted from the final AgentISR objects."""

    agent_id: str
    domain: str
    revision_round: int
    claim_count: int
    mean_confidence: float
    technique_ids: list[str]
    has_dissent: bool


@dataclass
class ValidationMetrics:
    """Summary of ATT&CK TTP validation results."""

    total_claims: int
    valid_ids: int
    invalid_ids: int
    low_alignment: int
    hallucination_rate: float


@dataclass
class CascadeMetrics:
    """Summary of three-layer TTP cascade results."""

    total_techniques: int
    corroborated_count: int
    consensus_count: int
    top_techniques: list[dict[str, Any]]  # technique_id, label, confidence, layers
    # Wave 4 (2026-05-28): claims rejected for platform incompatibility.
    # Empty for legacy runs that didn't supply a sample_platform.
    dropped_by_platform: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# RunSummary
# ---------------------------------------------------------------------------


@dataclass
class RunSummary:
    """Full observability report for a single Maljan analysis run.

    Attributes:
        file_hash:          Sample identifier.
        file_name:          Human-readable filename (if provided).
        final_decision:     Pipeline verdict (Malware / Benign / Suspicious).
        stix_object_count:  Number of objects in the STIX Bundle.
        negotiation:        Negotiation loop metrics.
        agent_stats:        Per-agent ISR statistics.
        validation:         ATT&CK TTP validation metrics (None if skipped).
        cascade:            Three-layer cascade metrics (None if no TTP claims).
        elapsed_seconds:    Wall-clock time from start to verdict.
        timestamp:          Unix timestamp of verdict generation.

        degraded_mode:      Set True when the verdict came from a partial /
                            failed pipeline (zero corroboration, analyst
                            errors). Audit 2026-05-19 OPS-DEGRADED-VERDICT-01.
        degradation_reasons: Human-readable bullets explaining why this run
                            is flagged as degraded.
        failed_analysts:    Names of analysts whose ``reports[name]`` started
                            with ``[ERROR]``. (Audit 2026-05-19
                            OBS-ANALYST-ERRORS-METRIC-01.)
        techniques_by_layer: Per-layer (yara / sigma / static / dynamic /
                            network) technique counts so the report can show
                            "1 yara + 9 sigma + 1 network + 0 static +
                            0 dynamic = 11 total" attribution instead of the
                            opaque "11 techniques". Audit 2026-05-19
                            OBS-TTP-ATTRIBUTION-01.
    """

    file_hash: str
    file_name: str | None
    final_decision: str
    stix_object_count: int
    negotiation: NegotiationMetrics
    agent_stats: list[ISRAgentStats]
    validation: ValidationMetrics | None
    cascade: CascadeMetrics | None
    elapsed_seconds: float
    timestamp: float = field(default_factory=time.time)
    degraded_mode: bool = False
    degradation_reasons: list[str] = field(default_factory=list)
    failed_analysts: list[str] = field(default_factory=list)
    techniques_by_layer: dict[str, int] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def to_markdown(self) -> str:
        """Render the full run summary as a human-readable Markdown report."""
        sample_label = f"{self.file_hash}"
        if self.file_name:
            sample_label = f"{self.file_name} ({self.file_hash})"

        lines: list[str] = [
            "# Maljan Analysis Report",
            "",
            f"**Sample**: `{sample_label}`  ",
            f"**Verdict**: {self.final_decision}  ",
            f"**STIX objects**: {self.stix_object_count}  ",
            f"**Elapsed**: {self.elapsed_seconds:.1f}s  ",
            "",
        ]

        # OPS-DEGRADED-VERDICT-01 (audit 2026-05-19): banner the degraded
        # run prominently so a reader can't miss it when scrolling.
        if self.degraded_mode:
            lines += [
                "> [!WARNING]",
                "> **DEGRADED RUN.** The verdict above was produced with "
                "reduced signal — confidence has been capped at 0.60.",
                "",
            ]
            if self.degradation_reasons:
                lines += ["**Degradation reasons:**", ""]
                for reason in self.degradation_reasons:
                    lines.append(f"- {reason}")
                lines.append("")

        # Negotiation
        n = self.negotiation
        lines += [
            "## Negotiation",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Rounds completed | {n.rounds_completed} / {n.max_rounds} |",
            f"| Termination reason | `{n.termination_reason}` |",
            f"| Sycophancy events | {n.sycophancy_events} |",
            f"| Final confidence | {n.final_confidence:.3f} |",
            f"| Converged early | {'yes' if n.converged_early else 'no'} |",
            "",
        ]

        if n.confidence_history:
            history_str = " → ".join(f"{c:.2f}" for c in n.confidence_history)
            lines.append(f"**Confidence history**: {history_str}")
            lines.append("")

        # Agent ISR statistics
        lines += ["## Agent ISR Statistics", ""]
        if self.agent_stats:
            lines.append("| Agent | Domain | Claims | Mean Conf | TTPs | Round | Dissent |")
            lines.append("|---|---|---|---|---|---|---|")
            for s in self.agent_stats:
                ttps = ", ".join(s.technique_ids) if s.technique_ids else "—"
                dissent = "yes" if s.has_dissent else "no"
                lines.append(
                    f"| {s.agent_id} | {s.domain} | {s.claim_count} | "
                    f"{s.mean_confidence:.2f} | {ttps} | {s.revision_round} | {dissent} |"
                )
            lines.append("")
        else:
            lines += ["*No ISR reports collected.*", ""]

        # TTP Cascade
        if self.cascade:
            c = self.cascade
            lines += [
                "## Three-Layer TTP Cascade",
                "",
                "| Metric | Value |",
                "|---|---|",
                f"| Total techniques | {c.total_techniques} |",
                f"| Corroborated (2+ layers) | {c.corroborated_count} |",
                f"| Consensus (3 layers) | {c.consensus_count} |",
                "",
            ]
            if c.top_techniques:
                lines.append("**Top techniques by weighted confidence:**")
                lines.append("")
                lines.append("| Technique | Label | Confidence | Layers |")
                lines.append("|---|---|---|---|")
                for t in c.top_techniques:
                    layers = ", ".join(t.get("layers", []))
                    lines.append(
                        f"| {t['technique_id']} | {t['label']} | {t['confidence']:.3f} | {layers} |"
                    )
                lines.append("")
            # OBS-TTP-ATTRIBUTION-01 (audit 2026-05-19): per-layer breakdown.
            if self.techniques_by_layer:
                lines.append("**Per-layer attribution:**")
                lines.append("")
                # Stable order so the report is diffable run-to-run.
                for layer in ("static", "dynamic", "network", "yara", "sigma"):
                    count = self.techniques_by_layer.get(layer, 0)
                    lines.append(f"- `{layer}`: {count}")
                # Surface any other layers we didn't enumerate above.
                for layer, count in sorted(self.techniques_by_layer.items()):
                    if layer not in {"static", "dynamic", "network", "yara", "sigma"}:
                        lines.append(f"- `{layer}`: {count}")
                lines.append("")
        else:
            lines += ["## Three-Layer TTP Cascade", "", "*No TTP claims found.*", ""]

        # OBS-ANALYST-ERRORS-METRIC-01 (audit 2026-05-19): always render the
        # failed-analyst section so operators see "0 failures" rather than
        # ambiguity.
        lines += ["## Analyst Errors", ""]
        if self.failed_analysts:
            for name in self.failed_analysts:
                lines.append(f"- `{name}` — reported `[ERROR]` status")
        else:
            lines.append("*No analyst failures recorded.*")
        lines.append("")

        # ATT&CK Validation
        if self.validation:
            v = self.validation
            lines += [
                "## ATT&CK TTP Validation",
                "",
                "| Metric | Value |",
                "|---|---|",
                f"| Total claims | {v.total_claims} |",
                f"| Valid IDs | {v.valid_ids} |",
                f"| Hallucinated IDs | {v.invalid_ids} |",
                f"| Low alignment | {v.low_alignment} |",
                f"| Hallucination rate | {v.hallucination_rate:.1%} |",
                "",
            ]
        else:
            lines += ["## ATT&CK TTP Validation", "", "*Validation skipped (cache not built).*", ""]

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        n = self.negotiation
        result: dict[str, Any] = {
            "file_hash": self.file_hash,
            "file_name": self.file_name,
            "final_decision": self.final_decision,
            "stix_object_count": self.stix_object_count,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "timestamp": self.timestamp,
            "negotiation": {
                "rounds_completed": n.rounds_completed,
                "max_rounds": n.max_rounds,
                "termination_reason": n.termination_reason,
                "sycophancy_events": n.sycophancy_events,
                "confidence_history": n.confidence_history,
                "final_confidence": round(n.final_confidence, 4),
                "converged_early": n.converged_early,
            },
            "agent_stats": [
                {
                    "agent_id": s.agent_id,
                    "domain": s.domain,
                    "revision_round": s.revision_round,
                    "claim_count": s.claim_count,
                    "mean_confidence": round(s.mean_confidence, 4),
                    "technique_ids": s.technique_ids,
                    "has_dissent": s.has_dissent,
                }
                for s in self.agent_stats
            ],
            "cascade": None,
            "validation": None,
            "degraded_mode": self.degraded_mode,
            "degradation_reasons": list(self.degradation_reasons),
            "failed_analysts": list(self.failed_analysts),
            "techniques_by_layer": dict(self.techniques_by_layer),
        }

        if self.cascade:
            result["cascade"] = {
                "total_techniques": self.cascade.total_techniques,
                "corroborated_count": self.cascade.corroborated_count,
                "consensus_count": self.cascade.consensus_count,
                "top_techniques": self.cascade.top_techniques,
            }

        if self.validation:
            result["validation"] = {
                "total_claims": self.validation.total_claims,
                "valid_ids": self.validation.valid_ids,
                "invalid_ids": self.validation.invalid_ids,
                "low_alignment": self.validation.low_alignment,
                "hallucination_rate": round(self.validation.hallucination_rate, 4),
            }

        return result


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class RunSummaryBuilder:
    """Constructs a RunSummary from pipeline state and phase-specific results.

    Designed to be called once at the end of the judge node, after all
    pipeline phases have completed.

    Usage:
        builder = RunSummaryBuilder(start_time=t0)
        builder.set_sample(file_hash, file_name)
        builder.set_verdict(final_decision, stix_object_count)
        builder.set_negotiation(state)
        builder.set_isr_stats(isr_reports)
        builder.set_validation_summary(ttp_validation_summary)
        builder.set_cascade_summary(cascade_summary)
        summary = builder.build()
    """

    def __init__(self, start_time: float) -> None:
        self._start_time = start_time
        self._file_hash: str = ""
        self._file_name: str | None = None
        self._final_decision: str = "Unknown"
        self._stix_object_count: int = 0
        self._negotiation: NegotiationMetrics | None = None
        self._agent_stats: list[ISRAgentStats] = []
        self._validation: ValidationMetrics | None = None
        self._cascade: CascadeMetrics | None = None
        self._degraded_mode: bool = False
        self._degradation_reasons: list[str] = []
        self._failed_analysts: list[str] = []
        self._techniques_by_layer: dict[str, int] = {}

    def set_degraded_mode(
        self, degraded: bool, reasons: list[str] | None = None
    ) -> RunSummaryBuilder:
        """Mark the run as degraded with optional human-readable reasons.

        Audit 2026-05-19 OPS-DEGRADED-VERDICT-01.
        """
        self._degraded_mode = bool(degraded)
        self._degradation_reasons = list(reasons or [])
        return self

    def set_failed_analysts(self, names: list[str]) -> RunSummaryBuilder:
        """Record analysts whose reports failed with an [ERROR] prefix.

        Audit 2026-05-19 OBS-ANALYST-ERRORS-METRIC-01.
        """
        self._failed_analysts = list(names)
        return self

    def set_sample(self, file_hash: str, file_name: str | None) -> RunSummaryBuilder:
        self._file_hash = file_hash
        self._file_name = file_name
        return self

    def set_verdict(self, final_decision: str, stix_object_count: int) -> RunSummaryBuilder:
        self._final_decision = final_decision
        self._stix_object_count = stix_object_count
        return self

    def set_negotiation(
        self,
        state: dict[str, Any],
        max_iterations: int | None = None,
    ) -> RunSummaryBuilder:
        """Extract negotiation metrics from the final pipeline state.

        Args:
            state: Final AnalysisState (subset OK).
            max_iterations: Configured hard limit. If None, falls back to
                ``iteration_count`` so the report stays self-consistent.
        """
        confidence_history: list[float] = state.get("confidence_history") or []
        iteration_count: int = state.get("iteration_count", 0)
        is_consensus: bool = state.get("is_consensus", False)
        sycophancy_detected: bool = state.get("sycophancy_detected", False)
        discussion_history = state.get("discussion_history") or []

        sycophancy_events = sum(
            1
            for arg in discussion_history
            if getattr(arg, "agent_name", "") == "Mediator"
            and "sycophancy" in getattr(arg, "finding", "").lower()
        )
        if sycophancy_detected and sycophancy_events == 0:
            sycophancy_events = 1

        if is_consensus:
            termination_reason = "consensus"
        elif len(confidence_history) >= 3:
            recent = confidence_history[-3:]
            std = _rolling_std(recent)
            termination_reason = "convergence" if std < 0.02 else "hard_limit"
        else:
            termination_reason = "hard_limit"

        if max_iterations is None:
            # Backward-compat: legacy callers passed state with "_max_iterations".
            max_iterations = state.get("_max_iterations", iteration_count)

        self._negotiation = NegotiationMetrics(
            rounds_completed=iteration_count,
            max_rounds=max_iterations,
            termination_reason=termination_reason,
            sycophancy_events=sycophancy_events,
            confidence_history=confidence_history,
            final_confidence=confidence_history[-1] if confidence_history else 0.0,
        )
        return self

    def set_isr_stats(self, isr_reports: dict[str, Any]) -> RunSummaryBuilder:
        """Extract per-agent ISR statistics."""
        stats: list[ISRAgentStats] = []
        for isr in isr_reports.values():
            technique_ids = [c.technique_id for c in isr.claims if c.technique_id is not None]
            stats.append(
                ISRAgentStats(
                    agent_id=isr.agent_id,
                    domain=isr.domain,
                    revision_round=isr.revision_round,
                    claim_count=len(isr.claims),
                    mean_confidence=isr.mean_confidence,
                    technique_ids=list(dict.fromkeys(technique_ids)),  # deduplicate, preserve order
                    has_dissent=bool(isr.dissent_items),
                )
            )
        self._agent_stats = stats
        return self

    def set_validation_summary(self, validation_summary: Any) -> RunSummaryBuilder:
        """Extract metrics from a TTPValidationSummary (duck-typed)."""
        if validation_summary is None:
            return self
        try:
            self._validation = ValidationMetrics(
                total_claims=validation_summary.total_claims,
                valid_ids=validation_summary.valid_ids,
                invalid_ids=validation_summary.invalid_ids,
                low_alignment=validation_summary.low_alignment,
                hallucination_rate=validation_summary.hallucination_rate,
            )
        except Exception as exc:
            logger.debug("set_validation_summary failed: %s", exc, exc_info=True)
        return self

    def set_cascade_summary(self, cascade_summary: Any, top_k: int = 5) -> RunSummaryBuilder:
        """Extract metrics from a CascadeSummary (duck-typed)."""
        if cascade_summary is None:
            return self
        try:
            top = cascade_summary.top_techniques(n=top_k)
            top_techniques = [
                {
                    "technique_id": r.technique_id,
                    "label": r.corroboration_label(),
                    "confidence": round(r.weighted_confidence, 4),
                    "layers": r.contributing_layers,
                }
                for r in top
            ]
            dropped = []
            for d in getattr(cascade_summary, "dropped_by_platform", None) or []:
                dropped.append(
                    {
                        "technique_id": getattr(d, "technique_id", ""),
                        "source_layer": getattr(d, "source_layer", ""),
                        "rule_platforms": getattr(d, "rule_platforms", []) or [],
                        "sample_platform": getattr(d, "sample_platform", "unknown"),
                        "reason": getattr(d, "reason", ""),
                    }
                )
            self._cascade = CascadeMetrics(
                total_techniques=cascade_summary.total_techniques,
                corroborated_count=cascade_summary.corroborated_count,
                consensus_count=cascade_summary.consensus_count,
                top_techniques=top_techniques,
                dropped_by_platform=dropped,
            )
            # OBS-TTP-ATTRIBUTION-01 (audit 2026-05-19): bucket every
            # cascade result by *every* contributing layer (a technique can
            # contribute to multiple layers if more than one analyst hit it).
            # Use ``results`` not ``top_techniques(n=k)`` so the breakdown
            # covers the whole cascade, not just the top-K.
            counts: dict[str, int] = {}
            try:
                all_results = (
                    list(cascade_summary.results.values())
                    if hasattr(cascade_summary, "results")
                    else top
                )
                for r in all_results:
                    layers = getattr(r, "contributing_layers", None) or []
                    for layer in layers:
                        counts[str(layer)] = counts.get(str(layer), 0) + 1
            except Exception as exc:  # noqa: BLE001
                logger.debug("techniques_by_layer compute failed: %s", exc)
            self._techniques_by_layer = counts
        except Exception as exc:
            logger.debug("set_cascade_summary failed: %s", exc, exc_info=True)
        return self

    def build(self) -> RunSummary:
        """Construct the final RunSummary. Raises ValueError if incomplete."""
        if self._negotiation is None:
            self._negotiation = NegotiationMetrics(
                rounds_completed=0,
                max_rounds=0,
                termination_reason="unknown",
                sycophancy_events=0,
                confidence_history=[],
                final_confidence=0.0,
            )

        return RunSummary(
            file_hash=self._file_hash,
            file_name=self._file_name,
            final_decision=self._final_decision,
            stix_object_count=self._stix_object_count,
            negotiation=self._negotiation,
            agent_stats=self._agent_stats,
            validation=self._validation,
            cascade=self._cascade,
            elapsed_seconds=time.time() - self._start_time,
            degraded_mode=self._degraded_mode,
            degradation_reasons=self._degradation_reasons,
            failed_analysts=self._failed_analysts,
            techniques_by_layer=self._techniques_by_layer,
        )


# ---------------------------------------------------------------------------
# Pure-Python helper (avoids importing from routing to prevent circular deps)
# ---------------------------------------------------------------------------


def _rolling_std(values: list[float]) -> float:
    """Population standard deviation of the provided values."""
    if len(values) < 2:
        return float("inf")
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return float(variance**0.5)
