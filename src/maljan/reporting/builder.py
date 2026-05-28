"""Assemble the deterministic part of a ``MalwareReport``.

The builder is intentionally simple: it owns the pipeline inputs as
attributes and calls each extractor in turn. Each extractor is robust to
missing inputs, so the builder degrades gracefully — a sample-only run
(no sandbox) still produces a useful identity + static section.

``build_deterministic()`` is the entry point used by ``report_node``. The
narrative LLM pass and detection-rule auto-generator are applied by
companion modules (``narrative_agent.py``, ``detection_signatures.py``)
after this deterministic phase.
"""

from __future__ import annotations

from typing import Any

from maljan.core.logger import logger
from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.extractors.dynamic_extractor import build_dynamic_behavior
from maljan.extractors.network_extractor import build_network_iocs
from maljan.extractors.pe_extractor import build_static_analysis
from maljan.extractors.persistence_extractor import build_persistence_list
from maljan.extractors.sample_identity import build_sample_identity
from maljan.reporting.models import (
    DefensiveRecommendation,
    ExternalReference,
    FamilyAttribution,
    MalwareReport,
    SeverityAssessment,
)


class MalwareReportBuilder:
    """Stateful builder — instantiate per analysis run, call ``build_*`` methods.

    Typical lifecycle inside ``report_node``::

        builder = MalwareReportBuilder(...)
        report = builder.build_deterministic()
        if not is_mock:
            report = builder.apply_narrative(narrative_output)
        report = builder.attach_detection_signatures(report)
        builder.render_extended_stix(report)  # mutates report.stix_bundle_extended
    """

    def __init__(
        self,
        *,
        file_hash: str | None,
        file_name: str | None,
        sample_path: str | None,
        sandbox_report: dict[str, Any] | None,
        reports: dict[str, str] | None,
        isr_reports: dict[str, Any] | None,
        stix_output: dict[str, Any] | None,
        run_summary: dict[str, Any] | None,
        discussion_history: list[dict[str, Any]] | None,
        final_decision: str,
        overall_confidence: float = 0.0,
        cascade_summary: Any | None = None,
        malware_category: str | None = None,
    ) -> None:
        self.file_hash = file_hash
        self.file_name = file_name
        self.sample_path = sample_path
        self.sandbox_report = sandbox_report or {}
        self.reports = reports or {}
        self.isr_reports = isr_reports or {}
        self.stix_output = stix_output or {}
        self.run_summary = run_summary or {}
        self.discussion_history = discussion_history or []
        self.final_decision = final_decision
        self.overall_confidence = overall_confidence
        self.cascade_summary = cascade_summary
        self.malware_category = malware_category

    # ------------------------------------------------------------------
    # Deterministic build
    # ------------------------------------------------------------------

    def build_deterministic(self) -> MalwareReport:
        """Run every extractor and return a deterministic ``MalwareReport``."""
        identity = build_sample_identity(
            sample_path=self.sample_path,
            sandbox_report=self.sandbox_report,
            file_hash=self.file_hash,
            file_name=self.file_name,
        )
        static = build_static_analysis(sample_path=self.sample_path)
        dynamic = build_dynamic_behavior(self.sandbox_report)
        network = build_network_iocs(self.sandbox_report)
        persistence = build_persistence_list(self.sandbox_report)
        cells, mappings = build_capability_matrix(
            cascade_summary=self.cascade_summary,
            isr_reports=self.isr_reports,
        )
        severity = self._severity_assessment(static, dynamic, network, persistence, cells)
        verdict = self._verdict_literal(self.final_decision)
        _family_str = self.malware_category if self.malware_category else None
        _grounded = self._is_family_grounded(_family_str)
        attribution = FamilyAttribution(
            family=_family_str,
            family_confidence=(self.overall_confidence if _grounded else 0.0),
            family_grounded=_grounded if _family_str else True,
        )
        if _family_str and not _grounded:
            logger.info(
                "Attribution guardrail: family=%r marked as ungrounded — no "
                "Triage CTI / sandbox sig / ISR claim corroborates it. "
                "family_confidence forced to 0.0.",
                _family_str,
            )

        # Negotiation summary — compact projection of run_summary fields most
        # useful for the report header.
        negotiation_summary = {
            "rounds_completed": self.run_summary.get("negotiation", {}).get("rounds_completed", 0),
            "termination_reason": self.run_summary.get("negotiation", {}).get(
                "termination_reason", "unknown"
            ),
            "final_confidence": self.run_summary.get("negotiation", {}).get(
                "final_confidence", self.overall_confidence
            ),
            "confidence_history": self.run_summary.get("negotiation", {}).get(
                "confidence_history", []
            ),
            "sycophancy_events": self.run_summary.get("negotiation", {}).get(
                "sycophancy_events", 0
            ),
        }

        references = self._build_references(mappings, identity.hashes.sha256)

        report = MalwareReport(
            verdict=verdict,
            overall_confidence=self.overall_confidence,
            malware_category=self.malware_category,
            severity=severity,
            identity=identity,
            static=static,
            dynamic=dynamic,
            network=network,
            persistence=persistence,
            capability_matrix=cells,
            ttp_mappings=mappings,
            attribution=attribution,
            executive_summary="",  # filled by NarrativeAgent
            capabilities_narrative=[],  # filled by NarrativeAgent
            defensive_recommendations=[],  # filled by NarrativeAgent + detection rules
            detection_signatures=[],  # filled by detection_signatures.py
            run_summary=self.run_summary,
            negotiation_summary=negotiation_summary,
            stix_bundle_extended=self.stix_output,
            references=references,
        )
        logger.info(
            "MalwareReportBuilder: deterministic build complete "
            "(verdict=%s, severity=%s, TTPs=%d, persistence=%d, IOCs=%d)",
            report.verdict,
            report.severity.rating,
            len(report.ttp_mappings),
            len(report.persistence),
            _ioc_count(report),
        )
        return report

    # ------------------------------------------------------------------
    # Narrative + detection attachment (called by report_node)
    # ------------------------------------------------------------------

    @staticmethod
    def apply_narrative(report: MalwareReport, narrative: dict[str, Any]) -> MalwareReport:
        """Merge an ``NarrativeOutput`` dict into the report in-place."""
        report.executive_summary = str(narrative.get("executive_summary") or "")
        report.capabilities_narrative = list(narrative.get("capabilities_narrative") or [])
        rec_raw = narrative.get("defensive_recommendations") or []
        recs: list[DefensiveRecommendation] = []
        for item in rec_raw:
            if isinstance(item, DefensiveRecommendation):
                recs.append(item)
                continue
            if isinstance(item, dict):
                try:
                    recs.append(DefensiveRecommendation.model_validate(item))
                except Exception:  # noqa: BLE001
                    continue
        report.defensive_recommendations = recs
        return report

    @staticmethod
    def attach_detection_signatures(report: MalwareReport) -> MalwareReport:
        """Populate ``report.detection_signatures`` with template-generated rules.

        Calls into :mod:`maljan.reporting.detection_signatures` which produces
        up to three rules (YARA / Sigma / Suricata) keyed by the report's
        IOCs. Missing evidence in any of the three input domains results in
        that format being skipped (never an empty rule). Generation is
        deterministic — no LLM involvement.
        """
        from maljan.reporting.detection_signatures import build_detection_rules

        report.detection_signatures = build_detection_rules(report)
        return report

    @staticmethod
    def apply_fallback_narrative(report: MalwareReport) -> MalwareReport:
        """Fill narrative fields with a deterministic templated summary.

        Used when no LLM is available (mock mode) or the structured-output
        invocation fails — guarantees the report never ships empty
        narrative blocks.
        """
        verdict = report.verdict
        family = report.attribution.family or report.malware_category or "unclassified malware"
        ttp_lines = [f"{m.technique_id} ({m.technique_name})" for m in report.ttp_mappings[:5]]
        ttp_summary = ", ".join(ttp_lines) if ttp_lines else "no MITRE techniques mapped"
        report.executive_summary = (
            f"Sample classified as {verdict.lower()}. Best-guess family: {family}. "
            f"Pipeline reported {len(report.ttp_mappings)} ATT&CK techniques: "
            f"{ttp_summary}. Confidence {report.overall_confidence:.2f}. "
            "This is an auto-generated summary (no LLM available); review the "
            "detailed sections for evidence."
        )
        report.capabilities_narrative = [
            "Detailed narrative was not generated because the analysis ran in "
            "mock/offline mode or the narrative LLM call failed. The deterministic "
            "evidence in the Static, Dynamic and Network sections below carries "
            "the full picture.",
        ]
        report.defensive_recommendations = [
            DefensiveRecommendation(
                category="edr_hunting",
                action="Review the listed MITRE ATT&CK techniques and hunt for the "
                "associated indicators in EDR telemetry.",
                rationale="Auto-generated fallback recommendation — narrative LLM unavailable.",
                priority="P1",
            )
        ]
        return report

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _verdict_literal(decision: str) -> Any:
        normalised = (decision or "").strip().lower()
        if normalised.startswith("malw"):
            return "Malware"
        if normalised.startswith("benign"):
            return "Benign"
        return "Suspicious"

    def _is_family_grounded(self, family: str | None) -> bool:
        """Return True when ``family`` is corroborated by deterministic evidence.

        D11 fix: in the 2026-05-23 E2E run the judge fallback path emitted
        ``attribution.family = "rat"`` for zararli.apk despite Triage
        returning an empty ``families[]`` and no analyst claim ever
        naming the family. The previous builder copied the value through
        unconditionally with the global ``overall_confidence`` as
        ``family_confidence`` — UI consumers had no way to tell which
        family assertions had grounding.

        Grounding sources (any one is enough):
        - Triage CTI ``family[]`` list contains the candidate (case
          insensitive substring match — Triage often emits multi-token
          entries like ``"trojan/rat"``).
        - Triage ``signatures[].name`` mentions the family literally.
        - Any ISR claim's ``claim``, ``evidence_ref``, or ``technique_id``
          text contains the family name.

        Returns ``True`` for an empty family input so callers that pass
        ``None`` get the legacy "no claim made" default and don't trip
        the guardrail on samples that simply have no family hypothesis.
        """
        if not family:
            return True
        needle = family.strip().lower()
        if not needle:
            return True

        # Triage CTI block (synthesised by TriageClient._synthesize_cti)
        cti = (self.sandbox_report or {}).get("cti") or {}
        if isinstance(cti.get("family"), list):
            for f in cti["family"]:
                if isinstance(f, str) and needle in f.lower():
                    return True

        # Triage / CAPE sandbox signatures
        sigs = (self.sandbox_report or {}).get("signatures") or []
        for sig in sigs:
            if not isinstance(sig, dict):
                continue
            name = str(sig.get("name") or "").lower()
            desc = str(sig.get("description") or "").lower()
            if needle in name or needle in desc:
                return True

        # ISR claims (analyst / yara_layer / sigma_layer)
        for isr in (self.isr_reports or {}).values():
            for claim in getattr(isr, "claims", []) or []:
                _ctext = " ".join(
                    (
                        str(getattr(claim, "claim", "") or ""),
                        str(getattr(claim, "evidence_ref", "") or ""),
                        str(getattr(claim, "technique_id", "") or ""),
                    )
                ).lower()
                if needle in _ctext:
                    return True

        return False

    def _severity_assessment(
        self,
        static: Any | None,
        dynamic: Any | None,
        network: Any | None,
        persistence: list[Any],
        cells: list[Any],
    ) -> SeverityAssessment:
        """Heuristic CVSS-style score from deterministic signal density."""
        confidence = max(0.0, min(1.0, float(self.overall_confidence)))
        score = 1.0 + 9.0 * confidence  # baseline anchored to verdict confidence

        # Persistence boosts severity
        score += min(2.0, 0.5 * len(persistence))
        # Network IOCs (with suspicion) boost severity
        if network is not None:
            sus_domains = sum(1 for d in network.domains if d.is_suspicious)
            score += min(1.5, 0.3 * sus_domains)
        # Anti-analysis indicators
        if static is not None:
            score += 0.2 * len(static.obfuscation_indicators)
            score += 0.3 if static.packer_hint else 0.0
        # Multi-tactic ATT&CK coverage
        distinct_tactics = len({c.tactic for c in cells if c.tactic})
        score += min(1.5, 0.2 * distinct_tactics)

        # Clamp & rate
        score = max(0.0, min(10.0, score))
        if score >= 9.0:
            rating = "Critical"
        elif score >= 7.0:
            rating = "High"
        elif score >= 4.0:
            rating = "Medium"
        elif score >= 1.0:
            rating = "Low"
        else:
            rating = "Informational"

        impact = (
            "Sample exhibits malicious capabilities likely to cause direct harm "
            "to affected endpoints; immediate containment is advised."
            if rating in ("Critical", "High")
            else "Sample displays suspicious behaviour consistent with malware; "
            "isolate and analyse further before allowing execution."
        )
        platforms = self._guess_platforms(static, dynamic)

        return SeverityAssessment(
            overall_score=round(score, 1),
            rating=rating,  # type: ignore[arg-type]
            business_impact=impact,
            affected_platforms=platforms,
            likely_targets=[],
        )

    def _guess_platforms(self, static: Any | None, dynamic: Any | None) -> list[str]:
        platforms: list[str] = []
        if dynamic is not None and dynamic.process_tree:
            platforms.append("Windows")  # behavior almost always Windows sandbox
        if static is not None and static.sections:
            first = static.sections[0]
            char = first.characteristics or ""
            if char == "ELF" or any(s.characteristics == "ELF" for s in static.sections):
                if "Windows" in platforms:
                    pass
                else:
                    platforms.append("Linux")
        if not platforms:
            platforms.append("Unknown")
        return platforms

    def _build_references(self, mappings: list[Any], sha256: str | None) -> list[ExternalReference]:
        refs: list[ExternalReference] = []
        if sha256 and len(sha256) == 64:
            refs.extend(
                [
                    ExternalReference(
                        source="VirusTotal",
                        url=f"https://www.virustotal.com/gui/file/{sha256}",
                        note="VT detection summary",
                    ),
                    ExternalReference(
                        source="MalwareBazaar",
                        url=f"https://bazaar.abuse.ch/sample/{sha256}/",
                        note="Sample lookup",
                    ),
                ]
            )
        for mapping in mappings[:10]:
            tid = mapping.technique_id
            refs.append(
                ExternalReference(
                    source="MITRE ATT&CK",
                    url=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                    note=mapping.technique_name,
                )
            )
        return refs


def _ioc_count(report: MalwareReport) -> int:
    if report.network is None:
        return 0
    return len(report.network.domains) + len(report.network.ips) + len(report.network.urls)
