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

import re
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.extractors.attribution import build_family_attribution
from maljan.extractors.capability_matrix import build_capability_matrix
from maljan.extractors.dynamic_extractor import build_dynamic_behavior
from maljan.extractors.network_extractor import build_network_iocs
from maljan.extractors.pe_extractor import build_static_analysis
from maljan.extractors.persistence_extractor import build_persistence_list
from maljan.extractors.sample_identity import build_sample_identity
from maljan.reporting.models import (
    ConsolidatedIOC,
    DefensiveRecommendation,
    ExternalReference,
    MalwareReport,
    ReportFrontMatter,
    SeverityAssessment,
    VersionHistoryEntry,
)

if TYPE_CHECKING:
    from maljan.providers.base import StaticEvidenceBundle


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
        degraded_mode: bool = False,
        degradation_reasons: list[str] | None = None,
        sample_platform: str | None = None,
        static_evidence: StaticEvidenceBundle | None = None,
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
        self.degraded_mode = degraded_mode
        self.degradation_reasons = degradation_reasons or []
        self.sample_platform = sample_platform
        # Evidence-only static providers (capa_yara) have no ISR and no tool
        # loop to thread findings through; report_node collects this once,
        # before the builder is constructed, and it is folded into
        # ``static`` right after the PE extractor runs, below.
        self.static_evidence = static_evidence

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
        if self.static_evidence is not None and static is not None:
            from maljan.providers.static.capa_yara import merge_static_evidence

            static = merge_static_evidence(static, self.static_evidence)
        dynamic = build_dynamic_behavior(self.sandbox_report)
        network = build_network_iocs(self.sandbox_report)
        persistence = build_persistence_list(self.sandbox_report, self.sample_platform)
        cells, mappings = build_capability_matrix(
            cascade_summary=self.cascade_summary,
            isr_reports=self.isr_reports,
            static=static,
        )
        severity = self._severity_assessment(static, dynamic, network, persistence, cells, identity)
        verdict = self._verdict_literal(self.final_decision)
        attribution = build_family_attribution(
            malware_category=self.malware_category,
            sandbox_report=self.sandbox_report,
            isr_reports=self.isr_reports,
            overall_confidence=self.overall_confidence,
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
            degraded_mode=self.degraded_mode,
            degradation_reasons=self.degradation_reasons,
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
        # Report-reshaping Phase 3: deterministic front-matter, version history,
        # and consolidated IOC table (the professional-report scaffolding the
        # Composer's prose sits inside). All derived from already-built fields.
        report.front_matter = self._build_front_matter(report)
        report.tlp = report.front_matter.tlp
        report.version_history = _build_version_history(report.front_matter)
        report.consolidated_iocs = build_consolidated_iocs(report)
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
        # 2026-07 audit (Bulgu #13): the narrative LLM gets no guidance on the
        # ``category`` enum and collapses every recommendation to "patching"
        # (none of which were patches). Re-derive the category deterministically
        # from the action/rationale text so the label matches the advice.
        valid_tids = {m.technique_id for m in report.ttp_mappings if m.technique_id}
        for rec in recs:
            rec.category = _derive_recommendation_category(  # type: ignore[assignment]
                rec.action, rec.rationale
            )
            # 2026-07 round 2: when the LLM omits technique_id, recover it from a
            # T#### cited in the action/rationale/detection text, preferring one
            # that is actually mapped in this report.
            if not rec.technique_id:
                rec.technique_id = _first_report_technique(
                    f"{rec.action} {rec.rationale} {rec.detection or ''}", valid_tids
                )
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

    def _severity_assessment(
        self,
        static: Any | None,
        dynamic: Any | None,
        network: Any | None,
        persistence: list[Any],
        cells: list[Any],
        identity: Any | None = None,
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
        platforms = self._guess_platforms(static, dynamic, identity)

        return SeverityAssessment(
            overall_score=round(score, 1),
            rating=rating,  # type: ignore[arg-type]
            business_impact=impact,
            affected_platforms=platforms,
            likely_targets=[],
        )

    def _guess_platforms(
        self, static: Any | None, dynamic: Any | None, identity: Any | None = None
    ) -> list[str]:
        platforms: list[str] = []
        if dynamic is not None and dynamic.process_tree:
            platforms.append("Windows")  # behavior almost always Windows sandbox

        # 2026-07 audit (Bulgu #9): infer Windows from the PE format itself so a
        # Windows PE with no dynamic run no longer falls through to "Unknown".
        # file_type "PE" or the MS-download MIME is a definitive Windows signal.
        if identity is not None and "Windows" not in platforms:
            file_type = str(getattr(identity, "file_type", "") or "").upper()
            mime = str(getattr(identity, "mime_type", "") or "").lower()
            if file_type == "PE" or "msdownload" in mime or "x-dosexec" in mime:
                platforms.append("Windows")

        if static is not None and static.sections:
            first = static.sections[0]
            char = first.characteristics or ""
            if char == "ELF" or any(s.characteristics == "ELF" for s in static.sections):
                if "Windows" not in platforms:
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
        # 2026-07 audit (Bulgu #17): one ExternalReference per technique produced
        # the "MITRE ATT&CK" source label repeated 7×. Emit a single grouped
        # ATT&CK reference (pointing at the matrix landing page) whose note lists
        # the techniques, plus deduped per-technique links keyed by technique id.
        seen_tids: set[str] = set()
        tech_notes: list[str] = []
        for mapping in mappings[:10]:
            tid = mapping.technique_id
            if not tid or tid in seen_tids:
                continue
            seen_tids.add(tid)
            tech_notes.append(f"{tid} {mapping.technique_name}".strip())
        if tech_notes:
            refs.append(
                ExternalReference(
                    source="MITRE ATT&CK",
                    url="https://attack.mitre.org/matrices/enterprise/",
                    note="; ".join(tech_notes),
                )
            )
        return refs

    def _build_front_matter(self, report: MalwareReport) -> ReportFrontMatter:
        """Deterministic report cover / TLP block (reference §1).

        Report number is ``{prefix}{YYYYMMDD}-{sha6}`` — deterministic (no DB
        counter) yet unique per sample. TLP escalates to AMBER when the report
        carries live network IOCs (real C2 = more sensitive to share), mirroring
        the reference's rationale; otherwise the configured default.
        """
        from datetime import UTC, datetime

        from maljan.core.config import get_settings

        rc = get_settings().reporting
        sha = report.identity.hashes.sha256 or ""
        now = datetime.now(UTC)
        report_number = f"{rc.report_number_prefix}{now:%Y%m%d}-{sha[:6]}" if sha else None

        tlp = rc.default_tlp
        net = report.network
        has_live_c2 = bool(net and (net.domains or net.ips or net.urls))
        if has_live_c2 and tlp == "CLEAR":
            tlp = "AMBER"

        name = report.malware_category or (
            report.attribution.family if report.attribution else None
        )
        subtitle = None
        if report.identity.platform and report.malware_category:
            subtitle = f"{report.malware_category} targeting {report.identity.platform.title()}"

        return ReportFrontMatter(
            publisher=rc.publisher,
            product_type=rc.product_type,
            malware_name=(name.title() if isinstance(name, str) and name else None),
            subtitle=subtitle,
            version="1.0",
            report_date=f"{now:%Y-%m-%d}",
            report_number=report_number,
            team=rc.author_team,
            tlp=tlp,
            copyright=f"© {now:%Y} {rc.publisher}",
        )


def _build_version_history(front_matter: ReportFrontMatter) -> list[VersionHistoryEntry]:
    """Single deterministic revision-history row (reference §2)."""
    return [
        VersionHistoryEntry(
            version=front_matter.version,
            date=front_matter.report_date or "",
            authors=front_matter.team or front_matter.publisher,
            description="Automated multi-agent analysis — initial report.",
        )
    ]


def defang(value: str) -> str:
    """Neutralise a live indicator for safe distribution (reference VI.3).

    Bracket the dots in domains/IPs and the scheme separator in URLs. Idempotent
    and conservative — only touches ``.``, ``://`` and the ``http``/``https``
    scheme so hashes/registry paths pass through unchanged.
    """
    if not value:
        return value
    out = value
    if "://" in out:
        out = out.replace("http://", "hxxp[://]").replace("https://", "hxxps[://]")
    # Only defang dotted network-looking tokens (contain a dot, no path sep and
    # not an obvious filesystem path) to avoid mangling registry/file paths.
    looks_networky = "." in out and "\\" not in out
    if looks_networky:
        out = out.replace("[.]", ".").replace(".", "[.]")
    return out


def build_consolidated_iocs(report: MalwareReport) -> list[ConsolidatedIOC]:
    """Gather + dedupe + defang every IOC into one typed table (reference §11).

    A recurring corpus weakness is IOCs dispersed inline; this consolidates
    hashes, network domains/IPs/URLs, suspicious static strings, and persistence
    targets into a single ``Type | Description | Value`` table, host- vs
    network-based via ``is_network``.
    """
    rows: list[ConsolidatedIOC] = []
    seen: set[tuple[str, str]] = set()

    def _add(ioc_type: str, value: str, description: str = "", is_network: bool = False) -> None:
        value = (value or "").strip()
        if not value:
            return
        rendered = defang(value) if is_network else value
        key = (ioc_type, rendered.lower())
        if key in seen:
            return
        seen.add(key)
        rows.append(
            ConsolidatedIOC(
                type=ioc_type, description=description, value=rendered, is_network=is_network
            )
        )

    h = report.identity.hashes
    _add("SHA-256", h.sha256 or "", "Sample hash")
    _add("MD5", h.md5 or "", "Sample hash")
    _add("SHA-1", h.sha1 or "", "Sample hash")

    net = report.network
    if net:
        for d in net.domains:
            _add("Domain", d.fqdn, d.reason or "", is_network=True)
        for ip in net.ips:
            _add("IPv4", ip.address, f"port {ip.port}" if ip.port else "", is_network=True)
        for u in net.urls:
            _add("URL", u.url, u.method or "", is_network=True)

    if report.static:
        _kind_to_type = {
            "url": "URL",
            "ip": "IPv4",
            "domain": "Domain",
            "registry": "Registry Key",
            "path": "Path",
            "mutex": "Mutex",
            "email": "Email",
            "command": "Command",
            # Without these two, a leaked AWS key lands in the table as an
            # untyped "String" — present, but indistinguishable from a version
            # banner, and therefore useless to whoever has to act on it.
            "secret": "Leaked Credential",
            "crypto_wallet": "Cryptocurrency Address",
        }
        for s in report.static.interesting_strings:
            ioc_type = _kind_to_type.get(s.kind, "String")
            is_net = s.kind in {"url", "ip", "domain"}
            _add(ioc_type, s.value, s.notes or "", is_network=is_net)

    for pm in report.persistence:
        if pm.target:
            _add("Persistence", pm.target, pm.kind.replace("_", " "))

    return rows


def _derive_recommendation_category(action: str, rationale: str) -> str:
    """Map a recommendation's free text to the correct ``category`` enum value.

    2026-07 audit (Bulgu #13): the narrative LLM labelled every recommendation
    "patching" regardless of content. This deterministic mapper inspects the
    action/rationale wording and returns one of the ``DefensiveRecommendation``
    enum members, defaulting to ``other`` when nothing matches. Order matters —
    the most specific signal wins.
    """
    text = f"{action} {rationale}".lower()
    if any(k in text for k in ("patch", "cve-", " cve", "vulnerab", "update the software")):
        return "patching"
    if any(
        k in text
        for k in (
            "firewall",
            "block outbound",
            "outbound traffic",
            "outbound connection",
            "network connection",
            "egress",
            "sinkhole",
            "proxy",
            " c2 ",
            "c2 infrastructure",
            "command and control",
            "block the domain",
            "block the ip",
        )
    ):
        return "firewall"
    if "registry" in text:
        return "registry_hardening"
    if any(
        k in text
        for k in (
            "group policy",
            "gpo",
            "applocker",
            "wdac",
            "constrained language",
            "software restriction",
        )
    ):
        return "gpo"
    if any(
        k in text
        for k in ("awareness", "phishing", "user training", "user education", "social engineering")
    ):
        return "user_awareness"
    if any(
        k in text
        for k in (
            "monitor",
            "alert",
            " edr",
            "endpoint detection",
            "hunt",
            "detect",
            "sigma",
            "yara",
            "sysmon",
            "telemetry",
            "process injection",
            "behaviour",
            "behavior",
            "log",
        )
    ):
        return "edr_hunting"
    return "other"


_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def _first_report_technique(text: str, valid_tids: set[str]) -> str | None:
    """Return the first T#### in ``text`` that is mapped in the report, else the
    first T#### found, else ``None``."""
    found: list[str] = _TECHNIQUE_RE.findall(text or "")
    if not found:
        return None
    for tid in found:
        if tid in valid_tids:
            return str(tid)
    return str(found[0])


def _ioc_count(report: MalwareReport) -> int:
    """Total network-flavoured IOC count.

    2026-07 audit (Bulgu #4): also count network IOCs recovered from static
    strings (``static.interesting_strings`` with kind domain/ip/url), so a
    hard-coded C2 domain like ``888kafa.com`` is no longer reported as "0
    domains" just because the sandbox never observed it on the wire.
    """
    total = 0
    if report.network is not None:
        total += len(report.network.domains) + len(report.network.ips) + len(report.network.urls)
    if report.static is not None:
        total += sum(
            1
            for s in report.static.interesting_strings
            if getattr(s, "kind", None) in {"domain", "ip", "url"}
        )
    return total
