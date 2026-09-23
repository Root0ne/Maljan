"""Assemble the deterministic part of a ``MalwareReport``.

The builder used to call an extractor per section: one re-parsed the PE, one
re-read the sandbox report for behaviour, one for network, one for
persistence. Every one of them worked from the same inputs the agents had and
reached its own conclusions, so a report could describe an import table no
analyst had looked at and a Run key no analyst had mentioned.

It builds from the evidence ledger now. ``sections`` come from what the tools
returned and what the agents established; the typed blocks (``static``,
``dynamic``, ``network``, ``persistence``) are projections of the same ledger,
kept because several layers still read them and empty whenever the matching
tool was never called. The only file the builder still opens is the sample
itself, for the hashes and size a report cannot be without.

``build_deterministic()`` is the entry point used by ``report_node``. The
narrative LLM pass and detection-rule auto-generator are applied by
companion modules (``narrative_agent.py``, ``detection_signatures.py``)
after this deterministic phase.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from maljan.analysis.run_summary import NOT_APPLICABLE
from maljan.core.logger import logger
from maljan.extractors.attribution import build_family_attribution
from maljan.extractors.capability_matrix import build_capability_matrix, unmapped_behaviours
from maljan.pipeline.outcome import (
    INCONCLUSIVE_VERDICT,
    normalise_verdict,
)
from maljan.reporting.dedupe import MergeTally
from maljan.reporting.ledger_projection import (
    dynamic_from_ledger,
    identity_from_ledger,
    network_from_ledger,
    persistence_from_ledger,
    static_from_ledger,
)
from maljan.reporting.ledger_report import build_sections
from maljan.reporting.models import (
    ConsolidatedIOC,
    DefensiveRecommendation,
    EvidenceIndexRow,
    ExternalReference,
    KeyFinding,
    MalwareReport,
    ReportFrontMatter,
    SeverityAssessment,
    VersionHistoryEntry,
)
from maljan.schemas.judgement import SEVERITY_RATINGS

if TYPE_CHECKING:
    from maljan.schemas.evidence import LedgerEntry

# How the reason for an absent summary begins, so the key-findings section can
# find it among the degradation reasons and print it where the summary would be.
NO_SUMMARY_REASON = "the report model wrote no summary"


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
        overall_confidence: float | None = 0.0,
        judge_assessment: Any | None = None,
        malware_category: str | None = None,
        degraded_mode: bool = False,
        degradation_reasons: list[str] | None = None,
        sample_platform: str | None = None,
        sample_file_type: str | None = None,
        evidence_ledger: list[LedgerEntry] | None = None,
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
        # The judge's severity / category / family, or ``None`` when the judge
        # produced none. Nothing here computes a replacement: a report that
        # cannot say what the judge decided says "not assessed".
        self.judge_assessment = judge_assessment
        self.malware_category = malware_category
        self.degraded_mode = degraded_mode
        self.degradation_reasons = degradation_reasons or []
        self.sample_platform = sample_platform
        self.sample_file_type = sample_file_type
        # Every tool call the run made, in the order the ids were issued. The
        # report's sections and its typed blocks are both built from this and
        # from the agents' own artifacts; an empty ledger means an empty
        # report body, which is the honest outcome for a run that gathered
        # nothing.
        self.evidence_ledger = list(evidence_ledger or [])

    # ------------------------------------------------------------------
    # Deterministic build
    # ------------------------------------------------------------------

    def build_deterministic(self) -> MalwareReport:
        """Build a deterministic ``MalwareReport`` out of the evidence ledger."""
        identity = identity_from_ledger(
            self.evidence_ledger,
            sample_path=self.sample_path,
            file_name=self.file_name,
            file_hash=self.file_hash,
            file_type=self.sample_file_type or "unknown",
            platform=self.sample_platform or "unknown",
        )
        # The typed blocks are projections, not a second analysis: each is
        # filled from the tools that were actually called and the artifacts the
        # analysts actually established, and each stays empty otherwise.
        static = static_from_ledger(self.evidence_ledger, self.isr_reports)
        dynamic = dynamic_from_ledger(self.evidence_ledger, self.isr_reports)
        network = network_from_ledger(self.evidence_ledger, self.isr_reports)
        persistence = persistence_from_ledger(self.evidence_ledger, self.isr_reports)
        cells, mappings = build_capability_matrix(
            stix_output=self.stix_output,
            isr_reports=self.isr_reports,
            # The routed minimum, which is what the analyst loop and the
            # judge's bundle check were given: a technique from a domain this
            # sample cannot host is kept in the matrix and left unpublished.
            sample={"platform": self.sample_platform, "file_type": self.sample_file_type},
        )
        severity = self._severity_from_judge(static, dynamic, identity)
        verdict = self._verdict_literal(self.final_decision)
        attribution = build_family_attribution(
            judge_family=getattr(self.judge_assessment, "family", None),
            sandbox_report=self.sandbox_report,
        )

        negotiation_summary = self._negotiation_summary(self.run_summary, self.overall_confidence)

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
            unmapped_behaviours=unmapped_behaviours(self.stix_output),
            attribution=attribution,
            executive_summary="",  # filled by NarrativeAgent
            defensive_recommendations=[],  # filled by NarrativeAgent
            detection_signatures=[],  # filled by detection_signatures.py
            run_summary=self.run_summary,
            negotiation_summary=negotiation_summary,
            stix_bundle_extended=self.stix_output,
            references=references,
        )
        # The sections the report is actually made of, and the index of the
        # calls behind them. Built last so a section builder can never affect
        # the verdict, the severity or the STIX bundle above it.
        merges = MergeTally()
        report.sections = build_sections(
            self.evidence_ledger,
            self.isr_reports,
            identity.file_type,
            str(identity.platform),
            merges=merges,
            # The one validated list, so the Findings table can say which of
            # the ids it prints this run did not publish. An analyst carries
            # technique ids on its findings as well as on its claims, and the
            # findings' were the ones no surface ever questioned.
            published_techniques=frozenset(
                str(mapping.technique_id or "").strip().upper()
                for mapping in mappings
                if str(mapping.technique_id or "").strip()
            ),
        )
        # What the run said twice and the report says once. The bundle's own
        # indicator merge happened in the judge, long before this, and is
        # counted by the integrity pass; both are the same act on the same
        # run, so the summary states one number for it.
        self.run_summary["dedupe"] = merges.as_dict(
            extra_indicators=_indicators_merged_in_the_bundle(self.run_summary)
        )
        report.evidence_index = [
            EvidenceIndexRow(
                id=entry.id,
                agent=entry.agent,
                server=entry.server,
                tool=entry.tool,
                ok=entry.ok,
                duration_ms=entry.duration_ms,
                truncated=entry.truncated,
            )
            for entry in self.evidence_ledger
        ]

        # Deterministic front-matter, version history,
        # and consolidated IOC table (the professional-report scaffolding the
        # Composer's prose sits inside). All derived from already-built fields.
        report.front_matter = self._build_front_matter(report)
        report.tlp = report.front_matter.tlp
        report.version_history = _build_version_history(report.front_matter)
        report.consolidated_iocs = build_consolidated_iocs(report)
        logger.info(
            "MalwareReportBuilder: deterministic build complete "
            "(verdict=%s, severity=%s, TTPs=%d, persistence=%d, IOCs=%d, "
            "sections=%d, evidence=%d)",
            report.verdict,
            report.severity.rating if report.severity else "not assessed",
            len(report.ttp_mappings),
            len(report.persistence),
            _ioc_count(report),
            len(report.sections),
            len(report.evidence_index),
        )
        return report

    @staticmethod
    def _negotiation_summary(
        run_summary: dict[str, Any], overall_confidence: float | None
    ) -> dict[str, Any]:
        """The compact projection of the run summary's negotiation block.

        ``final_confidence`` is a float wherever this key is declared, so a run
        whose judge never answered — and which therefore has no negotiation
        block to read one from — contributes 0.0 rather than a ``None`` a
        reader of the projection has no field for. A debate that measured no
        agreement has none to project: the key is absent, and the verdict's
        own confidence is not borrowed for it.
        """
        negotiation = run_summary.get("negotiation", {}) or {}
        summary: dict[str, Any] = {
            "rounds_completed": negotiation.get("rounds_completed", 0),
            "termination_reason": negotiation.get("termination_reason", "unknown"),
            "confidence_history": negotiation.get("confidence_history", []),
            "sycophancy_events": negotiation.get("sycophancy_events", 0),
        }
        if negotiation.get("termination_reason") != NOT_APPLICABLE:
            summary["final_confidence"] = negotiation.get(
                "final_confidence", overall_confidence or 0.0
            )
        return summary

    # ------------------------------------------------------------------
    # Narrative + detection attachment (called by report_node)
    # ------------------------------------------------------------------

    @staticmethod
    def apply_narrative(report: MalwareReport, narrative: dict[str, Any]) -> MalwareReport:
        """Merge an ``NarrativeOutput`` dict into the report, as the model wrote it."""
        report.executive_summary = str(narrative.get("executive_summary") or "")
        findings: list[KeyFinding] = []
        for item in narrative.get("key_findings") or []:
            try:
                findings.append(
                    item if isinstance(item, KeyFinding) else KeyFinding.model_validate(item)
                )
            except Exception:  # noqa: BLE001
                continue
        report.key_findings = findings
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
        valid_tids = {m.technique_id for m in report.ttp_mappings if m.technique_id}
        # A fresh row per recommendation rather than an edit in place. The
        # technique id is read out of the model's own sentence — it wrote
        # "block T1547 autorun" and left the structured field empty — so this
        # moves a value the LLM supplied into the field it belongs in rather
        # than choosing one on its behalf. The category is the model's own:
        # the prompt names the vocabulary, and the report prints what it chose.
        report.defensive_recommendations = [
            rec.model_copy(
                update={
                    "technique_id": rec.technique_id
                    or _first_report_technique(
                        f"{rec.action} {rec.rationale} {rec.detection or ''}", valid_tids
                    ),
                }
            )
            for rec in recs
        ]
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
    def apply_fallback_narrative(
        report: MalwareReport, why: str = "no report model ran"
    ) -> MalwareReport:
        """Say that no summary was written, and write none.

        Used when no LLM is available (mock mode) or the narrative round failed.
        It used to fill the summary, the capability paragraphs and a
        recommendation from a template, and the report printed them where the
        model's words go, so a reader could not tell the platform's sentence
        from the model's. The prose fields stay empty now; the reason is
        recorded once among the degradation reasons, and the report's key
        findings section says it and lists the verdict's facts itself.
        """
        reason = f"{NO_SUMMARY_REASON}: {why}"
        if not any(
            str(existing).startswith(NO_SUMMARY_REASON) for existing in report.degradation_reasons
        ):
            report.degradation_reasons.append(reason)
        return report

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _verdict_literal(decision: str) -> Any:
        """The decision as the report's own enum, through the one reading of it.

        The prefix rule this used to hold itself is now
        ``pipeline.outcome.normalise_verdict``, which the verdict statement is
        read with as well: two readings of one word is how a judge that wrote
        "Benign (legitimate utility)" was published as Malware while the
        renderer two layers down would have called it Benign. A word neither
        can read falls to ``Suspicious``, which is what the pipeline has
        already decided for it by the time this runs.
        """
        return normalise_verdict(decision) or INCONCLUSIVE_VERDICT

    def _severity_from_judge(
        self,
        static: Any | None,
        dynamic: Any | None,
        identity: Any | None,
    ) -> SeverityAssessment | None:
        """The judge's rating, or ``None`` when the judge did not give one.

        What this replaces was a CVSS-shaped sum — a baseline anchored to the
        verdict confidence, plus 0.5 per persistence entry, plus 0.3 per
        suspicious domain, plus 0.2 per obfuscation indicator — presented in the
        report header as a severity score out of ten. Every constant in it was
        chosen here, by a builder that had read no evidence. The score that
        replaced it was read off the rating through a fixed table, which is the
        rating said twice in a precision nobody has, and it is gone too.
        """
        verdict = getattr(self.judge_assessment, "severity", None)
        rating = str(getattr(verdict, "rating", "") or "")
        if rating not in SEVERITY_RATINGS:
            logger.info("MalwareReportBuilder: the judge assessed no severity.")
            return None
        return SeverityAssessment(
            rating=rating,  # type: ignore[arg-type]
            business_impact=str(getattr(verdict, "rationale", "") or ""),
            affected_platforms=self._guess_platforms(static, dynamic, identity),
            likely_targets=[],
        )

    def _guess_platforms(
        self, static: Any | None, dynamic: Any | None, identity: Any | None = None
    ) -> list[str]:
        platforms: list[str] = []
        if dynamic is not None and dynamic.process_tree:
            platforms.append("Windows")  # behavior almost always Windows sandbox

        # Infer Windows from the PE format itself so a
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
        # One ExternalReference per technique produced
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


def _indicators_merged_in_the_bundle(run_summary: dict[str, Any]) -> int:
    """How many indicators the STIX integrity pass folded, from the summary it wrote."""
    truncation = run_summary.get("truncation")
    if not isinstance(truncation, dict):
        return 0
    dropped = truncation.get("integrity_dropped")
    if not isinstance(dropped, dict):
        return 0
    try:
        return int(dropped.get("duplicate_indicator", 0) or 0)
    except (TypeError, ValueError):
        return 0


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


def build_consolidated_iocs(report: MalwareReport) -> list[ConsolidatedIOC]:
    """Every indicator the report holds, typed, deduplicated and live, in one table.

    Host indicators first — the sample's own hashes, then carved and dropped
    files, paths, directories, registry keys, mutexes, named pipes, scheduled
    tasks, services and command lines — then the network indicators. Each row
    carries who recorded it and the one publish rule's answer
    (:func:`~maljan.reporting.renderers.stix_renderer.publish_answer`), asked
    with the arguments ``/reports/{id}/iocs`` and the STIX export ask it with.
    Values are stored live; the human-readable renderings defang them by kind.
    """
    from maljan.extractors.network_extractor import url_host
    from maljan.reporting.renderers.stix_renderer import (
        corroborating_values,
        path_names_a_file,
        publish_answer,
    )

    rows: list[ConsolidatedIOC] = []
    seen: set[tuple[str, str]] = set()
    corroborating = corroborating_values(report)

    def _add(
        ioc_type: str,
        kind: str,
        value: str,
        source: str | None,
        context: str = "",
        *,
        published: str | None = None,
        is_network: bool = False,
    ) -> None:
        value = (value or "").strip()
        if not value:
            return
        key = (ioc_type, value.lower())
        if key in seen:
            return
        seen.add(key)
        rows.append(
            ConsolidatedIOC(
                type=ioc_type,
                kind=kind,
                value=value,
                source=source,
                context=context,
                description=context,
                published=published,
                is_network=is_network,
            )
        )

    def _from_strings(kind: str, value: str) -> str:
        return publish_answer(kind, value, "strings", corroborating=corroborating)

    h = report.identity.hashes
    # The sample's own identity, established by the router: `/iocs` serves
    # every one of these as published, and so does this table.
    for label, digest in (
        ("SHA-256", h.sha256),
        ("SHA-1", h.sha1),
        ("MD5", h.md5),
        ("SHA-512", h.sha512),
        ("imphash", h.imphash),
        ("ssdeep", h.ssdeep),
        ("TLSH", h.tlsh),
    ):
        _add(label, "hash", digest or "", "identity", "the sample", published="yes")

    static = report.static
    dynamic = report.dynamic
    strings = list(static.interesting_strings) if static else []
    file_ops = [op for op in (dynamic.file_operations if dynamic else []) if isinstance(op, dict)]

    if static:
        for res in static.embedded_resources:
            if res.get("carved") and res.get("sha256"):
                _add("SHA-256", "hash", str(res["sha256"]), "static", f"carved at {res.get('id')}")
    for op in file_ops:
        if op.get("operation") == "write" and op.get("sha256"):
            name = str(op.get("path") or op.get("name") or "")
            _add("SHA-256", "hash", str(op["sha256"]), "sandbox", f"dropped {name}".strip())

    for op in file_ops:
        if op.get("operation") == "write" and op.get("path"):
            _add("File path", "path", str(op["path"]), "sandbox", "written by the sample")
    for s in strings:
        if s.kind == "path" and not _is_pipe(s.value):
            ioc_type = "File path" if path_names_a_file(s.value) else "Directory"
            _add(ioc_type, "path", s.value, "strings", s.notes or "")

    if dynamic:
        for mod in dynamic.registry_mods:
            if mod.operation in ("create", "modify") and mod.key:
                target = f"{mod.key} ({mod.value_name})" if mod.value_name else mod.key
                _add("Registry key", "registry", target, "sandbox", mod.operation)
    for mech in report.persistence:
        if mech.kind == "registry_run" and mech.target:
            _add("Registry key", "registry", mech.target, "persistence", "run key")
    for s in strings:
        if s.kind == "registry":
            _add("Registry key", "registry", s.value, "strings", s.notes or "")

    for op in file_ops:
        if op.get("operation") == "mutex" and op.get("name"):
            _add("Mutex", "mutex", str(op["name"]), "sandbox", "created at run time")
    for s in strings:
        if s.kind == "mutex":
            _add("Mutex", "mutex", s.value, "strings", s.notes or "")

    for s in strings:
        if s.kind == "path" and _is_pipe(s.value):
            _add("Named pipe", "path", s.value, "strings", s.notes or "")

    for mech in report.persistence:
        if mech.kind == "scheduled_task" and mech.target:
            _add("Scheduled task", "scheduled_task", mech.target, "persistence", mech.payload)
    for mech in report.persistence:
        if mech.kind in ("service", "systemd_service") and mech.target:
            _add("Service", "service", mech.target, "persistence", mech.payload)

    for node in _spawned(dynamic.process_tree if dynamic else []):
        if node.command_line:
            _add("Command line", "command", node.command_line, "sandbox", f"pid {node.pid}")
    for s in strings:
        if s.kind == "command":
            _add("Command line", "command", s.value, "strings", s.notes or "")

    # Credentials and wallet addresses: no export carries them, and a
    # responder still needs to see them.
    for s in strings:
        if s.kind == "secret":
            _add("Leaked credential", "secret", s.value, "strings", s.notes or "")
        elif s.kind == "crypto_wallet":
            _add("Cryptocurrency address", "crypto_wallet", s.value, "strings", s.notes or "")

    # A string row of a kind the rule answers for is asked it; the sandbox's,
    # the persistence mechanisms' and the identity's rows are observations
    # and records the export reads on its own terms, and keep what they carry.
    for row in rows:
        if row.source == "strings" and row.kind in ("path", "registry", "mutex", "command"):
            row.published = _from_strings(row.kind, row.value)

    net = report.network
    reputations: dict[str, Any] = {}
    if net:
        for d in net.domains:
            reputations[d.fqdn.strip().lower().rstrip(".")] = d.reputation
            _add(
                "Domain",
                "domain",
                d.fqdn,
                d.source,
                _domain_context(d),
                published=publish_answer("domain", d.fqdn, d.source, d.reputation),
                is_network=True,
            )
        for ip in net.ips:
            where = [f"port {ip.port}" if ip.port else "", ip.transport or "", ip.asn or ""]
            _add(
                "IPv6" if ":" in ip.address else "IPv4",
                "ip",
                ip.address,
                ip.source,
                "; ".join(part for part in [*where, ip.geo or ""] if part),
                published=publish_answer("ip", ip.address, ip.source, ip.reputation),
                is_network=True,
            )
        for u in net.urls:
            # ``or "strings"`` exactly as the export and the feed read it: a URL
            # that records no source is the weakest claim there is.
            source = u.source or "strings"
            _add(
                "URL",
                "url",
                u.url,
                source,
                "; ".join(
                    part for part in (u.method, f"HTTP {u.status}" if u.status else "") if part
                ),
                published=publish_answer("url", u.url, source, reputations.get(url_host(u.url))),
                is_network=True,
            )
        for ua in net.user_agents:
            _add("User-Agent", "user_agent", ua, "sandbox", published="yes", is_network=True)
        for ja3 in net.ja3_fingerprints:
            _add("JA3", "ja3", ja3, "sandbox", published="yes", is_network=True)
        for ja3s in net.ja3s_fingerprints:
            _add("JA3S", "ja3s", ja3s, "sandbox", published="yes", is_network=True)

    labels = {"url": "URL", "domain": "Domain", "email": "Email"}
    for s in strings:
        if s.kind in ("url", "domain", "ip", "email"):
            label = labels.get(s.kind) or ("IPv6" if ":" in s.value else "IPv4")
            _add(
                label,
                s.kind,
                s.value,
                "strings",
                s.notes or "",
                published=_from_strings(s.kind, s.value),
                is_network=True,
            )

    return _with_what_the_export_publishes(rows, report)


# The table's type for each kind an exported indicator can name.
_EXPORTED_TYPE_LABELS = {
    "domain": "Domain",
    "url": "URL",
    "email": "Email",
    "path": "File path",
    "registry": "Registry key",
    "mutex": "Mutex",
    "command": "Command line",
}


def _with_what_the_export_publishes(
    rows: list[ConsolidatedIOC], report: MalwareReport
) -> list[ConsolidatedIOC]:
    """The table with every value the STIX export publishes on it, marked published.

    The export mints indicators from this table's own rows, and carries the
    judge's indicators besides, asked the host question and grounded in the
    run's evidence before it did. A value only the judge's objects carry was
    published by the export and missing here: a run exported the two C2 names
    FLOSS decoded while this table and ``/iocs`` listed four hashes, and another
    exported an address this table called "seen only in the file's strings".
    Such a value is a row whose source is ``judge``: added where the table had
    none, and standing in for the string sweep's row of the same value where
    the table had that one refused. A value this table already publishes stays
    the table's own row.
    """
    from maljan.reporting.renderers.stix_renderer import exported_indicator_values

    exported = exported_indicator_values(getattr(report, "stix_bundle_extended", None))
    if not exported:
        return rows
    out = list(rows)
    for item in exported:
        wanted = item.value.strip().lower()
        same = [
            index
            for index, row in enumerate(out)
            if (row.kind or "") == item.kind and row.value.strip().lower() == wanted
        ]
        if any(out[index].published == "yes" for index in same):
            continue
        if item.kind == "hash":
            label = item.algorithm or "Hash"
        elif item.kind == "ip":
            label = "IPv6" if ":" in item.value else "IPv4"
        else:
            label = _EXPORTED_TYPE_LABELS.get(item.kind, item.kind)
        network = item.kind in ("domain", "ip", "url", "email")
        row = ConsolidatedIOC(
            type=label,
            kind=item.kind,
            value=item.value,
            source="judge",
            context="the judge's indicator, carried by the STIX export",
            description="the judge's indicator, carried by the STIX export",
            published="yes",
            is_network=network,
        )
        if same:
            out[same[0]] = row
            continue
        if network:
            out.append(row)
            continue
        last_host = max(
            (index for index, existing in enumerate(out) if not existing.is_network), default=-1
        )
        out.insert(last_host + 1, row)
    return out


_PIPE_PREFIXES = ("\\\\.\\pipe\\", "//./pipe/")


def _is_pipe(value: str) -> bool:
    """Whether a path names a Windows named pipe."""
    return str(value or "").lower().startswith(_PIPE_PREFIXES)


def _spawned(roots: list[Any]) -> list[Any]:
    """Every process below the roots: the ones the sample started."""
    out: list[Any] = []
    for root in roots:
        for child in root.children:
            out.append(child)
            out.extend(_spawned([child]))
    return out


def _domain_context(d: Any) -> str:
    """What else the network block knows about a name, for the IOC table's context cell."""
    notes = [d.reason] if d.reason else []
    if isinstance(d.dga_score, int | float) and d.dga_score > 0:
        notes.append(f"DGA score {float(d.dga_score):.2f}")
    if d.is_punycode:
        target = f" resembling {d.homograph_target}" if d.homograph_target else ""
        notes.append(f"punycode{target}")
    if d.resolved_ips:
        notes.append("resolved to " + ", ".join(d.resolved_ips[:4]))
    if d.queried_pids:
        # Which process asked: when a dropped child resolves the C2 rather
        # than the parent, this is the whole story.
        notes.append("queried by pid " + ", ".join(str(p) for p in d.queried_pids[:6]))
    return "; ".join(notes)


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

    Also count network IOCs recovered from static
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
