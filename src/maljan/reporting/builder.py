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

from typing import TYPE_CHECKING, Any

from maljan.analysis.run_summary import NOT_APPLICABLE
from maljan.analysis.technique_ids import TECHNIQUE_WORD_RE
from maljan.core.logger import logger
from maljan.core.reputation import reputation_of
from maljan.extractors.attribution import build_family_attribution
from maljan.extractors.capability_matrix import build_capability_matrix, unmapped_behaviours
from maljan.memory.attck_defense import defense_for, release_for
from maljan.pipeline.outcome import (
    INCONCLUSIVE_VERDICT,
    normalise_verdict,
)
from maljan.reporting.dedupe import MergeTally
from maljan.reporting.ledger_projection import (
    analyst_listed_values,
    directed_text_from_ledger,
    dynamic_from_ledger,
    identity_from_ledger,
    network_from_ledger,
    persistence_from_ledger,
    static_from_ledger,
    tool_sightings,
)
from maljan.reporting.ledger_report import build_sections
from maljan.reporting.models import (
    AttckDefenseRow,
    AttckLink,
    ConsolidatedIOC,
    DefensiveRecommendation,
    EvidenceIndexRow,
    ExternalReference,
    JudgeIndicator,
    KeyFinding,
    MalwareReport,
    ReportFrontMatter,
    ReputationAnswer,
    SeverityAssessment,
    VersionHistoryEntry,
)
from maljan.reporting.section_servers import index_of, source_server
from maljan.schemas.judgement import SEVERITY_RATINGS

if TYPE_CHECKING:
    from maljan.reporting.detection_signatures import OwnSample
    from maljan.schemas.evidence import LedgerEntry

# How the reason for an absent summary begins, so the key-findings section can
# find it among the degradation reasons and print it where the summary would be.
NO_SUMMARY_REASON = "the report model wrote no summary"


# Words a family field holds when no family was resolved, beside the rule-name placeholders.
_FAMILY_PLACEHOLDERS = frozenset({"generic", "unknown family", "-"})

# The label the report prints for each platform a sample's identity can record.
_PLATFORM_LABELS = {
    "windows": "Windows",
    "linux": "Linux",
    "macos": "macOS",
    "android": "Android",
    "ios": "iOS",
}


class MalwareReportBuilder:
    """Stateful builder — instantiate per analysis run, call ``build_*`` methods.

    Typical lifecycle inside ``report_node``::

        builder = MalwareReportBuilder(...)
        report = builder.build_deterministic()
        if not is_mock:
            report = builder.apply_narrative(narrative_output)
        builder.render_extended_stix(report)  # mutates report.stix_bundle_extended
        report.consolidated_iocs = build_consolidated_iocs(report)  # reads the export
        report.misp_attributes = build_misp_attributes(report, owner=job_id)  # published rows
        report = builder.attach_detection_signatures(report, sample)  # published rows only
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
        overall_confidence: float | None = None,
        judge_assessment: Any | None = None,
        malware_category: str | None = None,
        degraded_mode: bool = False,
        degradation_reasons: list[str] | None = None,
        operator_choices: list[str] | None = None,
        sample_platform: str | None = None,
        sample_file_type: str | None = None,
        evidence_ledger: list[LedgerEntry] | None = None,
        job_id: str | None = None,
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
        # A reason that is the operator's choice is listed apart whoever
        # handed it in (``pipeline.operator_choice``): never a degradation.
        from maljan.pipeline.operator_choice import split_operator_choices

        self.degradation_reasons, chosen = split_operator_choices(degradation_reasons or [])
        self.operator_choices = list(dict.fromkeys([*(operator_choices or []), *chosen]))
        self.sample_platform = sample_platform
        self.sample_file_type = sample_file_type
        # Every tool call the run made, in the order the ids were issued. The
        # report's sections and its typed blocks are both built from this and
        # from the agents' own artifacts; an empty ledger means an empty
        # report body, which is the honest outcome for a run that gathered
        # nothing.
        self.evidence_ledger = list(evidence_ledger or [])
        # The job the report is built for: what its MISP attributes' uuids are
        # derived from. A build with none (the command line, a test) uses the
        # report's own number.
        self.job_id = job_id

    # ------------------------------------------------------------------
    # Deterministic build
    # ------------------------------------------------------------------

    def build_deterministic(self) -> MalwareReport:
        """Build a deterministic ``MalwareReport`` out of the evidence ledger."""
        from maljan.pipeline.evidence_summary import yara_rule_strings
        from maljan.reporting.renderers.stix_renderer import (
            emulation_from_ledger,
            exported_indicator_values,
            recovered_network_values,
        )

        # What the calls answered. A repeat the guard answered from an earlier
        # entry holds a note, not an answer, and is in the index alone.
        ledger = [e for e in self.evidence_ledger if not getattr(e, "repeated_of", None)]
        identity = identity_from_ledger(
            ledger,
            sample_path=self.sample_path,
            file_name=self.file_name,
            file_hash=self.file_hash,
            file_type=self.sample_file_type or "unknown",
            platform=self.sample_platform or "unknown",
        )
        # The typed blocks are projections, not a second analysis: each is
        # filled from the tools that were actually called, and each stays
        # empty otherwise. The network block also reads which values the
        # analysts listed, which it states and never publishes on alone.
        static = static_from_ledger(ledger)
        directed = directed_text_from_ledger(ledger)
        dynamic = dynamic_from_ledger(ledger)
        # What only a recovering tool read. Each domain, address and URL in it
        # is a candidate row of its own, whether or not a model named it: a
        # C2 URL FLOSS and the static decoder both recovered once had no row
        # anywhere, not even a refused one, while the record gave it standing.
        emulated = emulation_from_ledger(ledger)
        # Where the run's tools saw each value an analyst listed: a listed
        # value stands on the answer that holds it, and "no tool saw it" is
        # said only when this search of the whole ledger found none.
        # The judge's indicator values too: a value it names and no row
        # publishes is said to be the judge's alone only after this search.
        sightings, queries = tool_sightings(
            ledger,
            [
                *analyst_listed_values(self.isr_reports),
                *(
                    (value.kind, value.value)
                    for value in exported_indicator_values(self.stix_output)
                ),
            ],
        )
        network = network_from_ledger(
            ledger,
            self.isr_reports,
            sandbox_report=self.sandbox_report,
            recovered=recovered_network_values(emulated),
            sightings=sightings,
        )
        persistence = persistence_from_ledger(ledger)
        cells, mappings = build_capability_matrix(
            stix_output=self.stix_output,
            isr_reports=self.isr_reports,
            # The routed minimum, which is what the analyst loop and the
            # judge's bundle check were given: a technique from a domain this
            # sample cannot host is kept in the matrix and left unpublished.
            sample={"platform": self.sample_platform, "file_type": self.sample_file_type},
            # Every call, repeats included: a statement citing a repeat cites
            # the entry that holds its answer, and its roots are that entry's.
            ledger=self.evidence_ledger,
        )
        severity = self._severity_from_judge(static, dynamic, identity)
        verdict = self._verdict_literal(self.final_decision)
        attribution = build_family_attribution(
            judge_family=getattr(self.judge_assessment, "family", None),
            sandbox_report=self.sandbox_report,
        )

        negotiation_summary = self._negotiation_summary(self.run_summary, self.overall_confidence)

        references = self._build_references(mappings, identity.hashes)

        defense = attck_defense_rows(mappings)
        report = MalwareReport(
            verdict=verdict,
            overall_confidence=self.overall_confidence,
            malware_category=self.malware_category,
            severity=severity,
            degraded_mode=self.degraded_mode,
            degradation_reasons=self.degradation_reasons,
            operator_choices=self.operator_choices,
            identity=identity,
            static=static,
            directed_text=directed,
            dynamic=dynamic,
            network=network,
            persistence=persistence,
            capability_matrix=cells,
            ttp_mappings=mappings,
            unmapped_behaviours=unmapped_behaviours(self.stix_output),
            attck_defense=defense,
            attck_defense_version=release_for(r.technique_id for r in defense),
            attribution=attribution,
            executive_summary="",  # filled by NarrativeAgent
            defensive_recommendations=[],  # filled by NarrativeAgent
            detection_signatures=[],  # filled by detection_signatures.py
            run_summary=self.run_summary,
            negotiation_summary=negotiation_summary,
            stix_bundle_extended=self.stix_output,
            judge_indicators=[
                JudgeIndicator(kind=value.kind, value=value.value, algorithm=value.algorithm)
                for value in exported_indicator_values(self.stix_output)
            ],
            rule_match_strings=yara_rule_strings(ledger),
            emulated_strings=emulated,
            tool_sightings=sightings,
            tool_queries=queries,
            references=references,
        )
        # The sections the report is actually made of, and the index of the
        # calls behind them. Built last so a section builder can never affect
        # the verdict, the severity or the STIX bundle above it.
        merges = MergeTally()
        report.sections = build_sections(
            ledger,
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
                repeated_of=entry.repeated_of or None,
                source=entry.source,
                facts=entry.facts,
                agent_role=entry.agent_role,
                agent_tab=entry.agent_tab,
            )
            for entry in self.evidence_ledger
        ]
        index = index_of(report.evidence_index)
        for section in report.sections:
            section.source_server = source_server(section, index)
        report.reputation = _reputation_answers(self.evidence_ledger)

        # Deterministic front-matter, version history,
        # and consolidated IOC table (the professional-report scaffolding the
        # Composer's prose sits inside). All derived from already-built fields.
        report.front_matter = self._build_front_matter(report)
        report.tlp = report.front_matter.tlp
        report.version_history = _build_version_history(report.front_matter)
        report.consolidated_iocs = build_consolidated_iocs(report)
        # The MISP attributes of the table's published rows and the published
        # techniques, so the console's MISP export and the job package carry them.
        from maljan.reporting.misp import build_misp_attributes, misp_owner

        report.misp_attributes = build_misp_attributes(
            report, owner=misp_owner(report, self.job_id)
        )
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

        ``final_confidence`` is present only where the mediator stated one. A
        debate that measured no agreement — it did not apply, or its mediation
        failed — has none to project: the key is absent, and neither the
        verdict's own confidence nor a 0.0 is put in its place.
        """
        negotiation = run_summary.get("negotiation", {}) or {}
        summary: dict[str, Any] = {
            "rounds_completed": negotiation.get("rounds_completed", 0),
            "termination_reason": negotiation.get("termination_reason", "unknown"),
            "confidence_history": negotiation.get("confidence_history", []),
            "sycophancy_events": negotiation.get("sycophancy_events", 0),
        }
        # The mediator's own last number, where it stated one. The verdict's
        # confidence is not borrowed for it, and no 0.0 stands in for none.
        final = negotiation.get("final_confidence")
        if negotiation.get("termination_reason") != NOT_APPLICABLE and final is not None:
            summary["final_confidence"] = final
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
    def attach_detection_signatures(
        report: MalwareReport, sample: OwnSample | None = None
    ) -> MalwareReport:
        """Populate ``report.detection_signatures`` with template-generated rules.

        Calls into :mod:`maljan.reporting.detection_signatures` which produces
        up to three rules (YARA / Sigma / Suricata) keyed by the report's
        IOCs. Missing evidence in any of the three input domains results in
        that format being skipped (never an empty rule). Generation is
        deterministic — no LLM involvement. ``sample`` is the file the YARA
        draft is run against once it compiles.
        """
        from maljan.reporting.detection_signatures import build_detection_rules

        report.detection_signatures = build_detection_rules(report, sample)
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
        # What the sample says it was built for comes first: its recorded
        # platform, its PE header, an ELF section. A sandbox process tree names
        # Windows only for a sample that says nothing of its own, so an ELF or
        # an APK that ran is not reported as a Windows threat.
        platforms: list[str] = []
        recorded = str(getattr(identity, "platform", "") or "").lower()
        if recorded in _PLATFORM_LABELS:
            platforms.append(_PLATFORM_LABELS[recorded])

        # file_type "PE" or the MS-download MIME is a definitive Windows signal.
        if identity is not None and not platforms:
            file_type = str(getattr(identity, "file_type", "") or "").upper()
            mime = str(getattr(identity, "mime_type", "") or "").lower()
            if file_type == "PE" or "msdownload" in mime or "x-dosexec" in mime:
                platforms.append("Windows")

        if not platforms and static is not None and static.sections:
            if any(s.characteristics == "ELF" for s in static.sections):
                platforms.append("Linux")

        if not platforms and dynamic is not None and dynamic.process_tree:
            platforms.append("Windows")  # the sandbox guest is Windows
        if not platforms:
            platforms.append("Unknown")
        return platforms

    def _build_references(self, mappings: list[Any], hashes: Any) -> list[ExternalReference]:
        """The report's references: the sample lookups of the sources the run used, then ATT&CK.

        A source links its declared lookups (``reference_urls``) only when
        the run recorded an entry from it, and the operator's own templates
        (``reporting.reference_urls``) are linked on every report
        (``reporting.references``). A run that asked no service links none.
        """
        from maljan.core.config import get_settings
        from maljan.reporting.references import declared_references

        operator: list[Any] = []
        try:
            operator = list(get_settings().reporting.reference_urls)
        except Exception as exc:  # noqa: BLE001 — a reference is never worth a report
            logger.debug(
                "MalwareReportBuilder: no operator references read (%s).", type(exc).__name__
            )
        try:
            refs = declared_references(self.evidence_ledger, hashes, operator=operator)
        except Exception as exc:  # noqa: BLE001 — a reference is never worth a report
            logger.warning(
                "MalwareReportBuilder: the sample lookups were not read (%s).", type(exc).__name__
            )
            refs = []
        # One ExternalReference per technique produced
        # the "MITRE ATT&CK" source label repeated 7×. Emit a single grouped
        # ATT&CK reference (pointing at the matrix landing page) whose note lists
        # the techniques, plus deduped per-technique links keyed by technique id.
        seen_tids: set[str] = set()
        tech_notes: list[str] = []
        for mapping in mappings:
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

        # The family the run resolved names the malware, when the verdict is not
        # benign and the family has a source behind it; otherwise the category.
        # "Unknown", "generic" and the like are no name.
        from maljan.reporting.detection_signatures import _PLACEHOLDER_NAMES, is_benign

        family = report.attribution.family if report.attribution else None
        family = family.strip() if isinstance(family, str) else ""
        family_named = bool(
            family
            and family.lower() not in _PLACEHOLDER_NAMES | _FAMILY_PLACEHOLDERS
            and not is_benign(report)
            and report.attribution.family_grounded
        )
        name = family if family_named else report.malware_category
        subtitle = None
        if report.identity.platform and report.malware_category:
            subtitle = f"{report.malware_category} targeting {report.identity.platform.title()}"

        return ReportFrontMatter(
            publisher=rc.publisher,
            product_type=rc.product_type,
            malware_name=(
                (name if family_named else name.title()) if isinstance(name, str) and name else None
            ),
            subtitle=subtitle,
            version="1.0",
            report_date=f"{now:%Y-%m-%d}",
            report_number=report_number,
            team=rc.author_team,
            tlp=tlp,
            copyright=f"© {now:%Y} {rc.publisher}",
        )


def _reputation_answers(ledger: list[LedgerEntry]) -> list[ReputationAnswer]:
    """Every reputation answer of the ledger that established something, in ledger order.

    Each is the record its lookup's declaration read when the entry was
    written (``core.reputation.reputation_of``), from any server.
    """
    out: list[ReputationAnswer] = []
    for entry in ledger:
        answer = reputation_of(entry)
        if answer is not None and answer.says_something():
            out.append(ReputationAnswer(entry_id=entry.id, tool=entry.tool, **answer.model_dump()))
    return out


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
    The report's lookups are built once for the whole table (``one_reading``).
    """
    from maljan.reporting.renderers.stix_renderer import one_reading

    with one_reading(report):
        return _build_consolidated_iocs(report)


def ioc_table(report: MalwareReport, *, raise_unread: bool = False) -> list[ConsolidatedIOC]:
    """The IOC table the report's §9 prints and ``/reports/{id}/iocs`` serves, from one source.

    Rebuilt from the stored report by the current rule
    (:func:`build_consolidated_iocs`), so a report stored before a row kind or
    an answer's wording existed reads the same in §9, in the feed's analyst
    rows, in a cell's publish state and in the composer's checks
    (``narrative_agent.published_answers``). The stored rows that carry a
    kind are read only when the rebuild fails; with ``raise_unread`` and no
    such row, the rebuild's error is raised, so a caller that fails closed
    can tell a table it could not read from a table with no rows.
    """
    try:
        return build_consolidated_iocs(report)
    except Exception:  # noqa: BLE001 — the stored rows are the fallback
        stored = [row for row in report.consolidated_iocs if row.kind]
        if raise_unread and not stored:
            raise
        logger.exception("builder: the IOC table could not be rebuilt; the stored rows are read.")
        return stored


def _build_consolidated_iocs(report: MalwareReport) -> list[ConsolidatedIOC]:
    from maljan.extractors.network_extractor import url_host
    from maljan.reporting.ledger_projection import listed_non_network_values
    from maljan.reporting.ledger_report import artifact_sections, listed_headings, listed_rows
    from maljan.reporting.renderers.stix_renderer import (
        corroborating_values,
        digest_label,
        emulation_kwargs,
        emulation_record,
        listed_value_sightings,
        path_names_a_file,
        persistence_run_keys,
        publish_answer,
        query_answers,
        recovered_by_words,
        sandbox_host_kwargs,
        yes_because,
    )

    rows: list[ConsolidatedIOC] = []
    seen: set[tuple[str, str]] = set()
    judged = {
        (str(item.kind or ""), str(item.value or "").strip().lower())
        for item in report.judge_indicators or []
    }
    corroborating = corroborating_values(report)
    # What the run's FLOSS entry recovered by emulation and the static decoder
    # read out of the file's bytes: a network value it holds is a source of
    # its own under the one rule.
    emulated = emulation_record(report)

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
        return publish_answer(
            kind,
            value,
            "strings",
            corroborating=corroborating,
            **emulation_kwargs(report, kind, value, emulated),
        )

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
        _add(
            label, "hash", digest or "", "identity", "the sample", published=yes_because("identity")
        )

    static = report.static
    dynamic = report.dynamic
    strings = list(static.interesting_strings) if static else []
    file_ops = [op for op in (dynamic.file_operations if dynamic else []) if isinstance(op, dict)]

    # A file, a digest, a key or a mutex the sandbox recorded is published
    # only as an indicator the judge names: one a record attributes to the
    # sample's tree on that keep, one no record attributes only when the judge
    # kept it when asked with that fact, as an unattributed flow is
    # (``stix_renderer.sandbox_host_kwargs``). Every other is withheld with
    # the reason.
    def _sandbox_host(kind: str, value: str) -> str:
        return publish_answer(kind, value, "sandbox", **sandbox_host_kwargs(report, kind, value))

    def _digest_type(value: str) -> str:
        # A digest is named by its length; any other length names none.
        return digest_label(value) or "Hash"

    if static:
        for res in static.embedded_resources:
            if res.get("carved") and res.get("sha256"):
                carved = str(res["sha256"])
                _add(_digest_type(carved), "hash", carved, "static", f"carved at {res.get('id')}")
    for op in file_ops:
        if op.get("operation") == "write" and op.get("sha256"):
            name = str(op.get("path") or op.get("name") or "")
            digest = str(op["sha256"])
            _add(
                _digest_type(digest),
                "hash",
                digest,
                "sandbox",
                f"dropped {name}".strip(),
                published=_sandbox_host("hash", digest),
            )

    for op in file_ops:
        if op.get("operation") == "write" and op.get("path"):
            written_path = str(op["path"])
            _add(
                "File path",
                "path",
                written_path,
                "sandbox",
                "written by the sample",
                published=_sandbox_host("path", written_path),
            )
    for s in strings:
        if s.kind == "path" and not _is_pipe(s.value):
            ioc_type = "File path" if path_names_a_file(s.value) else "Directory"
            _add(ioc_type, "path", s.value, "strings", s.notes or "")

    # The key is the row's value, as every surface carries it (a STIX
    # registry key, a MISP regkey, the Sigma selection); each value the sample
    # wrote under it is named in the row's context. A key a persistence
    # mechanism names is that mechanism's row, answered as a persistence
    # record, with the sandbox's writes under it in its context.
    written: dict[str, tuple[str, dict[str, None]]] = {}
    for mod in dynamic.registry_mods if dynamic else []:
        if mod.operation in ("create", "modify") and mod.key.strip():
            said = f"{mod.operation} value {mod.value_name}" if mod.value_name else mod.operation
            written.setdefault(mod.key.strip().lower(), (mod.key.strip(), {}))[1][said] = None
    run_keys = persistence_run_keys(report.persistence)
    for folded, (key, operations) in written.items():
        if folded in run_keys:
            continue
        # A key is attributed by the pids of the calls that wrote it, where
        # the sandbox kept them (``RegistryMod.pids``).
        _add(
            "Registry key",
            "registry",
            key,
            "sandbox",
            "; ".join(operations),
            published=_sandbox_host("registry", key),
        )
    for folded, target in run_keys.items():
        under = written.get(folded)
        context = "; ".join(["run key", *(under[1] if under else [])])
        _add("Registry key", "registry", target, "persistence", context)
    for s in strings:
        if s.kind == "registry":
            _add("Registry key", "registry", s.value, "strings", s.notes or "")

    for op in file_ops:
        if op.get("operation") == "mutex" and op.get("name"):
            mutex = str(op["name"])
            _add(
                "Mutex",
                "mutex",
                mutex,
                "sandbox",
                "created at run time",
                published=_sandbox_host("mutex", mutex),
            )
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

    # Every row is asked the one rule: a string row as the string sweep's,
    # with the run's second-source record, and a row the sandbox, a
    # persistence record or a static carve recorded under the source that
    # recorded it — the export carries the ones it publishes (a dropped
    # file's digest, a path, a key, a mutex), and refuses a command line, a
    # task and a service, for which it has no object.
    for row in rows:
        if row.published is not None:
            continue
        if row.source == "strings":
            row.published = _from_strings(row.kind or "", row.value)
        else:
            row.published = publish_answer(row.kind or "", row.value, row.source)

    # What the analysts listed that no tool recorded: each value its own row,
    # in the analyst's name and with the rule's refusal, after every tool row
    # so a value a tool recorded keeps the tool's row. A value the judge names
    # is the judge's row.
    for kind, section in artifact_sections(report.sections):
        headings = listed_headings(section)
        for analyst, _cited, cells in listed_rows(section):
            for ioc_kind, value, _payload in listed_non_network_values(kind, [cells], headings):
                if (ioc_kind, value.strip().lower()) in judged:
                    continue
                listed = f"an artifact of the {analyst} analyst" if analyst else ""
                sighted, searched = listed_value_sightings(report, ioc_kind, value)
                _add(
                    _LISTED_LABELS.get(ioc_kind, ioc_kind)
                    if ioc_kind != "path"
                    else ("File path" if path_names_a_file(value) else "Directory"),
                    ioc_kind,
                    value,
                    "analyst",
                    f"listed by the {analyst} analyst" if analyst else "listed by an analyst",
                    published=publish_answer(
                        ioc_kind,
                        value,
                        "analyst",
                        listed_by=listed,
                        seen_in=sighted,
                        tool_search=searched,
                        asked_in="" if sighted else query_answers(report, ioc_kind, value),
                    ),
                )

    net = report.network
    reputations: dict[str, Any] = {}
    # A fingerprint and a user agent are the sandbox's own records of the
    # traffic; no string sweep produces one, and the reason says so.
    _seen = yes_because("sandbox")
    if net:
        for d in net.domains:
            reputations[d.fqdn.strip().lower().rstrip(".")] = d.reputation
            _add(
                "Domain",
                "domain",
                d.fqdn,
                d.source,
                _domain_context(d),
                published=publish_answer(
                    "domain",
                    d.fqdn,
                    d.source,
                    d.reputation,
                    **emulation_kwargs(report, "domain", d.fqdn, emulated),
                ),
                is_network=True,
            )
        for ip in net.ips:
            where = [
                f"port {ip.port}" if ip.port else "",
                ip.transport or "",
                f"AS {ip.asn}" if ip.asn else "",
                "public DNS resolver" if ip.public_resolver else "",
                _process_tree_words(
                    ip.sample_process_tree,
                    ip.outside_processes,
                    ip.marked_only_processes,
                    ip.file_only_processes,
                    ip.marked_by,
                )
                if ip.source == "sandbox"
                else "",
            ]
            _add(
                "IPv6" if ":" in ip.address else "IPv4",
                "ip",
                ip.address,
                ip.source,
                "; ".join(part for part in [*where, ip.geo or ""] if part),
                published=publish_answer(
                    "ip",
                    ip.address,
                    ip.source,
                    ip.reputation,
                    **emulation_kwargs(report, "ip", ip.address, emulated),
                ),
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
                published=publish_answer(
                    "url",
                    u.url,
                    source,
                    reputations.get(url_host(u.url)),
                    **emulation_kwargs(report, "url", u.url, emulated),
                ),
                is_network=True,
            )
        for ua in net.user_agents:
            _add("User-Agent", "user_agent", ua, "sandbox", published=_seen, is_network=True)
        for ja3 in net.ja3_fingerprints:
            _add("JA3", "ja3", ja3, "sandbox", published=_seen, is_network=True)
        for ja3s in net.ja3s_fingerprints:
            _add("JA3S", "ja3s", ja3s, "sandbox", published=_seen, is_network=True)

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

    table = _with_the_hosts_of_published_urls(_with_the_judge_s_values(rows, report), report)
    # Which tool recovered each network value the sample hid, and where: the
    # table states it on every row the record holds, whoever recorded the row.
    return [
        row.model_copy(update={"recovered_by": said})
        if (said := recovered_by_words(emulated, row.kind or "", row.value))
        else row
        for row in table
    ]


# The table's type for each non-network kind an analyst's table lists.
_LISTED_LABELS = {
    "mutex": "Mutex",
    "registry": "Registry key",
    "scheduled_task": "Scheduled task",
    "service": "Service",
}


# The table's type for each kind a judge indicator can name.
_EXPORTED_TYPE_LABELS = {
    "domain": "Domain",
    "url": "URL",
    "email": "Email",
    "path": "File path",
    "registry": "Registry key",
    "mutex": "Mutex",
    "command": "Command line",
}


def _with_the_judge_s_values(
    rows: list[ConsolidatedIOC], report: MalwareReport
) -> list[ConsolidatedIOC]:
    """The table with the values the judge's indicators name, each with the rule's answer.

    The export asks the one publish rule of every judge indicator before it
    carries one (``stix_renderer.judge_value_answer``); this table asks the same
    rule of the same values, so it prints what the export decided: a judge
    value the rule publishes is ``yes``, and one it refuses — a host only the
    file's strings carry — is ``no:`` with the reason, and is not exported. A
    value the table already has a row for keeps that row: its answer is the
    same one, asked of the same source. A run once exported two C2 names the
    judge read out of decoded strings while this table listed four hashes.
    """
    from maljan.reporting.renderers.stix_renderer import judge_indicator_rows

    judged = judge_indicator_rows(report)
    if not judged:
        return rows
    out = list(rows)
    for item, answer in judged:
        wanted = item.value.strip().lower()
        same = [
            index
            for index, row in enumerate(out)
            if (row.kind or "") == item.kind and row.value.strip().lower() == wanted
        ]
        if same:
            # The row was asked the rule under the source that recorded it,
            # with the judge's keep where the rule reads one: the same answer
            # the judge's indicator for the value gets.
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
            context="the judge's indicator",
            description="the judge's indicator",
            published=answer,
            is_network=network,
        )
        if network:
            out.append(row)
            continue
        last_host = max(
            (index for index, existing in enumerate(out) if not existing.is_network), default=-1
        )
        out.insert(last_host + 1, row)
    return out


def _with_the_hosts_of_published_urls(
    rows: list[ConsolidatedIOC], report: MalwareReport
) -> list[ConsolidatedIOC]:
    """The table with a Domain row for the host of each URL it publishes.

    A published URL's host follows the URL's decision
    (``stix_renderer.published_url_hosts``): one live run published two C2
    URLs and neither of their names, because the judge wrote URL indicators
    only and nothing carried a URL's host to a row. A host the table already
    has a row for keeps that row, asked the same rule.
    """
    from maljan.reporting.renderers.stix_renderer import (
        emulation_kwargs,
        publish_answer,
        published_url_hosts,
    )

    hosts = published_url_hosts(report)
    if not hosts:
        return rows
    out = list(rows)
    listed = {row.value.strip().lower().rstrip(".") for row in out if row.kind == "domain"}
    for host, (url, source) in hosts.items():
        if host in listed:
            continue
        out.append(
            ConsolidatedIOC(
                type="Domain",
                kind="domain",
                value=host,
                source=source,
                context=f"the host of {url}",
                description=f"the host of {url}",
                published=publish_answer(
                    "domain", host, source, **emulation_kwargs(report, "domain", host)
                ),
                is_network=True,
            )
        )
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


def _process_tree_words(
    attributed: bool | None,
    outside: list[str] | None = None,
    marked_only: list[str] | None = None,
    file_only: list[str] | None = None,
    marked_by: str | None = None,
) -> str:
    """What the sandbox report says about which process reached an address."""
    if attributed is True:
        return "reached by the sample's process tree"
    if attributed is False:
        named = f" ({', '.join(outside)})" if outside else ""
        return f"reached by a process outside the sample's process tree{named}"
    if marked_only or file_only:
        from maljan.reporting.renderers.stix_renderer import disputed_flow_reason

        return disputed_flow_reason(list(marked_only or []), list(file_only or []), marked_by)
    return "the sandbox report does not say which process reached it"


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
    if getattr(d, "resolved_ips_partial", False):
        notes.append(
            f"some addresses withheld for size ({d.resolved_ips_withheld} of its DNS "
            "request's answers not read)"
        )
    if d.queried_pids:
        # Which process asked: when a dropped child resolves the C2 rather
        # than the parent, this is the whole story.
        notes.append("queried by pid " + ", ".join(str(p) for p in d.queried_pids[:6]))
    return "; ".join(notes)


def attck_defense_rows(mappings: list[Any]) -> list[AttckDefenseRow]:
    """ATT&CK's own defence for each published technique, in the report's technique order.

    Deterministic and offline: read from the cached bundles
    (``memory.attck_defense``). A technique ATT&CK lists nothing for, and a
    run with no cached bundle, add no row.
    """
    published = [m for m in mappings if str(m.technique_id or "").strip()]
    found = defense_for(m.technique_id for m in published)
    rows: list[AttckDefenseRow] = []
    for mapping in published:
        defense = found.get(str(mapping.technique_id).strip().upper())
        if defense is None:
            continue
        rows.append(
            AttckDefenseRow(
                technique_id=mapping.technique_id,
                technique_name=mapping.technique_name,
                mitigations=[AttckLink(**vars(o)) for o in defense.mitigations],
                detection_strategies=[AttckLink(**vars(o)) for o in defense.detection_strategies],
                data_components=[AttckLink(**vars(o)) for o in defense.data_components],
                evidence_ids=list(mapping.sources),
            )
        )
    return rows


def _first_report_technique(text: str, valid_tids: set[str]) -> str | None:
    """Return the first T#### in ``text`` that the report publishes, else ``None``.

    An id the prose names and the report's ATT&CK table does not carry is not
    moved into the technique column: it would print as the technique the
    action acts on, with nothing behind it.
    """
    for tid in TECHNIQUE_WORD_RE.findall(text or ""):
        if tid in valid_tids:
            return str(tid)
    return None


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
