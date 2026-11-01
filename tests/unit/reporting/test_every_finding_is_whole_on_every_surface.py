"""A finding the report carries is whole on every surface it reaches.

Three ways the report used to lose part of a finding:

* **A body cell cut to fit (T-399).** A model-written table cell, a command
  line, a URL and the rows of a body evidence section were cut at 240 (or 160)
  characters and ended in ``…``; the HTML report, drawn from the Markdown, lost
  the same text. Every body cell is now whole; only Appendix A cuts a one-line
  value, and says where it is whole.
* **An indicator related to nothing (T-402).** Only the sample's hash and the
  indicators the judge related indicated the malware object; every other
  indicator the export published, a mutex or a domain among them, had no
  ``indicates`` edge. Each now has one to the sample's malware object, said to
  be the platform's, unless it is typed ``benign``.
* **One claim counted once per technique (T-406).** A claim block whose
  TECHNIQUE line listed several ids is read as one claim per id; §13.1, the
  claims in force and the per-analyst claim count numbered each copy. Each is
  one claim now, with its techniques together, and the per-technique views keep
  every technique.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from typing import Any

import pytest
from stix2validator import ValidationOptions, validate_instance

from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.claim_coverage import claims_in_force, claims_not_discussed
from maljan.reporting.models import (
    CommandRow,
    EvidenceSection,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
    StaticAnalysis,
    TechnicalAnalysis,
)
from maljan.reporting.renderers import HtmlRenderer, MarkdownRenderer
from maljan.reporting.renderers.pdf import PdfRenderer, PdfUnavailableError
from maljan.reporting.renderers.stix_renderer import (
    PLATFORM_INDICATES_EDGE,
    ExtendedSTIXRenderer,
    sample_similarity_pattern,
)
from maljan.schemas.isr_models import (
    ABSENCE_TECHNIQUE_MARKER,
    UNVERIFIED_TECHNIQUE_MARKER,
    AgentISR,
    ClaimEvidence,
)
from maljan.schemas.stix_models import Bundle

SHA256 = "36dabc40fa8983ce900a90b8156d2c754875fe1b5413a997843c4a0ef3908220"
# Longer than every width a body cell was ever cut to, and ending in a word
# a cut would have dropped.
LONG = " ".join(f"step{i} reads slot 0x{0x10000 + i:x}" for i in range(40)) + " ENDMARK"


def _report(**fields: Any) -> MalwareReport:
    return MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)), **fields)


def _body(markdown: str) -> str:
    return markdown.split("## Appendix A")[0]


class TestABodyCellIsWhole:
    def test_a_model_written_cell_is_printed_whole_in_the_markdown_and_the_html(self) -> None:
        report = _report(
            technical_analysis=TechnicalAnalysis(
                commands=[CommandRow(id="7", name="run", description=LONG)]
            )
        )

        markdown = MarkdownRenderer().render(report)
        html = HtmlRenderer().render(report, nonce="fixed")

        (row,) = [line for line in markdown.splitlines() if line.startswith("| 7 |")]
        assert LONG in row
        assert not row.rstrip(" |").endswith("…")
        (cell,) = [
            td.split("</td>")[0]
            for td in html.split("<td>")[1:]
            if "step0 " in td.split("</td>")[0]
        ]
        assert cell.rstrip().endswith("ENDMARK")

    def test_a_20_kb_cell_prints_to_pdf_whole_and_in_bounded_time(self) -> None:
        """A sample's command line can run to kilobytes; the print layout is
        fixed, so the PDF is not measured word by word, and keeps every word."""
        words = " ".join(f"W{i:05d}" for i in range(2900))
        assert len(words) > 20_000
        report = _report(
            technical_analysis=TechnicalAnalysis(
                commands=[CommandRow(id="7", name="run", description=f"{words} ENDMARK")]
            )
        )
        pdftotext = shutil.which("pdftotext")
        if pdftotext is None:
            pytest.skip("pdftotext is not installed on this host")
        started = time.monotonic()
        try:
            pdf = PdfRenderer().render(report)
        except PdfUnavailableError:
            pytest.skip("WeasyPrint cannot be loaded on this host")
        took = time.monotonic() - started

        text = subprocess.run(
            [pdftotext, "-", "-"], input=pdf, capture_output=True, check=True
        ).stdout.decode()
        assert set(re.findall(r"W\d{5}", text)) == set(words.split())
        assert "ENDMARK" in text
        # An automatic layout took over two minutes on half this cell.
        assert took < 30, took

    def test_a_body_evidence_section_row_is_whole_and_appendix_a_still_cuts(self) -> None:
        report = _report(
            static=StaticAnalysis(),
            sections=[
                EvidenceSection(
                    key="yara_matches",
                    title="YARA matches",
                    kind="table",
                    columns=["rule"],
                    rows=[[LONG]],
                    evidence_ids=["ev_0001"],
                )
            ],
        )

        markdown = MarkdownRenderer().render(report)

        body = [line for line in _body(markdown).splitlines() if "step0 " in line]
        appendix = markdown[markdown.index("## Appendix A") :].split("\n## Appendix B")[0]
        cut = [line for line in appendix.splitlines() if "step0 " in line]
        assert body and all("ENDMARK" in line for line in body)
        assert cut and all("ENDMARK" not in line and "…" in line for line in cut)
        assert "is cut to fit the page" in appendix

    def test_the_methodology_says_the_body_cuts_no_table_value(self) -> None:
        markdown = MarkdownRenderer().render(_report())

        assert "No table value in the body of the report is cut." in markdown


def _network_report(verdict: str = "Malware") -> MalwareReport:
    return _report(
        verdict=verdict,
        malware_category="loader",
        network=NetworkIOCs(
            domains=[NetworkDomain(fqdn="titnovacrion.top", source="sandbox")],
        ),
    )


class TestEveryIndicatorIndicatesTheSample:
    def test_every_indicator_has_an_indicates_edge_to_the_malware_object(self) -> None:
        bundle = ExtendedSTIXRenderer().render(_network_report())

        objects = bundle.objects
        (malware,) = [o for o in objects if o.type == "malware"]
        indicators = [o for o in objects if o.type == "indicator"]
        assert len(indicators) >= 2
        edges = {
            str(o.source_ref): o
            for o in objects
            if o.type == "relationship" and o.relationship_type == "indicates"
        }
        for indicator in indicators:
            assert str(indicator.id) in edges, indicator.name
            assert str(edges[str(indicator.id)].target_ref) == str(malware.id)
        (report_object,) = [o for o in objects if o.type == "report"]
        added = [o for o in edges.values() if o.description == PLATFORM_INDICATES_EDGE]
        assert added
        assert {str(o.id) for o in added} <= set(report_object.object_refs)

    def test_the_bundle_with_the_added_edges_passes_the_official_validator(self) -> None:
        bundle = ExtendedSTIXRenderer().render(_network_report())

        result = validate_instance(bundle.model_dump(mode="json"), ValidationOptions(version="2.1"))
        assert result.is_valid, [str(e) for e in result.errors]

    def test_an_indicator_the_judge_related_otherwise_is_not_upgraded(self) -> None:
        """A judge's ``related-to`` ("shared hosting; not specific") is its word
        that the value does not indicate the malware: no platform edge is added."""
        malware = "malware--0f1e2d3c-4b5a-4968-8776-655443332299"
        indicator = "indicator--1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d"
        judge = Bundle.model_validate(
            {
                "type": "bundle",
                "id": "bundle--2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e",
                "objects": [
                    {
                        "type": "malware",
                        "id": malware,
                        "name": "Loader",
                        "is_family": False,
                        "malware_types": ["trojan"],
                    },
                    {
                        "type": "indicator",
                        "id": indicator,
                        "name": "Domain titnovacrion.top",
                        "pattern": "[domain-name:value = 'titnovacrion.top']",
                        "pattern_type": "stix",
                        "indicator_types": ["anomalous-activity"],
                    },
                    {
                        "type": "relationship",
                        "id": "relationship--3c4d5e6f-7a8b-4c9d-8e1f-2a3b4c5d6e7f",
                        "relationship_type": "related-to",
                        "source_ref": indicator,
                        "target_ref": malware,
                        "description": "shared hosting; not specific",
                    },
                ],
            }
        )

        bundle = ExtendedSTIXRenderer().render(_network_report(), judge)

        by_id = {str(o.id): o for o in bundle.objects}
        (domain,) = [
            o
            for o in bundle.objects
            if o.type == "indicator" and "titnovacrion.top" in str(o.pattern)
        ]
        edges = [
            o
            for o in bundle.objects
            if o.type == "relationship" and str(domain.id) in (str(o.source_ref), str(o.target_ref))
        ]
        assert [(o.relationship_type, o.description) for o in edges] == [
            ("related-to", "shared hosting; not specific")
        ]
        assert by_id[str(edges[0].target_ref)].type == "malware"

    def test_the_similarity_digests_indicate_the_sample_like_every_other_digest(self) -> None:
        """The imphash, ssdeep and TLSH are published as the sample's own
        digests: their indicator gets the platform's ``indicates`` edge as the
        hash indicator and every other published indicator does, and keeps the
        softer type that says they also match files sharing the sample's imports."""
        report = _network_report()
        report.identity.hashes.imphash = "f34d5f2d4577ed6d9ceec516c1f5a744"

        bundle = ExtendedSTIXRenderer().render(report)

        similarity = sample_similarity_pattern(report.identity.hashes)
        (similar,) = [
            o for o in bundle.objects if o.type == "indicator" and o.pattern == similarity
        ]
        assert similar.indicator_types == ["anomalous-activity"]
        (malware,) = [o for o in bundle.objects if o.type == "malware"]
        edges = [
            o
            for o in bundle.objects
            if o.type == "relationship"
            and str(similar.id) in (str(o.source_ref), str(o.target_ref))
        ]
        assert [
            (o.relationship_type, str(o.source_ref), str(o.target_ref), o.description)
            for o in edges
        ] == [("indicates", str(similar.id), str(malware.id), PLATFORM_INDICATES_EDGE)]
        (report_object,) = [o for o in bundle.objects if o.type == "report"]
        assert str(edges[0].id) in report_object.object_refs
        result = validate_instance(bundle.model_dump(mode="json"), ValidationOptions(version="2.1"))
        assert result.is_valid, [str(e) for e in result.errors]

    def test_a_benign_export_has_no_malware_object_and_no_edge(self) -> None:
        bundle = ExtendedSTIXRenderer().render(_network_report("Benign"))

        assert not [o for o in bundle.objects if o.type == "malware"]
        assert not [o for o in bundle.objects if getattr(o, "relationship_type", "") == "indicates"]


def _split_isr() -> AgentISR:
    """One block listing three techniques, read as three claims, then one plain claim."""
    sentence = "Routine 0x7fa8 calls GetComputerNameExA and GetAdaptersInfo for the host."
    split = [
        ClaimEvidence(claim=sentence, evidence_ref="ev_0074", confidence=0.85, technique_id=tid)
        for tid in ("T1082", "T1016", "T1033")
    ]
    plain = ClaimEvidence(
        claim="Routine 0x1c38 walks the process list with Process32FirstW.",
        evidence_ref="ev_0074",
        confidence=0.85,
        technique_id="T1057",
    )
    return AgentISR(agent_id="static", domain="static", claims=[*split, plain])


class TestAClaimIsCountedOnce:
    def test_a_block_with_several_techniques_is_one_claim_in_force(self) -> None:
        claims = claims_in_force({"static": _split_isr()})

        assert [(c.number, c.technique_ids) for c in claims] == [
            (1, ("T1082", "T1016", "T1033")),
            (2, ("T1057",)),
        ]

    def test_section_13_1_lists_it_once_with_its_techniques_together(self) -> None:
        report = _report()
        report.claims_not_discussed = claims_not_discussed(report, {"static": _split_isr()})

        markdown = MarkdownRenderer().render(report)

        section = markdown.split("### 13.1")[1].split("\n## ")[0]
        rows = [line for line in section.splitlines() if line.startswith("- **")]
        assert len(rows) == 2
        assert rows[0].startswith("- **static claim 1** (techniques T1082, T1016, T1033; ")
        assert rows[1].startswith("- **static claim 2** (technique T1057; ")

    def test_section_13_1_marks_each_technique_as_the_attck_table_does(self) -> None:
        isr = _split_isr()
        isr.claims[1].technique_id_valid = False
        isr.claims[2].kept_after_absence_question = True
        report = _report()
        report.claims_not_discussed = claims_not_discussed(report, {"static": isr})

        markdown = MarkdownRenderer().render(report)

        section = markdown.split("### 13.1")[1].split("\n## ")[0]
        (row,) = [line for line in section.splitlines() if line.startswith("- **static claim 1")]
        assert row.startswith(
            f"- **static claim 1** (techniques T1082, T1016 ({UNVERIFIED_TECHNIQUE_MARKER}), "
            f"T1033 ({ABSENCE_TECHNIQUE_MARKER}); "
        )

    def test_a_report_built_from_the_split_claim_keeps_every_technique(self) -> None:
        report = MalwareReportBuilder(
            file_hash="c" * 64,
            file_name="sample.exe",
            sample_path=None,
            sandbox_report={},
            reports={},
            isr_reports={"static": _split_isr()},
            stix_output={"objects": []},
            run_summary={},
            discussion_history=[],
            final_decision="Malware",
            overall_confidence=0.7,
            judge_assessment=None,
            malware_category="dropper",
            evidence_ledger=[],
        ).build_deterministic()

        every = ["T1082", "T1016", "T1033", "T1057"]
        assert [m.technique_id for m in report.ttp_mappings] == every
        assert [c.technique_id for c in report.capability_matrix] == every

    def test_the_per_analyst_count_counts_it_once_and_keeps_every_technique(self) -> None:
        summary = RunSummaryBuilder(start_time=0.0).set_isr_stats({"static": _split_isr()})

        (stats,) = summary._agent_stats
        assert stats.claim_count == 2
        assert stats.technique_ids == ["T1082", "T1016", "T1033", "T1057"]

    def test_the_claims_themselves_keep_one_row_per_technique(self) -> None:
        isr = _split_isr()

        claims_in_force({"static": isr})

        assert [c.technique_id for c in isr.claims] == ["T1082", "T1016", "T1033", "T1057"]
