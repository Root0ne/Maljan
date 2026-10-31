"""The analyst report prints the findings in a fixed order; the evidence bundle holds the rest.

A reader of the single-file report read past every tool's table, the run's
bookkeeping and every citation to find what the sample does. The served report
is now two products of the same report document: the analyst report, in the
order a professional malware report keeps — title block, executive summary,
introduction and scope, sample metadata, execution flow, functionality,
command and control, conclusion, detection, recommendations, the ATT&CK table,
limitations and an appendix — and the evidence bundle, which prints every
section the single-file report printed and the notes the analyst report cites.

What is held here:

* the analyst report's section order, and what it does not print;
* a citation written into the prose becomes a numbered note, and every link
  the analyst report makes — a note, an evidence id, a section — lands on an
  anchor of the bundle;
* the single-file layout is still what a renderer prints when no layout is
  named, and what ``reporting.full_report_in_one_file`` serves;
* over every stored run: the two products together hold everything the
  single-file report held, and every scored quote of the haiku6 and haiku7
  scores is in the analyst report.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from maljan.reporting.models import (
    C2Channel,
    CapabilityCell,
    ConfigItem,
    DynamicBehavior,
    EvidenceIndexRow,
    FileHashes,
    FlowStep,
    KeyFinding,
    MalwareReport,
    PESection,
    ProcessNode,
    SampleIdentity,
    StaticAnalysis,
    TechnicalAnalysis,
    TechnicalSubsection,
    TTPMapping,
)
from maljan.reporting.renderers import HtmlRenderer, MarkdownRenderer
from maljan.reporting.renderers.bundle import bundle_json, render_products
from maljan.reporting.renderers.layout import (
    ANALYST,
    BUNDLE,
    BUNDLE_HTML,
    FULL,
    report_layout,
)
from tests.unit.reporting._report_inventory import missing, plain, stored_runs

ROOT = Path(__file__).resolve().parents[3]
QUOTES = ROOT / "tests" / "fixtures" / "benchmark" / "scored-quotes-haiku6-haiku7.json"

ORDER = [
    "1. Executive summary",
    "2. Introduction and scope",
    "3. Sample metadata",
    "4. Execution flow",
    "5. Functionality",
    "6. Command and control",
    "7. Conclusion",
    "8. Detection",
    "9. Recommendations",
    "10. MITRE ATT&CK mapping",
    "11. Limitations",
    "Appendix",
]


def _report() -> MalwareReport:
    """A report with a finding in every section the analyst report prints, and in some it does
    not."""
    return MalwareReport(
        identity=SampleIdentity(
            hashes=FileHashes(sha256="ab" * 32, md5="cd" * 16), file_name="sample.exe"
        ),
        verdict="Malware",
        overall_confidence=0.85,
        executive_summary="The sample decodes its strings at run time [ev_0002].",
        key_findings=[KeyFinding(text="It beacons over HTTPS.", evidence_ids=["ev_0003"])],
        static=StaticAnalysis(
            sections=[PESection(name=".text", virtual_address="0x1000", entropy=6.1)],
        ),
        dynamic=DynamicBehavior(
            process_tree=[ProcessNode(pid=4, ppid=0, name="unique-tree-node.exe")]
        ),
        technical_analysis=TechnicalAnalysis(
            execution_flow=[
                FlowStep(
                    order=1, action="Routine 0x3868 checks the host.", evidence_refs=["ev_0002"]
                )
            ],
            configuration=[ConfigItem(key="sleep", value="450 s", evidence_refs=["ev_0003"])],
            packing_obfuscation=TechnicalSubsection(
                title="Packing",
                body="Routine 0xae78 decodes each string (ev_0002; ev_0003). It is not packed.",
                evidence_refs=["ev_0002", "ev_0004"],
            ),
            command_and_control=TechnicalSubsection(
                title="C2", body="The check-in is a POST [ev_0003].", evidence_refs=["ev_0003"]
            ),
        ),
        c2_channels=[C2Channel(name="https", protocol="HTTPS", evidence_refs=["ev_0003"])],
        capability_matrix=[
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1140",
                technique_name="Deobfuscate/Decode Files or Information",
                evidence=["3. Routine 0xae78 decodes the strings [ev_0002]. More detail here."],
            ),
            CapabilityCell(
                tactic="TA0002",
                tactic_name="Execution",
                technique_id="T1055",
                technique_name="Process Injection",
                not_published="no producer claimed it",
            ),
        ],
        ttp_mappings=[
            TTPMapping(
                technique_id="T1140",
                technique_name="Deobfuscate/Decode Files or Information",
                tactic="TA0005",
                tactic_name="Defense Evasion",
            )
        ],
        evidence_index=[
            EvidenceIndexRow(id=f"ev_000{n}", agent="static", tool="tool") for n in range(1, 5)
        ],
    )


def _headings(markdown: str) -> list[str]:
    return [line[3:] for line in markdown.splitlines() if line.startswith("## ")]


def _ids_of(html: str) -> set[str]:
    return set(re.findall(r'\bid="([^"]+)"', html))


def _links_into_the_bundle(html: str) -> list[str]:
    return re.findall(r'href="' + re.escape(BUNDLE_HTML) + r'#([^"]+)"', html)


class TestTheAnalystReport:
    def test_its_sections_stand_in_the_fixed_order(self) -> None:
        markdown = MarkdownRenderer(layout=ANALYST).render(_report())
        assert _headings(markdown) == ORDER
        assert markdown.startswith("# ")

    def test_it_prints_no_tool_table_no_ledger_and_no_voice_tag(self) -> None:
        markdown = MarkdownRenderer(layout=ANALYST).render(_report())
        for absent in (
            "unique-tree-node.exe",  # the process tree
            "| .text |",  # the section table
            "Written by the report model",
            "_Measured_",
            "0.85",  # a confidence number: the analyst report says it in words
        ):
            assert absent not in markdown, absent
        headings = " ".join(line for line in markdown.splitlines() if line.startswith("#"))
        for heading in ("Static properties", "Evidence index", "Run summary", "Observed"):
            assert heading not in headings, heading
        assert "moderate-to-high confidence" in markdown

    def test_a_citation_in_the_prose_becomes_a_numbered_note(self) -> None:
        markdown, notes = MarkdownRenderer(layout=ANALYST).render_with_notes(_report())
        assert "[ev_" not in markdown and "(ev_0002; ev_0003)" not in markdown
        assert "decodes each string[[" in markdown
        cited = {tuple(note.evidence_ids) for note in notes}
        assert ("ev_0002", "ev_0003") in cited
        # The ids a subsection cites and its words do not are one marker after it.
        assert ("ev_0004",) in cited

    def test_the_attack_table_is_compact_and_prints_published_techniques(self) -> None:
        markdown = MarkdownRenderer(layout=ANALYST).render(_report())
        table = markdown.split("## 10. MITRE ATT&CK mapping", 1)[1]
        assert "| Tactic | ID | Technique | Procedure |" in table
        assert "Routine 0xae78 decodes the strings.[[" in table
        assert "More detail here" not in table
        assert "| T1055 |" not in table
        assert "1 further technique was named and not published" in table
        assert "- T1055 Process Injection: claimed, not published: no producer claimed it" in table

    def test_every_link_into_the_bundle_lands(self) -> None:
        report = _report()
        analyst = HtmlRenderer(layout=ANALYST).render(report)
        bundle = HtmlRenderer(layout=BUNDLE).render(report)
        links = _links_into_the_bundle(analyst)
        assert any(link.startswith("cite-") for link in links)
        assert any(link.startswith("sec-") for link in links)
        anchors = _ids_of(bundle)
        assert [link for link in links if link not in anchors] == []
        # A note is a superscript number in HTML.
        assert re.search(r'<sup class="cite"><a href="evidence-bundle\.html#cite-1">1</a>', analyst)

    def test_each_note_lists_its_evidence_linked_to_its_index_row(self) -> None:
        report = _report()
        bundle = HtmlRenderer(layout=BUNDLE).render(report)
        assert '<tr id="ev_0002">' in bundle
        assert re.search(r'<li id="cite-1"><strong>Note 1</strong>', bundle)
        assert '<a href="#ev_0002">ev_0002</a>' in bundle

    def test_an_id_the_index_does_not_hold_still_resolves_in_the_bundle(self) -> None:
        report = _report()
        report.key_findings = [KeyFinding(text="A claim.", evidence_ids=["ev_9999"])]
        bundle = HtmlRenderer(layout=BUNDLE).render(report)
        assert '<li id="ev_9999"><strong>ev_9999</strong>' in bundle

    def test_the_html_draws_only_the_figures_of_its_own_sections(self) -> None:
        from maljan.reporting.figures import build_figures

        report = _report()
        report.figures = build_figures(report)
        kinds = {fig.kind for fig in report.figures}
        assert "process_tree" in kinds
        analyst = HtmlRenderer(layout=ANALYST).render(report)
        bundle = HtmlRenderer(layout=BUNDLE).render(report)
        assert "process-tree" not in analyst.lower() or "unique-tree-node" not in analyst
        assert "unique-tree-node" in bundle


def _checked_report() -> MalwareReport:
    """``_report`` with a finding of every validation code the analyst report must show."""
    from maljan.reporting.models import FamilyAttribution, FlaggedStatement, HostIdentifier

    report = _report()
    report.dynamic = None  # no sandbox watched: an observed step is marked so
    report.attribution = FamilyAttribution(family="Examplefam", family_grounded=False)
    report.technical_analysis.execution_flow.append(  # type: ignore[union-attr]
        FlowStep(order=2, action="It is watched.", voice="observed")
    )
    report.technical_analysis.host_identifiers = [  # type: ignore[union-attr]
        HostIdentifier(kind="Mutex", value="unique-mutex-name", purpose="a gate")
    ]
    report.flagged_statements = [
        FlaggedStatement(sentence="It is not packed.", code="narrative.claim_doubted")
    ]
    report.run_summary = {
        "validation": {
            "unresolved": [
                {"code": "verdict.unsupported", "message": "the verdict cites nothing"},
                {"code": "narrative.uncited", "message": "a summary sentence cites nothing"},
                {"code": "report.flow_voice", "message": "step 1 is marked observed"},
                {"code": "report.configuration_uncited", "message": "configuration item 1"},
                {"code": "report.value_not_in_cited_entry", "message": "configuration item 1"},
                {"code": "report.identifier_uncited", "message": "identifier 1 cites nothing"},
                {"code": "attck.platform", "message": "not for this platform", "subject": "T1140"},
            ]
        },
        "evidence": {"entries": 4, "failed": 1},
    }
    return report


class TestThePlatformsCaveats:
    """Every mark the single-file report prints beside a finding, the analyst report prints."""

    def test_each_validation_code_s_mark_is_in_the_analyst_report(self) -> None:
        report = _checked_report()
        full = MarkdownRenderer().render(report)
        analyst = MarkdownRenderer(layout=ANALYST).render(report)
        for marker in (
            "verdict.unsupported",  # under the title and in the conclusion
            "narrative.uncited",  # in the executive summary
            "(unresolved: report.flow_voice)",
            "(unresolved: report.flow_voice; no sandbox observation in this run)",
            "(unresolved: report.configuration_uncited)",
            "(unresolved: report.value_not_in_cited_entry)",
            "(unresolved: report.identifier_uncited)",
            "unresolved: attck.platform",
            "(no evidence cited)",  # a family the judge grounded on nothing
        ):
            assert marker in full, marker
            assert marker in analyst, marker
        assert analyst.count("verdict.unsupported") >= 2

    def test_a_flagged_sentence_keeps_its_mark_and_the_mark_is_no_citation(self) -> None:
        report = _checked_report()
        analyst, notes = MarkdownRenderer(layout=ANALYST).render_with_notes(report)
        assert re.search(r"It is not packed\. \*\*\[[^\]]+\]\*\*", analyst)
        assert all("ev_" in i for note in notes for i in note.evidence_ids)

    def test_a_mark_in_a_table_cell_cannot_split_its_row(self) -> None:
        from maljan.reporting.models import FlaggedStatement

        report = _checked_report()
        report.technical_analysis.configuration = [  # type: ignore[union-attr]
            ConfigItem(key="sleep", value="450 s", evidence_refs=["ev_0003"])
        ]
        report.flagged_statements = [
            FlaggedStatement(
                sentence="450 s", code="narrative.claim_doubted", label="a | b\nnext line"
            )
        ]
        analyst = MarkdownRenderer(layout=ANALYST).render(report)
        table = analyst.split("### 6.2 Configuration", 1)[1].split("\n\n", 2)[1]
        rows = table.splitlines()
        assert len(rows) == 3  # header, divider, the one row
        assert rows[2].count(" | ") == rows[0].count(" | ") == 2
        assert "a \\| b" in rows[2]
        assert "next line" in rows[2]

    def test_an_unexported_value_says_why(self) -> None:
        analyst = MarkdownRenderer(layout=ANALYST).render(_checked_report())
        row = next(line for line in analyst.splitlines() if "unique-mutex-name" in line)
        assert "not exported: the report model's identifier table publishes nothing itself" in row


class TestTheBundle:
    def test_it_holds_the_single_file_report_whole(self) -> None:
        report = _report()
        full = MarkdownRenderer().render(report)
        bundle = MarkdownRenderer(layout=BUNDLE).render(report)
        body = full.split("\n", 1)[1]
        assert body.strip() in bundle
        assert bundle.startswith("# Evidence bundle: ")

    def test_its_json_carries_the_notes_the_index_and_every_section(self) -> None:
        report = _report()
        document = json.loads(bundle_json(report))
        assert document["format"] == "maljan-evidence-bundle/1"
        assert [row["id"] for row in document["evidence_index"]] == [
            "ev_0001",
            "ev_0002",
            "ev_0003",
            "ev_0004",
        ]
        assert document["notes"][0]["anchor"] == "cite-1"
        anchors = {section["anchor"] for section in document["sections"]}
        assert {"sec-technical-analysis", "sec-evidence-index"} <= anchors

    def test_the_command_line_writes_it_beside_the_report(self, tmp_path: Path) -> None:
        from maljan.cli import _write_markdown_report

        target = tmp_path / "report.md"
        _write_markdown_report({"malware_report": _report().model_dump(mode="json")}, str(target))
        assert _headings(target.read_text()) == ORDER
        bundle = (tmp_path / "evidence-bundle.html").read_text()
        assert '<h2 id="sec-evidence-index">' in bundle
        assert json.loads((tmp_path / "evidence-bundle.json").read_text())["notes"]

    def test_its_json_and_its_html_number_a_repeated_title_alike(self) -> None:
        from maljan.reporting.renderers.analyst import unique_anchor

        taken: set[str] = set()
        assert [unique_anchor("sec-a", taken) for _ in range(3)] == [
            "sec-a",
            "sec-a-2",
            "sec-a-3",
        ]
        report = _report()
        html_ids = _ids_of(HtmlRenderer(layout=BUNDLE).render(report))
        anchors = [s["anchor"] for s in json.loads(bundle_json(report))["sections"][1:]]
        assert [a for a in anchors if a not in html_ids] == []

    def test_the_pdf_reads_alone(self) -> None:
        report = _report()
        path = "/api/v1/reports/r1/evidence-bundle.html"
        html = HtmlRenderer(layout=ANALYST, self_contained=True, bundle_location=path).render(
            report
        )
        assert 'href="evidence-bundle.html' not in html
        assert re.search(r'<sup class="cite"><a href="#note-1">1</a></sup>', html)
        assert re.search(r'<li id="note-1">1\. ev_\d+', html)
        # Where the bundle is, in words: never a link built to it.
        assert f"served at <code>{path}</code> (the API requires sign-in)" in html
        assert f'href="{path}' not in html
        alone = HtmlRenderer(layout=ANALYST, self_contained=True).render(report)
        assert 'href="evidence-bundle.html' not in alone
        assert "downloaded beside this report as <code>evidence-bundle.html</code>" in alone

    def test_rendering_changes_nothing_in_the_report(self) -> None:
        report = _report()
        before = report.model_dump_json()
        render_products(report)
        assert report.model_dump_json() == before


class TestTheLayoutChoice:
    def test_a_renderer_naming_no_layout_prints_the_single_file_report(self) -> None:
        report = _report()
        assert MarkdownRenderer().render(report) == MarkdownRenderer(layout=FULL).render(report)
        assert "## 13. Limitations and analysis notes" in MarkdownRenderer().render(report)

    def test_the_setting_restores_the_single_file_report(self) -> None:
        on = SimpleNamespace(reporting=SimpleNamespace(full_report_in_one_file=True))
        off = SimpleNamespace(reporting=SimpleNamespace(full_report_in_one_file=False))
        assert report_layout(on) == FULL
        assert report_layout(off) == ANALYST

    def test_the_setting_is_off_by_default_and_in_the_catalog(self) -> None:
        from maljan.core.config import ReportingConfig
        from maljan.core.settings_annotations import ANNOTATIONS

        assert ReportingConfig().full_report_in_one_file is False
        assert ANNOTATIONS["reporting.full_report_in_one_file"]["subgroup"] == "Report content"

    def test_an_unknown_layout_is_refused(self) -> None:
        with pytest.raises(ValueError, match="unknown report layout"):
            MarkdownRenderer(layout="short")

    def test_only_the_bundle_files_are_linked_beside_the_page(self) -> None:
        from maljan.reporting.renderers.html import _report_link

        assert _report_link("evidence-bundle.html#ev_0001")
        assert _report_link("evidence-bundle.json")
        assert not _report_link("other.html#x")
        assert not _report_link("evidence-bundle.html.exe")


# ---------------------------------------------------------------------------
# Over every stored run
# ---------------------------------------------------------------------------


REDACTED = ROOT / "tests" / "fixtures" / "reporting" / "stored_report_redacted.json"
# The committed fixture runs wherever the suite runs; the stored runs where they are.
FIXTURE_RUN = "redacted-stored-report"


def _stored() -> list[str]:
    root = stored_runs()
    if root is None:
        return [FIXTURE_RUN]
    stored = sorted(p.name for p in root.iterdir() if (p / "report.json").is_file())
    return [FIXTURE_RUN, *stored]


def _load(run: str) -> MalwareReport:
    from maljan.reporting.models import key_ordered

    if run == FIXTURE_RUN:
        return MalwareReport.model_validate(key_ordered(json.loads(REDACTED.read_text())))
    root = stored_runs()
    assert root is not None
    return MalwareReport.model_validate(
        key_ordered(json.loads((root / run / "report.json").read_text()))
    )


def _skip_without_runs() -> None:
    if stored_runs() is None:
        pytest.skip("the stored benchmark runs are not on this machine")


@pytest.mark.parametrize("run", _stored())
def test_the_two_products_hold_everything_the_single_file_report_held(run: str) -> None:
    report = _load(run)
    full = MarkdownRenderer().render(report)
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    bundle = MarkdownRenderer(layout=BUNDLE).render(report)
    assert "rendering failed" not in analyst + bundle
    # The bundle prints the single-file report's body byte for byte.
    assert full.split("\n", 1)[1].rstrip("\n") in bundle
    lost = {key: values[:3] for key, values in missing(full, analyst + "\n" + bundle).items()}
    assert {key: values for key, values in lost.items() if values} == {}


# The caveats the single-file report prints in its body: each one it prints
# there, the analyst report prints.
CAVEATS = (
    "[NO VERDICT]",
    "[NO CONFIDENCE ASSESSED]",
    "[DEGRADED RUN]",
    "not published by this run",
    "unresolved:",
    "report.flow_voice",
    "The evidence is partial",
)


def _decisions(report: MalwareReport) -> dict[str, list[str]]:
    """What the run decided, by class, as the single-file report prints each value."""
    from maljan.reporting.defang import defang
    from maljan.reporting.renderers.markdown import (
        _NETWORK_KINDS,
        _RULE_SECTIONS,
        _indicator_rows,
    )
    from maljan.reporting.renderers.stix_renderer import publishes

    rows = _indicator_rows(report) or []
    rules: list[str] = []
    for section in report.sections:
        if section.key in _RULE_SECTIONS:
            at = section.columns.index("Rule") if "Rule" in section.columns else 0
            rules.extend(str(row[at]) for row in section.rows[:20] if len(row) > at)
    published = [
        cell.technique_id
        for cell in report.capability_matrix
        if not cell.not_published and cell.technique_id_valid
    ]
    return {
        "published indicator values": [
            defang(row.value, row.kind or "") if row.kind in _NETWORK_KINDS else row.value
            for row in rows
            if publishes(row.published)
        ],
        "published techniques": [*published, *(m.technique_id for m in report.ttp_mappings)],
        "matched rules": rules,
        "P0 and P1 actions": [
            rec.action for rec in report.defensive_recommendations if rec.priority in ("P0", "P1")
        ],
    }


@pytest.mark.parametrize("run", _stored())
def test_every_decision_the_single_file_body_prints_the_analyst_report_prints(run: str) -> None:
    report = _load(run)
    body = plain(MarkdownRenderer().render(report).split("\n## 13. ", 1)[0])
    analyst = plain(MarkdownRenderer(layout=ANALYST).render(report))
    lost = {
        kind: [value for value in values if plain(value) in body and plain(value) not in analyst]
        for kind, values in _decisions(report).items()
    }
    assert {kind: values[:5] for kind, values in lost.items() if values} == {}


@pytest.mark.parametrize("run", _stored())
def test_each_caveat_stands_in_the_analyst_report_as_often_as_in_the_single_file_body(
    run: str,
) -> None:
    report = _load(run)
    body = MarkdownRenderer().render(report).split("\n## 13. ", 1)[0]
    analyst = MarkdownRenderer(layout=ANALYST).render(report)
    short = {
        marker: (analyst.count(marker), body.count(marker))
        for marker in CAVEATS
        if analyst.count(marker) < body.count(marker)
    }
    assert short == {}


@pytest.mark.parametrize("run", _stored())
def test_every_link_of_a_stored_run_s_analyst_report_lands_in_its_bundle(run: str) -> None:
    report = _load(run)
    analyst = HtmlRenderer(layout=ANALYST).render(report)
    anchors = _ids_of(HtmlRenderer(layout=BUNDLE).render(report))
    links = _links_into_the_bundle(analyst)
    assert links
    assert sorted({link for link in links if link not in anchors}) == []
    # An evidence id the analyst report still names as a word is an anchor too.
    named = set(re.findall(r"\bev_\d+\b", re.sub(r"<pre>.*?</pre>", "", analyst, flags=re.S)))
    assert sorted(named - anchors) == []


def _quotes() -> list[dict[str, Any]]:
    return list(json.loads(QUOTES.read_text())["quotes"])


@pytest.mark.parametrize("run", ["haiku6", "haiku7"])
def test_every_scored_quote_is_in_the_analyst_report(run: str) -> None:
    _skip_without_runs()
    if run not in _stored():
        pytest.skip(f"the stored run {run} is not on this machine")
    analyst = plain(MarkdownRenderer(layout=ANALYST).render(_load(run)))
    quotes = [q for q in _quotes() if q["run"] == run]
    assert quotes
    assert [q for q in quotes if q["quote"] not in analyst] == []


@pytest.mark.parametrize("run", ["haiku6", "haiku7"])
def test_every_beyond_human_fact_is_in_the_analyst_report(run: str) -> None:
    _skip_without_runs()
    if run not in _stored():
        pytest.skip(f"the stored run {run} is not on this machine")
    analyst = plain(MarkdownRenderer(layout=ANALYST).render(_load(run)))
    facts = [f for f in json.loads(QUOTES.read_text())["beyond_human"] if f["run"] == run]
    assert facts
    assert [f for f in facts if f["token"] not in analyst] == []
