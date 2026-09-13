"""Cross-layer report invariants — the guard that was missing.

Every bug this file pins had the same shape: a value was **correct in the
layer that computed it and wrong in the layer the user actually reads**. The
1710 unit tests all passed, because each one checked a single layer.

* The report's confidence was one number and the DB column another, so the UI
  showed "DEGRADED RUN" next to a confidence the report did not carry.
* View-decomposition produced ATT&CK technique IDs that the free-text parser
  then dropped, so the report shipped with none.
* The D11 guardrail let a rule through and the namer fell back to
  ``Maljan_AutoGen_unknown`` — the exact placeholder the gate exists to stop.

So these tests deliberately span layers: one report object is pushed through
the persistence extractor *and* every renderer, and the assertions are about
agreement between them. A test here should fail whenever two surfaces would
disagree about the same report, even if both surfaces are internally fine.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.worker.analysis_worker import _extract_confidence
from maljan.reporting.detection_signatures import build_detection_rules
from maljan.reporting.figures import build_figures
from maljan.reporting.models import (
    CapabilityCell,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    PESection,
    SampleIdentity,
    StaticAnalysis,
    TTPMapping,
)
from maljan.reporting.renderers import (
    ExtendedSTIXRenderer,
    HtmlRenderer,
    MarkdownRenderer,
    PdfRenderer,
)


def _report(*, degraded: bool = False, confidence: float = 0.91) -> MalwareReport:
    """A report with data in every section the renderers care about."""
    report = MalwareReport(
        identity=SampleIdentity(
            hashes=FileHashes(sha256="c" * 64), file_name="invariant-sample.exe"
        ),
        verdict="Malware",
        overall_confidence=confidence,
        static=StaticAnalysis(
            sections=[PESection(name=".text", virtual_address="0x1000", entropy=7.7)]
        ),
        network=NetworkIOCs(domains=[NetworkDomain(fqdn="c2.invariant.test")]),
        ttp_mappings=[
            TTPMapping(
                technique_id="T1055",
                technique_name="Process Injection",
                tactic="TA0005",
            ),
            TTPMapping(
                technique_id="T1071.001",
                technique_name="Web Protocols",
                tactic="TA0011",
            ),
        ],
        capability_matrix=[
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1055",
                technique_name="Process Injection",
                confidence=0.8,
                contributing_layers=["static"],
            )
        ],
    )
    if degraded:
        report.degraded_mode = True
        report.degradation_reasons = [
            "no sandbox report (dynamic detonation unavailable) — static-only evidence"
        ]
    report.figures = build_figures(report)
    # The renderers print ``generated_at`` to the microsecond, and a test below
    # asserts that a number is *absent* from the rendered page. Left at "now",
    # the seconds fraction eventually spells that number: CI run 34268210590
    # failed on ``"0.91" not in markdown`` with a timestamp ending in 0.91xxxx.
    report.generated_at = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    return report


def _persisted_confidence(report: MalwareReport, *, raw_judge_value: float) -> float:
    """What the worker would write to ``analysis_reports.overall_confidence``.

    ``raw_judge_value`` is what ``run_summary`` kept; the two must agree.
    """
    return _extract_confidence(
        {
            "malware_report": report.model_dump(mode="json"),
            "run_summary": {"final_confidence": raw_judge_value},
            "confidence_history": [raw_judge_value],
        }
    )


class TestDegradedConfidenceAgreesAcrossLayers:
    """The report's number and the persisted column must be the same number.

    Nothing caps a degraded run any more. The judge is told why the run is thin
    and sets its own confidence; what this pins is that whatever it set travels
    intact, and that the degradation is stated on every surface rather than
    encoded as a suspiciously round 0.60.
    """

    def test_the_persisted_value_is_the_reports_own(self) -> None:
        report = _report(degraded=True, confidence=0.42)
        assert _persisted_confidence(report, raw_judge_value=0.42) == pytest.approx(0.42)

    def test_a_healthy_run_is_not_flattened(self) -> None:
        report = _report(degraded=False, confidence=0.91)
        assert _persisted_confidence(report, raw_judge_value=0.91) == pytest.approx(0.91)

    def test_a_degraded_run_is_not_silently_capped(self) -> None:
        """The cap was the thing that made every thin run look identically thin."""
        report = _report(degraded=True, confidence=0.91)
        assert report.overall_confidence == pytest.approx(0.91)
        assert "0.91" in MarkdownRenderer().render(report)

    @pytest.mark.parametrize("renderer", ["markdown", "html"])
    def test_no_export_claims_the_confidence_was_capped(self, renderer: str) -> None:
        """There is no cap. A banner still saying so describes a mechanism that
        was deleted, and tells the reader the number above it is not the one
        the judge set."""
        report = _report(degraded=True, confidence=0.91)
        body = (
            MarkdownRenderer().render(report)
            if renderer == "markdown"
            else HtmlRenderer().render(report)
        )

        lowered = body.lower()
        for claim in ("capped", "capping", "confidence cap"):
            assert claim not in lowered, f"the export still says the confidence was {claim}"

    @pytest.mark.parametrize("renderer", ["markdown", "html"])
    def test_no_export_shows_a_degraded_run_without_its_warning(self, renderer: str) -> None:
        report = _report(degraded=True)
        body = (
            MarkdownRenderer().render(report)
            if renderer == "markdown"
            else HtmlRenderer().render(report)
        )
        assert "[DEGRADED RUN]" in body
        assert "no sandbox report" in body


class TestTechniqueIdsSurviveToEveryExport:
    """The view-decomposition bug: IDs existed on the model, reached no output."""

    @pytest.mark.parametrize("technique", ["T1055", "T1071.001"])
    def test_technique_ids_appear_in_markdown_and_html(self, technique: str) -> None:
        report = _report()
        assert technique in MarkdownRenderer().render(report)
        assert technique in HtmlRenderer().render(report)

    def test_mapped_techniques_are_never_reported_as_none(self) -> None:
        report = _report()
        assert report.ttp_mappings
        assert "_No ATT&CK techniques mapped._" not in MarkdownRenderer().render(report)


class TestSignatureNamingIsNeverAPlaceholder:
    """D11: a rule named after nothing is worse than no rule."""

    def test_unattributed_report_yields_no_placeholder_named_rules(self) -> None:
        report = _report()  # no attribution.family, no malware_category
        rules = build_detection_rules(report)
        assert rules, "fixture produced no rules — the assertions below would be vacuous"
        for rule in rules:
            lowered = rule.name.lower()
            assert "unknown" not in lowered, rule.name
            assert "unclassified" not in lowered, rule.name

    def test_an_ungated_rule_is_named_after_the_sample_it_matches(self) -> None:
        """Suricata stays ungated (network IOCs are valid without attribution),
        so its name must state the sample rather than claim a family."""
        report = _report()
        suricata = [r for r in build_detection_rules(report) if r.kind == "suricata"]
        assert suricata, "no Suricata rule generated from the network IOCs"
        assert suricata[0].name == f"Maljan_AutoGen_Suricata_Sample_{'c' * 12}"

    def test_rule_bodies_never_contain_the_autogen_stub(self) -> None:
        report = _report()
        for rule in build_detection_rules(report):
            assert "Maljan_AutoGen_unknown" not in rule.body
            assert "Family: unknown" not in rule.body


class TestEveryExportSurfaceRenders:
    """One report, every renderer. Cheap, and it catches whole-surface breakage."""

    @pytest.mark.parametrize("degraded", [False, True])
    def test_all_renderers_succeed_on_the_same_report(self, degraded: bool) -> None:
        report = _report(degraded=degraded)
        markdown = MarkdownRenderer().render(report)
        html = HtmlRenderer().render(report)
        stix = ExtendedSTIXRenderer().render(report)
        pdf = PdfRenderer().render(report)

        assert markdown.startswith("# Malware Analysis Report")
        assert html.startswith("<!DOCTYPE html>")
        assert stix.objects, "STIX bundle carried no objects"
        assert pdf.startswith(b"%PDF-")

    def test_an_empty_report_still_renders_everywhere(self) -> None:
        """Legacy and hard-failed runs must degrade, not explode."""
        bare = MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64)))
        assert MarkdownRenderer().render(bare)
        assert HtmlRenderer().render(bare).startswith("<!DOCTYPE html>")
        assert PdfRenderer().render(bare).startswith(b"%PDF-")

    def test_hostile_sample_content_never_becomes_markup(self) -> None:
        """Field values come from the sample itself; treat them as attacker input."""
        hostile: Any = "<script>fetch('//evil')</script>"
        report = _report()
        report.identity.file_name = hostile
        report.executive_summary = hostile
        html = HtmlRenderer().render(report)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html
