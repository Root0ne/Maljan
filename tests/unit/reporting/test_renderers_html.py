"""Tests for ``HtmlRenderer`` / ``PdfRenderer`` (Phase 6 export).

The HTML export deliberately reuses ``MarkdownRenderer`` for content, so these
tests do not re-assert every field — ``test_renderers_markdown.py`` owns that.
What is asserted here is everything the HTML layer adds or could break:
escaping, figure placement, the table of contents, self-containment, and that a
PDF actually comes out the other end.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from maljan.reporting.figures import build_figures
from maljan.reporting.models import (
    DynamicBehavior,
    Figure,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    PESection,
    ProcessNode,
    SampleIdentity,
    StaticAnalysis,
)
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.pdf import PdfRenderer, PdfUnavailableError

# Mirrors REQUIRED_HEADINGS in test_renderers_markdown.py. Duplicated on
# purpose: if a heading is renamed, the figure anchors in html.py silently stop
# matching, and only a test that pins the HTML side catches that.
REQUIRED_SECTIONS = [
    "Sample Identification",
    "Severity &amp; Impact",
    "Executive Summary",
    "Capabilities Narrative",
    "Static Analysis",
    "Dynamic Behavior",
    "Network IOCs",
    "Persistence Mechanisms",
    "MITRE ATT&amp;CK Matrix",
    "Family Attribution",
    "Detection Signatures",
    "Defensive Recommendations",
    "References",
    "Run Summary",
]


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), **over.pop("ident", {})),
        **over,
    )


def _rich_report() -> MalwareReport:
    """A report with enough data that every anchored figure kind is produced."""
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="b" * 64), file_name="sample.exe"),
        static=StaticAnalysis(
            sections=[
                PESection(name=".text", virtual_address="0x1000", entropy=7.6),
                PESection(name=".data", virtual_address="0x5000", entropy=3.2),
            ]
        ),
        dynamic=DynamicBehavior(process_tree=[ProcessNode(pid=1, ppid=0, name="sample.exe")]),
        network=NetworkIOCs(domains=[NetworkDomain(fqdn="c2.evil.com")]),
    )
    report.figures = build_figures(report)
    return report


class TestDocumentShape:
    def test_is_a_complete_html_document(self) -> None:
        html = HtmlRenderer().render(_report())
        assert html.startswith("<!DOCTYPE html>")
        assert html.rstrip().endswith("</html>")
        assert '<meta charset="utf-8">' in html

    def test_every_section_survives_conversion(self) -> None:
        html = HtmlRenderer().render(_report())
        for heading in REQUIRED_SECTIONS:
            assert f">{heading}</h2>" in html, f"missing section: {heading}"

    def test_title_block_precedes_contents(self) -> None:
        """The report must open on its cover, not on the table of contents."""
        html = HtmlRenderer().render(_report())
        assert html.index("<h1>") < html.index('nav class="toc"')

    def test_tables_are_converted_not_left_as_pipes(self) -> None:
        html = HtmlRenderer().render(_report())
        assert "<table>" in html
        assert "|---|" not in html

    def test_degraded_banner_is_rendered_as_a_callout(self) -> None:
        report = _report()
        report.degraded_mode = True
        report.degradation_reasons = ["no sandbox report (dynamic detonation unavailable)"]
        html = HtmlRenderer().render(report)
        assert "<blockquote>" in html
        assert "[DEGRADED RUN]" in html
        assert "no sandbox report" in html


class TestTableOfContents:
    def test_entry_per_section_and_ids_resolve(self) -> None:
        html = HtmlRenderer().render(_report())
        hrefs = re.findall(r'<nav class="toc">.*?</nav>', html, re.DOTALL)
        assert hrefs, "no table of contents emitted"
        targets = re.findall(r'href="#(sec-[^"]+)"', hrefs[0])
        assert len(targets) == len(REQUIRED_SECTIONS)
        for target in targets:
            assert f'<h2 id="{target}">' in html, f"dangling TOC link: {target}"


class TestEscaping:
    """Report text is LLM- and malware-derived; none of it may become markup."""

    def test_script_in_file_name_is_escaped(self) -> None:
        report = _report(ident={"file_name": "<script>alert(1)</script>.exe"})
        html = HtmlRenderer().render(report)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_html_in_narrative_is_escaped(self) -> None:
        report = _report()
        report.executive_summary = '<img src=x onerror="alert(1)">'
        html = HtmlRenderer().render(report)
        assert "&lt;img" in html, "narrative was not rendered at all"
        assert "<img" not in html

    def test_failed_section_becomes_a_visible_note_not_an_escaped_comment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.reporting.renderers import markdown as md_mod

        def _boom(self: Any, report: MalwareReport) -> str:
            raise RuntimeError("synthetic")

        monkeypatch.setattr(md_mod.MarkdownRenderer, "_section_references", _boom)
        html = HtmlRenderer().render(_report())
        assert "&lt;!--" not in html
        assert "could not be rendered" in html


class TestFigures:
    def test_figures_land_in_their_own_sections(self) -> None:
        html = HtmlRenderer().render(_rich_report())
        # Each figure must appear after its anchor heading and before the next one.
        for anchor, fig_id in (
            ("Static Analysis", "fig-entropy"),
            ("Dynamic Behavior", "fig-process-tree"),
            ("Network IOCs", "fig-network"),
        ):
            start = html.index(f">{anchor}</h2>")
            following = html.index("<h2", start + 1)
            assert start < html.index(f'<figure id="{fig_id}"') < following, (
                f"{fig_id} not inside the {anchor} section"
            )

    def test_figures_are_numbered_and_captioned(self) -> None:
        html = HtmlRenderer().render(_rich_report())
        assert "<b>Figure 1.</b>" in html
        assert "<b>Figure 2.</b>" in html
        assert "<b>Figure 3.</b>" in html

    def test_unanchored_figure_goes_to_the_appendix_rather_than_being_dropped(self) -> None:
        report = _rich_report()
        report.figures.append(
            Figure(
                id="fig-listing-0",
                caption="Decompiled main",
                kind="code_listing",
                content="<pre class='listing'>int main()</pre>",
            )
        )
        html = HtmlRenderer().render(report)
        assert 'id="sec-figures"' in html
        assert 'id="fig-listing-0"' in html
        assert html.count("<figure") == 4

    def test_embed_figures_false_omits_them(self) -> None:
        html = HtmlRenderer().render(_rich_report(), embed_figures=False)
        assert "<figure" not in html

    def test_legacy_report_without_figures_still_renders(self) -> None:
        report = _rich_report()
        report.figures = []
        html = HtmlRenderer().render(report)
        assert "<figure" not in html
        assert 'id="sec-figures"' not in html


class TestSelfContainment:
    def test_no_external_subresources(self) -> None:
        """No CDN, font, or image fetch — the export must open offline."""
        html = HtmlRenderer().render(_rich_report())
        assert "<link" not in html
        assert "<script" not in html
        assert "<img" not in html
        assert "url(http" not in html
        assert "@import" not in html

    def test_stylesheet_is_inlined(self) -> None:
        html = HtmlRenderer().render(_report())
        assert "<style>" in html
        assert "@page" in html


class TestPdfRenderer:
    def test_produces_a_pdf(self) -> None:
        pdf = PdfRenderer().render(_rich_report())
        assert pdf.startswith(b"%PDF-")
        assert len(pdf) > 1000

    def test_missing_weasyprint_raises_actionable_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A host without libpango must 503 with guidance, not ImportError."""
        import builtins

        real_import = builtins.__import__

        def _fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "weasyprint":
                raise OSError("cannot load library 'libpango-1.0.so.0'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _fake_import)
        with pytest.raises(PdfUnavailableError, match="libpango"):
            PdfRenderer.render_html("<html><body>x</body></html>")
