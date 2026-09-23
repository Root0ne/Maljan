"""The renderers print evidence sections generically, in every shape they take."""

from __future__ import annotations

from maljan.reporting.models import (
    EvidenceSection,
    FileHashes,
    MalwareReport,
    SampleIdentity,
)
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.markdown import MarkdownRenderer


def _report(*sections: EvidenceSection) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        sections=list(sections),
    )


SAID = "This answer was shortened to fit the analyst's budget: /strings (221 rows not shown)."


def _shortened(kind: str) -> EvidenceSection:
    """A section that carries rows and a sentence about how it got them."""
    return EvidenceSection(
        key="strings",
        title="Strings",
        kind=kind,  # type: ignore[arg-type]
        columns=["Offset", "Text"] if kind != "list" else [],
        rows=[["0x4d", "a string"]] if kind != "list" else [],
        items=["a string"] if kind == "list" else [],
        text=SAID,
        evidence_ids=["ev_0021"],
    )


class TestASectionThatCarriesBothRowsAndASentence:
    """A table of a page of an answer says that it is a page of one.

    The sentence is now the only place the report says an answer was
    shortened — the bookkeeping is deliberately out of the key-value table —
    and a body that returns as soon as it has rows never reaches it, so the
    reader sees seventy-nine rows of a three-hundred-row answer with nothing
    anywhere saying so.
    """

    def test_the_markdown_draws_it_above_the_table(self) -> None:
        markdown = MarkdownRenderer().render(_report(_shortened("table")))

        assert SAID in markdown
        assert markdown.index(SAID) < markdown.index("| Offset | Text |")
        assert "| 0x4d | a string |" in markdown

    def test_the_markdown_draws_it_above_a_key_value_table(self) -> None:
        markdown = MarkdownRenderer().render(_report(_shortened("kv")))

        assert SAID in markdown
        assert markdown.index(SAID) < markdown.index("| 0x4d | a string |")

    def test_the_markdown_draws_it_above_a_list(self) -> None:
        markdown = MarkdownRenderer().render(_report(_shortened("list")))

        assert SAID in markdown
        assert markdown.index(SAID) < markdown.index("- a string")

    def test_it_is_prose_beside_a_table_and_a_fenced_block_on_its_own(self) -> None:
        with_rows = MarkdownRenderer().render(_report(_shortened("table")))
        alone = MarkdownRenderer().render(
            _report(EvidenceSection(key="k", title="T", kind="text", text=SAID))
        )

        assert f"```\n{SAID}\n```" not in with_rows
        assert f"```\n{SAID}\n```" in alone

    def test_the_html_export_carries_it_too(self) -> None:
        html = HtmlRenderer().render(_report(_shortened("table")))

        assert "shortened to fit the analyst" in html
        assert "<table" in html

    def test_a_section_with_no_sentence_draws_no_empty_line_for_one(self) -> None:
        plain = MarkdownRenderer().render(
            _report(
                EvidenceSection(
                    key="strings",
                    title="Strings",
                    kind="table",
                    columns=["Offset", "Text"],
                    rows=[["0x4d", "a string"]],
                )
            )
        )

        assert "### Strings\n\n| Offset | Text |" in plain


class TestMarkdown:
    def test_a_table_section_renders_as_a_table(self) -> None:
        markdown = MarkdownRenderer().render(
            _report(
                EvidenceSection(
                    key="pe_imports",
                    title="PE imports",
                    kind="table",
                    columns=["Library", "Function"],
                    rows=[["KERNEL32.dll", "VirtualAllocEx"]],
                    evidence_ids=["ev_0002"],
                )
            )
        )
        assert "### PE imports" in markdown
        assert "| Library | Function |" in markdown
        assert "| KERNEL32.dll | VirtualAllocEx |" in markdown
        assert "_Evidence: ev_0002_" in markdown

    def test_a_kv_section_renders_as_a_two_column_table(self) -> None:
        markdown = MarkdownRenderer().render(
            _report(
                EvidenceSection(
                    key="identity",
                    title="Sample identity",
                    kind="kv",
                    columns=["Field", "Value"],
                    rows=[["file type", "PE"]],
                    source="routing",
                )
            )
        )
        assert "| file type | PE |" in markdown
        # No ledger entry behind it, so no footnote claiming one.
        assert "_Evidence:" not in markdown

    def test_a_list_section_renders_as_bullets(self) -> None:
        markdown = MarkdownRenderer().render(
            _report(
                EvidenceSection(
                    key="functions_examined",
                    title="Functions examined",
                    kind="list",
                    items=["FUN_00401310 (decompile_function)"],
                    evidence_ids=["ev_0007"],
                )
            )
        )
        assert "- FUN_00401310 (decompile_function)" in markdown

    def test_a_text_section_renders_as_a_block(self) -> None:
        markdown = MarkdownRenderer().render(
            _report(
                EvidenceSection(
                    key="pcap_summary",
                    title="Capture summary",
                    kind="text",
                    text="12 conversations, beacon interval 60s",
                    evidence_ids=["ev_0009"],
                )
            )
        )
        assert "12 conversations, beacon interval 60s" in markdown

    def test_a_report_with_no_sections_has_no_evidence_heading(self) -> None:
        assert "## Evidence" not in MarkdownRenderer().render(_report())

    def test_a_row_shorter_than_its_columns_is_padded(self) -> None:
        markdown = MarkdownRenderer().render(
            _report(
                EvidenceSection(
                    key="ragged",
                    title="Ragged",
                    kind="table",
                    columns=["A", "B", "C"],
                    rows=[["one"]],
                    evidence_ids=["ev_0001"],
                )
            )
        )
        assert "| one |  |  |" in markdown


class TestHtml:
    def test_the_evidence_section_survives_the_html_conversion(self) -> None:
        html = HtmlRenderer().render(
            _report(
                EvidenceSection(
                    key="pe_imports",
                    title="PE imports",
                    kind="table",
                    columns=["Library", "Function"],
                    rows=[["KERNEL32.dll", "VirtualAllocEx"]],
                    evidence_ids=["ev_0002"],
                )
            )
        )
        assert "Appendix A. Evidence index" in html
        assert "<td>VirtualAllocEx</td>" in html
        assert "ev_0002" in html


class TestTheReaderIsToldWhatWasTrimmed:
    """A count the report keeps to itself is a count nobody acts on."""

    def _report_with(self, evidence: dict) -> MalwareReport:
        report = _report()
        report.run_summary = {"evidence": evidence}
        return report

    def test_the_header_names_the_calls_and_points_at_the_limitations(self) -> None:
        markdown = MarkdownRenderer().render(
            self._report_with({"entries": 40, "ok": 39, "failed": 1, "trimmed": 12})
        )
        header = markdown.split("## 1.", 1)[0]
        assert "Evidence: 40 tool call(s), 1 failed (see §13)." in header

    def test_the_limitations_name_the_trimmed_entries(self) -> None:
        markdown = MarkdownRenderer().render(
            self._report_with({"entries": 40, "ok": 39, "failed": 1, "trimmed": 12})
        )
        limits = markdown.split("## 13. Limitations and analysis notes", 1)[1]
        assert "40 ledger entries, 39 ok, 1 failed, 12 trimmed to the budget" in limits

    def test_a_run_that_trimmed_nothing_says_nothing_about_trimming(self) -> None:
        markdown = MarkdownRenderer().render(
            self._report_with({"entries": 4, "ok": 4, "failed": 0, "trimmed": 0})
        )
        assert "Evidence: 4 tool call(s) (see §13)." in markdown
        assert "trimmed to the budget" not in markdown.split("## 13.")[0]

    def test_a_run_with_no_evidence_adds_no_line(self) -> None:
        assert "tool call(s)" not in MarkdownRenderer().render(_report())

    def test_the_run_summary_appendix_carries_the_ungrounded_count(self) -> None:
        report = self._report_with({"entries": 40, "ok": 39, "failed": 1, "trimmed": 12})
        report.run_summary["sections_without_evidence"] = 2
        markdown = MarkdownRenderer().render(report)
        assert "- Report sections with no evidence: 2" in markdown

    def test_the_html_export_carries_it_too(self) -> None:
        html = HtmlRenderer().render(
            self._report_with({"entries": 40, "ok": 39, "failed": 1, "trimmed": 12})
        )
        assert "12 trimmed to the budget" in html
