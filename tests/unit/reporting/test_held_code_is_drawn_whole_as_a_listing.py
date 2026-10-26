"""Code a section holds is drawn whole, as a listing, and never cut into a table cell.

Appendix A cut a cell at 160 characters, so a batch of decompiled functions
printed each body as its first line and an ellipsis though the report held it
(T-384). A value that is code is now drawn as a fenced listing under its
section's table, headed by the function's address and name, and the cell
points to it. What is code is read from the kind the cited entry declared,
or from the value naming its row's function; never from a tool's name. A
one-line value is still cut to the page, and its section says where it is
whole.
"""

from __future__ import annotations

from maljan.reporting.models import (
    EvidenceIndexRow,
    EvidenceSection,
    FileHashes,
    MalwareReport,
    SampleIdentity,
)
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.markdown import MarkdownRenderer, declares_code, holds_code

BODY = (
    "\nint FUN_00401000(int param_1)\n\n{\n"
    + "".join(f"  local_{i} = param_1 + {i};\n" for i in range(40))
    + "  return param_1 + 1;\n}\n\n"
)
OTHER = "\nvoid entry(void)\n\n{\n" + "  helper();\n" * 30 + "  return;\n}\n"


def _report(
    rows: list[list[str]],
    kind: str | None = "decompile_batch",
    tool: str = "list_functions",
    ids: tuple[str, ...] = ("ev_0007",),
) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        evidence_index=[
            EvidenceIndexRow(id=i, tool=tool, facts={"kind": kind} if kind else None) for i in ids
        ],
        sections=[
            EvidenceSection(
                key="tool_functions",
                title="Functions",
                kind="kv",
                columns=["Field", "Value"],
                rows=rows,
                evidence_ids=list(ids),
                source=f"tool:{tool}",
            )
        ],
    )


def _appendix(report: MalwareReport) -> str:
    markdown = MarkdownRenderer().render(report)
    return markdown[markdown.index("Appendix A") : markdown.index("Appendix B")]


class TestDeclaredCode:
    def test_each_body_is_a_whole_listing_under_its_function(self) -> None:
        appendix = _appendix(_report([["0x401000", BODY], ["0x402000", OTHER]]))

        assert "| 0x401000 | code: Listing 1 below |" in appendix
        assert "| 0x402000 | code: Listing 2 below |" in appendix
        assert "**Listing 1** · `0x401000` · `FUN_00401000` · ev_0007" in appendix
        assert "**Listing 2** · `0x402000` · `entry` · ev_0007" in appendix
        assert f"```\n{BODY.strip(chr(10))}\n```" in appendix
        assert f"```\n{OTHER.strip(chr(10))}\n```" in appendix
        assert "…" not in appendix

    def test_the_html_draws_the_same_listing_whole(self) -> None:
        page = HtmlRenderer().render(_report([["0x401000", BODY]]), nonce="fixed")

        assert "local_39 = param_1 + 39;" in page
        assert "return param_1 + 1;" in page

    def test_a_body_the_report_holds_cut_says_where_it_is_whole(self) -> None:
        held = BODY[:300] + "…"
        appendix = _appendix(_report([["0x401000", held]]))

        assert held.strip("\n") in appendix
        assert (
            "_The report was built with this listing cut at the …; the evidence ledger "
            "carries it whole under ev_0007._"
        ) in appendix

    def test_a_listing_of_a_merged_section_points_to_its_entries(self) -> None:
        appendix = _appendix(_report([["0x401000", BODY]], ids=("ev_0007", "ev_0009")))

        assert "**Listing 1** · `0x401000` · `FUN_00401000`\n" in appendix
        assert "_Evidence: ev_0007, ev_0009_" in appendix

    def test_a_one_line_value_of_a_code_section_stays_a_cell(self) -> None:
        assert not holds_code("x" * 300, ["0x401000"], True)
        assert holds_code(BODY, ["0x401000"], True)


class TestCodeReadByContent:
    def test_an_undeclared_body_naming_its_function_is_a_listing(self) -> None:
        appendix = _appendix(_report([["0x401000", BODY]], kind=None))

        assert "**Listing 1** · `0x401000` · `FUN_00401000`" in appendix
        assert "local_39 = param_1 + 39;" in appendix

    def test_a_tool_s_name_makes_no_text_code(self) -> None:
        report = _report([["0x402000", OTHER]], kind=None, tool="batch_decompile")

        assert not declares_code(report.sections[0].evidence_ids, report.evidence_index)
        assert "Listing" not in _appendix(report)

    def test_a_kind_that_is_no_code_makes_no_listing(self) -> None:
        report = _report([["0x402000", OTHER]], kind="strings")

        assert "Listing" not in _appendix(report)


class TestAOneLineCut:
    def test_the_section_says_where_the_whole_value_is(self) -> None:
        appendix = _appendix(_report([["note", "y" * 300]], kind="strings"))

        assert "y" * 159 + "…" in appendix
        assert (
            "_A value above that ends in … is cut to fit the page (160 characters a cell, "
            "200 an item; no code is cut to fit it); the evidence ledger carries it whole "
            "under ev_0007._"
        ) in appendix

    def test_a_section_with_nothing_cut_says_nothing(self) -> None:
        assert "is cut to fit the page" not in _appendix(_report([["note", "short"]]))
