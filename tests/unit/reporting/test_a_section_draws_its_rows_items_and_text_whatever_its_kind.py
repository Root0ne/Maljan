"""A section draws its rows, its items and its text, whatever kind it was opened as.

A section is keyed by the tool that built it, so a tool that answered once in
prose and once with records fills one section with both: the section keeps
the kind of its first answer, and the Markdown body drew only the part that
kind names. The rows of a tool whose first answer was text were in the JSON
report and on no page (T-342). Every part a section carries now reaches the
Markdown, and through it the HTML and the PDF: the rows as a table, the items
as a list, a tool's own text in its fence.
"""

from __future__ import annotations

import json

from maljan.reporting.ledger_report import build_sections
from maljan.reporting.models import EvidenceSection, FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import build_entry, format_entry_id

LISTING = "KERNEL32.dll PeekNamedPipe\nKERNEL32.dll GetLastError"
RECORDS = [
    {"name": "PeekNamedPipe", "address": "EXTERNAL:00000001"},
    {"name": "GetLastError", "address": "EXTERNAL:00000002"},
]


def _entry(seq: int, output: str):
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent="static",
        tool="list_imports",
        args={},
        server=None,
        output=output,
    )


def _report(*sections: EvidenceSection) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), sections=list(sections)
    )


def _appendix(markdown: str) -> str:
    return markdown[markdown.index("Appendix A") :]


def test_a_tool_that_answered_in_prose_then_records_keeps_both_on_the_page() -> None:
    sections = build_sections([_entry(1, LISTING), _entry(2, json.dumps(RECORDS))])
    (section,) = [s for s in sections if s.key == "tool_list_imports"]
    assert section.text and section.rows

    markdown = _appendix(MarkdownRenderer().render(_report(section)))

    assert f"```\n{LISTING}\n```" in markdown
    assert "| name | address |" in markdown
    assert "| PeekNamedPipe | EXTERNAL:00000001 |" in markdown
    assert markdown.index(LISTING) < markdown.index("| name | address |")


def test_a_text_section_s_rows_reach_the_html() -> None:
    section = EvidenceSection(
        key="tool_list_imports",
        title="List imports",
        kind="text",
        columns=["name", "address"],
        rows=[["PeekNamedPipe", "EXTERNAL:00000001"]],
        text=LISTING,
        evidence_ids=["ev_0001", "ev_0002"],
    )

    html = HtmlRenderer().render(_report(section))

    assert "<td>PeekNamedPipe</td>" in html
    assert "<td>EXTERNAL:00000001</td>" in html
    assert "KERNEL32.dll GetLastError" in html


def test_a_table_s_items_and_a_list_s_rows_are_drawn_too() -> None:
    table = EvidenceSection(
        key="t",
        title="Table with items",
        kind="table",
        columns=["A"],
        rows=[["row-cell"]],
        items=["an item beside the rows"],
        evidence_ids=["ev_0001"],
    )
    listing = EvidenceSection(
        key="l",
        title="List with rows",
        kind="list",
        columns=["B"],
        rows=[["list-row-cell"]],
        items=["a listed item"],
        evidence_ids=["ev_0002"],
    )

    markdown = _appendix(MarkdownRenderer().render(_report(table, listing)))

    assert "| row-cell |" in markdown
    assert "- an item beside the rows" in markdown
    assert "| list-row-cell |" in markdown
    assert "- a listed item" in markdown


def test_a_section_of_one_part_renders_as_it_did() -> None:
    alone = EvidenceSection(key="k", title="T", kind="text", text="said once", evidence_ids=["e"])
    table = EvidenceSection(
        key="t", title="Tab", kind="table", columns=["A"], rows=[["x1"]], evidence_ids=["e"]
    )

    markdown = _appendix(MarkdownRenderer().render(_report(alone, table)))

    assert "```\nsaid once\n```" in markdown
    assert "| A |\n|---|\n| x1 |" in markdown
