"""A cell cut to fit the page is never cut inside a defang mark.

A table cell is defanged and then cut, so the cut could fall inside the mark
the defanger wrote: ``skinnyjeanso[.…`` is neither the value nor a defanged
spelling of it, and a reader or a checker cannot tell what was there (T-348).
A cut that would fall inside ``[.]``, ``[:]`` or ``[@]`` falls before the mark
instead; a cut anywhere else is where it was.
"""

from __future__ import annotations

import re

import pytest

from maljan.reporting.models import EvidenceSection, FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer, _truncate, _truncate_escaped

SPLIT_MARK = re.compile(r"\[[.:@]?…")


@pytest.mark.parametrize("cut", [_truncate, _truncate_escaped])
@pytest.mark.parametrize("mark", ["[.]", "[:]", "[@]"])
def test_a_cut_inside_a_mark_falls_before_it(cut, mark: str) -> None:
    for lead in range(6, 14):
        text = "a" * lead + mark + "b" * 40
        out = cut(text, 12)
        assert not SPLIT_MARK.search(out), out
        assert out.endswith("…")
        assert len(out) <= 12


@pytest.mark.parametrize("cut", [_truncate, _truncate_escaped])
def test_a_cut_away_from_a_mark_is_where_it_was(cut) -> None:
    assert cut("a" * 20 + "[.]b", 12) == "a" * 11 + "…"
    assert cut("aaaa[.]bbbbbbbbbbbbbbbbbbb", 12) == "aaaa[.]bbbb…"


def test_no_table_cell_of_the_page_ends_inside_a_mark() -> None:
    rows = [
        ["x" * lead + " c2=https://skinnyjeanso.com/live/, user@example.com and more text " * 3]
        for lead in range(120, 165)
    ]
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        sections=[
            EvidenceSection(
                key="sandbox_items_extracted",
                title="Extracted",
                kind="table",
                columns=["fields"],
                rows=rows,
                evidence_ids=["ev_0001"],
            )
        ],
    )

    markdown = MarkdownRenderer().render(report)
    appendix = markdown[markdown.index("Appendix A") :]

    assert "skinnyjeanso[.]com" in appendix
    assert not SPLIT_MARK.search(appendix)
