"""The PDF's contents page prints the page each section starts on (T-477).

The contents entry is a flex row on screen, and WeasyPrint leaves a
``target-counter()`` inside a flex item at 0, so every entry printed "0". The
PDF lays the entry out as a block with its number floated right; the HTML
export is unchanged. Read from WeasyPrint's laid-out pages, the very document
the PDF is written from: every entry's number is the page its section's anchor
is on, so it is above 0 and never goes down.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.pdf import PdfRenderer
from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import _benchmark
from tests.unit.reporting.test_renderers_html import _rich_report


def _toc_numbers(document: Any) -> list[tuple[str, int]]:
    """Each contents entry's target and the page number printed after it."""
    numbers: list[tuple[str, int]] = []
    for page in document.pages:
        for kind, target, _rect, box in page.links:
            if (
                kind == "internal"
                and box.element_tag.endswith("::after")
                and target.startswith("sec-")
            ):
                text = "".join(getattr(b, "text", "") for b in box.descendants())
                numbers.append((target, int(text)))
    return numbers


def _anchor_pages(document: Any) -> dict[str, int]:
    return {
        anchor: number
        for number, page in enumerate(document.pages, start=1)
        for anchor in page.anchors
    }


def _assert_contents_pages(html_doc: str) -> None:
    document = PdfRenderer.layout_html(html_doc)
    numbers = _toc_numbers(document)
    listed = re.findall(
        r'<a href="#(sec-[^"]+)">', html_doc.split('<nav class="toc">', 1)[1].split("</nav>", 1)[0]
    )
    assert [target for target, _ in numbers] == listed
    pages = [page for _, page in numbers]
    assert all(page > 0 for page in pages)
    assert pages == sorted(pages)
    anchors = _anchor_pages(document)
    assert all(page == anchors[target] for target, page in numbers)


def test_every_contents_entry_prints_its_section_s_page() -> None:
    _assert_contents_pages(HtmlRenderer(self_contained=True).render(_rich_report()))


def test_a_stored_run_s_contents_print_their_pages() -> None:
    root = _benchmark()
    if root is None or not (root / "run7" / "report.json").is_file():
        pytest.skip("the stored benchmark runs are not on this machine")
    report = MalwareReport.model_validate(json.loads((root / "run7" / "report.json").read_text()))
    _assert_contents_pages(HtmlRenderer(self_contained=True).render(report))


def test_the_html_export_keeps_its_flex_contents_row() -> None:
    html_doc = HtmlRenderer().render(_rich_report())
    assert "nav.toc a { display: flex;" in html_doc
    assert (
        "nav.toc a::after" in html_doc
        and "float" not in html_doc.split("nav.toc a::after", 1)[1][:120]
    )
