"""A citation and a document recorded before the extracted section was renamed resolve as before.

A run recorded before the rename has an index naming the section ``cape`` and
claims citing ``cape:<n>``, the n-th row of the report's ``CAPE`` lists in name
order. Read now, every such citation names the same row, through every
lookup a report check makes. A document laid out before the rename (the old
words ``CAPE``, ``procdump``, ``suricata``) is read as what it holds. Run on
every stored CAPE report the session has, and on the fixtures always.
"""

from __future__ import annotations

from typing import Any

import pytest
from tests.unit.providers.test_sandbox_tools_golden import cape_reports

from maljan.analysis import sandbox_sections as ss
from maljan.schemas.sandbox_document import sandbox_document
from maljan.schemas.sandbox_report import cape_report_to_sandbox_report

_REPORTS = [(name, raw) for name, raw in cape_reports() if raw.get("CAPE")]
_IDS = [name for name, _ in _REPORTS]


def _stored_rows(raw: dict[str, Any]) -> list[Any]:
    """The rows ``cape:1``, ``cape:2`` ... named before the rename, in that order."""
    block = raw["CAPE"]
    if isinstance(block, list):
        return list(block)
    return [row for key in sorted(str(k) for k in block) for row in (block[key] or [])]


def _synthetic() -> dict[str, Any]:
    return {
        "behavior": {"processes": [{"process_id": 10}]},
        "CAPE": {"payloads": [{"sha256": "b" * 64}], "configs": [{"Family": {"k": "v"}}]},
        "procdump": [{"pid": 10}],
        "suricata": {"alerts": [{"signature": "s"}]},
    }


CASES = [("synthetic", _synthetic()), *_REPORTS]
CASE_IDS = ["synthetic", *_IDS]


@pytest.mark.parametrize("name,raw", CASES, ids=CASE_IDS)
def test_every_stored_cape_citation_names_the_row_it_named(name: str, raw: dict[str, Any]) -> None:
    document = sandbox_document(cape_report_to_sandbox_report(raw, provider="cape2"))
    sections = ss.Sections(document, ("cape2", "cape2", "raw"))
    rows = _stored_rows(raw)
    stored_index = ss.ItemIndex.from_answer(
        {"sections": {"cape": {"items": len(rows), "prefix": "cape"}}}
    )
    assert stored_index is not None
    citations = ss.ItemCitations(stored_index, sections)
    for number, row in enumerate(rows, 1):
        stored, current = f"cape:{number}", f"ext:{number}"
        item = sections.item(stored)
        assert item is not None and item == sections.item(current)
        assert item["fields"] == (row if isinstance(row, dict) else {"value": row})
        assert stored_index.known(stored)
        assert citations.item(stored) == item
        assert citations.text(stored) is not None
        assert ss.is_item_id(stored)
    assert sections.item(f"cape:{len(rows) + 1}") is None


@pytest.mark.parametrize("name,raw", CASES, ids=CASE_IDS)
def test_a_document_laid_out_before_the_rename_is_read_as_what_it_holds(
    name: str, raw: dict[str, Any]
) -> None:
    current = ss.section_index(
        sandbox_document(cape_report_to_sandbox_report(raw, provider="cape2")), ("cape2", "cape2")
    )["sections"]
    stored = ss.section_index(raw, ("cape2", "cape2"))["sections"]
    for section in ("extracted", "procdumps", "alerts", "resolved_apis", "processes"):
        assert stored[section].get("items") == current[section].get("items"), section
