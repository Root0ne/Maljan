"""A format section is keyed by the tool whole, not by its name's first word (RC-17)."""

from __future__ import annotations

from maljan.reporting.ledger_report import _binary_info, _Sections
from maljan.schemas.evidence import EvidenceCounter
from tests.unit._ledger_helpers import entry


def _keys(acc: _Sections) -> list[str]:
    return sorted(acc._by_key)


def test_pe_info_keeps_its_section_key() -> None:
    counter = EvidenceCounter()
    acc = _Sections()
    _binary_info(acc, entry("pe_info", {"machine": "x86"}, counter), {"machine": "x86"})
    assert _keys(acc) == ["pe_header"]


def test_a_second_tool_with_the_same_first_word_is_its_own_section() -> None:
    counter = EvidenceCounter()
    acc = _Sections()
    _binary_info(acc, entry("pe_info", {"machine": "x86"}, counter), {"machine": "x86"})
    _binary_info(acc, entry("pe_rebuilt", {"machine": "arm"}, counter), {"machine": "arm"})
    assert _keys(acc) == ["pe_header", "pe_rebuilt_header"]
