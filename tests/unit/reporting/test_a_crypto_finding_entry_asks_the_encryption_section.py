"""An answered entry of a crypto-finding kind reaches the encryption section.

The encryption bundle read crypto constants only from the analysts' captured
outputs, and its facts counted only crypto APIs. A run whose pack (or any
server's tool of the kind) found a published constant set in the file, with
no crypto API imported or called, was skipped as evidence-empty. The bundle
now names every answered entry whose declared kind is a crypto finding,
whichever server or step wrote it. A failed entry, or an entry of another
kind, is not named, and a run with none has the facts it always had.
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.evidence_bundles import bundle_for, crypto_finding_entries, is_empty
from maljan.reporting.models import (
    EvidenceIndexRow,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    StaticAnalysis,
)
from tests.linear_cost import assert_scales


def _row(n: int, tool: str, kind: str, ok: bool = True, source: str = "pack") -> EvidenceIndexRow:
    return EvidenceIndexRow(
        id=f"ev_{n:04d}", tool=tool, ok=ok, source=source, facts={"v": 1, "kind": kind}
    )


def _report(rows: list[EvidenceIndexRow], static: bool) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        static=StaticAnalysis() if static else None,
        evidence_index=rows,
    )


def test_an_answered_constant_set_entry_asks_the_section() -> None:
    for static in (False, True):
        report = _report([_row(21, "any_constant_finder", "crypto_constants")], static)
        bundle = bundle_for("encryption_scheme", report)
        assert bundle["facts"]["crypto_finding_entries"] == ["ev_0021 (any_constant_finder)"]
        assert not is_empty(bundle)


def test_an_operator_servers_tool_of_the_kind_counts_too() -> None:
    report = _report(
        [_row(40, "srv__scan_consts", "crypto_constants", source="mcp:other")], static=True
    )
    assert crypto_finding_entries(report) == ["ev_0040 (srv__scan_consts)"]


def test_a_failed_entry_or_another_kind_is_not_named() -> None:
    report = _report(
        [
            _row(1, "any_constant_finder", "crypto_constants", ok=False),
            _row(2, "string_sweep", "listing_strings"),
        ],
        static=True,
    )
    bundle = bundle_for("encryption_scheme", report)
    assert "crypto_finding_entries" not in bundle["facts"]
    assert is_empty(bundle)


def test_no_other_section_gains_the_fact() -> None:
    report = _report([_row(21, "any_constant_finder", "crypto_constants")], static=True)
    for section in ("discovery", "evasion_antiforensics", "packing_obfuscation"):
        assert "crypto_finding_entries" not in bundle_for(section, report)["facts"]


def test_the_fact_is_linear_in_the_index() -> None:
    def built(n: int) -> Any:
        return _report([_row(i + 1, f"tool{i}", "crypto_constants") for i in range(n)], static=True)

    def read(report: Any) -> None:
        assert crypto_finding_entries(report)

    assert_scales(built, 2_000, read, factor=10, repeats=5)
