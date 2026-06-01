"""Capability-matrix signal-quality tests (§2.4).

Zero-signal techniques (no confidence, no evidence, no contributing layer) must
not be emitted as cells/mappings — they would render as "verified" capabilities
and seed fabricated narrative prose.
"""

from __future__ import annotations

from types import SimpleNamespace

from maljan.extractors.capability_matrix import build_capability_matrix


def test_zero_signal_technique_dropped() -> None:
    empty = SimpleNamespace(
        technique_id="T1000", weighted_confidence=0.0, contributing_layers=[], evidence=[]
    )
    real = SimpleNamespace(
        technique_id="T1055",
        weighted_confidence=0.8,
        contributing_layers=["yara"],
        evidence=["WriteProcessMemory @ 0x401000"],
    )
    cells, mappings = build_capability_matrix(cascade_summary=[empty, real], isr_reports=None)
    cell_ids = {c.technique_id for c in cells}
    mapping_ids = {m.technique_id for m in mappings}
    assert "T1055" in cell_ids
    assert "T1000" not in cell_ids
    assert "T1000" not in mapping_ids


def test_technique_with_evidence_but_zero_conf_kept() -> None:
    # Evidence present (even if confidence wasn't computed) is real signal.
    entry = SimpleNamespace(
        technique_id="T1059",
        weighted_confidence=0.0,
        contributing_layers=[],
        evidence=["cmd.exe /c whoami"],
    )
    cells, _ = build_capability_matrix(cascade_summary=[entry], isr_reports=None)
    assert {c.technique_id for c in cells} == {"T1059"}
