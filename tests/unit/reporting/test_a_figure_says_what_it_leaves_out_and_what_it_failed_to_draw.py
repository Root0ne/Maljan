"""Captions say what is drawn, caps are counted in the legend, failures are logged (RC-14)."""

from __future__ import annotations

import logging
from typing import Any

import pytest

from maljan.reporting import figures
from maljan.reporting.figures import build_attack_matrix, build_entropy_chart, build_infection_chain
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    PESection,
    SampleIdentity,
    StaticAnalysis,
    TTPMapping,
)


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), **over)


def _ttp(n: int, tactic: str = "TA0002") -> TTPMapping:
    return TTPMapping(technique_id=f"T{1000 + n}", technique_name=f"t{n}", tactic=tactic)


def test_techniques_past_a_column_s_cells_are_counted() -> None:
    fig = build_attack_matrix(_report(ttp_mappings=[_ttp(n) for n in range(11)]))
    assert fig is not None and fig.legend is not None
    assert "3 more techniques are not drawn" in fig.legend


def test_a_tactic_without_a_column_is_counted() -> None:
    fig = build_attack_matrix(_report(ttp_mappings=[_ttp(1), _ttp(2, "TA9999")]))
    assert fig is not None and fig.legend is not None
    assert "1 more techniques are not drawn" in fig.legend


def test_a_matrix_that_drew_everything_has_no_legend() -> None:
    fig = build_attack_matrix(_report(ttp_mappings=[_ttp(1)]))
    assert fig is not None and fig.legend is None


def test_sections_past_the_chart_are_counted_and_it_is_no_pe_chart() -> None:
    sections = [PESection(name=f".s{n}", virtual_address="0x1000", entropy=1.0) for n in range(15)]
    fig = build_entropy_chart(_report(static=StaticAnalysis(sections=sections)))
    assert fig is not None and fig.legend is not None
    assert "3 more sections are not drawn" in fig.legend
    assert "PE" not in fig.caption


def test_the_chain_does_not_claim_an_observed_order() -> None:
    fig = build_infection_chain(_report(ttp_mappings=[_ttp(1), _ttp(2, "TA0011")]))
    assert fig is not None and fig.legend is not None
    assert "not the order" in fig.legend


def test_a_failing_figure_is_logged(monkeypatch: pytest.MonkeyPatch, caplog: Any) -> None:
    def boom(_report: MalwareReport) -> None:
        raise ValueError("x")

    monkeypatch.setattr(figures, "build_infection_chain", boom)
    with caplog.at_level(logging.WARNING):
        drawn = figures.build_figures(_report())
    assert "infection_chain" in caplog.text
    (said,) = drawn
    assert said.kind == "not_drawn"
    assert "Figure not drawn: infection_chain (ValueError)" in said.content
