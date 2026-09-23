"""No sandbox observation is stated where no sandbox ran.

The mock sandbox answers a sample it has no fixture for with an empty
stand-in report whose sections read like a detonation that did nothing. Every
reader of the sandbox report says what is true of it: no sandbox ran, or the
report is a recorded fixture and not a live detonation, or (unchanged) what a
sandbox observed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.pipeline import sandbox_status as status
from maljan.pipeline.triage_pack import PIPELINE, render_pack, run_pack
from maljan.schemas.evidence import EvidenceCounter
from tests.unit.pipeline.test_triage_pack import SANDBOX_REPORT, _inputs, _write
from tests.unit.tools.test_binary import _pe

SYNTHETIC: dict[str, Any] = {
    "synthetic": True,
    "target": {"sha256": "a" * 64, "name": "s.exe"},
    "behavior": {"processes": [], "apistats": {}, "generic": []},
    "network": {},
    "signatures": [],
}
FIXTURE: dict[str, Any] = {**SANDBOX_REPORT, "recorded_fixture": True}

SANDBOX_DERIVED = ("sigma_match_sandbox", "lolbin_lookup", "pcap_summary")


def _pack(tmp_path: Path, report: dict[str, Any] | None) -> Any:
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    path = _write(tmp_path, "s.exe", _pe())
    return run_pack(recorder, _inputs(path, "pe", sandbox_report=report))


def _tools(result: Any) -> list[str]:
    return [entry.tool for entry in result.entries]


class TestTheStatus:
    def test_no_report_is_no_sandbox_run(self) -> None:
        for report in (None, {}):
            found = status.sandbox_status(report)
            assert found.status == status.NOT_RUN
            assert found.statement.startswith("No sandbox ran on this run")

    def test_a_stand_in_report_is_no_sandbox_run(self) -> None:
        found = status.sandbox_status(SYNTHETIC)

        assert found.status == status.NOT_RUN
        assert found.statement.startswith("No sandbox ran for this sample")
        assert "mock sandbox" in found.statement

    def test_a_recorded_fixture_says_it_is_not_a_live_detonation(self) -> None:
        found = status.sandbox_status(FIXTURE)

        assert found.status == status.RECORDED_FIXTURE
        assert "recorded fixture" in found.statement
        assert "not a live detonation" in found.statement

    def test_a_real_report_has_nothing_to_add(self) -> None:
        found = status.sandbox_status(SANDBOX_REPORT)

        assert found.status == status.OBSERVED
        assert found.statement == ""

    def test_every_statement_is_one_sentence(self) -> None:
        for report in (None, SYNTHETIC, FIXTURE):
            statement = status.sandbox_status(report).statement
            assert statement.endswith(".")
            assert statement.count(". ") == 0, statement
            assert "?" not in statement


class TestThePack:
    def test_a_stand_in_report_is_one_sentence_and_no_sandbox_section(self, tmp_path: Path) -> None:
        result = _pack(tmp_path, SYNTHETIC)
        tools = _tools(result)

        assert tools.count("sandbox_status") == 1
        assert not [
            tool for tool in tools if tool.startswith("sandbox_") and tool != "sandbox_status"
        ]
        assert not [tool for tool in tools if tool in SANDBOX_DERIVED]
        (entry,) = [e for e in result.entries if e.tool == "sandbox_status"]
        line = render_pack([entry], 0)
        assert line == f"[{entry.id}] sandbox: {status.sandbox_status(SYNTHETIC).statement}"
        assert "sandbox_status" not in result.failed

    def test_no_report_is_said_the_same_way(self, tmp_path: Path) -> None:
        result = _pack(tmp_path, None)

        (entry,) = [e for e in result.entries if e.tool == "sandbox_status"]
        assert entry.ok is True
        assert entry.structured == {
            "sandbox": status.NOT_RUN,
            "statement": status.sandbox_status(None).statement,
        }
        assert "0 processes" not in render_pack(result.entries, 0)

    def test_a_recorded_fixture_is_said_first_and_its_contents_follow(self, tmp_path: Path) -> None:
        tools = _tools(_pack(tmp_path, FIXTURE))

        first = tools.index("sandbox_status")
        assert tools[first + 1 : first + 6] == [
            "sandbox_processes",
            "sandbox_network",
            "sandbox_signatures",
            "sandbox_dropped_files",
            "sandbox_channels",
        ]
        assert "sigma_match_sandbox" in tools

    def test_a_real_report_carries_no_status_line(self, tmp_path: Path) -> None:
        assert "sandbox_status" not in _tools(_pack(tmp_path, SANDBOX_REPORT))


class TestTheProviderMarksAFixture:
    def _run(self, raw: dict[str, Any], provider: str, source_format: str) -> dict[str, Any]:
        from maljan.providers.cape_view import to_cape_shaped_dict
        from maljan.schemas.sandbox_report import cape_report_to_sandbox_report

        report = cape_report_to_sandbox_report(
            raw, provider=provider, source_format=source_format, task_id="1"
        )
        return to_cape_shaped_dict(report)

    def test_the_mock_s_fixture_is_marked_as_one(self) -> None:
        shaped = self._run(dict(SANDBOX_REPORT), "mock", "mock")

        assert shaped.get("recorded_fixture") is True
        assert status.sandbox_status(shaped).status == status.RECORDED_FIXTURE

    def test_the_mock_s_stand_in_is_marked_synthetic_and_not_a_fixture(self) -> None:
        shaped = self._run(dict(SYNTHETIC), "mock", "mock")

        assert shaped.get("synthetic") is True
        assert "recorded_fixture" not in shaped
        assert status.sandbox_status(shaped).status == status.NOT_RUN

    def test_a_real_sandbox_s_report_is_not_marked(self) -> None:
        shaped = self._run(dict(SANDBOX_REPORT), "cape2", "cape2")

        assert "recorded_fixture" not in shaped
        assert status.sandbox_status(shaped).status == status.OBSERVED


class TestTheDegradationReason:
    @pytest.mark.parametrize("report", [None, {}])
    def test_no_report_keeps_its_reason(self, report: Any) -> None:
        from maljan.pipeline.nodes import sandbox_degradation_reason

        assert sandbox_degradation_reason(report) == (
            "no sandbox report (dynamic detonation unavailable) — static-only evidence"
        )

    def test_a_stand_in_report_is_the_same_absence(self) -> None:
        from maljan.pipeline.nodes import sandbox_degradation_reason

        reason = sandbox_degradation_reason(SYNTHETIC)

        assert reason is not None
        assert reason.startswith("no sandbox ran")
        assert reason.endswith("static-only evidence")

    @pytest.mark.parametrize("report", [FIXTURE, SANDBOX_REPORT])
    def test_a_report_with_contents_is_no_degradation(self, report: Any) -> None:
        from maljan.pipeline.nodes import sandbox_degradation_reason

        assert sandbox_degradation_reason(report) is None


class TestTheRunSummary:
    def _summary(self, report: Any) -> Any:
        from maljan.analysis.run_summary import RunSummaryBuilder

        return RunSummaryBuilder(start_time=0.0).set_sandbox(report).build()

    def test_the_summary_says_no_sandbox_ran(self) -> None:
        summary = self._summary(SYNTHETIC)
        statement = status.sandbox_status(SYNTHETIC).statement

        assert summary.to_dict()["sandbox"] == {"status": status.NOT_RUN, "statement": statement}
        assert f"**Sandbox**: {statement}" in summary.to_markdown()

    def test_a_real_report_leaves_the_field_empty(self) -> None:
        summary = self._summary(SANDBOX_REPORT)

        assert summary.to_dict()["sandbox"] is None
        assert "**Sandbox**" not in summary.to_markdown()

    def test_the_report_s_run_summary_prints_it(self) -> None:

        statement = status.sandbox_status(FIXTURE).statement
        text = _run_summary_text(
            {"sandbox": {"status": status.RECORDED_FIXTURE, "statement": statement}}
        )

        assert f"- Sandbox: {statement}" in text


class TestTheReportSection:
    def test_the_status_entry_is_a_sandbox_section_of_its_own(self) -> None:
        from maljan.reporting.ledger_report import build_sections
        from maljan.schemas.evidence import build_entry, format_entry_id

        statement = status.sandbox_status(SYNTHETIC).statement
        entry = build_entry(
            entry_id=format_entry_id(12),
            seq=12,
            agent=PIPELINE,
            tool="sandbox_status",
            args={},
            server=PIPELINE,
            output='{"sandbox": "not run", "statement": "' + statement + '"}',
            ok=True,
            error=None,
            stage="triage_pack",
        )

        (section,) = [s for s in build_sections([entry]) if s.key == "sandbox_status"]

        assert section.title == "Sandbox"
        assert section.text == statement


def _run_summary_text(run_summary: dict) -> str:
    """The report's run-summary appendix for a report carrying ``run_summary``."""
    from maljan.reporting.models import MalwareReport
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    report = MalwareReport.model_validate(
        {"identity": {"hashes": {"sha256": "0" * 64}}, "run_summary": run_summary}
    )
    return MarkdownRenderer()._appendix_run(report)
