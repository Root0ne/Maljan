"""The run summary's elapsed time is the whole run, with the stages beside it.

The clock used to start inside the judge node, so the figure the report
published was the verdict stage's duration: a 473 s job printed 66 s, five to
seven times short of what the job row said. The pipeline now carries the
instant the caller started counting, and the per-stage durations are printed
from the same rollup the console's stage headers are drawn from, so a reader
comparing the two surfaces cannot find them disagreeing.
"""

from __future__ import annotations

import inspect

from maljan.analysis.run_summary import RunSummaryBuilder, stage_duration_lines
from maljan.reporting.renderers.markdown import MarkdownRenderer

STAGES = [
    {"key": "triage_pack", "kind": "triage", "ran": True, "duration_ms": 191_017},
    {"key": "analysis", "kind": "analysis", "ran": True, "duration_ms": 57_837},
    {"key": "verdict", "kind": "verdict", "ran": True, "duration_ms": 66_282},
    {"key": "report", "kind": "report", "ran": False, "duration_ms": 0},
]


class TestTheClockStartsWithTheRun:
    def test_the_pipeline_accepts_the_caller_s_own_start(self) -> None:
        from maljan.app import MaljanApp

        assert "started_at" in inspect.signature(MaljanApp.arun).parameters

    def test_the_state_carries_it(self) -> None:
        from maljan.pipeline.state import AnalysisState

        assert AnalysisState.__annotations__["run_started_at"] is float

    def test_the_summary_measures_from_the_start_it_was_given(self) -> None:
        import time

        summary = RunSummaryBuilder(start_time=time.time() - 400.0).build()
        assert summary.elapsed_seconds > 399.0


class TestTheStagesArePrintedBesideIt:
    def test_only_the_stages_that_ran_are_named(self) -> None:
        (line,) = stage_duration_lines(STAGES)
        assert "triage_pack 191.0s" in line
        assert "analysis 57.8s" in line
        assert "verdict 66.3s" in line
        assert "report" not in line

    def test_nothing_is_printed_when_no_stage_reported(self) -> None:
        assert stage_duration_lines([]) == []
        assert stage_duration_lines(None) == []

    def test_the_report_prints_the_run_and_the_stages(self) -> None:
        from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity

        rendered = MarkdownRenderer()._appendix_run(
            MalwareReport(
                identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
                run_summary={"elapsed_seconds": 472.9, "stages": STAGES},
            )
        )
        assert "Elapsed: 472.9s (the whole run, to this report)" in rendered
        assert "Per stage: triage_pack 191.0s" in rendered
