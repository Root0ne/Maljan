"""A run stopped part-way keeps the report it had, and says what it does not have.

The report node's own report when it returned; else the report it was
building, with every composer section already written into it; else the
deterministic report from the state. A stage that did not run is not filled
in: no summary is written, and with no judge no verdict is claimed. The run
summary is the judge's when there is one, else built from the state, and what
the run spent is read again at the stop.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import pytest

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.pipeline.stopped_run import (
    NO_VERDICT_REASON,
    partial_report,
    stopped_run_summary,
    stopped_state,
)
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers import MarkdownRenderer

NOTE = "Stopped by the job timeout (60 s, core.job_timeout) 61 s into the run, here."


@pytest.fixture
def container() -> ServiceContainer:
    return ServiceContainer(Settings(_env_file=None), mock=True)


def _state(**extra: Any) -> dict[str, Any]:
    return {
        "file_hash": "b" * 64,
        "file_name": "sample.exe",
        "run_started_at": time.time() - 61,
        "reports": {"static": "the static analyst's prose"},
        "isr_reports": {},
        "evidence_ledger": [],
        "discussion_history": [],
        "degradation_reasons": [],
        "stage_results": {},
        **extra,
    }


class TestTheState:
    def test_the_report_node_s_state_wins_over_the_last_step(self) -> None:
        app = SimpleNamespace(built_report={"a": 1}, latest_state={"b": 2})
        assert stopped_state(app) == {"a": 1}

    def test_otherwise_the_last_complete_step(self) -> None:
        app = SimpleNamespace(built_report=None, latest_state={"b": 2})
        assert stopped_state(app) == {"b": 2}

    def test_a_run_stopped_before_its_first_step_has_an_empty_state(self) -> None:
        assert stopped_state(SimpleNamespace()) == {}


class TestThePartialReport:
    def test_before_the_report_stage_the_deterministic_report_says_what_did_not_run(
        self, container: ServiceContainer
    ) -> None:
        dump = partial_report(_state(), container, note=NOTE)
        assert dump is not None
        report = MalwareReport.model_validate(dump)
        assert report.degraded_mode is True
        assert report.degradation_reasons[-1] == NOTE
        assert NO_VERDICT_REASON in report.degradation_reasons
        assert report.overall_confidence is None
        assert report.executive_summary == ""
        assert report.key_findings == []
        markdown = MarkdownRenderer().render(report)
        assert "No summary was written: the run was stopped before its report stage" in markdown
        assert NOTE in markdown

    def test_with_no_judge_the_verdict_is_not_assessed_and_no_judge_is_named(
        self, container: ServiceContainer
    ) -> None:
        dump = partial_report(_state(), container, note=NOTE)
        assert dump is not None
        assert dump["verdict_not_assessed"] == "the run was stopped before its verdict stage ran"
        markdown = MarkdownRenderer().render(MalwareReport.model_validate(dump))
        assert (
            "Verdict: not assessed (the run was stopped before its verdict stage ran) "
            "_(Not assessed)_"
        ) in markdown
        assert "**Verdict:** not assessed (the run was stopped" in markdown
        assert "Assessed by the judge" not in markdown
        assert "Suspicious" not in markdown

    def test_with_a_judge_the_verdict_is_the_judge_s(self, container: ServiceContainer) -> None:
        dump = partial_report(_state(final_decision="Malware"), container, note=NOTE)
        assert dump is not None
        assert dump["verdict"] == "Malware"
        assert dump["verdict_not_assessed"] is None
        assert "Assessed by the judge" in MarkdownRenderer().render(
            MalwareReport.model_validate(dump)
        )

    def test_a_report_stopped_in_the_making_keeps_its_written_sections(
        self, container: ServiceContainer
    ) -> None:
        dump = partial_report(_state(), container, note=NOTE)
        in_progress = MalwareReport.model_validate(dump)
        in_progress.degradation_reasons = []
        in_progress.intro_background = "the introduction the composer wrote"
        container.report_in_progress = in_progress
        in_progress.executive_summary = "the narrative's summary"
        container.report_in_progress = in_progress
        kept = partial_report(_state(final_decision="Malware"), container, note=NOTE)
        assert kept is not None
        assert kept["intro_background"] == "the introduction the composer wrote"
        assert kept["degradation_reasons"] == [NOTE]

    def test_a_report_stopped_inside_the_narrative_says_the_run_stopped(
        self, container: ServiceContainer
    ) -> None:
        held = MalwareReport.model_validate(partial_report(_state(), container, note=NOTE))
        held.degradation_reasons = []
        held.verdict_not_assessed = None
        container.report_in_progress = held
        kept = partial_report(_state(final_decision="Malware"), container, note=NOTE)
        markdown = MarkdownRenderer().render(MalwareReport.model_validate(kept))
        assert (
            "No summary was written: the run was stopped before the report's narrative "
            "round answered."
        ) in markdown
        assert "the report model wrote none" not in markdown

    def test_a_returned_report_is_kept_as_it_was(self, container: ServiceContainer) -> None:
        state = _state(malware_report={"verdict": "Benign", "degradation_reasons": ["x"]})
        kept = partial_report(state, container, note=NOTE)
        assert kept == {
            "verdict": "Benign",
            "degradation_reasons": ["x", NOTE],
            "degraded_mode": True,
        }


class TestTheRunSummary:
    def test_with_no_judge_it_is_built_from_the_state_with_what_was_spent(
        self, container: ServiceContainer
    ) -> None:
        container.get_token_ledger().add(
            {"input_tokens": 700, "output_tokens": 70}, agent="static", model="m1"
        )
        summary = stopped_run_summary(_state(), container, note=NOTE)
        assert summary["final_decision"] == "Unknown"
        assert summary["file_hash"] == "b" * 64
        assert summary["tokens"]["input_tokens"] == 700
        assert summary["degraded_mode"] is True
        assert summary["degradation_reasons"] == [NOTE]
        assert summary["elapsed_seconds"] >= 60
        # Every stage of the profile is a row; the ones that did not report say so.
        assert summary["stages"]
        assert all(row["reason"] == "stage did not report" for row in summary["stages"])

    def test_the_judge_s_summary_is_kept_and_its_spend_read_again(
        self, container: ServiceContainer
    ) -> None:
        judge_summary = {
            "final_decision": "Malware",
            "degraded_mode": False,
            "degradation_reasons": ["an earlier reason"],
            "tokens": {"llm_calls": 1},
        }
        ledger = container.get_token_ledger()
        ledger.add({"input_tokens": 10, "output_tokens": 1}, agent="judge", model="m1")
        ledger.add({"input_tokens": 20, "output_tokens": 2}, agent="reporter", model="m1")
        summary = stopped_run_summary(
            _state(final_decision="Malware", run_summary=judge_summary), container, note=NOTE
        )
        assert summary["final_decision"] == "Malware"
        assert summary["tokens"]["llm_calls"] == 2
        assert summary["degradation_reasons"] == ["an earlier reason", NOTE]
        assert judge_summary["degradation_reasons"] == ["an earlier reason"]
