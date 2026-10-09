"""The rehearsal checklist passes a whole run and fails each thing it names, and only that.

One complete record passes every check; each test then breaks one fact — a
section lost between its answer and the report, totals that are not the
provider's usage, a claim missing from the report, a setting not in force, a
fault that never happened — and exactly that check fails. Repeated runs that
differ are named, field by field.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
from scripts.rehearsal.checklist import (
    RunRecord,
    check_run,
    compare,
    section_statuses,
    signature,
)


def _log(n: int, role: str, **extra: Any) -> dict[str, Any]:
    entry = {
        "n": n,
        "role": role,
        "status": 200,
        "model": "expert",
        "effort": "high",
        "max_tokens": 9000,
        "input_tokens": 100,
        "output_tokens": 10,
        "fault": "",
    }
    entry.update(extra)
    return entry


def _record(**changes: Any) -> RunRecord:
    record = RunRecord(
        scenario="normal",
        job_status="completed",
        verdict="Malware",
        run_summary={
            "verdict_reading": "stated",
            "stages": [{"key": "analysis", "ran": True, "failure": False}],
            "tokens": {
                "llm_calls": 4,
                "unreported_calls": 0,
                "input_tokens": 400,
                "output_tokens": 40,
            },
            "budget": {"static": {"max_steps": 40, "timeout_s": 900, "steps_used": 3}},
            "degradation_reasons": [],
        },
        malware_report={
            "intro_background": "The run recorded the sample.",
            "executive_summary": "A summary.",
            "claims_not_discussed": [{"claim": "It talks HTTP."}],
            "technical_analysis": {},
        },
        markdown="# Report\n\nVerdict: Malware\n",
        stix_bundle={"type": "bundle", "objects": [{"type": "malware"}]},
        stix_extended={"type": "bundle", "objects": [{"type": "malware"}]},
        claims_in_force={"static": ["It talks HTTP."]},
        events=[
            {"type": "stage_started", "stage": "analysis"},
            {"type": "stage_finished", "stage": "analysis"},
        ],
        stub_log=[
            _log(1, "analyst"),
            _log(2, "judge", model="judge-model"),
            _log(3, "composer", section="introduction", content=True),
            _log(4, "composer", section="cli_flags", content=False),
        ],
        expected={
            "model.static": "expert",
            "model.judge": "judge-model",
            "effort": "high",
            "max_steps": 40,
        },
    )
    for key, value in changes.items():
        setattr(record, key, value)
    return record


def _failed(record: RunRecord) -> list[str]:
    return [c.name for c in check_run(record) if not c.ok]


def test_a_whole_run_passes_every_check() -> None:
    assert _failed(_record()) == []


class TestEachCheckFailsOnItsOwnFact:
    def test_a_failed_job(self) -> None:
        assert _failed(_record(job_status="failed")) == ["job completed"]

    def test_a_stage_that_never_finished(self) -> None:
        events = [{"type": "stage_started", "stage": "analysis"}]
        assert _failed(_record(events=events)) == ["every stage started and finished"]

    def test_an_analyst_lost_to_an_error(self) -> None:
        record = _record()
        record.run_summary["failed_analysts"] = ["static"]
        assert _failed(record) == ["every analyst answered"]

    def test_a_section_answered_and_then_lost(self) -> None:
        record = _record()
        record.stub_log.append(_log(5, "composer", section="configuration", content=True))
        record.run_summary["tokens"]["llm_calls"] = 5
        record.run_summary["tokens"]["input_tokens"] = 500
        record.run_summary["tokens"]["output_tokens"] = 50
        assert section_statuses(record)["configuration"] == "lost"
        assert _failed(record) == ["every report section written or accounted for"]

    def test_a_section_a_degradation_marks_is_accounted_for(self) -> None:
        record = _record()
        record.stub_log.append(_log(5, "composer", section="configuration", status=500))
        record.run_summary["degradation_reasons"] = [
            "report section 'configuration' is not written: the call failed"
        ]
        assert section_statuses(record)["configuration"] == "marked not written"
        assert section_statuses(record)["cli_flags"] == "answered empty"
        assert section_statuses(record)["ransom_note"] == "not asked (no evidence for it)"

    def test_totals_that_are_not_the_provider_s_usage(self) -> None:
        record = _record()
        record.run_summary["tokens"]["output_tokens"] = 41
        assert _failed(record) == ["run summary and token totals"]

    def test_a_missing_markdown(self) -> None:
        assert _failed(_record(markdown="")) == ["STIX and markdown rendered"]

    def test_a_claim_missing_from_the_report(self) -> None:
        claims = {"static": ["It talks HTTP.", "It never reached the report."]}
        assert _failed(_record(claims_in_force=claims)) == [
            "no claim lost on the way to the report"
        ]

    @pytest.mark.parametrize(
        ("key", "value"),
        [("effort", "max"), ("model.judge", "other"), ("max_steps", 8)],
    )
    def test_a_setting_not_in_force(self, key: str, value: Any) -> None:
        record = _record()
        record.expected[key] = value
        assert _failed(record) == ["settings in force as configured"]

    def test_a_verdict_the_judge_did_not_state(self) -> None:
        record = _record()
        record.run_summary["verdict_reading"] = "fallback"
        assert _failed(record) == ["verdict stated by the judge"]

    def test_a_fault_scenario_where_no_fault_happened(self) -> None:
        assert _failed(_record(scenario="cut_at_cap")) == ["the cut_at_cap scenario happened"]

    def test_a_server_error_never_answered_afterwards(self) -> None:
        record = _record(scenario="server_error_once")
        record.stub_log.insert(0, _log(0, "mediator", status=500, fault="server_error_once"))
        assert _failed(record) == ["the server_error_once scenario happened"]


class TestRepeatedRuns:
    def test_identical_runs_compare_equal(self) -> None:
        first, second = _record(), _record()
        signatures = [signature(r, check_run(r)) for r in (first, second)]
        assert compare(signatures) == []

    def test_a_run_that_differs_is_named_by_field(self) -> None:
        first = _record()
        second = copy.deepcopy(first)
        second.verdict = "Suspicious"
        second.markdown = "# Report\n\nVerdict: Suspicious\n"
        signatures = [signature(r, check_run(r)) for r in (first, second)]
        differences = compare(signatures)
        assert any("run 2 differs from run 1 in verdict" in d for d in differences)
