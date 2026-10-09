"""The rehearsal checklist passes a whole run and fails each thing it names, and only that.

One complete record passes every check; each test then breaks one fact and
exactly that check fails. Every hole a green rehearsal could hide is built by
hand here and must fail: a report stage that never ran, sections nobody asked
for and nobody excused, a model call no role script recognised, an analyst
with no claim or none at all, a request the API refused, an unreported call,
spend that does not match the usage, a claim the report never discusses, a
claim the model wrote that vanished, a fallback narrative, nothing configured
to compare. Repeated runs that differ are named, field by field.
"""

from __future__ import annotations

import copy
import time
from typing import Any

import pytest
from scripts.rehearsal.checklist import (
    COMPOSED,
    RunRecord,
    check_run,
    compare,
    priced_usage,
    section_statuses,
    signature,
)

MODEL = "deepseek-v4-flash"
NOW = time.time()


def _log(n: int, role: str, **extra: Any) -> dict[str, Any]:
    entry = {
        "n": n,
        "at": NOW,
        "role": role,
        "status": 200,
        "model": MODEL,
        "effort": "high",
        "max_tokens": 9000,
        "input_tokens": 1000,
        "output_tokens": 100,
        "cache_read_tokens": 0,
        "cache_write_5m_tokens": 0,
        "cache_write_1h_tokens": 0,
        "text_chars": 10,
        "fault": "",
        "refused": "",
    }
    entry.update(extra)
    return entry


def _stub_log() -> list[dict[str, Any]]:
    log = [
        _log(1, "analyst", answer="final", claims=["It talks HTTP"]),
        _log(2, "judge"),
        _log(3, "narrative"),
    ]
    for n, section in enumerate(COMPOSED, 4):
        log.append(_log(n, "composer", section=section, content=True, deliberately_empty=False))
    return log


def _report() -> dict[str, Any]:
    ta = {
        name: {"title": name, "body": "Static claim 1 is discussed here.", "evidence_refs": []}
        for name in COMPOSED
        if name not in ("introduction", "communications")
    }
    return {
        "intro_background": "The run recorded the sample; static claim 1 stands.",
        "executive_summary": "A summary of the run.",
        "technical_analysis": ta,
        "c2_channels": [{"name": "HTTP channel", "endpoints": ["http://x"]}],
        "claims_not_discussed": [],
        "degradation_reasons": [],
    }


def _record(**changes: Any) -> RunRecord:
    log = _stub_log()
    calls = len(log)
    record = RunRecord(
        scenario="normal",
        api="openai",
        job_status="completed",
        verdict="Malware",
        run_summary={
            "verdict_reading": "stated",
            "stages": [
                {
                    "key": "analysis",
                    "kind": "analysis",
                    "ran": True,
                    "failure": False,
                    "agents": ["static"],
                },
                {
                    "key": "report",
                    "kind": "report",
                    "ran": True,
                    "failure": False,
                    "agents": ["reporter"],
                },
            ],
            "tokens": {
                "llm_calls": calls,
                "unreported_calls": 0,
                "input_tokens": 1000 * calls,
                "output_tokens": 100 * calls,
            },
            "budget": {"static": {"max_steps": 40, "timeout_s": 900, "steps_used": 3}},
            "degradation_reasons": [],
        },
        malware_report=_report(),
        markdown="# Report\n\nVerdict: Malware\n",
        stix_bundle={"type": "bundle", "objects": [{"type": "malware"}]},
        stix_extended={"type": "bundle", "objects": [{"type": "malware"}]},
        claims_in_force={"static": ["It talks HTTP"]},
        events=[
            {"type": "stage_started", "stage": "analysis"},
            {"type": "stage_finished", "stage": "analysis"},
            {"type": "stage_started", "stage": "report"},
            {"type": "stage_finished", "stage": "report"},
        ],
        stub_log=log,
        expected={"model.static": MODEL, "effort.static": "high", "max_steps": 40},
        required_stages={"analysis": ["static"], "report": ["reporter"]},
        empty_evidence_sections=[],
        probe={"ok": True, "detail": "answered"},
    )
    usd, _ = priced_usage(record)
    record.run_summary["spend"] = {"spent_usd": round(usd, 6)}
    for key, value in changes.items():
        setattr(record, key, value)
    return record


def _failed(record: RunRecord) -> list[str]:
    return [c.name for c in check_run(record) if not c.ok]


def test_a_whole_run_passes_every_check() -> None:
    assert _failed(_record()) == []


class TestTheHolesAGreenRunCouldHide:
    def test_the_reviewer_s_record_fails(self) -> None:
        record = _record()
        record.run_summary["stages"][1]["ran"] = False
        record.malware_report["technical_analysis"] = {}
        record.malware_report["intro_background"] = ""
        record.malware_report["c2_channels"] = []
        record.stub_log = [e for e in record.stub_log if e["role"] != "composer"]
        record.stub_log[1]["role"] = "other"
        record.stub_log[2]["role"] = "other"
        record.empty_evidence_sections = None
        failed = _failed(record)
        assert "every stage of the profile ran" in failed
        assert "every report section written or accounted for" in failed
        assert "every model call recognised" in failed
        assert all(s.startswith("LOST") for s in section_statuses(record).values())

    def test_a_stage_that_never_ran(self) -> None:
        record = _record()
        record.run_summary["stages"][1]["ran"] = False
        assert _failed(record) == ["every stage of the profile ran"]

    def test_a_required_stage_missing_from_the_run(self) -> None:
        record = _record()
        record.required_stages["verdict"] = ["judge"]
        assert _failed(record) == ["every stage of the profile ran"]

    def test_a_call_no_script_recognised(self) -> None:
        record = _record()
        record.stub_log[1]["role"] = "other"
        assert "every model call recognised" in _failed(record)

    def test_a_composer_call_naming_no_section(self) -> None:
        record = _record()
        record.stub_log.append(_log(99, "composer", section=""))
        assert "every model call recognised" in _failed(record)

    def test_a_section_never_asked_with_no_excuse(self) -> None:
        record = _record()
        record.malware_report["technical_analysis"].pop("discovery")
        record.stub_log = [e for e in record.stub_log if e.get("section") != "discovery"]
        record.run_summary["tokens"].update(
            llm_calls=len(record.stub_log),
            input_tokens=1000 * len(record.stub_log),
            output_tokens=100 * len(record.stub_log),
        )
        record.run_summary["spend"]["spent_usd"] = round(priced_usage(record)[0], 6)
        assert section_statuses(record)["discovery"].startswith("LOST: never asked")
        assert _failed(record) == ["every report section written or accounted for"]
        record.empty_evidence_sections = ["discovery"]
        assert _failed(record) == []

    def test_a_section_answered_and_then_lost(self) -> None:
        record = _record()
        record.malware_report["technical_analysis"].pop("payloads")
        assert section_statuses(record)["payloads"].startswith("LOST: asked and answered")
        assert _failed(record) == ["every report section written or accounted for"]

    def test_a_section_left_empty_is_accepted_only_when_the_script_meant_it(self) -> None:
        record = _record()
        record.malware_report["technical_analysis"].pop("cli_flags")
        entry = next(e for e in record.stub_log if e.get("section") == "cli_flags")
        entry.update(content=False, deliberately_empty=True)
        assert _failed(record) == []
        entry["deliberately_empty"] = False
        assert _failed(record) == ["every report section written or accounted for"]

    def test_a_degradation_marks_a_section_not_written(self) -> None:
        record = _record()
        record.malware_report["technical_analysis"].pop("payloads")
        record.run_summary["degradation_reasons"] = [
            "report section 'payloads' is not written: cut"
        ]
        assert section_statuses(record)["payloads"] == "marked not written"

    def test_an_analyst_with_no_claim(self) -> None:
        record = _record()
        record.claims_in_force = {"static": []}
        assert "every analyst answered" in _failed(record)

    def test_an_analyst_that_never_started(self) -> None:
        record = _record()
        record.required_stages["analysis"] = ["static", "dynamic"]
        assert "every analyst answered" in _failed(record)

    def test_an_analyst_lost_to_an_error(self) -> None:
        record = _record()
        record.run_summary["failed_analysts"] = ["static"]
        assert _failed(record) == ["every analyst answered"]

    def test_a_request_the_api_refused(self) -> None:
        record = _record()
        record.stub_log.append(_log(99, "analyst", status=400, refused="Invalid `signature`"))
        assert _failed(record) == ["the model refused no request"]

    def test_a_failed_connection_test(self) -> None:
        assert _failed(_record(probe={"ok": False, "detail": "refused"})) == [
            "the connection test passed"
        ]
        assert _failed(_record(probe={})) == ["the connection test passed"]

    def test_a_fallback_narrative(self) -> None:
        record = _record()
        record.run_summary["degradation_reasons"] = [
            "narrative fell back to the deterministic text"
        ]
        assert _failed(record) == ["narrative written by the model"]

    def test_a_narrative_the_model_never_wrote(self) -> None:
        record = _record()
        record.stub_log[2]["status"] = 500
        assert "narrative written by the model" in _failed(record)

    def test_an_unreported_call(self) -> None:
        record = _record()
        record.run_summary["tokens"]["unreported_calls"] = 1
        assert _failed(record) == ["tokens and spend as the provider reported them"]

    def test_totals_that_are_not_the_provider_s_usage(self) -> None:
        record = _record()
        record.run_summary["tokens"]["output_tokens"] += 1
        assert _failed(record) == ["tokens and spend as the provider reported them"]

    def test_spend_that_is_not_the_usage_priced(self) -> None:
        record = _record()
        record.run_summary["spend"]["spent_usd"] *= 2
        assert _failed(record) == ["tokens and spend as the provider reported them"]

    def test_a_model_with_no_price(self) -> None:
        record = _record()
        for entry in record.stub_log:
            entry["model"] = "no-such-model"
        record.expected = {"effort.static": "high", "max_steps": 40}
        assert "tokens and spend as the provider reported them" in _failed(record)

    def test_a_claim_in_force_the_body_never_discusses(self) -> None:
        record = _record()
        record.claims_in_force = {"static": ["It talks HTTP", "It hides a second payload"]}
        failed = check_run(record)
        (claims,) = [c for c in failed if c.name == "no claim lost on the way to the report"]
        assert not claims.ok and "static claim 2" in claims.detail

    def test_a_claim_the_model_wrote_that_vanished(self) -> None:
        record = _record()
        record.stub_log[0]["claims"] = ["It talks HTTP", "It persists through a Run key"]
        assert _failed(record) == ["no claim lost on the way to the report"]
        record.run_summary["negotiation"] = {
            "dropped_claims": [
                'The static analyst no longer states "It persists through a Run key".'
            ]
        }
        assert _failed(record) == []

    def test_nothing_configured_to_compare(self) -> None:
        assert _failed(_record(expected={})) == ["settings in force as configured"]

    @pytest.mark.parametrize(
        ("key", "value"), [("effort.static", "max"), ("model.static", "other"), ("max_steps", 8)]
    )
    def test_a_setting_not_in_force(self, key: str, value: Any) -> None:
        record = _record()
        record.expected[key] = value
        assert _failed(record) == ["settings in force as configured"]

    def test_a_verdict_the_judge_did_not_state(self) -> None:
        record = _record()
        record.run_summary["verdict_reading"] = "fallback"
        assert _failed(record) == ["verdict stated by the judge"]

    def test_a_run_too_close_to_its_deadline(self) -> None:
        record = _record(elapsed_s=95.0, scenario_params={"job_timeout_s": 100})
        assert _failed(record) == ["finished inside its deadline"]

    def test_a_fault_scenario_where_no_fault_happened(self) -> None:
        assert _failed(_record(scenario="cut_at_cap")) == ["the cut_at_cap scenario happened"]

    def test_a_scenario_its_wire_cannot_carry_passes_as_normal(self) -> None:
        assert _failed(_record(scenario="prose_instead_of_tool")) == []

    def test_a_deadline_run_is_held_to_ending_cleanly_at_its_deadline(self) -> None:
        record = _record(
            scenario="deadline_hit",
            job_status="failed",
            job_error="the run passed its 12s deadline",
        )
        for entry in record.stub_log:
            entry["delay"] = 2.0
        record.scenario_params = {"slow_seconds": 2.0}
        record.elapsed_s = 13.0
        assert _failed(record) == []
        record.job_status = "completed"
        assert _failed(record) == ["job ended at its deadline as a failed job"]


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
        assert any("run 2 differs from run 1 in verdict" in d for d in compare(signatures))
