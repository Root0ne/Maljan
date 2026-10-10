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
from scripts.rehearsal.checklist import _price_rows as price_rows
from scripts.rehearsal.checklist import _stub_cost as stub_cost

MODEL = "deepseek-v4-flash"
NOW = time.time()
WINDOW = 1_000_000


def _cap_from(window: int, source: str) -> str:
    return (
        "llm.expert_max_tokens is 0, so derived: 8192 tokens — the smallest of a quarter of "
        f"the model's {window}-token context window ({source}), the documented fallback of 8192"
    )


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


def _usage_event(entry: dict[str, Any], **extra: Any) -> dict[str, Any]:
    """The per-call usage record the product writes for one answered stub call."""
    data = {
        "agent": entry["role"],
        "model": entry["model"],
        "call": "loop turn",
        "reported": True,
        "input_tokens": entry["input_tokens"],
        "output_tokens": entry["output_tokens"],
        "cached_input_tokens": entry["cache_read_tokens"],
        "priced_usd": stub_cost(entry, price_rows()),
        "price_source": "vendored table",
    }
    data.update(extra)
    return {"type": "model_usage", "data": data}


def _usage_events(log: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_usage_event(e) for e in log if e.get("status") == 200]


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
            "truncation": {
                "context_window": {
                    "tokens": WINDOW,
                    "source": "declared",
                    "detail": "the window this deployment's settings name for the endpoint",
                }
            },
            "generation": {
                "output_caps": {
                    "static": {"tokens": 8192, "derivation": _cap_from(WINDOW, "declared")},
                    "judge": {"tokens": 9000, "derivation": "9000 tokens — set to 9000"},
                }
            },
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
            *_usage_events(log),
        ],
        stub_log=log,
        expected={"model.static": MODEL, "effort.static": "high", "max_steps": 40},
        required_stages={"analysis": ["static"], "report": ["reporter"]},
        empty_evidence_sections=[],
        probe={"ok": True, "detail": "answered"},
        scenario_params={"served_windows": {MODEL: WINDOW}},
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
        record.events = [
            *(e for e in record.events if e.get("type") != "model_usage"),
            *_usage_events(record.stub_log),
        ]
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
        record.malware_report["technical_analysis"].pop("ransom_note")
        entry = next(e for e in record.stub_log if e.get("section") == "ransom_note")
        entry.update(content=False, deliberately_empty=True)
        assert _failed(record) == []
        entry["deliberately_empty"] = False
        assert _failed(record) == ["every report section written or accounted for"]

    def test_a_section_the_sample_fills_cannot_be_left_empty_on_purpose(self) -> None:
        record = _record()
        record.malware_report["technical_analysis"].pop("cli_flags")
        entry = next(e for e in record.stub_log if e.get("section") == "cli_flags")
        entry.update(content=False, deliberately_empty=True)
        assert section_statuses(record)["cli_flags"].startswith("LOST: left empty")
        assert _failed(record) == ["every report section written or accounted for"]

    def test_the_reviewer_s_all_excused_record_fails(self) -> None:
        record = _record()
        record.malware_report["technical_analysis"] = {}
        record.malware_report["intro_background"] = ""
        record.malware_report["c2_channels"] = []
        record.stub_log = [e for e in record.stub_log if e["role"] != "composer"]
        record.empty_evidence_sections = list(COMPOSED)
        statuses = section_statuses(record)
        assert sum(s.startswith("not asked") for s in statuses.values()) == 4
        assert "every report section written or accounted for" in _failed(record)

    def test_a_section_the_report_should_write_cannot_be_excused_as_evidence_empty(self) -> None:
        record = _record()
        record.malware_report["technical_analysis"].pop("payloads")
        record.stub_log = [e for e in record.stub_log if e.get("section") != "payloads"]
        record.empty_evidence_sections = ["payloads"]
        assert section_statuses(record)["payloads"].startswith("LOST: excused as evidence-empty")

    def test_a_degradation_marks_a_section_not_written(self) -> None:
        record = _record()
        record.malware_report["technical_analysis"].pop("payloads")
        record.run_summary["degradation_reasons"] = [
            "report section 'payloads' is not written: cut"
        ]
        assert section_statuses(record)["payloads"] == "marked not written"
        assert "every report section written or accounted for" in _failed(record)
        record.scenario = "cut_at_cap"
        assert "every report section written or accounted for" not in _failed(record)

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

    def test_an_answered_call_with_no_usage_record(self) -> None:
        record = _record()
        first = next(e for e in record.events if e.get("type") == "model_usage")
        record.events.remove(first)
        (check,) = [c for c in check_run(record) if not c.ok]
        assert check.name == "tokens and spend as the provider reported them"
        assert "per-call usage record(s), the model answered" in check.detail
        assert "no usage record carries its reported usage" in check.detail

    def test_a_usage_record_charged_apart_from_its_usage(self) -> None:
        record = _record()
        usage = next(e for e in record.events if e.get("type") == "model_usage")
        usage["data"]["priced_usd"] *= 1.5
        assert _failed(record) == ["tokens and spend as the provider reported them"]

    def test_a_usage_record_with_no_charge(self) -> None:
        record = _record()
        usage = next(e for e in record.events if e.get("type") == "model_usage")
        del usage["data"]["priced_usd"]
        assert _failed(record) == ["tokens and spend as the provider reported them"]

    def test_an_answered_call_charged_by_estimate(self) -> None:
        record = _record()
        usage = next(e for e in record.events if e.get("type") == "model_usage")
        usage["data"].update(estimated_usd=0.0001, estimated_part="output")
        assert _failed(record) == ["tokens and spend as the provider reported them"]

    def test_a_usage_record_no_call_accounts_for(self) -> None:
        record = _record()
        record.events.append(_usage_event(_log(99, "judge", input_tokens=7, output_tokens=3)))
        assert _failed(record) == ["tokens and spend as the provider reported them"]

    def test_a_retry_record_is_not_a_call(self) -> None:
        record = _record()
        record.events.append(
            {"type": "model_usage", "data": {"call": "retry", "reported": False, "reason": "x"}}
        )
        assert _failed(record) == []

    def test_usage_totals_that_are_not_the_records(self) -> None:
        record = _record()
        spent = record.run_summary["spend"]["spent_usd"]
        calls = len(record.stub_log)
        record.usage_totals = {"calls": calls, "spend": {"spent_usd": spent, "repriced_calls": 0}}
        assert _failed(record) == []
        record.usage_totals["spend"]["spent_usd"] = spent * 2
        assert _failed(record) == ["tokens and spend as the provider reported them"]
        record.usage_totals = {"calls": calls - 1, "spend": {"spent_usd": spent}}
        assert _failed(record) == ["tokens and spend as the provider reported them"]
        record.usage_totals = {"calls": calls, "spend": {"spent_usd": spent, "repriced_calls": 2}}
        assert _failed(record) == ["tokens and spend as the provider reported them"]
        record.usage_totals = {"error": "HTTPStatusError: 404"}
        assert _failed(record) == ["tokens and spend as the provider reported them"]

    def test_a_run_summary_with_no_spend(self) -> None:
        record = _record()
        del record.run_summary["spend"]
        assert _failed(record) == ["tokens and spend as the provider reported them"]

    def test_stages_not_known_from_the_settings(self) -> None:
        assert "every stage of the profile ran" in _failed(_record(required_stages={}))

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
        record = _record(
            elapsed_s=95.0,
            scenario_params={"job_timeout_s": 100, "served_windows": {MODEL: WINDOW}},
        )
        assert _failed(record) == ["finished inside its deadline"]

    @pytest.mark.parametrize("scenario", ["schema_break", "empty_answer", "server_error_once"])
    def test_a_section_marked_where_the_fault_cannot_reach_it(self, scenario: str) -> None:
        record = _record(scenario=scenario)
        record.malware_report["technical_analysis"].pop("payloads")
        record.run_summary["degradation_reasons"] = [
            "report section 'payloads' is not written: its answer broke the schema"
        ]
        failed = {c.name: c.detail for c in check_run(record) if not c.ok}
        detail = failed["every report section written or accounted for"]
        assert detail.startswith(
            f"payloads (marked not written, which the {scenario} fault cannot cause)"
        )

    def test_a_cut_at_the_cap_may_mark_every_section_it_reaches(self) -> None:
        from scripts.rehearsal.checklist import FAULT_REACHES, WRITTEN_SECTIONS

        assert FAULT_REACHES["cut_at_cap"] >= WRITTEN_SECTIONS
        assert "schema_break" not in FAULT_REACHES

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
        record.scenario_params.update({"slow_seconds": 2.0})
        record.elapsed_s = 13.0
        assert _failed(record) == []
        record.job_status = "completed"
        assert _failed(record) == ["job ended at its deadline as a failed job"]

    def _aimed_at(self, stage: str, roles: list[str]) -> RunRecord:
        record = _record(
            scenario="deadline_hit",
            job_status="failed",
            job_error="the run passed its 12s deadline",
        )
        record.scenario_params = {
            "slow_seconds": 3600.0,
            "deadline_in": stage,
            "slow_roles": roles,
        }
        for entry in record.stub_log:
            entry["delay"] = 3600.0 if entry.get("role") in roles else 0.0
        last = next(e for e in reversed(record.stub_log) if e.get("role") in roles)
        record.stub_log.remove(last)
        record.stub_log.append({**last, "waiting": True})
        return record

    def test_a_deadline_aimed_at_a_stage_landed_there(self) -> None:
        record = self._aimed_at("report", ["composer", "narrative"])
        assert _failed(record) == []

    def test_a_deadline_aimed_at_a_stage_the_run_never_reached(self) -> None:
        record = self._aimed_at("report", ["composer", "narrative"])
        held = ("composer", "narrative")
        record.stub_log = [e for e in record.stub_log if e.get("role") not in held]
        failed = {c.name: c.detail for c in check_run(record) if not c.ok}
        assert (
            "the run never reached the report stage" in failed["the deadline_hit scenario happened"]
        )

    def test_a_deadline_aimed_at_a_stage_that_landed_after_it(self) -> None:
        record = self._aimed_at("analysis", ["analyst"])
        judge = next(e for e in record.stub_log if e.get("role") == "judge")
        record.stub_log.append({**judge, "delay": 0.0})
        failed = {c.name: c.detail for c in check_run(record) if not c.ok}
        assert "the last call was judge" in failed["the deadline_hit scenario happened"]

    def _stopped_by_the_worker(self) -> RunRecord:
        note = "Stopped by the job timeout (20 s, core.job_timeout) 21 s into the run"
        record = _record(scenario="deadline_hit", job_status="failed", job_error=note)
        for entry in record.stub_log:
            entry["delay"] = 2.0
        record.scenario_params = {
            "slow_seconds": 2.0,
            "job_timeout_s": 20,
            "deadline_by": "core.job_timeout",
        }
        record.elapsed_s = 24.0
        record.incomplete_reason = note
        return record

    def test_a_job_the_worker_s_job_timeout_stopped_keeps_its_run_summary_and_report(
        self,
    ) -> None:
        assert _failed(self._stopped_by_the_worker()) == []

    @pytest.mark.parametrize(
        ("field", "value"),
        [("incomplete_reason", ""), ("run_summary", {}), ("markdown", "")],
    )
    def test_a_stopped_job_that_kept_nothing(self, field: str, value: Any) -> None:
        record = self._stopped_by_the_worker()
        setattr(record, field, value)
        assert _failed(record) == ["the stopped run kept its run summary and a partial report"]

    def test_a_stopped_job_that_kept_no_spend_or_usage(self) -> None:
        record = self._stopped_by_the_worker()
        record.run_summary = {
            k: v for k, v in record.run_summary.items() if k not in ("tokens", "spend")
        }
        record.events = [e for e in record.events if e.get("type") != "model_usage"]
        kept = check_run(record)
        assert [c.detail for c in kept if not c.ok] == [
            "no spend was kept; no token totals were kept for "
            f"{sum(1 for e in record.stub_log if e.get('status') == 200)} answered call(s)"
        ]
        answered = sum(1 for e in record.stub_log if e.get("status") == 200)
        record.events.append({"type": "model_usage", "data": {"output_tokens": 10}})
        assert answered > 1
        assert _failed(record) == ["the stopped run kept its run summary and a partial report"]
        record.events += [
            {"type": "model_usage", "data": {"output_tokens": 10}} for _ in range(answered - 1)
        ]
        assert _failed(record) == []

    def test_a_stopped_job_with_no_answered_call_keeps_a_spend_and_no_token_totals(
        self,
    ) -> None:
        record = self._stopped_by_the_worker()
        for entry in record.stub_log:
            entry["waiting"] = True
        record.run_summary["tokens"] = None
        record.run_summary["spend"] = {"spent_usd": 0.0}
        record.events = [e for e in record.events if e.get("type") != "model_usage"]
        assert _failed(record) == []

    def test_a_job_stopped_by_anything_but_its_job_timeout(self) -> None:
        record = self._stopped_by_the_worker()
        record.job_error = "Cancelled by the operator"
        assert _failed(record) == ["job stopped by core.job_timeout as a failed job"]


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


class TestABrokenStreamIsChargedItsReportedPrompt:
    """A stream broken after ``message_start`` is charged its prompt, the output estimated."""

    @staticmethod
    def _broken(estimated_output: float = 0.00002, **record_extra: Any) -> RunRecord:
        record = _record(scenario="stream_error", api="anthropic")
        broken = _log(
            len(record.stub_log) + 1,
            "analyst",
            api="anthropic",
            stream=True,
            fault="stream_error",
            stream_error=True,
            input_tokens=4000,
            output_tokens=300,
            cache_read_tokens=1000,
        )
        record.stub_log.append(broken)
        prompt = stub_cost(broken, price_rows(), prompt_only=True)
        data = {
            "agent": "static",
            "model": MODEL,
            "call": "failed attempt",
            "reported": True,
            "input_tokens": 4000,
            "cached_input_tokens": 1000,
            "output_tokens": 0,
            "priced_usd": prompt + estimated_output,
            "price_source": "vendored table",
            "estimated_usd": estimated_output,
            "estimated_part": "output",
            "estimated": {"input_tokens": 0, "output_tokens": 12, "source": "streamed"},
        }
        data.update(record_extra)
        record.events.append({"type": "model_usage", "data": data})
        usd, _ = priced_usage(record)
        record.run_summary["spend"] = {
            "spent_usd": round(usd + float(data["estimated_usd"]), 6),
            "estimated_usd": round(float(data["estimated_usd"]), 6),
        }
        return record

    @staticmethod
    def _detail(record: RunRecord) -> str:
        (check,) = [c for c in check_run(record) if c.name.startswith("tokens and spend")]
        return check.detail if not check.ok else ""

    def test_its_prompt_priced_and_its_output_estimated_passes(self) -> None:
        record = self._broken()
        assert "tokens and spend as the provider reported them" not in _failed(record)
        # The estimate may be any size: it is the output the client never received.
        record = self._broken(estimated_output=0.004)
        assert "tokens and spend as the provider reported them" not in _failed(record)

    def test_a_prompt_charged_apart_from_its_reported_usage_fails(self) -> None:
        record = self._broken(input_tokens=4000)
        data = record.events[-1]["data"]
        data["priced_usd"] += 0.001
        record.run_summary["spend"]["spent_usd"] += 0.001
        assert "beyond its estimate" in self._detail(record)

    def test_a_whole_estimate_fails(self) -> None:
        record = self._broken(estimated_part="input and output")
        assert "only 'output' may be estimated" in self._detail(record)

    def test_a_broken_stream_left_uncharged_fails(self) -> None:
        record = self._broken()
        record.events.pop()
        record.run_summary["spend"]["spent_usd"] = round(priced_usage(record)[0], 6)
        record.run_summary["spend"].pop("estimated_usd")
        assert "0 failed-attempt record(s), 1 broken stream(s)" in self._detail(record)

    def test_the_summary_s_estimate_must_be_the_records(self) -> None:
        record = self._broken()
        record.run_summary["spend"]["estimated_usd"] = 0.0
        assert "the records' output estimates" in self._detail(record)

    def test_an_openai_broken_stream_reports_nothing_and_is_owed_nothing(self) -> None:
        record = self._broken()
        record.stub_log[-1]["api"] = "openai"
        record.events.pop()
        record.run_summary["spend"] = {"spent_usd": round(priced_usage(record)[0], 6)}
        assert "tokens and spend as the provider reported them" not in _failed(record)


class TestTheWindowInForce:
    """The window the product sized each model with must be the one the stub serves."""

    NAME = "window in force as the provider serves it"

    def _detail(self, record: RunRecord) -> str:
        (check,) = [c for c in check_run(record) if c.name == self.NAME]
        return "" if check.ok else check.detail

    def test_the_served_window_passes(self) -> None:
        assert self._detail(_record()) == ""

    def test_the_fallback_window_fails(self) -> None:
        record = _record()
        record.run_summary["truncation"]["context_window"] = {
            "tokens": 8192,
            "source": "fallback",
            "detail": "no endpoint reported a window and the model is not in the table",
        }
        record.run_summary["generation"]["output_caps"]["static"]["derivation"] = (
            "llm.expert_max_tokens is 0, so derived: 8192 tokens — the documented fallback: "
            "no window was learned for the model"
        )
        assert _failed(record) == [self.NAME]
        assert self._detail(record) == (
            "the analysts' window is the 8192-token fallback (no endpoint reported a window and "
            f"the model is not in the table); the stub serves {MODEL} {WINDOW}; output caps "
            "derived from no window: static"
        )

    def test_a_window_other_than_the_served_one_fails(self) -> None:
        record = _record()
        record.run_summary["truncation"]["context_window"]["tokens"] = 200_000
        assert "the analysts' window is 200000 tokens (declared)" in self._detail(record)
        record = _record()
        record.run_summary["generation"]["output_caps"]["static"]["derivation"] = _cap_from(
            200_000, "probed"
        )
        assert "static's output cap was derived from a 200000-token window" in self._detail(record)

    def test_nothing_to_compare_fails(self) -> None:
        record = _record()
        record.scenario_params = {}
        assert self._detail(record) == "the windows the stub served were not recorded"

    def test_no_window_recorded_passes_only_under_the_operator_s_own_cap(self) -> None:
        record = _record()
        record.run_summary["truncation"]["context_window"] = {}
        assert "records no window" in self._detail(record)
        record.expected["settings.preprocessing.max_tool_output_chars"] = 6000
        assert self._detail(record) == ""
