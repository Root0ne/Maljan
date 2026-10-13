"""The worker writes the signature scale the run noted into the stored run summary.

A run that read a sandbox report carries the key, with its provider's scale or
``None``; a run that read none carries no key, so its summary is shaped as
every summary before scales were recorded.
"""

from __future__ import annotations

from typing import Any

from app.worker.analysis_worker import _report_inputs
from maljan.core.config import Settings
from maljan.core.report_formats import SIGNATURE_SCALE_KEY

SCALE = {"name": "CAPE 1–3", "max": 3, "rungs": ["Low", "Medium", "High"]}


def _summary(scale_record: Any) -> dict[str, Any]:
    state = {"run_summary": {"final_decision": "Malware", "degradation_reasons": []}}
    _, summary = _report_inputs(
        state,
        core_settings=Settings(_env_file=None),
        override_keys=(),
        hash_mismatch_reason=None,
        scale_record=scale_record,
    )
    return summary


def test_a_recorded_scale_is_stored_on_the_run_summary() -> None:
    assert _summary({SIGNATURE_SCALE_KEY: SCALE})[SIGNATURE_SCALE_KEY] == SCALE


def test_a_run_whose_provider_declared_no_scale_stores_none() -> None:
    summary = _summary({SIGNATURE_SCALE_KEY: None})
    assert SIGNATURE_SCALE_KEY in summary and summary[SIGNATURE_SCALE_KEY] is None


def test_a_run_that_read_no_sandbox_report_stores_no_key() -> None:
    assert SIGNATURE_SCALE_KEY not in _summary({})
    assert SIGNATURE_SCALE_KEY not in _summary(None)


def test_the_settings_snapshot_records_the_report_formats_that_ran() -> None:
    from app.worker.analysis_worker import settings_snapshot

    fork = {"name": "cape2", "signature_scale": {"name": "Fork 1–5", "rungs": ["Low"] * 5}}
    settings = Settings.model_validate({"sandbox": {"report_formats": [fork]}})
    (recorded,) = settings_snapshot(settings)["sandbox.report_formats"]
    assert recorded["signature_scale"]["name"] == "Fork 1–5"
    assert recorded["reader"] == "cape2"
    assert recorded["task_id_paths"] == ["/info/id"]
    assert recorded["detect"]


def test_a_run_with_no_declared_formats_records_an_empty_list() -> None:
    from app.worker.analysis_worker import settings_snapshot

    assert settings_snapshot(Settings(_env_file=None))["sandbox.report_formats"] == []
