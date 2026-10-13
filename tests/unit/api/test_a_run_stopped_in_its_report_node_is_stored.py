"""A run stopped inside its report node is stored with its partial report and run summary.

The judge keeps its STIX bundle on the state as a Python dump, timestamps as
``datetime`` objects. Until the report node returns there is no extended export
on the state, so the stored ``stix_bundle`` column falls back to the judge's
bundle — and a JSONB column cannot hold a ``datetime``. The stop is tried at
every point of the report node: before the deterministic build, after it,
after the narrative round, with the composer part-way through its sections,
after the STIX export, and after the node returned. At each one the stored row
is JSON in every JSON column, as the database's driver writes it.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.dialects.postgresql import JSONB
from tests.integration._session_probe import SessionFactory, fake_job, fake_sample, rows_for

from app.worker.analysis_worker import _report_inputs, judge_bundle_record, keep_the_stopped_run
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.pipeline.stopped_run import partial_report
from maljan.reporting.models import MalwareReport

NOTE = "Stopped by the job timeout (60 s, core.job_timeout) 61 s into the run, node report."

STAMP = datetime(2026, 9, 22, 23, 30, tzinfo=UTC)


def _judge_bundle() -> dict[str, Any]:
    """The judge's bundle as the judge node keeps it: ``Bundle.model_dump()``."""
    from maljan.schemas.stix_models import Bundle

    return Bundle.model_validate(
        {
            "type": "bundle",
            "id": "bundle--6b1d3c1e-6f0a-4d51-9f3a-0c9d2f1e4a01",
            "objects": [
                {
                    "type": "malware",
                    "id": "malware--0f1e2d3c-4b5a-4968-8776-655443332211",
                    "spec_version": "2.1",
                    "created": STAMP,
                    "modified": STAMP,
                    "name": "sample",
                    "is_family": False,
                }
            ],
        }
    ).model_dump()


def _judged_state(**extra: Any) -> dict[str, Any]:
    return {
        "file_hash": "c" * 64,
        "file_name": "sample.exe",
        "run_started_at": time.time() - 61,
        "reports": {"static": "the static analyst's prose"},
        "isr_reports": {},
        "evidence_ledger": [],
        "discussion_history": [],
        "degradation_reasons": [],
        "stage_results": {},
        "final_decision": "Malware",
        "stix_output": _judge_bundle(),
        "run_summary": {
            "final_decision": "Malware",
            "degraded_mode": False,
            "degradation_reasons": [],
        },
        **extra,
    }


@pytest.fixture
def container() -> ServiceContainer:
    return ServiceContainer(Settings(_env_file=None), mock=True)


def _built(container: ServiceContainer) -> MalwareReport:
    """The deterministic report the report node holds once its builder has run."""
    report = MalwareReport.model_validate(partial_report(_judged_state(), container, note=NOTE))
    report.degradation_reasons = []
    report.executive_summary = ""
    return report


def _before_the_builder(container: ServiceContainer) -> dict[str, Any]:
    return {}


def _after_the_builder(container: ServiceContainer) -> dict[str, Any]:
    return {"report_in_progress": _built(container)}


def _after_the_narrative(container: ServiceContainer) -> dict[str, Any]:
    report = _built(container)
    report.executive_summary = "the narrative's summary"
    return {"report_in_progress": report}


def _inside_the_composer(container: ServiceContainer) -> dict[str, Any]:
    report = _built(container)
    report.executive_summary = "the narrative's summary"
    report.intro_background = "the introduction the composer wrote"
    return {"report_in_progress": report}


def _after_the_export(container: ServiceContainer) -> dict[str, Any]:
    report = _built(container)
    report.executive_summary = "the narrative's summary"
    report.stix_bundle_extended = {"type": "bundle", "id": "bundle--export", "objects": []}
    return {"report_in_progress": report}


def _after_the_node_returned(container: ServiceContainer) -> dict[str, Any]:
    report = _built(container)
    return {
        "built_report": _judged_state(
            malware_report=report.model_dump(mode="json"),
            stix_bundle_extended={"type": "bundle", "id": "bundle--export", "objects": []},
        )
    }


POINTS = {
    "before the deterministic build": _before_the_builder,
    "after the deterministic build": _after_the_builder,
    "after the narrative round": _after_the_narrative,
    "inside the composer": _inside_the_composer,
    "after the STIX export": _after_the_export,
    "after the node returned": _after_the_node_returned,
}


def _json_columns(obj: Any) -> dict[str, Any]:
    table = getattr(obj, "__table__", None)
    if table is None:
        return {}
    return {
        column.name: getattr(obj, column.key, None)
        for column in table.columns
        if isinstance(column.type, JSONB)
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("point", list(POINTS))
async def test_a_stop_inside_the_report_node_stores_every_json_column_as_json(
    point: str, container: ServiceContainer
) -> None:
    from app.models.report import AnalysisReport

    at = POINTS[point](container)
    if "report_in_progress" in at:
        container.report_in_progress = at["report_in_progress"]
    app = SimpleNamespace(
        container=container,
        built_report=at.get("built_report"),
        latest_state=_judged_state(),
    )
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))

    kept = await keep_the_stopped_run(
        factory,
        job_uuid=job.id,
        job_id=str(job.id),
        app=app,
        note=NOTE,
        transcript=[],
        core_settings=Settings(_env_file=None),
        override_keys=(),
        hash_mismatch_reason=None,
    )

    assert kept is True
    added = [obj for session in factory.sessions for obj in session.added]
    [report] = [obj for obj in added if isinstance(obj, AnalysisReport)]
    for obj in added:
        for name, value in _json_columns(obj).items():
            # The driver's own serialiser: strict ``json.dumps``.
            try:
                json.dumps(value)
            except TypeError as exc:
                pytest.fail(f"{type(obj).__name__}.{name} is not JSON: {exc}")
    assert report.incomplete_reason == NOTE
    assert report.malware_report["degradation_reasons"][-1] == NOTE
    assert report.run_summary["degradation_reasons"][-1] == NOTE
    assert report.verdict == "Malware"


class TestTheStoredBundle:
    def test_the_judges_bundle_is_stored_as_the_judges_record_holds_it(self) -> None:
        state = _judged_state()
        stix_bundle, _ = _report_inputs(
            state,
            core_settings=Settings(_env_file=None),
            override_keys=(),
            hash_mismatch_reason=None,
        )
        record = judge_bundle_record(_judged_state())
        assert record is not None
        assert stix_bundle == record["bundle"]
        (malware,) = stix_bundle["objects"]
        assert malware["created"].startswith("2026-09-22T23:30:00")
        json.dumps(stix_bundle)

    def test_the_export_is_stored_as_the_report_node_wrote_it(self) -> None:
        export = {"type": "bundle", "id": "bundle--export", "objects": [{"x_kept": 1}]}
        stix_bundle, _ = _report_inputs(
            _judged_state(stix_bundle_extended=dict(export)),
            core_settings=Settings(_env_file=None),
            override_keys=(),
            hash_mismatch_reason=None,
        )
        assert stix_bundle == {**export, "spec_version": "2.1"}
