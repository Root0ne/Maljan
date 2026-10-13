"""A job stopped before it finishes keeps its run summary and a partial report.

Three things stop a run part-way: the operator's ``core.job_timeout``, the
operator's cancel and the worker shutting down. Each stores what the run had
produced — the run summary as of the stop, with what every model call spent,
and the report the run built or was building, or the deterministic one from its
state — marked partial with the reason, and the job row says why it stopped.
With no job timeout set, which is the default, a job is never stopped by time,
however long it runs.

Nothing here reaches a service: the database is the tracking factory from
``_session_probe``, Redis is a stub, and the clock the job timeout is measured
on is moved rather than waited for.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from app.worker import analysis_worker as worker_module
from app.worker.analysis_worker import run_analysis
from tests.integration._session_probe import (
    JobRow,
    SessionFactory,
    fake_job,
    fake_sample,
    rows_for,
)
from tests.integration._session_probe import updates_to as _updates_to

EIGHT_HOURS = 28_800


@pytest.fixture(autouse=True)
def _isolated_runtime_settings(monkeypatch: pytest.MonkeyPatch):
    from app import runtime_config as rc
    from maljan.core.config import reset_settings_cache

    async def _mock_mode_allowed_override() -> dict[str, Any]:
        return {"api.mock_mode_allowed": True}

    monkeypatch.setattr(rc.runtime_config, "_overrides", _mock_mode_allowed_override)
    yield
    reset_settings_cache()


@pytest.fixture(autouse=True)
def _no_object_store(tmp_path: Path):
    from app import config as api_config

    api_config._settings = None
    with (
        patch("minio.Minio", side_effect=ConnectionError("no object store here")),
        patch.dict(
            "os.environ",
            {
                "MALJAN_MOCK_MODE": "true",
                "UPLOAD_TEMP_DIR": str(tmp_path / "tmp"),
                "SAMPLES_DIR": str(tmp_path / "samples"),
            },
            clear=False,
        ),
    ):
        yield
    api_config._settings = None


@pytest_asyncio.fixture
async def redis_stub() -> MagicMock:
    redis = MagicMock()
    redis.publish = AsyncMock()
    redis.aclose = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock()
    redis.delete = AsyncMock()
    return redis


class _Clock:
    """The job timeout's clock, moved by the test."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _overrides(values: dict[str, Any]) -> Any:
    async def _load(_db: Any) -> dict[str, Any]:
        return dict(values)

    return patch("app.services.settings_service.load_core_overrides", new=_load)


def _stored_reports(factory: SessionFactory) -> list[Any]:
    from app.models.report import AnalysisReport

    return [
        obj
        for session in factory.sessions
        for obj in session.added
        if isinstance(obj, AnalysisReport)
    ]


def _job_updates(factory: SessionFactory) -> list[dict[str, Any]]:
    return _updates_to(factory, "analysis_jobs")


def _state(app: Any, **extra: Any) -> dict[str, Any]:
    """What a run had after its first steps: a sample, an analyst's prose, no verdict."""
    import time

    return {
        "file_hash": "a" * 64,
        "file_name": "sample.exe",
        "run_started_at": time.time(),
        "reports": {"static": "the static analyst's prose"},
        "isr_reports": {},
        "evidence_ledger": [],
        "discussion_history": [],
        "degradation_reasons": [],
        "stage_results": {},
        **extra,
    }


def _spend(app: Any) -> None:
    """Two model calls the run made before it stopped, one of them unreported."""
    ledger = app.container.get_token_ledger()
    ledger.add({"input_tokens": 1200, "output_tokens": 300}, agent="static", model="m1")
    ledger.add(None, agent="reporter", model="m1", call="composer section")


async def _run(factory: SessionFactory, redis: MagicMock, job: Any) -> dict[str, Any]:
    return await run_analysis({"redis": redis, "db_session": factory}, str(job.id))


@pytest.mark.asyncio
async def test_the_job_timeout_stops_the_run_and_keeps_what_it_produced(
    redis_stub: MagicMock,
) -> None:
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))
    clock = _Clock()

    async def _runs_past_its_limit(self: Any, **_: Any) -> dict[str, Any]:
        self.latest_state = _state(self)
        _spend(self)
        clock.now = EIGHT_HOURS + 1
        await asyncio.sleep(3600)
        return {}

    with (
        _overrides({"job_timeout": EIGHT_HOURS}),
        patch("maljan.app.MaljanApp.arun", new=_runs_past_its_limit),
        patch.object(worker_module, "CANCEL_POLL_SECONDS", 0.01),
        patch.object(worker_module, "job_clock", clock),
    ):
        result = await _run(factory, redis_stub, job)

    assert result["status"] == "failed"
    note = result["error"]
    # Measured from the job's start on the timeout's own clock, so the number
    # the note gives is the number the limit was compared with.
    assert note.startswith(
        "Stopped by the job timeout (28800 s, core.job_timeout) 28801 s into the run, "
    )
    assert "The report kept is partial" in note

    failed = [u for u in _job_updates(factory) if u.get("status") == "failed"]
    assert len(failed) == 1
    assert failed[0]["error_message"] == note

    [report] = _stored_reports(factory)
    assert report.incomplete_reason == note
    # No judge ran: no verdict is claimed, and the report says so.
    assert report.verdict == "Unknown"
    assert report.overall_confidence is None
    assert report.malware_report["degraded_mode"] is True
    reasons = report.malware_report["degradation_reasons"]
    assert reasons[-1] == note
    assert any(r.startswith("verdict not assessed: the run was stopped") for r in reasons)
    assert report.malware_report["executive_summary"] == ""
    assert report.agent_reports == {"static": "the static analyst's prose"}
    # The run summary is built from the state and carries what was spent.
    summary = report.run_summary
    assert summary["degradation_reasons"][-1] == note
    assert summary["degraded_mode"] is True
    assert summary["final_decision"] == "Unknown"
    assert summary["tokens"]["llm_calls"] == 2
    assert summary["tokens"]["input_tokens"] == 1200
    assert summary["tokens"]["unreported_calls"] == 1
    assert summary["tokens"]["per_agent"]["static"]["output_tokens"] == 300


@pytest.mark.asyncio
async def test_a_report_stopped_in_the_making_keeps_its_written_sections(
    redis_stub: MagicMock,
) -> None:
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))
    clock = _Clock()

    async def _stops_inside_the_composer(self: Any, **_: Any) -> dict[str, Any]:
        self.latest_state = _state(
            self,
            final_decision="Malware",
            run_summary={"degraded_mode": False, "degradation_reasons": [], "tokens": None},
        )
        self.container.report_in_progress = {
            "verdict": "Malware",
            "intro_background": "the introduction the composer wrote",
            "executive_summary": "the narrative's summary",
            "degradation_reasons": [],
        }
        _spend(self)
        clock.now = EIGHT_HOURS + 1
        await asyncio.sleep(3600)
        return {}

    with (
        _overrides({"job_timeout": EIGHT_HOURS}),
        patch("maljan.app.MaljanApp.arun", new=_stops_inside_the_composer),
        patch.object(worker_module, "CANCEL_POLL_SECONDS", 0.01),
        patch.object(worker_module, "job_clock", clock),
    ):
        result = await _run(factory, redis_stub, job)

    note = result["error"]
    [report] = _stored_reports(factory)
    assert report.verdict == "Malware"
    assert report.malware_report["intro_background"] == "the introduction the composer wrote"
    assert report.malware_report["degradation_reasons"] == [note]
    # The judge's summary, with the calls made after it counted.
    assert report.run_summary["tokens"]["llm_calls"] == 2
    assert report.run_summary["degradation_reasons"] == [note]


@pytest.mark.asyncio
async def test_the_operators_cancel_keeps_what_the_run_produced(redis_stub: MagicMock) -> None:
    job = fake_job()
    row = JobRow(job)
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)), on_execute=row)

    async def _cancelled_by_the_api(self: Any, **_: Any) -> dict[str, Any]:
        self.latest_state = _state(self)
        _spend(self)
        # What ``AnalysisService.cancel_job`` does: the row turns
        # ``cancelled`` first, then the flag the worker polls is set.
        row.row.status = "cancelled"
        redis_stub.get = AsyncMock(return_value=b"1")
        await asyncio.sleep(3600)
        return {}

    with (
        patch("maljan.app.MaljanApp.arun", new=_cancelled_by_the_api),
        patch.object(worker_module, "CANCEL_POLL_SECONDS", 0.01),
    ):
        result = await _run(factory, redis_stub, job)

    assert result["status"] == "cancelled"
    assert row.row.status == "cancelled"
    assert row.row.error_message.startswith("Cancelled by the operator ")
    [report] = _stored_reports(factory)
    assert report.incomplete_reason == row.row.error_message
    assert report.run_summary["tokens"]["llm_calls"] == 2
    assert report.malware_report["degradation_reasons"][-1] == row.row.error_message


@pytest.mark.asyncio
async def test_a_worker_shutdown_keeps_what_the_run_produced(redis_stub: MagicMock) -> None:
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))
    running = asyncio.Event()

    async def _long_run(self: Any, **_: Any) -> dict[str, Any]:
        self.latest_state = _state(self)
        _spend(self)
        running.set()
        await asyncio.sleep(3600)
        return {}

    with patch("maljan.app.MaljanApp.arun", new=_long_run):
        task = asyncio.create_task(_run(factory, redis_stub, job))
        await running.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    [failed] = [u for u in _job_updates(factory) if u.get("status") == "failed"]
    assert failed["error_message"].startswith("Stopped because the worker running it shut down ")
    [report] = _stored_reports(factory)
    assert report.incomplete_reason == failed["error_message"]
    assert report.run_summary["tokens"]["llm_calls"] == 2


@pytest.mark.asyncio
async def test_with_no_job_timeout_a_run_longer_than_eight_hours_is_not_cut(
    redis_stub: MagicMock,
) -> None:
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))
    clock = _Clock()

    async def _runs_nine_hours(self: Any, **_: Any) -> dict[str, Any]:
        # Nine hours pass on the job's clock while the heartbeat polls.
        clock.now = 9 * 3600
        await asyncio.sleep(0.2)
        return {
            "final_decision": "Malware",
            "judge_report": "the judge answered",
            "malware_report": {"verdict": "Malware", "degradation_reasons": []},
            "isr_reports": {},
            "evidence_ledger": [],
        }

    with (
        _overrides({}),
        patch("maljan.app.MaljanApp.arun", new=_runs_nine_hours),
        patch.object(worker_module, "CANCEL_POLL_SECONDS", 0.01),
        patch.object(worker_module, "job_clock", clock),
    ):
        result = await _run(factory, redis_stub, job)

    assert result["status"] == "completed"
    assert [u["status"] for u in _job_updates(factory)] == ["running", "completed"]
    [report] = _stored_reports(factory)
    assert report.incomplete_reason is None


class TestTheCancelReasonReachesTheRow:
    """The reason is written whoever turned the row ``cancelled`` first, and never over another."""

    async def _mark(self, status: str, message: str | None = None) -> Any:
        job = fake_job(status=status)
        job.error_message = message
        row = JobRow(job)
        factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)), on_execute=row)
        await worker_module.mark_job_cancelled(factory, job.id, reason="the reason")
        return row.row

    @pytest.mark.asyncio
    async def test_a_row_the_api_already_cancelled_gets_the_reason(self) -> None:
        row = await self._mark("cancelled")
        assert (row.status, row.error_message) == ("cancelled", "the reason")

    @pytest.mark.asyncio
    async def test_a_running_row_is_cancelled_with_the_reason(self) -> None:
        row = await self._mark("running")
        assert (row.status, row.error_message) == ("cancelled", "the reason")

    @pytest.mark.asyncio
    async def test_a_message_already_on_the_row_is_kept(self) -> None:
        row = await self._mark("cancelled", "written before")
        assert row.error_message == "written before"

    @pytest.mark.asyncio
    async def test_a_finished_row_is_left_alone(self) -> None:
        row = await self._mark("completed")
        assert (row.status, row.error_message) == ("completed", None)
