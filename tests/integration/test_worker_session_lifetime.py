"""The worker holds no transaction while the models run, and fails loudly.

Two properties of ``run_analysis``, both learned from one live run: a session
left open for the length of an analysis blocked a migration and every read
behind it, and a job whose session was killed under it published an ``error``
event and left its row saying ``running`` for ever.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from app.worker.analysis_worker import run_analysis
from tests.integration._session_probe import (
    SessionFactory,
    fake_job,
    fake_sample,
    rows_for,
    updates_to,
)


@pytest.fixture(autouse=True)
def _isolated_runtime_settings(monkeypatch: pytest.MonkeyPatch):
    """Keep these tests off the real runtime-settings singletons."""
    from app import runtime_config as rc
    from maljan.core.config import reset_settings_cache

    async def _mock_mode_allowed_override() -> dict[str, Any]:
        return {"api.mock_mode_allowed": True}

    monkeypatch.setattr(rc.runtime_config, "_overrides", _mock_mode_allowed_override)
    yield
    reset_settings_cache()


@pytest_asyncio.fixture
async def redis_stub() -> MagicMock:
    redis = MagicMock()
    redis.publish = AsyncMock()
    redis.aclose = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    return redis


def _pipeline_result() -> dict[str, Any]:
    """A run that produced a verdict and a report, and nothing else."""
    return {
        "final_decision": "Malware",
        "judge_report": "the judge answered",
        "malware_report": {"summary": {"verdict": "Malware"}},
        "isr_reports": {},
        "evidence_ledger": [],
    }


def _mock_mode():
    return patch.dict("os.environ", {"MALJAN_MOCK_MODE": "true"}, clear=False)


@pytest.mark.asyncio
async def test_no_transaction_is_open_while_the_pipeline_runs(redis_stub: MagicMock) -> None:
    """The defect the live run found: a backend idle in transaction for 13 min.

    The pipeline stands in for the models. While it is running, no session
    this task made may be holding a transaction — that is exactly what
    ``pg_stat_activity`` reported as ``idle in transaction`` with the
    ``runtime_settings`` SELECT as its last statement.
    """
    job = fake_job()
    sample = fake_sample(job.sample_id)
    factory = SessionFactory(rows_for(job, sample))
    open_during_the_run: list[int] = []

    async def _slow_pipeline(*args: Any, **kwargs: Any) -> dict[str, Any]:
        for _ in range(5):
            await asyncio.sleep(0.01)
            open_during_the_run.append(len(factory.open_transactions))
        return _pipeline_result()

    from app import config as api_config

    api_config._settings = None
    with (
        _mock_mode(),
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(side_effect=_slow_pipeline)),
    ):
        result = await run_analysis({"redis": redis_stub, "db_session": factory}, str(job.id))
    api_config._settings = None

    assert result["status"] == "completed"
    assert open_during_the_run and max(open_during_the_run) == 0
    # And every session this run opened was closed again.
    assert [s for s in factory.sessions if s.open] == []


@pytest.mark.asyncio
async def test_the_settings_read_is_committed_before_the_pipeline(
    redis_stub: MagicMock,
) -> None:
    """The session that read the settings ends before the models start.

    The first session does the reads and the status change and then closes;
    the report is written through a different one, opened when the pipeline
    has already returned.
    """
    job = fake_job()
    sample = fake_sample(job.sample_id)
    factory = SessionFactory(rows_for(job, sample))
    sessions_at_pipeline_time: list[int] = []

    async def _pipeline(*args: Any, **kwargs: Any) -> dict[str, Any]:
        sessions_at_pipeline_time.append(len(factory.sessions))
        assert [s for s in factory.sessions if s.open] == []
        return _pipeline_result()

    from app import config as api_config

    api_config._settings = None
    with (
        _mock_mode(),
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(side_effect=_pipeline)),
    ):
        result = await run_analysis({"redis": redis_stub, "db_session": factory}, str(job.id))
    api_config._settings = None

    assert result["status"] == "completed"
    # One session for the reads and the status change, and at least one more
    # for the writes at the end.
    assert sessions_at_pipeline_time == [1]
    assert len(factory.sessions) > 1
    first = factory.sessions[0]
    assert first.commits >= 1 and not first.open


@pytest.mark.asyncio
async def test_the_job_is_marked_failed_through_a_fresh_session(
    redis_stub: MagicMock,
) -> None:
    """A session that has gone invalid mid-run must not cost the job row.

    Job ``892659bc`` ended exactly here: the backend was terminated under the
    worker, every statement on that session then raised
    ``PendingRollbackError``, and the row stayed ``running`` with no error and
    no ``completed_at`` although the worker had published its ``error`` event.
    """

    class PendingRollbackError(Exception):
        """Stands in for the SQLAlchemy error a killed backend produces."""

    job = fake_job()
    sample = fake_sample(job.sample_id)
    killed_from: dict[str, int] = {"index": -1}

    def _refuse_on_the_killed_backend(record: Any, statement: Any) -> None:
        # The session the run writes its result through is the one whose
        # backend was terminated: every statement on it raises from then on.
        # A session opened afterwards takes another connection and works,
        # which is the whole point of not reusing the job's own.
        if killed_from["index"] >= 0 and record.index == killed_from["index"]:
            raise PendingRollbackError("Can't reconnect until invalid transaction is rolled back")

    factory = SessionFactory(rows_for(job, sample), on_execute=_refuse_on_the_killed_backend)

    async def _pipeline(*args: Any, **kwargs: Any) -> dict[str, Any]:
        # The next session this run opens is the persistence one.
        killed_from["index"] = len(factory.sessions)
        return _pipeline_result()

    from app import config as api_config

    api_config._settings = None
    with (
        _mock_mode(),
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(side_effect=_pipeline)),
    ):
        result = await run_analysis({"redis": redis_stub, "db_session": factory}, str(job.id))
    api_config._settings = None

    assert result["status"] == "failed"
    failures = [u for u in updates_to(factory, "analysis_jobs") if u.get("status") == "failed"]
    assert failures, "the job row was never marked failed"
    recorded = failures[-1]
    assert recorded["completed_at"] is not None
    assert "PendingRollbackError" in recorded["error_message"]
    assert "error id" in recorded["error_message"]
    # The reason carries the class and the id, never the exception's text.
    assert "reconnect" not in recorded["error_message"]
    # The failure was written by a session opened after the invalid one.
    assert len(factory.sessions) >= 3


@pytest.mark.asyncio
async def test_a_failure_names_the_class_and_an_error_id_only(
    redis_stub: MagicMock,
) -> None:
    """``job.error_message`` is an API field, so it carries no exception text."""
    job = fake_job()
    sample = fake_sample(job.sample_id)
    factory = SessionFactory(rows_for(job, sample))

    from app import config as api_config

    api_config._settings = None
    with (
        _mock_mode(),
        patch(
            "maljan.app.MaljanApp.arun",
            new=AsyncMock(side_effect=FileNotFoundError("/home/someone/samples/secret.exe")),
        ),
    ):
        result = await run_analysis({"redis": redis_stub, "db_session": factory}, str(job.id))
    api_config._settings = None

    assert result["status"] == "failed"
    failures = [u for u in updates_to(factory, "analysis_jobs") if u.get("status") == "failed"]
    assert len(failures) == 1
    reason = failures[0]["error_message"]
    assert reason.startswith("FileNotFoundError (error id ")
    assert "/home/someone" not in reason
    assert "/home/someone" not in result["error"]
    # The event the console sees carries the id and nothing else.
    published = [
        call.args for call in redis_stub.publish.call_args_list if "error" in str(call.args)
    ]
    assert published
    assert "/home/someone" not in str(published)


@pytest.mark.asyncio
async def test_a_cancelled_run_still_flushes_its_feed(redis_stub: MagicMock) -> None:
    """Cancellation semantics are unchanged: the feed is written on the way out.

    The task's one ``finally`` is what writes the last queued lines of a run
    that stopped part-way, and a cancellation is the case it exists for.
    """
    job = fake_job()
    sample = fake_sample(job.sample_id)
    factory = SessionFactory(rows_for(job, sample))
    flushed: list[str] = []

    from app.worker import analysis_worker as worker_module

    real_stop = worker_module._stop_event_feed

    async def _record_stop(job_id: str) -> None:
        flushed.append(job_id)
        await real_stop(job_id)

    async def _cancelled_pipeline(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise asyncio.CancelledError

    from app import config as api_config

    api_config._settings = None
    with (
        _mock_mode(),
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(side_effect=_cancelled_pipeline)),
        patch.object(worker_module, "_stop_event_feed", _record_stop),
        pytest.raises(asyncio.CancelledError),
    ):
        await run_analysis({"redis": redis_stub, "db_session": factory}, str(job.id))
    api_config._settings = None

    assert flushed == [str(job.id)]
    # A cancellation is not a failure: nothing marked the row failed.
    assert [u for u in updates_to(factory, "analysis_jobs") if u.get("status") == "failed"] == []


@pytest.mark.asyncio
async def test_the_operators_cancellation_writes_the_cancelled_row(
    redis_stub: MagicMock,
) -> None:
    """The user-cancel branch marks the row ``cancelled`` on a session of its own."""
    job = fake_job()
    sample = fake_sample(job.sample_id)
    factory = SessionFactory(rows_for(job, sample))

    async def _wait_to_be_cancelled(*args: Any, **kwargs: Any) -> dict[str, Any]:
        await asyncio.sleep(3600)
        return _pipeline_result()

    from app.worker import analysis_worker as worker_module

    # The heartbeat is the cancellation poller; the flag it reads is already
    # set, so the only thing to shorten is the wait between polls.
    redis_stub.get = AsyncMock(return_value=b"1")

    from app import config as api_config

    api_config._settings = None
    with (
        _mock_mode(),
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(side_effect=_wait_to_be_cancelled)),
        patch.object(worker_module, "CANCEL_POLL_SECONDS", 0.01),
    ):
        result = await run_analysis({"redis": redis_stub, "db_session": factory}, str(job.id))
    api_config._settings = None

    assert result["status"] == "cancelled"
    cancelled = [u for u in updates_to(factory, "analysis_jobs") if u.get("status") == "cancelled"]
    assert len(cancelled) == 1
    assert cancelled[0]["completed_at"] is not None


@pytest.mark.asyncio
async def test_an_unparseable_job_id_records_nothing(redis_stub: MagicMock) -> None:
    factory = SessionFactory(rows_for(None, None))
    result = await run_analysis({"redis": redis_stub, "db_session": factory}, "not-a-uuid")
    assert result["status"] == "error"
    assert updates_to(factory, "analysis_jobs") == []


@pytest.mark.asyncio
async def test_a_cancelled_row_is_not_overwritten_by_a_failure() -> None:
    """``mark_job_failed`` leaves the operator's decision alone."""
    from app.worker.analysis_worker import mark_job_failed

    factory = SessionFactory(rows_for(None, None))
    ok = await mark_job_failed(
        factory, uuid.uuid4(), reason="RuntimeError (error id abc)", error_id="abc"
    )
    assert ok
    statement = factory.statements()[0]
    where = str(statement.whereclause)
    assert "status" in where and "!=" in where
