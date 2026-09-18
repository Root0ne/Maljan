"""The worker holds no transaction while the models run, and fails loudly.

Two properties of ``run_analysis``, both learned from one live run: a session
left open for the length of an analysis blocked a migration and every read
behind it, and a job whose session was killed under it published an ``error``
event and left its row saying ``running`` for ever.

Nothing here reaches a service. The database is the tracking factory from
``_session_probe``, Redis is a stub, and the object store is stubbed per test —
because whether the sample download succeeds changes how many short sessions a
run opens before the pipeline, and a test that counted them was a test of the
environment. What these assert is the invariant instead: when the pipeline
starts, every session the run has opened is closed and settled, whichever way
the download went.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from app.worker.analysis_worker import (
    _OWNED_JOBS,
    JOB_OWNER_TTL_SECONDS,
    WORKER_ID,
    job_owner_key,
    run_analysis,
)
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


class _FakeMinioClient:
    """Writes the bytes the download step is there to fetch."""

    def fget_object(self, bucket: str, object_name: str, file_path: str) -> None:
        Path(file_path).write_bytes(b"MZfakebinary")


@pytest.fixture(autouse=True)
def _object_store(tmp_path: Path):
    """A reachable object store, and private directories under this test's own.

    Every path below runs the download for real, so it is stubbed here rather
    than left to whatever is listening on the host: on this machine MinIO is
    up and the download succeeds, in CI it is not and the run takes its
    "Sandbox submission skipped" path, and the two differ by a session. A test
    that depends on which one it got is a test of the deployment it ran on.
    """
    from app import config as api_config

    api_config._settings = None
    with (
        patch("minio.Minio", return_value=_FakeMinioClient()),
        patch.dict(
            "os.environ",
            {
                "UPLOAD_TEMP_DIR": str(tmp_path / "tmp"),
                "SAMPLES_DIR": str(tmp_path / "samples"),
            },
            clear=False,
        ),
    ):
        yield
    api_config._settings = None


def _unreachable_object_store():
    """The CI shape: nothing is listening, and the run says so and carries on."""
    return patch("minio.Minio", side_effect=ConnectionError("no object store here"))


def assert_every_session_has_ended(factory: SessionFactory) -> None:
    """No session of this run is open, and each one committed or rolled back.

    The invariant the count used to stand in for. How many short sessions a
    run opens before the models start depends on what it had to do — read the
    settings, flush a batch of events — and none of that matters as long as
    each one ended.
    """
    assert [s.index for s in factory.sessions if s.open] == []
    assert [s.index for s in factory.sessions if s.in_transaction] == []
    assert [s.index for s in factory.sessions if s.commits + s.rollbacks == 0] == []


@pytest_asyncio.fixture
async def redis_stub() -> MagicMock:
    redis = MagicMock()
    redis.publish = AsyncMock()
    redis.aclose = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    # The owner heartbeat this run writes and drops.
    redis.set = AsyncMock()
    redis.delete = AsyncMock()
    return redis


def _heartbeats(redis: MagicMock) -> list[str]:
    """The keys this run claimed, in the order it claimed them."""
    return [str(call.args[0]) for call in redis.set.call_args_list]


def _released(redis: MagicMock) -> list[str]:
    return [str(call.args[0]) for call in redis.delete.call_args_list]


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
    # And every session this run opened was closed and settled.
    assert_every_session_has_ended(factory)


async def _run_and_watch_the_boundary(
    redis_stub: MagicMock,
) -> tuple[dict[str, Any], SessionFactory, list[int]]:
    """Run a job whose pipeline inspects the sessions at the moment it starts."""
    job = fake_job()
    sample = fake_sample(job.sample_id)
    factory = SessionFactory(rows_for(job, sample))
    sessions_at_pipeline_time: list[int] = []

    async def _pipeline(*args: Any, **kwargs: Any) -> dict[str, Any]:
        sessions_at_pipeline_time.append(len(factory.sessions))
        assert_every_session_has_ended(factory)
        return _pipeline_result()

    from app import config as api_config

    api_config._settings = None
    with (
        _mock_mode(),
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(side_effect=_pipeline)),
    ):
        result = await run_analysis({"redis": redis_stub, "db_session": factory}, str(job.id))
    api_config._settings = None
    return result, factory, sessions_at_pipeline_time


@pytest.mark.asyncio
async def test_the_reads_are_settled_before_the_pipeline(redis_stub: MagicMock) -> None:
    """Whatever the run did first, it had finished doing it.

    The reads and the status change go through sessions that end before the
    models start, and the report is written through one opened after they
    stop. How many the run opened on the way is not the invariant — a batch of
    events flushed on its own session is one more, and so is a download that
    had to be retried — so this asserts that each of them ended and that the
    writes came later.
    """
    result, factory, at_pipeline_time = await _run_and_watch_the_boundary(redis_stub)

    assert result["status"] == "completed"
    assert at_pipeline_time and at_pipeline_time[0] >= 1, "the reads happen before the models"
    assert len(factory.sessions) > at_pipeline_time[0], "and the writes after them"
    first = factory.sessions[0]
    assert first.commits >= 1 and not first.open
    assert_every_session_has_ended(factory)


@pytest.mark.asyncio
async def test_the_reads_are_settled_when_the_object_store_is_unreachable(
    redis_stub: MagicMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The path CI takes: no object store, so the run skips the download.

    It opens a session more or fewer than the reachable case — which is what
    made a count fail there and pass here — and the invariant is the same.
    """
    with _unreachable_object_store(), caplog.at_level(logging.WARNING):
        result, factory, at_pipeline_time = await _run_and_watch_the_boundary(redis_stub)

    # The run really did take the other path, rather than quietly finding an
    # object store somewhere.
    assert any("Sandbox submission skipped" in record.message for record in caplog.records)
    assert result["status"] == "completed"
    assert at_pipeline_time and at_pipeline_time[0] >= 1
    assert len(factory.sessions) > at_pipeline_time[0]
    assert_every_session_has_ended(factory)


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
    assert isinstance(recorded["completed_at"], datetime)
    assert (datetime.now(UTC) - recorded["completed_at"]).total_seconds() < 60
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
    assert isinstance(cancelled[0]["completed_at"], datetime)
    assert (datetime.now(UTC) - cancelled[0]["completed_at"]).total_seconds() < 60


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


@pytest.mark.asyncio
async def test_the_run_claims_its_job_and_drops_the_claim_on_success(
    redis_stub: MagicMock,
) -> None:
    """The heartbeat is what the sweep reads, so it spans exactly the run."""
    job = fake_job()
    sample = fake_sample(job.sample_id)
    factory = SessionFactory(rows_for(job, sample))
    owned_during_the_run: list[bool] = []

    async def _pipeline(*args: Any, **kwargs: Any) -> dict[str, Any]:
        owned_during_the_run.append(str(job.id) in _OWNED_JOBS)
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
    assert owned_during_the_run == [True]
    assert _heartbeats(redis_stub) == [job_owner_key(str(job.id))]
    assert redis_stub.set.call_args_list[0].kwargs["ex"] == JOB_OWNER_TTL_SECONDS
    assert redis_stub.set.call_args_list[0].args[1] == WORKER_ID
    assert _released(redis_stub) == [job_owner_key(str(job.id))]
    assert str(job.id) not in _OWNED_JOBS


@pytest.mark.asyncio
async def test_the_claim_is_dropped_when_the_run_fails(redis_stub: MagicMock) -> None:
    job = fake_job()
    sample = fake_sample(job.sample_id)
    factory = SessionFactory(rows_for(job, sample))

    from app import config as api_config

    api_config._settings = None
    with (
        _mock_mode(),
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(side_effect=RuntimeError("no"))),
    ):
        result = await run_analysis({"redis": redis_stub, "db_session": factory}, str(job.id))
    api_config._settings = None

    assert result["status"] == "failed"
    assert _released(redis_stub) == [job_owner_key(str(job.id))]
    assert str(job.id) not in _OWNED_JOBS


@pytest.mark.asyncio
async def test_the_claim_is_dropped_when_the_run_is_cancelled(redis_stub: MagicMock) -> None:
    job = fake_job()
    sample = fake_sample(job.sample_id)
    factory = SessionFactory(rows_for(job, sample))

    async def _cancelled(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise asyncio.CancelledError

    from app import config as api_config

    api_config._settings = None
    with (
        _mock_mode(),
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(side_effect=_cancelled)),
        pytest.raises(asyncio.CancelledError),
    ):
        await run_analysis({"redis": redis_stub, "db_session": factory}, str(job.id))
    api_config._settings = None

    assert _released(redis_stub) == [job_owner_key(str(job.id))]
    assert str(job.id) not in _OWNED_JOBS


@pytest.mark.asyncio
async def test_the_refresher_cannot_outlive_the_job(redis_stub: MagicMock) -> None:
    """A refresher still running would keep saying a finished job is running."""
    job = fake_job()
    sample = fake_sample(job.sample_id)
    factory = SessionFactory(rows_for(job, sample))
    before = {id(task) for task in asyncio.all_tasks()}

    from app import config as api_config

    api_config._settings = None
    with (
        _mock_mode(),
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(return_value=_pipeline_result())),
    ):
        await run_analysis({"redis": redis_stub, "db_session": factory}, str(job.id))
    api_config._settings = None

    left = [task for task in asyncio.all_tasks() if id(task) not in before and not task.done()]
    assert left == []


@pytest.mark.asyncio
async def test_a_redis_that_refuses_the_claim_never_costs_the_run(
    redis_stub: MagicMock,
) -> None:
    """The sweep skips the jobs this process is running, so the run is safe."""
    job = fake_job()
    sample = fake_sample(job.sample_id)
    factory = SessionFactory(rows_for(job, sample))
    redis_stub.set = AsyncMock(side_effect=ConnectionError("queue unreachable"))
    redis_stub.delete = AsyncMock(side_effect=ConnectionError("queue unreachable"))

    from app import config as api_config

    api_config._settings = None
    with (
        _mock_mode(),
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(return_value=_pipeline_result())),
    ):
        result = await run_analysis({"redis": redis_stub, "db_session": factory}, str(job.id))
    api_config._settings = None

    assert result["status"] == "completed"
    assert str(job.id) not in _OWNED_JOBS


@pytest.mark.asyncio
async def test_a_cancel_request_writes_its_row_even_between_two_polls(
    redis_stub: MagicMock,
) -> None:
    """The operator asked, so the row says so — whoever noticed first.

    The heartbeat reads the cancel flag every fifteen seconds; a cancel that
    arrives between two polls reaches the task as a bare ``CancelledError``,
    which used to be re-raised with nothing written. The flag is still in
    Redis, so the task reads it where it lands and the row is written through
    a session of its own.
    """
    job = fake_job()
    sample = fake_sample(job.sample_id)
    factory = SessionFactory(rows_for(job, sample))
    redis_stub.get = AsyncMock(return_value=b"1")

    async def _cancelled(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise asyncio.CancelledError

    from app import config as api_config

    api_config._settings = None
    with (
        _mock_mode(),
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(side_effect=_cancelled)),
    ):
        result = await run_analysis({"redis": redis_stub, "db_session": factory}, str(job.id))
    api_config._settings = None

    assert result["status"] == "cancelled"
    cancelled = [u for u in updates_to(factory, "analysis_jobs") if u.get("status") == "cancelled"]
    assert len(cancelled) == 1
    assert isinstance(cancelled[0]["completed_at"], datetime)
    # Written by a session opened after the reads, not by the run's own.
    assert len(factory.sessions) >= 2
    assert_every_session_has_ended(factory)


@pytest.mark.asyncio
async def test_a_shutdown_cancellation_writes_no_row(redis_stub: MagicMock) -> None:
    """Nobody asked, so nothing is claimed.

    arq cancels the task on its own job timeout and on SIGTERM. The process is
    going away, writing a row on the way out races its own teardown, and the
    heartbeat dies with it — so the periodic sweep repairs the row within ten
    minutes, and the ``CancelledError`` travels on untouched.
    """
    job = fake_job()
    sample = fake_sample(job.sample_id)
    factory = SessionFactory(rows_for(job, sample))
    redis_stub.get = AsyncMock(return_value=None)

    async def _cancelled(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise asyncio.CancelledError

    from app import config as api_config

    api_config._settings = None
    with (
        _mock_mode(),
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(side_effect=_cancelled)),
        pytest.raises(asyncio.CancelledError),
    ):
        await run_analysis({"redis": redis_stub, "db_session": factory}, str(job.id))
    api_config._settings = None

    assert [u for u in updates_to(factory, "analysis_jobs") if u.get("status") == "cancelled"] == []
    assert [u for u in updates_to(factory, "analysis_jobs") if u.get("status") == "failed"] == []


@pytest.mark.asyncio
async def test_a_redis_that_cannot_answer_is_read_as_a_shutdown(
    redis_stub: MagicMock,
) -> None:
    """The run is going down either way; the sweep repairs what nobody claimed."""
    job = fake_job()
    sample = fake_sample(job.sample_id)
    factory = SessionFactory(rows_for(job, sample))
    redis_stub.get = AsyncMock(side_effect=ConnectionError("queue unreachable"))

    async def _cancelled(*args: Any, **kwargs: Any) -> dict[str, Any]:
        raise asyncio.CancelledError

    from app import config as api_config

    api_config._settings = None
    with (
        _mock_mode(),
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(side_effect=_cancelled)),
        pytest.raises(asyncio.CancelledError),
    ):
        await run_analysis({"redis": redis_stub, "db_session": factory}, str(job.id))
    api_config._settings = None

    assert updates_to(factory, "analysis_jobs") == [
        u for u in updates_to(factory, "analysis_jobs") if u.get("status") == "running"
    ]
