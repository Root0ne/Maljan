"""A job reaches the queue only after its row is committed.

The worker reads the job from a session of its own. A row still inside the
request's open transaction is invisible to it, so a job enqueued before the
commit was read as "Job not found", the worker gave up, and the row stayed
``pending`` with nothing queued behind it.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest


def _service(order: list[str], *, enqueue_error: Exception | None = None) -> Any:
    from app.services import analysis_service as svc_mod

    db = MagicMock()
    sample = MagicMock()
    sample.id = uuid.uuid4()
    found = MagicMock()
    found.scalar_one_or_none.return_value = sample
    db.execute = AsyncMock(return_value=found)
    db.add = MagicMock(side_effect=lambda job: setattr(job, "id", uuid.uuid4()))

    async def _flush() -> None:
        order.append("flush")

    async def _commit() -> None:
        order.append("commit")

    db.flush = _flush
    db.commit = _commit
    db.refresh = AsyncMock()

    async def _enqueue(*_: Any, **__: Any) -> None:
        order.append("enqueue")
        if enqueue_error is not None:
            raise enqueue_error

    arq = MagicMock()
    arq.enqueue_job = _enqueue
    svc = svc_mod.AnalysisService(db)
    svc._arq_redis = arq
    return svc, sample


class TestTheRowIsCommittedBeforeTheQueueHearsOfIt:
    @pytest.mark.asyncio
    async def test_commit_comes_before_enqueue(self) -> None:
        order: list[str] = []
        svc, sample = _service(order)
        user = MagicMock()
        user.id = uuid.uuid4()

        job = await svc.create_job(sample.id, user)

        assert order.index("commit") < order.index("enqueue")
        assert job.status == "pending"

    @pytest.mark.asyncio
    async def test_a_failed_enqueue_commits_the_failure(self) -> None:
        """The route's error path rolls back; the committed row must not stay pending."""
        from app.services.analysis_service import JobEnqueueError

        order: list[str] = []
        svc, sample = _service(order, enqueue_error=ConnectionError("redis down"))
        user = MagicMock()
        user.id = uuid.uuid4()

        with pytest.raises(JobEnqueueError):
            await svc.create_job(sample.id, user)

        assert order == ["flush", "commit", "enqueue", "commit"]
        added = svc.db.add.call_args.args[0]
        assert added.status == "failed"
        assert "redis down" in added.error_message
        assert added.completed_at is not None


def _sessions(answers: list[Any]) -> tuple[Any, list[Any]]:
    """A session factory whose reads answer in turn; records every statement."""
    statements: list[Any] = []
    pending = list(answers)

    session = MagicMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.flush = AsyncMock()

    async def _execute(statement: Any, *_: Any, **__: Any) -> MagicMock:
        statements.append(statement)
        return pending.pop(0) if pending else MagicMock()

    session.execute = _execute
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return (lambda: session), statements


def _read(value: Any) -> MagicMock:
    result = MagicMock()
    result.scalar_one_or_none.return_value = value
    return result


def _sleep_recorder(slept: list[float]) -> Any:
    async def _sleep(seconds: float) -> None:
        slept.append(seconds)

    return _sleep


class TestAWorkerWaitsABoundedWhileForTheRow:
    @pytest.mark.asyncio
    async def test_a_row_that_arrives_late_is_found(self) -> None:
        from app.worker.analysis_worker import wait_for_job_row

        factory, _ = _sessions([_read(None), _read(None), _read(uuid.uuid4())])
        slept: list[float] = []

        found, reads, waited = await wait_for_job_row(
            factory,
            uuid.uuid4(),
            pauses=(0.5, 1.0, 2.0, 4.0),
            sleep=_sleep_recorder(slept),
        )

        assert (found, reads) == (True, 3)
        assert slept == [0.5, 1.0, 2.0]
        assert waited == pytest.approx(3.5)

    @pytest.mark.asyncio
    async def test_the_wait_ends_when_the_pauses_run_out(self) -> None:
        from app.worker.analysis_worker import wait_for_job_row

        factory, _ = _sessions([_read(None) for _ in range(10)])
        slept: list[float] = []

        found, reads, waited = await wait_for_job_row(
            factory, uuid.uuid4(), pauses=(0.5, 1.0), sleep=_sleep_recorder(slept)
        )

        assert (found, reads, waited) == (False, 2, 1.5)
        assert slept == [0.5, 1.0]

    def test_the_shipped_wait_is_bounded(self) -> None:
        from app.worker.analysis_worker import JOB_ROW_READ_PAUSES

        assert JOB_ROW_READ_PAUSES
        assert 0 < sum(JOB_ROW_READ_PAUSES) <= 60

    @pytest.mark.asyncio
    async def test_a_job_given_up_is_marked_failed_only_while_pending(self) -> None:
        from app.worker.analysis_worker import fail_unread_job

        marked_row = MagicMock()
        marked_row.first.return_value = (uuid.uuid4(),)
        factory, statements = _sessions([marked_row])

        assert await fail_unread_job(factory, uuid.uuid4(), 6, 15.5) is True
        compiled = statements[0].compile()
        assert str(compiled).startswith("UPDATE analysis_jobs")
        values = [str(value) for value in compiled.params.values()]
        assert "pending" in values
        assert "failed" in values
        assert any("gave up" in value and "15.5 s" in value for value in values)


@pytest.mark.asyncio
async def test_the_worker_gives_up_a_missing_row_after_the_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.worker import analysis_worker

    monkeypatch.setattr(analysis_worker, "JOB_ROW_READ_PAUSES", (0.0, 0.0, 0.0))
    nothing = MagicMock()
    nothing.first.return_value = None
    factory, statements = _sessions([_read(None)] * 4 + [nothing])
    redis = MagicMock()
    redis.publish = AsyncMock()
    redis.set = AsyncMock()
    redis.delete = AsyncMock()

    result = await analysis_worker.run_analysis(
        {"redis": redis, "db_session": factory}, str(uuid.uuid4())
    )

    assert result == {"status": "error", "message": "Job not found"}
    selects = [s for s in statements if str(s).startswith("SELECT")]
    assert len(selects) == 4
    assert any(str(s).startswith("UPDATE analysis_jobs") for s in statements)


@pytest.mark.parametrize("status", ["failed", "completed"])
@pytest.mark.asyncio
async def test_a_row_already_ended_is_not_run(status: str) -> None:
    """An enqueue that raised after the queue took the job leaves a failed row behind."""
    from app.worker import analysis_worker

    job = MagicMock()
    job.status = status
    factory, statements = _sessions([_read(job)])
    redis = MagicMock()
    redis.publish = AsyncMock()
    redis.set = AsyncMock()
    redis.delete = AsyncMock()

    result = await analysis_worker.run_analysis(
        {"redis": redis, "db_session": factory}, str(uuid.uuid4())
    )

    assert result["status"] == "skipped"
    assert not any(str(s).startswith("UPDATE analysis_jobs") for s in statements)
