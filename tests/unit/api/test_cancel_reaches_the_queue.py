"""Cancelling a job has to cancel the *queued work*, not just the row.

``cancel_job`` marked the DB row, set a cooperative Redis flag and published an
event — and never touched arq. ``enqueue_job("run_analysis", str(job.id))``
passes no ``_job_id``, so arq minted a random one that nothing else in the
system knew, which is why the queued job could not be reached afterwards.

Observed live 2026-08-07, hours after the cancel:

    arq:in-progress:22d7c6d4…  ttl 13763s  -> run_analysis('1ad79a9e…')  [CANCELLED]
    arq:in-progress:a1af5817…  ttl 24094s  -> run_analysis('e6bdcb3d…')  [COMPLETED]

With ``max_jobs = 1`` those two locks blocked the queue outright — a freshly
submitted analysis sat ``pending`` and never started. Worse, both were still
*scheduled for retry*: a cancelled analysis would have re-run on its own once
the lock expired, and a re-run cannot even save its report (``analysis_reports``
has a unique ``job_id``), so it would have burned an hour to end in an
IntegrityError.

Giving arq our own job id fixes the reachability at the root and makes
enqueueing idempotent as a side effect: the same analysis cannot be queued
twice under two different arq identities.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest


class _Job:
    """Stand-in for ``arq.jobs.Job`` that records whether abort() was called."""

    instances: list[_Job] = []

    def __init__(self, job_id: str, redis: Any = None, **_: Any) -> None:
        self.job_id = job_id
        self.aborted = False
        _Job.instances.append(self)

    async def abort(self, *_: Any, **__: Any) -> bool:
        self.aborted = True
        return True


@pytest.fixture(autouse=True)
def _reset() -> None:
    _Job.instances.clear()


class TestTheArqJobIdIsOurJobId:
    @pytest.mark.asyncio
    async def test_enqueue_passes_our_id_as_the_arq_job_id(self, monkeypatch: Any) -> None:
        """Without this the queued work has an identity nothing else knows."""
        from app.services import analysis_service as svc_mod

        arq = MagicMock()
        arq.enqueue_job = AsyncMock()
        job_id = uuid.uuid4()

        await svc_mod._enqueue_analysis(arq, job_id)

        arq.enqueue_job.assert_awaited_once()
        kwargs = arq.enqueue_job.await_args.kwargs
        assert kwargs.get("_job_id") == str(job_id), (
            "arq must be given our job id; a random one cannot be cancelled later"
        )

    @pytest.mark.asyncio
    async def test_enqueueing_the_same_job_twice_is_not_two_arq_jobs(
        self, monkeypatch: Any
    ) -> None:
        """arq dedupes on _job_id — the same analysis cannot double-queue."""
        from app.services import analysis_service as svc_mod

        arq = MagicMock()
        arq.enqueue_job = AsyncMock()
        job_id = uuid.uuid4()

        await svc_mod._enqueue_analysis(arq, job_id)
        await svc_mod._enqueue_analysis(arq, job_id)

        ids = {c.kwargs.get("_job_id") for c in arq.enqueue_job.await_args_list}
        assert ids == {str(job_id)}


class TestCancelReachesTheQueuedWork:
    @pytest.mark.asyncio
    async def test_cancel_aborts_the_arq_job(self, monkeypatch: Any) -> None:
        from app.services import analysis_service as svc_mod

        monkeypatch.setattr(svc_mod, "ArqJob", _Job, raising=False)
        redis = MagicMock()
        job_id = uuid.uuid4()

        await svc_mod._abort_queued_analysis(redis, job_id)

        assert [j.job_id for j in _Job.instances] == [str(job_id)]
        assert _Job.instances[0].aborted is True

    @pytest.mark.asyncio
    async def test_a_failing_abort_never_breaks_the_cancel(self, monkeypatch: Any) -> None:
        """The row is already marked cancelled; the queue is best-effort."""
        from app.services import analysis_service as svc_mod

        class _Boom(_Job):
            async def abort(self, *_: Any, **__: Any) -> bool:
                raise RuntimeError("redis gone")

        monkeypatch.setattr(svc_mod, "ArqJob", _Boom, raising=False)

        await svc_mod._abort_queued_analysis(MagicMock(), uuid.uuid4())
