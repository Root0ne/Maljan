"""Enrichment never takes the slot an analysis is waiting for.

The worker runs one job at a time on purpose, and the post-verdict enrichment
was queued into the same queue: one measured run spent 451.98 s looking up
domains at VirusTotal while the next analysis sat ``pending`` for 4 m 33 s. The
two workloads now have a queue each, and the analysis worker reads only its
own — so an enrichment in flight is not a job the analysis worker can be busy
with.

A deployment that would rather run one process keeps the old behaviour behind
``api.enrichment_dedicated_worker``: the enrichment goes back on the analysis
queue and waits its turn there.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.worker.analysis_worker import WorkerSettings
from app.worker.enrich_worker import (
    ENRICHMENT_QUEUE,
    EnrichmentWorkerSettings,
    enqueue_enrichment,
    enrich_threat_intel,
)


def _pool() -> MagicMock:
    pool = MagicMock()
    pool.enqueue_job = AsyncMock(return_value=MagicMock(job_id="enrich-1"))
    return pool


def _analysis_queue() -> str:
    from arq.constants import default_queue_name

    return str(getattr(WorkerSettings, "queue_name", default_queue_name))


class TestTheTwoQueues:
    def test_the_enrichment_worker_reads_a_queue_of_its_own(self) -> None:
        assert EnrichmentWorkerSettings.queue_name == ENRICHMENT_QUEUE
        assert ENRICHMENT_QUEUE != _analysis_queue()

    def test_the_enrichment_worker_runs_only_enrichment(self) -> None:
        names = {getattr(f, "__name__", str(f)) for f in EnrichmentWorkerSettings.functions}
        assert names == {"enrich_threat_intel"}

    def test_the_analysis_worker_still_answers_for_both(self) -> None:
        """The fallback needs the task registered where the fallback queues it."""
        names = {getattr(f, "__name__", str(f)) for f in WorkerSettings.functions}
        assert "run_analysis" in names
        assert "enrich_threat_intel" in names

    def test_the_enrichment_worker_takes_more_than_one_at_a_time(self) -> None:
        """Nothing about a reputation lookup needs the one-job-at-a-time rule."""
        assert EnrichmentWorkerSettings.max_jobs > 1
        assert WorkerSettings.max_jobs == 1

    def test_the_analysis_worker_keeps_the_nightly_sweep(self) -> None:
        """One cron owner, so two processes do not both purge the feed."""
        assert WorkerSettings.cron_jobs
        assert not getattr(EnrichmentWorkerSettings, "cron_jobs", [])


class TestWhereAnEnrichmentIsQueued:
    @pytest.mark.asyncio
    async def test_it_goes_to_the_enrichment_queue_by_default(self) -> None:
        pool = _pool()
        report_id = uuid.uuid4()

        with patch(
            "app.worker.enrich_worker.runtime_config.get", AsyncMock(return_value=True)
        ) as gate:
            job_id = await enqueue_enrichment(pool, report_id)

        assert gate.await_args.args == ("enrichment_dedicated_worker",)
        assert pool.enqueue_job.await_args.kwargs["_queue_name"] == ENRICHMENT_QUEUE
        assert pool.enqueue_job.await_args.kwargs["_job_id"] == f"enrich:{report_id}"
        assert job_id == "enrich-1"

    @pytest.mark.asyncio
    async def test_the_single_process_fallback_queues_it_beside_the_analyses(self) -> None:
        pool = _pool()

        with patch("app.worker.enrich_worker.runtime_config.get", AsyncMock(return_value=False)):
            await enqueue_enrichment(pool, uuid.uuid4())

        assert pool.enqueue_job.await_args.kwargs["_queue_name"] == _analysis_queue()

    @pytest.mark.asyncio
    async def test_a_settings_read_that_fails_still_queues_the_work(self) -> None:
        """The enrichment matters more than which queue it lands on."""
        pool = _pool()

        with patch(
            "app.worker.enrich_worker.runtime_config.get",
            AsyncMock(side_effect=ConnectionError("no settings store")),
        ):
            await enqueue_enrichment(pool, uuid.uuid4())

        assert pool.enqueue_job.await_args.kwargs["_queue_name"] == ENRICHMENT_QUEUE

    @pytest.mark.asyncio
    async def test_the_run_queues_its_enrichment_through_the_same_helper(self) -> None:
        """So the auto path and the operator's button cannot drift apart."""
        import inspect

        from app.worker import analysis_worker

        source = inspect.getsource(analysis_worker.run_analysis)
        assert "enqueue_enrichment(" in source
        assert '"enrich_threat_intel"' not in source, (
            "the task name belongs in one place, beside the queue it goes to"
        )


class TestTheSlotIsFree:
    @pytest.mark.asyncio
    async def test_an_enrichment_in_flight_leaves_the_analysis_queue_empty(self) -> None:
        """What the measured delay was: a 452 s enrichment holding the one slot.

        The queues are read by different workers, so the analysis worker's slot
        is free for as long as the enrichment runs — here, the enrichment is
        still running when the next analysis is queued, and nothing it did
        touched the analysis queue.
        """
        queued: list[tuple[str, str]] = []

        pool = MagicMock()

        async def _enqueue(function: str, *args: Any, **kwargs: Any) -> MagicMock:
            queued.append((function, str(kwargs.get("_queue_name"))))
            return MagicMock(job_id=function)

        pool.enqueue_job = AsyncMock(side_effect=_enqueue)

        with patch("app.worker.enrich_worker.runtime_config.get", AsyncMock(return_value=True)):
            await enqueue_enrichment(pool, uuid.uuid4())

        from app.services.analysis_service import _enqueue_analysis

        await _enqueue_analysis(pool, uuid.uuid4())

        by_queue: dict[str, list[str]] = {}
        for function, queue in queued:
            by_queue.setdefault(queue, []).append(function)
        assert by_queue[ENRICHMENT_QUEUE] == ["enrich_threat_intel"]
        assert "enrich_threat_intel" not in by_queue.get(_analysis_queue(), []) + by_queue.get(
            "None", []
        )

    def test_the_task_the_enrichment_worker_runs_is_the_one_that_was_queued(self) -> None:
        assert enrich_threat_intel in EnrichmentWorkerSettings.functions
