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
    enrichment_health_key,
)


def _pool() -> MagicMock:
    pool = MagicMock()
    pool.enqueue_job = AsyncMock(return_value=MagicMock(job_id="enrich-1"))
    return pool


def _repo_root() -> Any:
    from pathlib import Path

    return Path(__file__).resolve().parents[2]


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

    def test_the_enrichment_worker_takes_a_few_at_a_time(self) -> None:
        """Nothing about a reputation lookup needs the one-job-at-a-time rule.

        Not many, either: the jobs share one VirusTotal key and one AbuseIPDB
        key, and a provider's rate limit is per key.
        """
        assert EnrichmentWorkerSettings.max_jobs == 2
        assert WorkerSettings.max_jobs == 1

    def test_the_concurrency_is_a_deployment_knob(self) -> None:
        """Sized where the worker's other sizing lives: the process environment."""
        import importlib
        import os

        from app.worker import enrich_worker

        original = os.environ.get("ENRICHMENT_MAX_JOBS")
        os.environ["ENRICHMENT_MAX_JOBS"] = "5"
        try:
            reloaded = importlib.reload(enrich_worker)
            assert reloaded.ENRICHMENT_MAX_JOBS == 5
            assert reloaded.EnrichmentWorkerSettings.max_jobs == 5
        finally:
            if original is None:
                del os.environ["ENRICHMENT_MAX_JOBS"]
            else:
                os.environ["ENRICHMENT_MAX_JOBS"] = original
            importlib.reload(enrich_worker)

    def test_the_analysis_worker_keeps_the_nightly_sweep(self) -> None:
        """One cron owner, so two processes do not both purge the feed."""
        assert WorkerSettings.cron_jobs
        assert not getattr(EnrichmentWorkerSettings, "cron_jobs", [])


class TestWhereAnEnrichmentIsQueued:
    def test_the_shipped_default_is_one_process(self) -> None:
        """Nothing stops silently on upgrade.

        A deployment that takes this release and changes nothing runs one
        worker, so the shipped default queues the enrichment where that worker
        is already looking. A stack that starts the second process says so.
        """
        from app.services.settings_catalog_api import (
            API_DEFAULTS,
            dedicated_enrichment_worker_default,
        )

        assert API_DEFAULTS["enrichment_dedicated_worker"] is False
        assert dedicated_enrichment_worker_default() is False

    def test_a_stack_that_runs_the_worker_turns_it_on(self, monkeypatch: Any) -> None:
        """What the compose file sets beside the ``enrichment-worker`` service."""
        from app.services.settings_catalog_api import dedicated_enrichment_worker_default

        monkeypatch.setenv("ENRICHMENT_DEDICATED_WORKER", "true")
        assert dedicated_enrichment_worker_default() is True
        monkeypatch.setenv("ENRICHMENT_DEDICATED_WORKER", "false")
        assert dedicated_enrichment_worker_default() is False

    def test_the_compose_file_sets_it_beside_the_service(self) -> None:
        import yaml

        compose = yaml.safe_load(
            (_repo_root() / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
        )
        services = compose["services"]
        assert "enrichment-worker" in services, "the service that reads the queue"
        for name in ("backend-api", "backend-worker"):
            env = services[name]["environment"]
            assert str(env.get("ENRICHMENT_DEDICATED_WORKER", "")).lower() == "true", name

    @pytest.mark.asyncio
    async def test_it_goes_to_the_enrichment_queue_when_the_setting_is_on(self) -> None:
        pool = _pool()
        report_id = uuid.uuid4()

        with patch(
            "app.worker.enrich_worker.runtime_config.get", AsyncMock(return_value=True)
        ) as gate:
            job_id = await enqueue_enrichment(pool, report_id)

        assert gate.await_args.args == ("enrichment_dedicated_worker",)
        assert pool.enqueue_job.await_args.kwargs["_queue_name"] == ENRICHMENT_QUEUE
        assert (
            pool.enqueue_job.await_args.kwargs["_job_id"]
            == f"enrich:{ENRICHMENT_QUEUE}:{report_id}"
        )
        assert job_id == "enrich-1"

    @pytest.mark.asyncio
    async def test_the_single_process_default_queues_it_beside_the_analyses(self) -> None:
        pool = _pool()

        with patch("app.worker.enrich_worker.runtime_config.get", AsyncMock(return_value=False)):
            await enqueue_enrichment(pool, uuid.uuid4())

        assert pool.enqueue_job.await_args.kwargs["_queue_name"] == _analysis_queue()

    @pytest.mark.asyncio
    async def test_the_same_report_can_be_queued_again_after_the_setting_flips(self) -> None:
        """arq refuses an id it has seen for a day, and the queue is part of it.

        Without that, a report queued while the setting was off could not be
        queued for the other worker until the next day: arq would refuse the
        id and the report would sit on the queue it was first put in.
        """
        pool = _pool()
        report_id = uuid.uuid4()

        with patch("app.worker.enrich_worker.runtime_config.get", AsyncMock(return_value=False)):
            await enqueue_enrichment(pool, report_id)
        first = pool.enqueue_job.await_args.kwargs

        with patch("app.worker.enrich_worker.runtime_config.get", AsyncMock(return_value=True)):
            await enqueue_enrichment(pool, report_id)
        second = pool.enqueue_job.await_args.kwargs

        assert first["_job_id"] != second["_job_id"]
        assert first["_queue_name"] != second["_queue_name"]
        # And two triggers for one report on one queue still coalesce.
        with patch("app.worker.enrich_worker.runtime_config.get", AsyncMock(return_value=True)):
            await enqueue_enrichment(pool, report_id)
        assert pool.enqueue_job.await_args.kwargs["_job_id"] == second["_job_id"]

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


class TestNothingStopsSilently:
    """When the queue has no reader, the worker and the API both say so."""

    @pytest.mark.asyncio
    async def test_the_worker_warns_when_its_queue_has_no_reader(self, caplog: Any) -> None:
        import logging

        from app.worker.analysis_worker import warn_if_enrichment_is_unmanned

        redis = MagicMock()
        redis.exists = AsyncMock(return_value=0)
        with (
            patch("app.worker.analysis_worker.runtime_config.get", AsyncMock(return_value=True)),
            caplog.at_level(logging.WARNING),
        ):
            await warn_if_enrichment_is_unmanned({"redis": redis}, delay=0)

        said = " ".join(record.getMessage() for record in caplog.records)
        assert ENRICHMENT_QUEUE in said
        assert "EnrichmentWorkerSettings" in said, "the line says what to start"
        assert "will run when a worker starts" in said, "and that nothing was dropped"
        assert redis.exists.await_args.args == (enrichment_health_key(),)

    @pytest.mark.asyncio
    async def test_a_worker_that_is_reading_draws_no_warning(self, caplog: Any) -> None:
        import logging

        from app.worker.analysis_worker import warn_if_enrichment_is_unmanned

        redis = MagicMock()
        redis.exists = AsyncMock(return_value=1)
        with (
            patch("app.worker.analysis_worker.runtime_config.get", AsyncMock(return_value=True)),
            caplog.at_level(logging.WARNING),
        ):
            await warn_if_enrichment_is_unmanned({"redis": redis}, delay=0)

        assert caplog.records == []

    @pytest.mark.asyncio
    async def test_the_single_process_default_is_not_warned_about(self, caplog: Any) -> None:
        import logging

        from app.worker.analysis_worker import warn_if_enrichment_is_unmanned

        redis = MagicMock()
        redis.exists = AsyncMock(return_value=0)
        with (
            patch("app.worker.analysis_worker.runtime_config.get", AsyncMock(return_value=False)),
            caplog.at_level(logging.WARNING),
        ):
            await warn_if_enrichment_is_unmanned({"redis": redis}, delay=0)

        assert caplog.records == []
        redis.exists.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_it_waits_a_health_interval_before_judging(self) -> None:
        """At boot the other process may be coming up beside this one."""
        import inspect

        from app.worker.analysis_worker import warn_if_enrichment_is_unmanned

        source = inspect.getsource(warn_if_enrichment_is_unmanned)
        assert "health_check_interval" in source
        assert "asyncio.sleep(wait)" in source

    @pytest.mark.asyncio
    async def test_the_status_endpoint_says_which(self) -> None:
        from app.api.v1 import system

        redis = MagicMock()
        redis.exists = AsyncMock(return_value=0)
        redis.aclose = AsyncMock()

        with (
            patch("app.api.v1.system.runtime_config.get", AsyncMock(return_value=True)),
            patch.object(system, "aioredis", MagicMock(from_url=lambda *a, **k: redis)),
        ):
            assert await system._enrichment_worker_state() == "down"

        redis.exists = AsyncMock(return_value=1)
        with (
            patch("app.api.v1.system.runtime_config.get", AsyncMock(return_value=True)),
            patch.object(system, "aioredis", MagicMock(from_url=lambda *a, **k: redis)),
        ):
            assert await system._enrichment_worker_state() == "up"

        with patch("app.api.v1.system.runtime_config.get", AsyncMock(return_value=False)):
            assert await system._enrichment_worker_state() == "not_required"

    @pytest.mark.asyncio
    async def test_a_queue_it_cannot_read_is_not_a_verdict(self) -> None:
        from app.api.v1 import system

        with patch(
            "app.api.v1.system.runtime_config.get",
            AsyncMock(side_effect=ConnectionError("no settings store")),
        ):
            assert await system._enrichment_worker_state() == "unknown"
