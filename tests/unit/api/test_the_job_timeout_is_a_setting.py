"""The analysis job's timeout is a setting, empty by default, and arq imposes none.

``core.job_timeout`` is a catalogue entry like every other core setting — so
the settings API, the console's Agents section and the JSON export and import
carry it with no code of their own — read from each job's own settings when the
job starts. arq is given no deadline a job can reach: what arq accepts for "no
timeout" is proved here, and so is the reason this worker cannot hand it
``None``.
"""

from __future__ import annotations

import asyncio
import time
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from arq.connections import RedisSettings
from arq.constants import in_progress_key_prefix
from arq.worker import Worker, func, get_kwargs
from pydantic import ValidationError

from app.worker.analysis_worker import (
    ARQ_NO_JOB_TIMEOUT,
    JOB_OWNER_TTL_SECONDS,
    STOP_CANCEL,
    STOP_SHUTDOWN,
    STOP_TIMEOUT,
    STOP_UNEXPLAINED,
    WorkerSettings,
    build_job_settings,
    hold_queue_claim,
    job_timeout_reached,
    lease_queue_claim,
    release_queue_claim,
    stop_note,
)

# Redis refuses an expiry whose absolute time in milliseconds does not fit a
# signed 64-bit integer.
_REDIS_EXPIRY_CEILING_MS = 2**63 - 1


class TestTheSetting:
    def test_it_is_a_catalogue_entry_with_no_limit_by_default(self) -> None:
        from app.services.settings_catalog_api import catalog_index

        entry = catalog_index()["core.job_timeout"]
        # Drawn and saved exactly as the loop's own time limit is, which has
        # the same shape: a whole number of seconds, or empty for none.
        loop_limit = catalog_index()["core.react_agent_timeout"]
        assert (entry.type, entry.nullable) == (loop_limit.type, loop_limit.nullable)
        assert entry.nullable is True
        assert entry.default is None
        assert entry.editable is True
        assert entry.applies == "next_job"
        assert entry.group == "agents"
        assert entry.subgroup == "Limits"

    def test_a_job_built_with_no_override_has_no_limit(self) -> None:
        assert build_job_settings({}, None).job_timeout is None

    def test_a_saved_value_reaches_the_job(self) -> None:
        assert build_job_settings({"job_timeout": 3600}, None).job_timeout == 3600

    def test_zero_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            build_job_settings({"job_timeout": 0}, None)

    def test_the_settings_save_takes_a_number_or_empty_and_refuses_zero(self) -> None:
        from app.services.settings_service import SettingsService, SettingsValidationError

        service = SettingsService(MagicMock())
        service.check_keys({"core.job_timeout": 3600})
        service.validate({"job_timeout": 3600}, {})
        service.validate({"job_timeout": None}, {})
        with pytest.raises(SettingsValidationError) as refused:
            service.validate({"job_timeout": 0}, {})
        assert "core.job_timeout" in refused.value.errors


class TestTheClock:
    def test_no_limit_is_never_reached(self) -> None:
        assert not job_timeout_reached(None, 0.0, 10.0 * 365 * 86400)

    def test_a_limit_is_reached_at_its_length(self) -> None:
        assert not job_timeout_reached(3600, 100.0, 3699.0)
        assert job_timeout_reached(3600, 100.0, 3700.0)

    def test_each_stop_says_why_and_where(self) -> None:
        where = "while node report was running, when its task was cancelled"
        timeout = stop_note(STOP_TIMEOUT, seconds=3601.4, where=where, limit=3600)
        assert timeout.startswith(
            "Stopped by the job timeout (3600 s, core.job_timeout) 3601 s into the run, "
            "while node report was running"
        )
        assert stop_note(STOP_CANCEL, seconds=5, where=where).startswith(
            "Cancelled by the operator 5 s into the run"
        )
        assert stop_note(STOP_SHUTDOWN, seconds=5, where=where).startswith(
            "Stopped because the worker running it shut down 5 s into the run"
        )
        assert stop_note(STOP_UNEXPLAINED, seconds=5, where=where).startswith(
            "Stopped by a cancellation inside the pipeline that neither the operator, the job "
            "timeout nor a worker shutdown made 5 s into the run"
        )
        for note in (timeout, stop_note(STOP_CANCEL, seconds=5, where=where)):
            assert note.endswith(
                "The report kept is partial: it holds what the run produced before it "
                "stopped, and nothing the run would have done after it."
            )


async def _job(ctx: dict) -> None:
    return None


async def _other(ctx: dict) -> None:
    return None


class TestWhatArqAccepts:
    # arq's worker takes the running loop when it is built, so these are built
    # inside one.
    @pytest.mark.asyncio
    async def test_none_is_no_deadline_on_a_worker_with_one_function(self) -> None:
        worker = Worker(functions=[_job], job_timeout=None, redis_settings=RedisSettings())
        assert worker.job_timeout_s is None

    @pytest.mark.asyncio
    async def test_none_is_refused_on_a_worker_with_more_than_one_function(self) -> None:
        with pytest.raises(TypeError):
            Worker(functions=[_job, _other], job_timeout=None, redis_settings=RedisSettings())
        with pytest.raises(TypeError):
            Worker(
                functions=[func(_job), func(_other, timeout=60)],
                job_timeout=None,
                redis_settings=RedisSettings(),
            )

    def test_this_worker_has_more_than_one_function(self) -> None:
        assert len(WorkerSettings.functions) + len(WorkerSettings.cron_jobs) > 1

    @pytest.mark.asyncio
    async def test_this_worker_is_built_with_the_longest_duration_python_holds(self) -> None:
        worker = Worker(**get_kwargs(WorkerSettings))
        assert WorkerSettings.job_timeout == ARQ_NO_JOB_TIMEOUT
        assert worker.job_timeout_s == timedelta.max.total_seconds()
        # Every function on this worker runs under it, and the in-progress key
        # arq derives from it is an expiry Redis accepts.
        assert all(f.timeout_s is None for f in worker.functions.values())
        expiry_ms = int(worker.in_progress_timeout_s * 1000)
        assert expiry_ms + int(time.time() * 1000) < _REDIS_EXPIRY_CEILING_MS

    @pytest.mark.asyncio
    async def test_arq_s_deadline_is_one_no_run_reaches(self) -> None:
        # arq waits on a job with ``asyncio.wait_for(task, job_timeout_s)``; the
        # deadline that sets is beyond any run, and a job that ends is its
        # result.
        loop = asyncio.get_running_loop()
        async with asyncio.timeout(ARQ_NO_JOB_TIMEOUT) as deadline:
            assert deadline.when() - loop.time() > 1_000_000 * 365 * 86400
        assert await asyncio.wait_for(asyncio.sleep(0, result="done"), ARQ_NO_JOB_TIMEOUT) == (
            "done"
        )


class TestTheQueueClaim:
    @pytest.mark.asyncio
    async def test_arq_s_claim_is_given_the_owner_heartbeat_s_life(self) -> None:
        redis = MagicMock()
        redis.pexpire = AsyncMock()
        await hold_queue_claim(redis, "job-1")
        redis.pexpire.assert_awaited_once_with(
            in_progress_key_prefix + "job-1", JOB_OWNER_TTL_SECONDS * 1000
        )

    @pytest.mark.asyncio
    async def test_no_arq_job_id_touches_nothing(self) -> None:
        redis = MagicMock()
        redis.pexpire = AsyncMock()
        await hold_queue_claim(redis, None)
        redis.pexpire.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_redis_that_refuses_never_raises_and_keeps_the_lease_going(self) -> None:
        redis = MagicMock()
        redis.pexpire = AsyncMock(side_effect=ConnectionError("down"))
        assert await hold_queue_claim(redis, "job-1") is True


class _ExpiringRedis:
    """The two expiry commands, with each key's remaining life in milliseconds."""

    def __init__(self) -> None:
        self.ttl_ms: dict[str, int] = {}
        self.renewals = 0

    async def psetex(self, key: str, ms: int, value: bytes) -> None:
        self.ttl_ms[key] = int(ms)

    async def pexpire(self, key: str, ms: int) -> int:
        if key not in self.ttl_ms:
            return 0
        self.ttl_ms[key] = int(ms)
        self.renewals += 1
        return 1


class TestTheQueueClaimIsALease:
    """A killed worker's claim on any job of this worker expires within one owner TTL."""

    def test_the_hooks_are_on_the_worker_so_every_function_has_them(self) -> None:
        kwargs = get_kwargs(WorkerSettings)
        assert kwargs["on_job_start"] is lease_queue_claim
        assert kwargs["on_job_end"] is release_queue_claim

    @pytest.mark.asyncio
    async def test_from_the_job_s_first_moment_the_claim_lives_one_owner_ttl(self) -> None:
        redis = _ExpiringRedis()
        key = in_progress_key_prefix + "enrich:q:report-1"
        worker = Worker(**get_kwargs(WorkerSettings))
        # What arq writes when it takes the job: the stand-in's life, in years.
        await redis.psetex(key, int(worker.in_progress_timeout_s * 1000), b"1")
        ctx: dict = {"redis": redis, "job_id": "enrich:q:report-1"}
        await lease_queue_claim(ctx)
        # A kill now, before any renewal, leaves a claim that expires in 90 s.
        assert redis.ttl_ms[key] == JOB_OWNER_TTL_SECONDS * 1000
        await release_queue_claim(ctx)
        assert "maljan_queue_lease" not in ctx

    @pytest.mark.asyncio
    async def test_the_lease_is_renewed_and_ends_when_the_key_is_gone(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.worker import analysis_worker as worker_module

        monkeypatch.setattr(worker_module, "JOB_OWNER_REFRESH_SECONDS", 0.01)
        redis = _ExpiringRedis()
        key = in_progress_key_prefix + "job-2"
        await redis.psetex(key, 10**15, b"1")
        ctx: dict = {"redis": redis, "job_id": "job-2"}
        await lease_queue_claim(ctx)
        await asyncio.sleep(0.05)
        assert redis.renewals >= 3
        del redis.ttl_ms[key]
        task = ctx["maljan_queue_lease"]
        await asyncio.wait_for(task, 1.0)
        assert task.done() and not task.cancelled()
