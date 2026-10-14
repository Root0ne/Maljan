"""The ATT&CK cache's own small worker, inside the analysis worker's process.

The cached ATT&CK bundles live on the analysis worker's volume
(``attck_cache`` in ``docker/docker-compose.yml``), and that process is the
only writer of them. The console's status, check and update are arq jobs on a
queue of their own (``ATTCK_QUEUE``), read by a second arq ``Worker`` the
analysis worker starts beside its own:

* in the same process, so the single writer stays single and no second
  service mounts the cache;
* not in the analysis slot: that worker runs one job at a time
  (``concurrent_analyses_refusal``), and an analysis can hold it for hours, so
  a check queued there would wait behind it. Here a check is answered in
  seconds while an analysis runs, and the file work happens in a thread so the
  analysis's own event loop is not held up.

The hourly cron is the automatic check: it runs the update when the cache is
older than ``validation.attck_refresh_days``, and never when that is 0.

Every function returns a plain dict and never raises: the API reads the result
and shows it as it is.
"""

from __future__ import annotations

import asyncio
import threading
import time
from contextlib import suppress
from typing import Any

from arq import cron
from arq.worker import Worker
from maljan.memory import attck_update

from app.config import settings
from app.logging_config import get_logger
from app.worker.queues import ATTCK_QUEUE, build_redis_settings

logger = get_logger("worker.attck")

# How many of these jobs run at once. A status read and a check must not wait
# behind an update that is downloading; two updates at once never interleave,
# because the second finds the cache lock held and says so.
ATTCK_MAX_JOBS = 4
# A slow mirror of three bundles of tens of megabytes, with room.
ATTCK_JOB_TIMEOUT = 1800
# The poll after an update reads its result from here.
ATTCK_KEEP_RESULT = 3600
# The share of the job's time the downloads and their read-back may take; the
# rest is for the swap and for the answer to reach arq before it gives up.
ATTCK_DOWNLOAD_SHARE = 0.9


def _failed(kind: str, exc: BaseException) -> dict[str, Any]:
    return {"ok": False, "outcome": "failed", "reason": f"the {kind} stopped: {exc}"}


async def attck_status(ctx: dict, refresh_days: int) -> dict[str, Any]:
    """The cache as the console shows it. ``refresh_days`` is the stored setting."""
    try:
        return await asyncio.to_thread(attck_update.status, int(refresh_days))
    except Exception as exc:  # noqa: BLE001 — answered, never raised
        logger.warning("ATT&CK status could not be read: %s", exc)
        return _failed("status read", exc)


async def attck_check(
    ctx: dict, triggered_by: dict[str, Any], refresh_days: int | None = None
) -> dict[str, Any]:
    """Compare the cache with MITRE's release index; downloads no bundle."""
    logger.info("ATT&CK check requested by user %s.", triggered_by.get("user_id") or "unknown")
    try:
        return await asyncio.to_thread(attck_update.check, triggered_by, refresh_days)
    except Exception as exc:  # noqa: BLE001 — answered, never raised
        logger.warning("ATT&CK check stopped: %s", exc)
        return _failed("check", exc)


async def attck_update_now(ctx: dict, triggered_by: dict[str, Any]) -> dict[str, Any]:
    """Download, read back and swap in every outdated domain, as one administrator asked."""
    logger.info("ATT&CK update requested by user %s.", triggered_by.get("user_id") or "unknown")
    # The thread outlives a cancelled job, so it is told to stop, and it has a
    # deadline of its own inside the job's: either way it ends before the
    # swap, and a job arq gave up on never replaces files afterwards.
    stop = threading.Event()
    deadline = time.monotonic() + ATTCK_JOB_TIMEOUT * ATTCK_DOWNLOAD_SHARE
    try:
        return await asyncio.to_thread(
            attck_update.update, triggered_by, trigger="console", deadline=deadline, stop=stop
        )
    except asyncio.CancelledError:
        stop.set()
        raise
    except Exception as exc:  # noqa: BLE001 — answered, never raised
        logger.warning("ATT&CK update stopped: %s", exc)
        return _failed("update", exc)


async def _stored_refresh_days(ctx: dict) -> int | None:
    """The saved interval, or ``None`` when the store cannot be read.

    Not the shipped default on a failed read: an operator who set 0 to keep
    this machine from downloading must not have a download started because
    the database was briefly unreachable.
    """
    from app.services.settings_service import core_settings_cache

    factory = ctx.get("db_session")
    if factory is None:
        return None
    try:
        async with factory() as db:
            core = await core_settings_cache.get(db)
        return int(core.validation.attck_refresh_days)
    except Exception as exc:  # noqa: BLE001 — a skipped hour, said
        logger.warning("ATT&CK automatic check skipped: the interval is not readable (%s).", exc)
        return None


async def attck_scheduled_update(ctx: dict) -> dict[str, Any]:
    """The automatic check: update when the cache is older than the interval."""
    days = await _stored_refresh_days(ctx)
    if days is None:
        return {"ok": False, "outcome": "skipped", "reason": "the interval is not readable"}
    try:
        result = await asyncio.to_thread(attck_update.scheduled_update, days)
    except Exception as exc:  # noqa: BLE001 — answered, never raised
        logger.warning("ATT&CK automatic check stopped: %s", exc)
        return _failed("automatic check", exc)
    if result is None:
        return {"ok": True, "outcome": "not_due", "reason": "", "refresh_days": days}
    return result


ATTCK_FUNCTIONS = (attck_status, attck_check, attck_update_now)


def build_attck_worker(db_session: Any) -> Worker:
    """The ATT&CK queue's worker, for the analysis worker to run beside its own.

    ``handle_signals`` is off: the analysis worker owns the process's signals
    and closes this one from its shutdown. Its own Redis pool, because closing
    a worker closes the pool it holds.
    """
    return Worker(
        functions=list(ATTCK_FUNCTIONS),
        queue_name=ATTCK_QUEUE,
        # Hourly (``attck_update.SCHEDULE_PERIOD_SECONDS``, the back-off's
        # unit), off the minute the nightly purge and most deployments use.
        cron_jobs=[cron(attck_scheduled_update, minute=41)],
        redis_settings=build_redis_settings(settings.redis_url),
        handle_signals=False,
        max_jobs=ATTCK_MAX_JOBS,
        job_timeout=ATTCK_JOB_TIMEOUT,
        keep_result=ATTCK_KEEP_RESULT,
        max_tries=1,
        ctx={"db_session": db_session},
    )


async def start_attck_worker(ctx: dict) -> None:
    """Start the ATT&CK worker beside the analysis worker. Never raises.

    A worker that cannot start leaves the analyses running: the console then
    says the worker did not answer, which is the truth.
    """
    try:
        worker = build_attck_worker(ctx.get("db_session"))
        ctx["attck_worker"] = worker
        task = asyncio.create_task(worker.main())
        # Where arq's own stop looks for the loop it cancels.
        worker.main_task = task
        ctx["attck_worker_task"] = task
        logger.info(
            "ATT&CK cache worker started: reading %s",
            ATTCK_QUEUE,
            extra={"component": "worker.lifecycle"},
        )
    except Exception as exc:  # noqa: BLE001 — the analyses go on without it
        logger.warning(
            "ATT&CK cache worker not started (%s); the console cannot check or update the cache.",
            exc,
            extra={"component": "worker.lifecycle"},
        )


async def stop_attck_worker(ctx: dict, grace: float) -> None:
    """Close the ATT&CK worker, bounded by ``grace`` seconds."""
    worker: Worker | None = ctx.get("attck_worker")
    task: asyncio.Task | None = ctx.get("attck_worker_task")
    # arq's close cancels the polling loop and any job still running; a job's
    # thread is left to finish or to die with the process, and what it leaves
    # is a ``.part`` file the next update clears.
    if worker is not None:
        with suppress(asyncio.CancelledError, Exception):
            await asyncio.wait_for(worker.close(), timeout=grace)
        # arq's close stops at the cancelled jobs it waits for; the pool it
        # would have closed after them is closed here.
        pool = getattr(worker, "_pool", None)
        if pool is not None:
            with suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(pool.close(close_connection_pool=True), timeout=grace)
    if task is not None and not task.done():
        task.cancel()
        with suppress(asyncio.CancelledError, Exception):
            await task


# What the catalogue in this process was read from. ``None`` until the first
# analysis looks.
_seen_signature: tuple[Any, ...] | None = None


def drop_a_replaced_catalogue() -> bool:
    """Forget the in-process ATT&CK catalogue when its files were replaced.

    Called at the start of an analysis, which is a moment no analysis is
    running in this process (one at a time). An update swaps files that a
    warm index in this process was built from; the next analysis reads the new
    ones instead of the catalogue the process happened to hold. Returns
    whether anything was dropped.
    """
    global _seen_signature
    try:
        signature = attck_update.cache_signature()
    except Exception:  # noqa: BLE001 — a failed look changes nothing
        return False
    if _seen_signature is None or signature == _seen_signature:
        _seen_signature = signature
        return False
    _seen_signature = signature
    from maljan.memory import attck_loader
    from maljan.tools import knowledge

    attck_loader.reset_caches()
    knowledge.reset_indices()
    logger.info("The ATT&CK cache was replaced; this analysis reads the new catalogue.")
    return True
