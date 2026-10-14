"""The API's side of the ATT&CK cache: ask the worker that holds it, and wait.

The cache is on the analysis worker's volume and nowhere else, so the API
never reads or writes it. Each question is an arq job on ``ATTCK_QUEUE``,
answered by the small worker that runs inside the analysis worker's process
(``app.worker.attck_worker``):

* status and check are waited for, briefly, and answered in the request;
* an update is queued and its id returned, and the console polls it.

A job that nobody picks up in time is dropped by arq (``_expires``) rather
than run later as a surprise, and the request says the worker did not answer.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

from arq.connections import ArqRedis, create_pool
from arq.jobs import Job, JobStatus

from app.config import settings
from app.worker.queues import ATTCK_QUEUE, build_redis_settings

# A status read is a few file stats; a check adds one small download with its
# own twenty-second limit.
STATUS_WAIT_SECONDS = 15.0
CHECK_WAIT_SECONDS = 45.0
# An update the worker has not started within this long is not started at all.
UPDATE_EXPIRES_SECONDS = 600

UPDATE_FUNCTION = "attck_update_now"

# arq's own job ids: 32 hex characters.
_JOB_ID_RE = re.compile(r"\A[0-9a-f]{32}\Z")

_pool: ArqRedis | None = None
_pool_lock = asyncio.Lock()


class WorkerDidNotAnswer(RuntimeError):
    """The worker that holds the ATT&CK cache did not answer in time."""


async def _arq() -> ArqRedis:
    global _pool
    async with _pool_lock:
        if _pool is None:
            _pool = await create_pool(
                build_redis_settings(settings.redis_url), default_queue_name=ATTCK_QUEUE
            )
        return _pool


def _no_answer(wait: float) -> WorkerDidNotAnswer:
    return WorkerDidNotAnswer(
        f"The analysis worker, which holds the ATT&CK cache, did not answer within "
        f"{int(wait)} seconds. Is it running?"
    )


async def _ask(function: str, *args: Any, wait: float) -> dict[str, Any]:
    try:
        pool = await _arq()
        job = await pool.enqueue_job(
            function, *args, _queue_name=ATTCK_QUEUE, _expires=int(wait) + 1
        )
    except Exception as exc:  # noqa: BLE001 — Redis down is the same answer
        raise WorkerDidNotAnswer(f"The ATT&CK job could not be queued: {exc}") from exc
    if job is None:
        raise WorkerDidNotAnswer("The ATT&CK job could not be queued.")
    try:
        result = await job.result(timeout=wait, poll_delay=0.25)
    except TimeoutError as exc:
        raise _no_answer(wait) from exc
    except Exception as exc:  # noqa: BLE001 — an expired or failed job
        raise WorkerDidNotAnswer(f"The ATT&CK job did not finish: {exc}") from exc
    if not isinstance(result, dict):
        raise WorkerDidNotAnswer("The ATT&CK job answered with nothing readable.")
    return result


async def status(refresh_days: int) -> dict[str, Any]:
    return await _ask("attck_status", int(refresh_days), wait=STATUS_WAIT_SECONDS)


async def check(triggered_by: dict[str, Any], refresh_days: int) -> dict[str, Any]:
    return await _ask("attck_check", triggered_by, int(refresh_days), wait=CHECK_WAIT_SECONDS)


async def start_update(triggered_by: dict[str, Any]) -> str:
    """Queue an update; its id, for ``update_progress``."""
    try:
        pool = await _arq()
        job = await pool.enqueue_job(
            UPDATE_FUNCTION, triggered_by, _queue_name=ATTCK_QUEUE, _expires=UPDATE_EXPIRES_SECONDS
        )
    except Exception as exc:  # noqa: BLE001
        raise WorkerDidNotAnswer(f"The ATT&CK update could not be queued: {exc}") from exc
    if job is None:
        raise WorkerDidNotAnswer("The ATT&CK update could not be queued.")
    return job.job_id


def is_job_id(job_id: str) -> bool:
    return bool(_JOB_ID_RE.match(job_id or ""))


async def update_progress(job_id: str) -> dict[str, Any]:
    """``{"state": queued|running|done|unknown, "result": ...}`` for one update.

    ``unknown`` for an id that is not an ATT&CK update this queue holds, or
    one whose result has expired: the poll never reads another job's result.
    """
    pool = await _arq()
    job = Job(job_id, pool, _queue_name=ATTCK_QUEUE)
    info = await job.info()
    if info is None or info.function != UPDATE_FUNCTION:
        return {"job_id": job_id, "state": "unknown", "result": None}
    state = await job.status()
    if state in (JobStatus.queued, JobStatus.deferred):
        return {"job_id": job_id, "state": "queued", "result": None}
    if state == JobStatus.in_progress:
        return {"job_id": job_id, "state": "running", "result": None}
    if state != JobStatus.complete:
        return {"job_id": job_id, "state": "unknown", "result": None}
    outcome = await job.result_info()
    result = getattr(outcome, "result", None)
    if not isinstance(result, dict):
        result = {"ok": False, "outcome": "failed", "reason": f"the update stopped: {result}"}
    return {"job_id": job_id, "state": "done", "result": result}
