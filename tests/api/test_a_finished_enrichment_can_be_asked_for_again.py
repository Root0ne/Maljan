"""A report enriched a minute ago can be enriched again; a queued one still coalesces.

arq refuses a job id while its job key or its result key exists, and keeps a
result for an hour. The manual "Enrich" button answered ``already_queued`` for
that hour after any enrichment finished, with nothing queued at all. The kept
result is dropped before the enqueue; the job key, which is what makes two
triggers for a queued or running enrichment one, is left alone (AUD-36).
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import fakeredis
import pytest
from arq.connections import ArqRedis
from arq.constants import job_key_prefix, result_key_prefix

from app.worker.enrich_worker import ENRICHMENT_QUEUE, enqueue_enrichment


def _pool() -> ArqRedis:
    server = fakeredis.FakeServer()
    return ArqRedis(connection_pool=fakeredis.FakeAsyncRedis(server=server).connection_pool)


@pytest.mark.asyncio
async def test_a_finished_enrichment_does_not_refuse_the_next_one() -> None:
    pool = _pool()
    report_id = uuid.uuid4()
    job_id = f"enrich:{ENRICHMENT_QUEUE}:{report_id}"
    # What arq keeps for an hour once the job has run: its result, no job key.
    await pool.set(result_key_prefix + job_id, b"finished", ex=3600)

    with patch("app.worker.enrich_worker.runtime_config.get", AsyncMock(return_value=True)):
        queued = await enqueue_enrichment(pool, report_id)

    assert queued == job_id
    assert await pool.exists(job_key_prefix + job_id)


@pytest.mark.asyncio
async def test_a_queued_enrichment_still_coalesces() -> None:
    pool = _pool()
    report_id = uuid.uuid4()

    with patch("app.worker.enrich_worker.runtime_config.get", AsyncMock(return_value=True)):
        first = await enqueue_enrichment(pool, report_id)
        second = await enqueue_enrichment(pool, report_id)

    assert first is not None
    assert second is None


@pytest.mark.asyncio
async def test_a_redis_that_cannot_drop_the_result_still_gets_the_enqueue() -> None:
    pool = MagicMock()
    pool.delete = AsyncMock(side_effect=ConnectionError("gone"))
    pool.enqueue_job = AsyncMock(return_value=MagicMock(job_id="enrich-1"))

    with patch("app.worker.enrich_worker.runtime_config.get", AsyncMock(return_value=True)):
        assert await enqueue_enrichment(pool, uuid.uuid4()) == "enrich-1"
