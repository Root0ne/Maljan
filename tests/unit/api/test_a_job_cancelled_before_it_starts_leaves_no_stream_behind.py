"""A job cancelled before it started leaves no event stream behind.

The cancel writes its ``cancelled`` event into the job's Redis stream. For a
job still queued that write is the only one the stream ever gets, and the
stream's expiry used to be set by the worker's publisher alone, so each such
job left a small key in Redis for good. The cancel now writes the event and
the stream's lifetime in one transaction, read from the one constant the
publisher uses too, and a Redis that refuses it is logged, not passed over.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest


class _Pipeline:
    """A MULTI/EXEC transaction: commands queued, sent together by ``execute``."""

    def __init__(self, redis: _Redis, transaction: bool) -> None:
        self._redis = redis
        self._transaction = transaction
        self.queued: list[tuple[str, tuple[Any, ...]]] = []

    async def __aenter__(self) -> _Pipeline:
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.queued = []

    def xadd(self, key: str, fields: dict[str, str], **kwargs: Any) -> _Pipeline:
        self.queued.append(("xadd", (key,)))
        return self

    def expire(self, key: str, seconds: int) -> _Pipeline:
        self.queued.append(("expire", (key, seconds)))
        return self

    async def execute(self) -> list[Any]:
        if self._redis.exec_fails:
            raise ConnectionError("redis gone")
        self._redis.calls.append(
            ("transaction" if self._transaction else "batch", tuple(self.queued))
        )
        return [True] * len(self.queued)


class _Redis:
    """The Redis calls the cancel and the publisher make, recorded in order."""

    def __init__(self, *, exec_fails: bool = False) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.counters: dict[str, int] = {}
        self.exec_fails = exec_fails

    def pipeline(self, transaction: bool = True) -> _Pipeline:
        return _Pipeline(self, transaction)

    async def set(self, key: str, value: Any, **kwargs: Any) -> bool:
        self.calls.append(("set", (key,)))
        return True

    async def exists(self, key: str) -> int:
        return 1 if key in self.counters else 0

    async def incr(self, key: str) -> int:
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

    async def publish(self, channel: str, message: str) -> int:
        self.calls.append(("publish", (channel,)))
        return 1

    async def xadd(self, key: str, fields: dict[str, str], **kwargs: Any) -> str:
        self.calls.append(("xadd", (key,)))
        return "1-0"

    async def expire(self, key: str, seconds: int) -> bool:
        self.calls.append(("expire", (key, seconds)))
        return True

    async def aclose(self) -> None:
        self.calls.append(("aclose", ()))


def _cancel(redis: _Redis, status: str, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, uuid.UUID]:
    from app.services import analysis_service as svc_mod

    monkeypatch.setattr(svc_mod.aioredis, "from_url", lambda *a, **k: redis)
    monkeypatch.setattr(svc_mod, "_abort_queued_analysis", AsyncMock())
    job_id = uuid.uuid4()
    service = svc_mod.AnalysisService(AsyncMock())
    job = SimpleNamespace(status=status, completed_at=None)
    service.get_job = AsyncMock(return_value=job)  # type: ignore[method-assign]
    returned = asyncio.run(service.cancel_job(job_id, SimpleNamespace(id=uuid.uuid4())))
    assert returned is job and job.status == "cancelled"
    return job, job_id


@pytest.mark.parametrize("status", ["pending", "running"])
def test_the_cancel_writes_the_event_and_the_stream_s_lifetime_in_one_transaction(
    status: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.job_events import STREAM_TTL_SECONDS, stream_key

    redis = _Redis()
    _, job_id = _cancel(redis, status, monkeypatch)

    key = stream_key(job_id)
    transactions = [args for kind, args in redis.calls if kind == "transaction"]
    assert transactions == [(("xadd", (key,)), ("expire", (key, STREAM_TTL_SECONDS)))]
    # Nothing writes the stream outside it.
    assert ("xadd", (key,)) not in redis.calls


def test_the_publisher_and_the_cancel_read_one_lifetime() -> None:
    """One constant, a day as before: the cancel cannot drift from the publisher."""
    from app.services.job_events import STREAM_TTL_SECONDS, stream_key
    from app.worker.analysis_worker import _publish_event

    assert STREAM_TTL_SECONDS == 86_400
    redis = _Redis()
    job_id = str(uuid.uuid4())

    asyncio.run(_publish_event(redis, job_id, "status_change", {"status": "running"}))

    assert ("xadd", (stream_key(job_id),)) in redis.calls
    assert ("expire", (stream_key(job_id), STREAM_TTL_SECONDS)) in redis.calls


def test_a_redis_that_refuses_the_transaction_is_logged_and_never_breaks_the_cancel(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The row is cancelled first; Redis is best-effort, and its refusal is said."""
    redis = _Redis(exec_fails=True)
    with caplog.at_level(logging.WARNING):
        _, job_id = _cancel(redis, "pending", monkeypatch)

    said = [r.getMessage() for r in caplog.records if str(job_id) in r.getMessage()]
    assert len(said) == 1 and "ConnectionError" in said[0], said
    assert not [kind for kind, _ in redis.calls if kind == "transaction"]


def test_the_cancel_is_committed_before_redis_is_touched(monkeypatch: pytest.MonkeyPatch) -> None:
    """The row lock is not held across Redis I/O."""
    from app.services import analysis_service as svc_mod

    order: list[str] = []
    redis = _Redis()
    monkeypatch.setattr(
        svc_mod.aioredis,
        "from_url",
        lambda *a, **k: (order.append("redis"), redis)[1],
    )
    monkeypatch.setattr(svc_mod, "_abort_queued_analysis", AsyncMock())
    db = AsyncMock()
    db.commit.side_effect = lambda: order.append("commit")
    service = svc_mod.AnalysisService(db)
    job = SimpleNamespace(status="running", completed_at=None)
    service.get_job = AsyncMock(return_value=job)  # type: ignore[method-assign]
    asyncio.run(service.cancel_job(uuid.uuid4(), SimpleNamespace(id=uuid.uuid4())))
    assert order[0] == "commit" and "redis" in order
