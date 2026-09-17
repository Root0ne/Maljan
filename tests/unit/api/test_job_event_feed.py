"""The sequenced feed: numbering, batching, resuming and replay.

The route functions are called directly against stubs, the way
``test_evidence_endpoint.py`` does: there is no async database driver in the
unit environment, and what is being pinned here is who gets which events and
in what order, not the SQL that fetches them.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import pytest

from app.services.job_events import read_events
from app.worker.analysis_worker import _JobEventBuffer, _publish_event, _start_event_feed
from app.worker.analysis_worker import _stop_event_feed as stop_feed


class _FakeRedis:
    """Enough Redis for the publisher and the stream reader.

    ``incr`` is atomic in the real thing and is a plain increment here, which
    is the same thing under asyncio as long as nothing awaits between the read
    and the write — which is what the publisher relies on.
    """

    def __init__(self, *, stream: list[tuple[str, dict[str, str]]] | None = None) -> None:
        self.counters: dict[str, int] = {}
        self.published: list[tuple[str, str]] = []
        self.stream: list[tuple[str, dict[str, str]]] = list(stream or [])
        self.incr_fails = False
        self.xrange_fails = False

    async def incr(self, key: str) -> int:
        if self.incr_fails:
            raise RuntimeError("READONLY")
        self.counters[key] = self.counters.get(key, 0) + 1
        return self.counters[key]

    async def expire(self, key: str, seconds: int) -> bool:
        return True

    async def publish(self, channel: str, message: str) -> int:
        self.published.append((channel, message))
        return 1

    async def xadd(self, key: str, fields: dict[str, str], **kwargs: Any) -> str:
        entry_id = f"{len(self.stream) + 1}-0"
        self.stream.append((entry_id, dict(fields)))
        return entry_id

    async def xrange(self, key: str, min: str, max: str, count: int) -> list[Any]:
        if self.xrange_fails:
            raise RuntimeError("no such key")
        return self.stream[:count]


class _Rows:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> _Rows:
        return self

    def all(self) -> list[Any]:
        return self._rows


class _Session:
    """Answers every query with the same rows and records what it was asked."""

    def __init__(self, rows: list[Any] | None = None) -> None:
        self.rows = rows or []
        self.statements: list[Any] = []
        self.added: list[Any] = []
        self.commits = 0

    async def execute(self, statement: Any) -> _Rows:
        self.statements.append(statement)
        return _Rows(self.rows)

    def add_all(self, rows: list[Any]) -> None:
        self.added.extend(rows)

    async def commit(self) -> None:
        self.commits += 1

    async def __aenter__(self) -> _Session:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


def _factory(session: _Session) -> Any:
    return lambda: session


def _row(seq: int, event_type: str = "agent_message") -> Any:
    class _JobEventRow:
        def __init__(self) -> None:
            self.seq = seq
            self.type = event_type
            self.payload = {"seq": seq, "speaker": "static"}
            self.ts = None

    return _JobEventRow()


def _stream_entry(seq: int, event_type: str = "agent_message") -> tuple[str, dict[str, str]]:
    payload = {"type": event_type, "data": {"seq": seq}, "ts": "2026-09-25T00:00:00+00:00"}
    return (f"{seq}-0", {"payload": json.dumps(payload)})


def _seqs(events: list[dict[str, Any]]) -> list[int]:
    return [int(e["data"]["seq"]) for e in events]


class TestTheSequence:
    def test_every_event_carries_the_next_number(self) -> None:
        redis_conn = _FakeRedis()
        job_id = str(uuid.uuid4())

        async def run() -> None:
            for _ in range(3):
                await _publish_event(redis_conn, job_id, "agent_message", {"speaker": "static"})

        asyncio.run(run())
        published = [json.loads(message) for _channel, message in redis_conn.published]
        assert [p["data"]["seq"] for p in published] == [1, 2, 3]
        assert published[0]["data"]["speaker"] == "static"

    def test_concurrent_publishers_leave_no_gap_and_no_repeat(self) -> None:
        redis_conn = _FakeRedis()
        job_id = str(uuid.uuid4())

        async def run() -> None:
            await asyncio.gather(
                *(
                    _publish_event(redis_conn, job_id, "tool_call_started", {"tool": f"t{i}"})
                    for i in range(200)
                )
            )

        asyncio.run(run())
        numbers = sorted(
            json.loads(message)["data"]["seq"] for _channel, message in redis_conn.published
        )
        assert numbers == list(range(1, 201))

    def test_two_jobs_are_numbered_apart(self) -> None:
        redis_conn = _FakeRedis()
        first, second = str(uuid.uuid4()), str(uuid.uuid4())

        async def run() -> None:
            await _publish_event(redis_conn, first, "status_change", {})
            await _publish_event(redis_conn, second, "status_change", {})
            await _publish_event(redis_conn, first, "status_change", {})

        asyncio.run(run())
        numbers = [json.loads(m)["data"]["seq"] for _c, m in redis_conn.published]
        assert numbers == [1, 1, 2]

    def test_a_refusing_counter_still_numbers_the_feed(self) -> None:
        redis_conn = _FakeRedis()
        redis_conn.incr_fails = True
        job_id = str(uuid.uuid4())

        async def run() -> None:
            for _ in range(3):
                await _publish_event(redis_conn, job_id, "agent_message", {})
            await stop_feed(job_id)

        asyncio.run(run())
        numbers = [json.loads(m)["data"]["seq"] for _c, m in redis_conn.published]
        assert numbers == [1, 2, 3]


class TestIncrementalPersistence:
    def test_a_full_batch_is_written_without_waiting_for_the_run_to_end(self) -> None:
        session = _Session()
        buffer = _JobEventBuffer(str(uuid.uuid4()), _factory(session))

        async def run() -> None:
            for seq in range(1, _JobEventBuffer.BATCH + 1):
                await buffer.add(seq, "agent_message", {"seq": seq}, "2026-09-25T00:00:00+00:00")

        asyncio.run(run())
        assert len(session.added) == _JobEventBuffer.BATCH
        assert session.commits == 1

    def test_a_cancelled_run_keeps_the_lines_it_had_got_to(self) -> None:
        session = _Session()
        job_id = str(uuid.uuid4())
        redis_conn = _FakeRedis()

        async def run() -> None:
            _start_event_feed(job_id, _factory(session))
            # Well under one batch, and the run stops here: this is the case
            # the table exists for.
            for index in range(5):
                await _publish_event(redis_conn, job_id, "agent_message", {"n": index})
            await _publish_event(redis_conn, job_id, "cancelled", {})
            await stop_feed(job_id)

        asyncio.run(run())
        assert [row.seq for row in session.added] == [1, 2, 3, 4, 5, 6]
        assert session.added[-1].type == "cancelled"

    def test_a_database_that_refuses_the_batch_never_fails_the_publish(self) -> None:
        class _Broken(_Session):
            async def commit(self) -> None:
                raise RuntimeError("connection reset")

        session = _Broken()
        buffer = _JobEventBuffer(str(uuid.uuid4()), _factory(session))

        async def run() -> None:
            await buffer.add(1, "agent_message", {"seq": 1}, "2026-09-25T00:00:00+00:00")
            await buffer.flush()

        asyncio.run(run())

    def test_a_run_with_no_feed_registered_still_publishes(self) -> None:
        redis_conn = _FakeRedis()

        async def run() -> None:
            await _publish_event(redis_conn, str(uuid.uuid4()), "status_change", {})

        asyncio.run(run())
        assert len(redis_conn.published) == 1


class TestReadingItBack:
    def test_since_returns_only_what_the_client_has_not_seen(self) -> None:
        redis_conn = _FakeRedis(stream=[_stream_entry(seq) for seq in range(1, 6)])
        events = asyncio.run(read_events(_Session(), redis_conn, uuid.uuid4(), since=3))
        assert _seqs(events) == [4, 5]

    def test_no_cursor_returns_the_whole_window(self) -> None:
        redis_conn = _FakeRedis(stream=[_stream_entry(seq) for seq in range(1, 4)])
        events = asyncio.run(read_events(_Session(), redis_conn, uuid.uuid4()))
        assert _seqs(events) == [1, 2, 3]

    def test_an_expired_stream_is_replayed_from_the_table(self) -> None:
        redis_conn = _FakeRedis(stream=[])
        session = _Session(rows=[_row(1), _row(2), _row(3)])
        events = asyncio.run(read_events(session, redis_conn, uuid.uuid4()))
        assert _seqs(events) == [1, 2, 3]
        assert events[0]["type"] == "agent_message"

    def test_an_unreadable_stream_falls_back_the_same_way(self) -> None:
        redis_conn = _FakeRedis()
        redis_conn.xrange_fails = True
        session = _Session(rows=[_row(7)])
        events = asyncio.run(read_events(session, redis_conn, uuid.uuid4(), since=6))
        assert _seqs(events) == [7]

    def test_a_cursor_older_than_the_capped_stream_is_filled_from_the_table(self) -> None:
        # The stream has been trimmed to its last two events; the client is
        # resuming from 1, so the hole in front of them has to come from the
        # table rather than being handed over silently.
        redis_conn = _FakeRedis(stream=[_stream_entry(4), _stream_entry(5)])
        session = _Session(rows=[_row(2), _row(3), _row(4), _row(5)])
        events = asyncio.run(read_events(session, redis_conn, uuid.uuid4(), since=1))
        assert _seqs(events) == [2, 3, 4, 5]

    def test_an_event_both_stores_hold_is_returned_once(self) -> None:
        redis_conn = _FakeRedis(stream=[_stream_entry(2), _stream_entry(3)])
        session = _Session(rows=[_row(1), _row(2), _row(3)])
        events = asyncio.run(read_events(session, redis_conn, uuid.uuid4(), since=0))
        assert _seqs(events) == [1, 2, 3]

    def test_a_run_from_before_sequencing_still_replays(self) -> None:
        legacy = (
            "1-0",
            {"payload": json.dumps({"type": "agent_message", "data": {"speaker": "static"}})},
        )
        redis_conn = _FakeRedis(stream=[legacy])
        events = asyncio.run(read_events(_Session(), redis_conn, uuid.uuid4()))
        assert len(events) == 1
        assert events[0]["data"] == {"speaker": "static"}

    def test_a_malformed_stream_entry_is_skipped_rather_than_raised(self) -> None:
        redis_conn = _FakeRedis(stream=[("1-0", {"payload": "not json"}), _stream_entry(2)])
        events = asyncio.run(read_events(_Session(), redis_conn, uuid.uuid4()))
        assert _seqs(events) == [2]


class TestTheEventsEndpoint:
    class _Service:
        def __init__(self, job: Any) -> None:
            self._job = job

        async def get_job(self, job_id: uuid.UUID, user: Any) -> Any:
            return self._job

    @pytest.mark.asyncio
    async def test_a_job_the_caller_does_not_own_is_not_found(self) -> None:
        from fastapi import HTTPException

        from app.api.v1.jobs import get_job_events

        with pytest.raises(HTTPException) as exc:
            await get_job_events(
                job_id=uuid.uuid4(),
                limit=500,
                since=None,
                user=object(),
                svc=self._Service(None),
                db=_Session(),
            )
        assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_the_cursor_is_passed_through_to_the_reader(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import app.api.v1.jobs as jobs_module

        seen: dict[str, Any] = {}

        async def fake_read(db, redis_conn, job_id, *, since=None, limit=500):  # noqa: ANN001
            seen["since"] = since
            seen["limit"] = limit
            return [{"type": "agent_message", "data": {"seq": 9}, "ts": None}]

        monkeypatch.setattr("app.services.job_events.read_events", fake_read)
        monkeypatch.setattr(
            jobs_module, "AnalysisService", jobs_module.AnalysisService, raising=False
        )

        class _Conn:
            async def aclose(self) -> None:
                return None

        monkeypatch.setattr("redis.asyncio.from_url", lambda *a, **k: _Conn())
        body = await jobs_module.get_job_events(
            job_id=uuid.uuid4(),
            limit=10,
            since=8,
            user=object(),
            svc=self._Service(object()),
            db=_Session(),
        )
        assert seen == {"since": 8, "limit": 10}
        assert body["count"] == 1
