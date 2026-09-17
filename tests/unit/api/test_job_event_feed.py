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

    def test_the_task_flushes_the_feed_on_every_way_out_of_a_run(self) -> None:
        """The property the cancelled-run test above can only assume.

        Driving ``run_analysis`` to its cancellation return needs a worker, a
        queue and a database, so what is checked here is the wiring: the flush
        is in the ``finally`` of the one ``try`` that encloses the task's early
        returns, so success, failure and every cancellation leave through it.
        """
        import ast
        import inspect

        from app.worker import analysis_worker

        tree = ast.parse(inspect.getsource(analysis_worker))
        task = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_analysis"
        )
        tries = [node for node in ast.walk(task) if isinstance(node, ast.Try) and node.finalbody]
        flushing = [
            node
            for node in tries
            if any(
                isinstance(call.func, ast.Name) and call.func.id == "_stop_event_feed"
                for statement in node.finalbody
                for call in ast.walk(statement)
                if isinstance(call, ast.Call)
            )
        ]
        assert len(flushing) == 1, "the feed is flushed in exactly one place"

        # Every ``return`` of the task — the early ones a cancelled or invalid
        # job takes among them, and the one the failure handler takes — is
        # inside that ``try``, which is what makes its ``finally`` run.
        guarded = {id(node) for node in ast.walk(flushing[0])}
        returns = [node for node in ast.walk(task) if isinstance(node, ast.Return)]
        assert returns
        assert all(id(node) in guarded for node in returns), (
            "a return that skips the try leaves the run's last lines unwritten"
        )

    def test_the_feed_is_registered_where_the_finally_can_reach_it(self) -> None:
        """Registered inside the same ``try``'s enclosing block, not above it.

        Registered above the session context, a raise while entering that
        context left the buffer in the module-global map for the life of the
        process.
        """
        import inspect

        from app.worker import analysis_worker

        source = inspect.getsource(analysis_worker.run_analysis)
        started = source.index("_start_event_feed(")
        session = source.index("async with db_session() as db:")
        assert session < started, "the feed is registered inside the session context"
        assert started < source.index("\n        try:"), "and before the try that flushes it"

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

    def test_a_cursorless_read_of_a_trimmed_stream_starts_at_the_beginning(self) -> None:
        """No cursor means "from the beginning", which is ``since=0``.

        A run publishes more than the stream's 1 000-entry cap — two events
        per tool call plus a delta per model turn makes that ordinary — and
        the stream no longer reaches back to its own start. A console mounting
        fresh would otherwise be handed a conversation beginning in the middle
        of the debate with nothing saying so, while the table holds all of it.
        """
        # The stream has been trimmed to its last three events.
        redis_conn = _FakeRedis(stream=[_stream_entry(seq) for seq in (4, 5, 6)])
        session = _Session(rows=[_row(seq) for seq in range(1, 7)])
        events = asyncio.run(read_events(session, redis_conn, uuid.uuid4()))
        assert _seqs(events) == [1, 2, 3, 4, 5, 6]

    def test_a_cursorless_read_of_an_untrimmed_stream_never_asks_the_table(self) -> None:
        # The stream reaches back to seq 1, so it is the whole answer and the
        # hot path stays one Redis call.
        redis_conn = _FakeRedis(stream=[_stream_entry(seq) for seq in (1, 2, 3)])
        session = _Session(rows=[_row(99)])
        events = asyncio.run(read_events(session, redis_conn, uuid.uuid4()))
        assert _seqs(events) == [1, 2, 3]
        assert session.statements == []

    def test_a_trimmed_stream_contributes_what_the_table_has_not_got_yet(self) -> None:
        # The batch writer is up to two seconds behind the publisher, so the
        # newest events are in the stream and not yet in the table.
        redis_conn = _FakeRedis(stream=[_stream_entry(seq) for seq in (4, 5, 6, 7)])
        session = _Session(rows=[_row(seq) for seq in range(1, 6)])
        events = asyncio.run(read_events(session, redis_conn, uuid.uuid4()))
        assert _seqs(events) == [1, 2, 3, 4, 5, 6, 7]

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


class TestThePublisherIsTheGuarantee:
    """Every string on the wire is scrubbed once, where the wire begins.

    Seven producers build these payloads and two of them scrubbed. A delta and
    the ``agent_message`` that closes the same turn carry the same model text,
    so a credential the model echoed was redacted while it streamed and then
    published in the clear in the closing message, its ``job_events`` row and
    the stored transcript. A producer may still scrub — this is the guarantee
    that one which forgets cannot leak.
    """

    SECRET = "sk-" + "P" * 32
    HOST_PATH = "/home/operator/maljan/data/samples/ab12/evil.exe"

    def _published(self, redis_conn: _FakeRedis) -> list[dict[str, Any]]:
        return [json.loads(message) for _channel, message in redis_conn.published]

    def _publish(self, event_type: str, data: dict[str, Any]) -> tuple[Any, _Session]:
        redis_conn = _FakeRedis()
        session = _Session()
        job_id = str(uuid.uuid4())
        _start_event_feed(job_id, _factory(session))

        async def run() -> None:
            await _publish_event(redis_conn, job_id, event_type, data)
            await stop_feed(job_id)

        asyncio.run(run())
        return redis_conn, session

    def test_an_agent_message_loses_the_key_and_the_path_everywhere(self) -> None:
        redis_conn, session = self._publish(
            "agent_message",
            {
                "speaker": "static",
                "text": f"the key is {self.SECRET}",
                "report": f"I read {self.HOST_PATH} and found it packed",
            },
        )

        (published,) = self._published(redis_conn)
        assert self.SECRET not in json.dumps(published)
        assert "/home/operator" not in json.dumps(published)
        assert published["data"]["text"] == "the key is ***"
        assert published["data"]["report"] == "I read evil.exe and found it packed"
        # The same payload, in the table that outlives the stream.
        (row,) = session.added
        assert self.SECRET not in json.dumps(row.payload)
        assert "/home/operator" not in json.dumps(row.payload)

    def test_a_validation_feedback_message_is_scrubbed(self) -> None:
        redis_conn, _session = self._publish(
            "validation_feedback",
            {"stage": "analysis", "code": "ungrounded", "message": f"see {self.HOST_PATH}"},
        )

        (published,) = self._published(redis_conn)
        assert published["data"]["message"] == "see evil.exe"

    def test_a_cap_detail_is_scrubbed(self) -> None:
        redis_conn, _session = self._publish(
            "stage_ended_at_cap",
            {"stage": "analysis", "cap": "time", "detail": f"gave up reading {self.HOST_PATH}"},
        )

        (published,) = self._published(redis_conn)
        assert published["data"]["detail"] == "gave up reading evil.exe"

    def test_it_reaches_into_nested_structures(self) -> None:
        redis_conn, _session = self._publish(
            "agent_message",
            {
                "speaker": "static",
                "claims": [
                    {"claim": f"it reads {self.HOST_PATH}", "evidence_ref": self.SECRET},
                    {"claim": "nothing here"},
                ],
                "nested": {"deep": {"deeper": [self.SECRET]}},
            },
        )

        (published,) = self._published(redis_conn)
        blob = json.dumps(published)
        assert self.SECRET not in blob
        assert "/home/operator" not in blob
        assert published["data"]["claims"][0]["claim"] == "it reads evil.exe"
        assert published["data"]["claims"][1]["claim"] == "nothing here"

    def test_keys_are_left_alone(self) -> None:
        """A key is a field name the console reads; only values are text."""
        redis_conn, _session = self._publish(
            "roster", {"agents": [{"key": "static", "label": "Static"}]}
        )

        (published,) = self._published(redis_conn)
        assert published["data"]["agents"][0]["key"] == "static"
        assert set(published["data"]["agents"][0]) == {"key", "label"}

    def test_numbers_and_flags_keep_their_type(self) -> None:
        redis_conn, _session = self._publish(
            "tool_call_finished",
            {"tool": "strings", "ok": False, "duration_ms": 1234, "confidence": 0.5, "x": None},
        )

        (published,) = self._published(redis_conn)
        data = published["data"]
        assert data["ok"] is False
        assert data["duration_ms"] == 1234
        assert data["confidence"] == 0.5
        assert data["x"] is None
        assert data["seq"] == 1

    def test_the_recorders_copy_is_numbered_here_and_scrubbed_elsewhere(self) -> None:
        """The number is the publisher's; the scrub is the sink's.

        The copy is taken and scrubbed on the pipeline's thread, before this
        coroutine is scheduled — see ``_make_event_sink`` and
        ``tests/integration/test_transcript_persistence.py``. All this does to
        it is give it the number its event went out under, so a stored row and
        the live message it replaces collapse to one.
        """
        redis_conn = _FakeRedis()
        job_id = str(uuid.uuid4())
        recorded: dict[str, Any] = {"text": "the key is ***"}

        async def run() -> None:
            await _publish_event(
                redis_conn,
                job_id,
                "agent_message",
                {"text": f"the key is {self.SECRET}"},
                stamp=recorded,
            )

        asyncio.run(run())

        assert recorded["seq"] == 1
        assert recorded["text"] == "the key is ***"
        (published,) = self._published(redis_conn)
        assert published["data"]["seq"] == 1
        assert self.SECRET not in json.dumps(published)


class TestWhatTheScrubMustNotTouchAndWhatItMust:
    """A name is exempted because it is a name, not because of its shape.

    Exempting by shape — "a lowercase run is a key this system issues" — let
    every lowercase credential format through: Mailgun's ``key-…``, Google's
    ``gocspx-…``, GitHub's ``ghs_…`` and any base64url blob without capitals in
    it. The publisher is the one place that knows which *field* a string sits
    in, so the identity fields are named here and everything else goes through
    the credential rules whatever it looks like.
    """

    AGENT_KEY = "windows_pe_static_reverse_engineer"
    LABEL = "StaticBinaryReverseEngineer"

    def _publish(self, event_type: str, data: dict[str, Any]) -> dict[str, Any]:
        redis_conn = _FakeRedis()

        async def run() -> None:
            await _publish_event(redis_conn, str(uuid.uuid4()), event_type, data)

        asyncio.run(run())
        (published,) = [json.loads(message) for _channel, message in redis_conn.published]
        return dict(published["data"])

    @pytest.mark.parametrize(
        "secret",
        [
            "key-3ax6xnjp29jd6fds4gc373sgvjxteol0",
            "gocspx-abcdefghijklmnopqrstuvwx",
            "ghs_abcdefghijklmnopqrstuvwxyz0123456789",
            "abcdefghij0123456789klmnopqrstuv",
            "dghpc2lzyxzlcnlsb25nc2vjcmv0a2v5mtizndu2nzg5ma",
        ],
    )
    def test_a_lowercase_key_in_a_tool_result_is_replaced(self, secret: str) -> None:
        data = self._publish(
            "tool_call_finished",
            {
                "stage": "analysis",
                "agent": self.AGENT_KEY,
                "tool": "iocs_from_file",
                "summary": '{"secrets":["' + secret + '"],"count":1}',
            },
        )

        assert secret not in json.dumps(data), data
        assert data["summary"] == '{"secrets":["***"],"count":1}'

    def test_the_names_around_it_are_left_as_they_are(self) -> None:
        data = self._publish(
            "tool_call_finished",
            {
                "stage": "analysis",
                "agent": self.AGENT_KEY,
                "tool": "iocs_from_file",
                "server": "analysis-mcp-on-the-second-host",
                "evidence_id": "ev_0007",
                "summary": "ok",
            },
        )

        assert data["agent"] == self.AGENT_KEY
        assert data["server"] == "analysis-mcp-on-the-second-host"
        assert data["evidence_id"] == "ev_0007"

    def test_a_long_custom_agent_key_still_speaks(self) -> None:
        data = self._publish(
            "agent_message",
            {
                "speaker": self.AGENT_KEY,
                "role": "analyst",
                "kind": "says",
                "status": "complete",
                "display_name": self.LABEL,
                "addressed_to": self.AGENT_KEY,
                "stage": "analysis",
                "text": "the sample is packed",
            },
        )

        assert data["speaker"] == self.AGENT_KEY
        assert data["addressed_to"] == self.AGENT_KEY
        assert data["display_name"] == self.LABEL

    def test_a_report_id_survives_and_so_does_a_digest(self) -> None:
        import hashlib

        report_id = str(uuid.uuid4())
        digest = hashlib.sha256(b"a sample").hexdigest()

        data = self._publish(
            "completed",
            {
                "status": "completed",
                "verdict": "Malicious",
                "report_id": report_id,
                "job_id": str(uuid.uuid4()),
                "sha256": digest,
            },
        )

        assert data["report_id"] == report_id
        assert data["sha256"] == digest
        assert uuid.UUID(data["job_id"])

    def test_a_roster_keeps_every_name_it_carries(self) -> None:
        data = self._publish(
            "roster",
            {
                "agents": [
                    {
                        "key": self.AGENT_KEY,
                        "label": self.LABEL,
                        "role": "analyst",
                        "stages": ["analysis"],
                        "via": ["lead"],
                    }
                ],
                "stages": [
                    {
                        "key": "analysis",
                        "label": "Analysis",
                        "kind": "analysis",
                        "agents": [self.AGENT_KEY],
                    }
                ],
            },
        )

        assert data["agents"][0]["key"] == self.AGENT_KEY
        assert data["agents"][0]["label"] == self.LABEL
        assert data["agents"][0]["via"] == ["lead"]
        assert data["stages"][0]["agents"] == [self.AGENT_KEY]

    def test_an_identity_field_exempts_a_name_and_not_a_sentence(self) -> None:
        """The exemption reaches a string and a list of strings under that key,
        never a structure nested below one."""
        secret = "key-3ax6xnjp29jd6fds4gc373sgvjxteol0"

        data = self._publish(
            "agent_message",
            {
                "speaker": "static",
                "claims": [{"claim": f"it posts {secret}", "evidence_ref": "ev_0001"}],
                "report": f"the config held {secret}",
                "text": f"found {secret}",
            },
        )

        blob = json.dumps(data)
        assert secret not in blob, blob
        assert data["claims"][0]["evidence_ref"] == "ev_0001"

    def test_a_sample_filename_is_not_a_name_this_system_gave(self) -> None:
        """The uploader chose it, so it is scrubbed like any other text."""
        data = self._publish(
            "pipeline_started",
            {
                "agents": ["static"],
                "sample_filename": "key-3ax6xnjp29jd6fds4gc373sgvjxteol0",
                "sha256": "ab12" + "0" * 12 + "...",
            },
        )

        assert data["sample_filename"] == "***"
        assert data["agents"] == ["static"]
