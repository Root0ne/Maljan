"""Service-level tests for the ARQ enrichment task + ReportService.enqueue_enrichment.

Hits both the worker logic (mock DB + mock Redis publish) and the service
layer (mock ARQ pool). End-to-end ARQ lifecycle is covered by manual smoke
during deployment.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.report_service import EnrichmentEnqueueError, ReportService  # noqa: E402
from app.worker.enrich_worker import enrich_threat_intel  # noqa: E402


def _fake_user() -> Any:
    return MagicMock(id=uuid.uuid4())


def _enabled_patch():
    """Patch runtime_config so the enrichment-enabled gate is deterministic.

    Task 7 moved the ``enrichment_enabled`` / API-key / ``enrichment_max_lookups``
    reads from ``settings`` to ``runtime_config`` (a 5-second TTL cache over the
    UI-managed overrides). These tests exercise the worker directly, without a
    database, so ``runtime_config`` would otherwise fall back to a real (failed)
    DB connection attempt before landing on the static default.
    """
    return (
        patch(
            "app.worker.enrich_worker.runtime_config.get",
            AsyncMock(
                side_effect=lambda n: {
                    "enrichment_enabled": True,
                    "enrichment_max_lookups": 25,
                }[n]
            ),
        ),
        patch(
            "app.worker.enrich_worker.runtime_config.get_secret",
            AsyncMock(side_effect=lambda n: {"virustotal_api_key": "", "abuseipdb_api_key": ""}[n]),
        ),
    )


def _malware_report_dict() -> dict[str, Any]:
    return {
        "network": {
            "domains": [{"fqdn": "evil.com", "is_suspicious": True}],
            "ips": [{"address": "1.2.3.4", "is_suspicious": True}],
        }
    }


# ---------------------------------------------------------------------------
# Worker (enrich_threat_intel)
# ---------------------------------------------------------------------------


class TestEnrichWorkerHappy:
    @pytest.mark.asyncio
    async def test_populates_reputation_and_publishes_event(self) -> None:
        # Pretend the orchestrator filled the dict with one new reputation.
        updated_payload = {
            "network": {
                "domains": [
                    {
                        "fqdn": "evil.com",
                        "is_suspicious": True,
                        "reputation": {"source": "virustotal", "malicious": 9},
                    }
                ],
                "ips": [
                    {
                        "address": "1.2.3.4",
                        "is_suspicious": True,
                        "reputation": {"source": "abuseipdb", "abuse_confidence": 80},
                    }
                ],
            }
        }

        report_id = uuid.uuid4()
        job_id = uuid.uuid4()
        fake_report = MagicMock()
        fake_report.id = report_id
        fake_report.job_id = job_id
        fake_report.malware_report = _malware_report_dict()

        db = MagicMock()
        db.get = AsyncMock(return_value=fake_report)
        db.commit = AsyncMock()
        session_cm = AsyncMock()
        session_cm.__aenter__.return_value = db
        session_cm.__aexit__.return_value = None
        session_factory = MagicMock(return_value=session_cm)

        redis = AsyncMock()
        ctx = {"redis": redis, "db_session": session_factory}

        get_patch, get_secret_patch = _enabled_patch()
        with (
            patch(
                "maljan.enrichment.enrich_malware_report",
                new=AsyncMock(return_value=updated_payload),
            ),
            get_patch,
            get_secret_patch,
        ):
            result = await enrich_threat_intel(ctx, str(report_id))

        assert result["status"] == "ok"
        assert result["domains_enriched"] == 1
        assert result["ips_enriched"] == 1
        # Both reputation keys should be present on the persisted dict.
        assert fake_report.malware_report["network"]["domains"][0]["reputation"]
        assert fake_report.malware_report["network"]["ips"][0]["reputation"]
        redis.publish.assert_awaited()


class TestEnrichWorkerSessionLifetime:
    @pytest.mark.asyncio
    async def test_no_session_is_open_across_the_reputation_lookups(self) -> None:
        """The lookups are third-party HTTP and took 452 s on one live report.

        A session held across them is a backend ``idle in transaction`` for
        the whole of it. The task reads the payload, closes, looks up, and
        opens a second session to write the result.
        """
        fake_report = MagicMock()
        fake_report.id = uuid.uuid4()
        fake_report.job_id = uuid.uuid4()
        fake_report.malware_report = _malware_report_dict()

        open_sessions: list[Any] = []
        open_during_lookups: list[int] = []

        class _Session:
            def __init__(self) -> None:
                self.get = AsyncMock(return_value=fake_report)
                self.commit = AsyncMock()

            async def __aenter__(self) -> Any:
                open_sessions.append(self)
                return self

            async def __aexit__(self, *exc: Any) -> bool:
                open_sessions.remove(self)
                return False

        sessions: list[_Session] = []

        def _factory() -> _Session:
            session = _Session()
            sessions.append(session)
            return session

        async def _lookups(payload: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
            open_during_lookups.append(len(open_sessions))
            return payload

        ctx = {"redis": AsyncMock(), "db_session": _factory}
        get_patch, get_secret_patch = _enabled_patch()
        with (
            patch("maljan.enrichment.enrich_malware_report", new=_lookups),
            get_patch,
            get_secret_patch,
        ):
            result = await enrich_threat_intel(ctx, str(fake_report.id))

        assert result["status"] == "ok"
        assert open_during_lookups == [0]
        # Three short ones: the payload read, the enriched write, and the row
        # the completion event is stored as. None of them spans the lookups.
        assert len(sessions) == 3
        assert open_sessions == []


class TestTheEnrichmentEventIsKept:
    @pytest.mark.asyncio
    async def test_the_completion_event_is_written_to_the_feed(self) -> None:
        """The feed's invariant: stored rows equal the last sequence number.

        Every event takes a number from the run's counter, so an event that
        takes one and stores nothing leaves the count one short for ever. This
        task runs after ``run_analysis`` has stopped the feed — in another
        process now — and its event was exactly that: one measured run
        published 71 and stored 70.
        """
        fake_report = MagicMock()
        fake_report.id = uuid.uuid4()
        fake_report.job_id = uuid.uuid4()
        fake_report.malware_report = _malware_report_dict()

        added: list[Any] = []

        class _Session:
            def __init__(self) -> None:
                self.get = AsyncMock(return_value=fake_report)
                self.commit = AsyncMock()

            def add_all(self, rows: Any) -> None:
                added.extend(rows)

            async def __aenter__(self) -> Any:
                return self

            async def __aexit__(self, *exc: Any) -> bool:
                return False

        redis = AsyncMock()
        redis.incr = AsyncMock(return_value=71)
        ctx = {"redis": redis, "db_session": _Session}

        get_patch, get_secret_patch = _enabled_patch()
        with (
            patch(
                "maljan.enrichment.enrich_malware_report",
                new=AsyncMock(return_value=_malware_report_dict()),
            ),
            get_patch,
            get_secret_patch,
        ):
            result = await enrich_threat_intel(ctx, str(fake_report.id))

        assert result["status"] == "ok"
        assert len(added) == 1, "the completion event is one stored row"
        row = added[0]
        assert row.type == "enrichment_complete"
        assert row.job_id == fake_report.job_id
        # The number it stored is the number it took.
        assert row.seq == 71
        assert row.payload["seq"] == 71

    @pytest.mark.asyncio
    async def test_the_feed_is_not_left_registered_behind_it(self) -> None:
        """A buffer left in the process map would collect another job's events."""
        from app.worker.analysis_worker import _EVENT_BUFFERS

        fake_report = MagicMock()
        fake_report.id = uuid.uuid4()
        fake_report.job_id = uuid.uuid4()
        fake_report.malware_report = _malware_report_dict()

        db = MagicMock()
        db.get = AsyncMock(return_value=fake_report)
        db.commit = AsyncMock()
        db.add_all = MagicMock()
        session_cm = AsyncMock()
        session_cm.__aenter__.return_value = db
        session_cm.__aexit__.return_value = None
        ctx = {"redis": AsyncMock(), "db_session": MagicMock(return_value=session_cm)}

        before = dict(_EVENT_BUFFERS)
        get_patch, get_secret_patch = _enabled_patch()
        with (
            patch(
                "maljan.enrichment.enrich_malware_report",
                new=AsyncMock(return_value=_malware_report_dict()),
            ),
            get_patch,
            get_secret_patch,
        ):
            await enrich_threat_intel(ctx, str(fake_report.id))

        assert _EVENT_BUFFERS == before


class TestEnrichWorkerSkips:
    @pytest.mark.asyncio
    async def test_invalid_uuid(self) -> None:
        ctx = {"redis": AsyncMock(), "db_session": MagicMock()}
        get_patch, get_secret_patch = _enabled_patch()
        with get_patch, get_secret_patch:
            result = await enrich_threat_intel(ctx, "not-a-uuid")
        assert result["status"] == "invalid_id"

    @pytest.mark.asyncio
    async def test_report_missing(self) -> None:
        db = MagicMock()
        db.get = AsyncMock(return_value=None)
        session_cm = AsyncMock()
        session_cm.__aenter__.return_value = db
        session_cm.__aexit__.return_value = None
        ctx = {"redis": AsyncMock(), "db_session": MagicMock(return_value=session_cm)}
        get_patch, get_secret_patch = _enabled_patch()
        with get_patch, get_secret_patch:
            result = await enrich_threat_intel(ctx, str(uuid.uuid4()))
        assert result["status"] == "not_found"

    @pytest.mark.asyncio
    async def test_no_malware_report_payload(self) -> None:
        fake_report = MagicMock()
        fake_report.malware_report = None
        db = MagicMock()
        db.get = AsyncMock(return_value=fake_report)
        session_cm = AsyncMock()
        session_cm.__aenter__.return_value = db
        session_cm.__aexit__.return_value = None
        ctx = {"redis": AsyncMock(), "db_session": MagicMock(return_value=session_cm)}
        get_patch, get_secret_patch = _enabled_patch()
        with get_patch, get_secret_patch:
            result = await enrich_threat_intel(ctx, str(uuid.uuid4()))
        assert result["status"] == "skipped"


class TestEnrichWorkerErrorIsContained:
    @pytest.mark.asyncio
    async def test_orchestrator_exception_returns_error_status(self) -> None:
        fake_report = MagicMock()
        fake_report.id = uuid.uuid4()
        fake_report.job_id = uuid.uuid4()
        fake_report.malware_report = _malware_report_dict()

        db = MagicMock()
        db.get = AsyncMock(return_value=fake_report)
        db.commit = AsyncMock()
        session_cm = AsyncMock()
        session_cm.__aenter__.return_value = db
        session_cm.__aexit__.return_value = None
        ctx = {"redis": AsyncMock(), "db_session": MagicMock(return_value=session_cm)}

        get_patch, get_secret_patch = _enabled_patch()
        with (
            patch(
                "maljan.enrichment.enrich_malware_report",
                new=AsyncMock(side_effect=RuntimeError("boom")),
            ),
            get_patch,
            get_secret_patch,
        ):
            result = await enrich_threat_intel(ctx, str(fake_report.id))

        assert result["status"] == "error"
        # The read session commits to end its own read transaction — the
        # lookups run with no session open at all — so what must not have
        # happened is the write: the report is never reopened and its payload
        # is the one it arrived with.
        assert db.get.await_count == 1
        assert fake_report.malware_report == _malware_report_dict()


# ---------------------------------------------------------------------------
# Service (ReportService.enqueue_enrichment)
# ---------------------------------------------------------------------------


class TestEnqueueEnrichment:
    @pytest.mark.asyncio
    async def test_enqueues_and_returns_job_id(self) -> None:
        svc = ReportService(db=AsyncMock())
        fake_report = MagicMock(id=uuid.uuid4())
        svc.get_report = AsyncMock(return_value=fake_report)  # type: ignore[method-assign]

        pool = AsyncMock()
        pool.enqueue_job = AsyncMock(return_value=MagicMock(job_id="enrich-xyz"))
        svc._get_arq_redis = AsyncMock(return_value=pool)  # type: ignore[method-assign]

        result = await svc.enqueue_enrichment(fake_report.id, _fake_user())
        assert result == "enrich-xyz"
        pool.enqueue_job.assert_awaited_once()
        call = pool.enqueue_job.await_args
        # ``_job_id`` keeps the enqueue idempotent.
        assert call.kwargs["_job_id"].endswith(f":{fake_report.id}")
        assert call.kwargs["_job_id"].startswith("enrich:")

    @pytest.mark.asyncio
    async def test_missing_report_returns_none(self) -> None:
        svc = ReportService(db=AsyncMock())
        svc.get_report = AsyncMock(return_value=None)  # type: ignore[method-assign]
        # No ARQ access expected when the report is missing.
        svc._get_arq_redis = AsyncMock()  # type: ignore[method-assign]

        result = await svc.enqueue_enrichment(uuid.uuid4(), _fake_user())
        assert result is None
        svc._get_arq_redis.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_arq_already_queued_returns_none(self) -> None:
        svc = ReportService(db=AsyncMock())
        svc.get_report = AsyncMock(return_value=MagicMock())  # type: ignore[method-assign]
        pool = AsyncMock()
        pool.enqueue_job = AsyncMock(return_value=None)  # ARQ collision case
        svc._get_arq_redis = AsyncMock(return_value=pool)  # type: ignore[method-assign]

        result = await svc.enqueue_enrichment(uuid.uuid4(), _fake_user())
        assert result is None

    @pytest.mark.asyncio
    async def test_redis_failure_raises(self) -> None:
        svc = ReportService(db=AsyncMock())
        svc.get_report = AsyncMock(return_value=MagicMock())  # type: ignore[method-assign]
        svc._get_arq_redis = AsyncMock(side_effect=ConnectionError("no redis"))  # type: ignore[method-assign]
        with pytest.raises(EnrichmentEnqueueError):
            await svc.enqueue_enrichment(uuid.uuid4(), _fake_user())


class TestTheMemoryStoreReadsOneSetOfSettings:
    """``api.qdrant_*`` and ``core.memory.qdrant_*`` addressed one server.

    The enrichment worker read the first and the analysis path the second, so
    an operator who filled in one of them got a 401 out of every enrich run.
    There is one set now, and it is the one a run's long-term memory uses.
    """

    def _store(self, url: str, collection: str, api_key: str | None) -> Any:
        import asyncio

        from app.worker import enrich_worker
        from maljan.core.config import Settings

        settings = Settings(
            _env_file=None,
            memory={
                "qdrant_url": url,
                "qdrant_collection": collection,
                "qdrant_api_key": api_key,
            },
        )
        built: dict[str, Any] = {}

        class _Store:
            def __init__(self, **kwargs: Any) -> None:
                built.update(kwargs)

        enrich_worker._memory_store_built = False
        enrich_worker._memory_store = None
        with (
            patch(
                "app.worker.enrich_worker.runtime_config.core",
                AsyncMock(return_value=settings),
            ),
            patch("maljan.memory.qdrant_store.QdrantStore", _Store),
        ):
            asyncio.run(enrich_worker._get_memory_store())
        enrich_worker._memory_store_built = False
        enrich_worker._memory_store = None
        return built

    def test_the_client_is_built_from_the_core_memory_values(self) -> None:
        built = self._store("http://qdrant:6333", "maljan_cases_v2", "s3cr3t")

        assert built == {
            "url": "http://qdrant:6333",
            "collection": "maljan_cases_v2",
            "api_key": "s3cr3t",
        }

    def test_an_unset_key_reaches_the_client_as_no_key(self) -> None:
        """An empty credential is "no authentication", not the empty string."""
        built = self._store("http://qdrant:6333", "maljan_cases_v2", None)

        assert built["api_key"] is None


class TestTheNumberingContinuesFromTheTable:
    """A counter that lived a day, and rows that live thirty.

    The sequence a job's events are numbered by is a Redis key with a 24-hour
    life. An operator pressing Enrich on an older report found it gone, took
    the number 1, collided with that job's first stored event and lost the row
    to a feed that never fails a run — the same "published but not stored" the
    enrichment event was fixed for.
    """

    @staticmethod
    def _redis(counter: dict[str, int]) -> Any:
        redis = AsyncMock()

        async def _exists(key: str) -> int:
            return 1 if key in counter else 0

        async def _set(key: str, value: Any, nx: bool = False, ex: int | None = None) -> bool:
            if nx and key in counter:
                return False
            counter[key] = int(value)
            return True

        async def _incr(key: str) -> int:
            counter[key] = counter.get(key, 0) + 1
            return counter[key]

        redis.exists = AsyncMock(side_effect=_exists)
        redis.set = AsyncMock(side_effect=_set)
        redis.incr = AsyncMock(side_effect=_incr)
        return redis

    @staticmethod
    def _sessions(stored_max: int | None, added: list[Any]) -> Any:
        class _Session:
            def __init__(self) -> None:
                self.commit = AsyncMock()

            async def get(self, *args: Any, **kwargs: Any) -> Any:
                report = MagicMock()
                report.id = uuid.uuid4()
                report.job_id = uuid.uuid4()
                report.malware_report = _malware_report_dict()
                return report

            async def execute(self, statement: Any) -> Any:
                result = MagicMock()
                result.scalar.return_value = stored_max
                return result

            def add_all(self, rows: Any) -> None:
                added.extend(rows)

            async def __aenter__(self) -> Any:
                return self

            async def __aexit__(self, *exc: Any) -> bool:
                return False

        return _Session

    @pytest.mark.asyncio
    async def test_an_enrichment_on_an_older_report_continues_the_numbering(self) -> None:
        from app.worker.analysis_worker import _seq_key

        job_id = uuid.uuid4()
        added: list[Any] = []
        counter: dict[str, int] = {}
        redis = self._redis(counter)

        session_cls = self._sessions(70, added)

        class _Fixed(session_cls):  # type: ignore[valid-type, misc]
            async def get(self, *args: Any, **kwargs: Any) -> Any:
                report = MagicMock()
                report.id = uuid.uuid4()
                report.job_id = job_id
                report.malware_report = _malware_report_dict()
                return report

        ctx = {"redis": redis, "db_session": _Fixed}
        get_patch, get_secret_patch = _enabled_patch()
        with (
            patch(
                "maljan.enrichment.enrich_malware_report",
                new=AsyncMock(return_value=_malware_report_dict()),
            ),
            get_patch,
            get_secret_patch,
        ):
            result = await enrich_threat_intel(ctx, str(uuid.uuid4()))

        assert result["status"] == "ok"
        assert counter[_seq_key(str(job_id))] == 71, "the counter continued the table"
        assert len(added) == 1
        assert added[0].seq == 71
        assert added[0].payload["seq"] == 71

    @pytest.mark.asyncio
    async def test_two_enrichments_in_a_row_take_the_next_two_numbers(self) -> None:
        from app.worker.analysis_worker import _seq_key

        job_id = uuid.uuid4()
        added: list[Any] = []
        counter: dict[str, int] = {}
        redis = self._redis(counter)
        session_cls = self._sessions(70, added)

        class _Fixed(session_cls):  # type: ignore[valid-type, misc]
            async def get(self, *args: Any, **kwargs: Any) -> Any:
                report = MagicMock()
                report.id = uuid.uuid4()
                report.job_id = job_id
                report.malware_report = _malware_report_dict()
                return report

        ctx = {"redis": redis, "db_session": _Fixed}
        get_patch, get_secret_patch = _enabled_patch()
        with (
            patch(
                "maljan.enrichment.enrich_malware_report",
                new=AsyncMock(return_value=_malware_report_dict()),
            ),
            get_patch,
            get_secret_patch,
        ):
            await enrich_threat_intel(ctx, str(uuid.uuid4()))
            await enrich_threat_intel(ctx, str(uuid.uuid4()))

        assert [row.seq for row in added] == [71, 72]
        assert counter[_seq_key(str(job_id))] == 72

    @pytest.mark.asyncio
    async def test_a_live_run_keeps_its_own_counter(self) -> None:
        """The seeding is ``NX`` and only when Redis holds nothing at all."""
        from app.worker.analysis_worker import _seq_key, seed_seq_from_the_table

        job_id = str(uuid.uuid4())
        counter = {_seq_key(job_id): 12}
        redis = self._redis(counter)
        added: list[Any] = []

        seeded = await seed_seq_from_the_table(redis, self._sessions(70, added), job_id)

        assert seeded is None, "a run in flight is not renumbered"
        assert counter[_seq_key(job_id)] == 12
        redis.set.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_job_with_no_stored_events_is_left_at_the_start(self) -> None:
        from app.worker.analysis_worker import seed_seq_from_the_table

        job_id = str(uuid.uuid4())
        redis = self._redis({})
        added: list[Any] = []

        assert await seed_seq_from_the_table(redis, self._sessions(None, added), job_id) is None
        redis.set.assert_not_awaited()
