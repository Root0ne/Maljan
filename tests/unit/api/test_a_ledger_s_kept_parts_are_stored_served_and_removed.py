"""The parts of a ledger answer kept whole are stored per job, referenced and served.

The worker gives the job's container a store that writes each part into the
one bucket under ``evidence/<job_id>/<sha256>``; the entry's references go onto
its row in ``spilled`` and come back from ``GET /jobs/{id}/evidence``. An older
row reads with no references. The revision is run on a bare SQLite table.
"""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

from app.config import settings
from app.schemas.evidence import EvidenceEntryResponse
from app.services import object_store
from app.worker import analysis_worker
from app.worker.analysis_worker import _evidence_row
from maljan.schemas.evidence import fit_structures_to_budget
from maljan.schemas.evidence_spill import settle_refs, spill_part

_REV = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261019000000_evidence_entry_references_its_kept_parts.py"
)


class _Item:
    def __init__(self, name: str) -> None:
        self.object_name = name


class _Store:
    """A MinIO client double holding objects in memory."""

    def __init__(self, *, refuses: bool = False) -> None:
        self.objects: dict[str, tuple[bytes, str]] = {}
        self.refuses = refuses
        self.exists = False
        self.removed: list[str] = []

    def bucket_exists(self, bucket: str) -> bool:
        return self.exists

    def make_bucket(self, bucket: str) -> None:
        self.exists = True

    def set_bucket_policy(self, bucket: str, policy: str) -> None:
        return None

    def put_object(self, bucket: str, path: str, data: Any, length: int, content_type: str) -> None:
        if self.refuses:
            raise OSError("connection refused")
        blob = data.read()
        assert len(blob) == length
        self.objects[path] = (blob, content_type)

    def list_objects(self, bucket: str, prefix: str, recursive: bool) -> list[_Item]:
        assert recursive
        return [_Item(name) for name in list(self.objects) if name.startswith(prefix)]

    def remove_object(self, bucket: str, path: str) -> None:
        self.objects.pop(path)
        self.removed.append(path)


def _kept(job: Any, store: Any, part: str, value: Any, max_bytes: int = 0) -> dict[str, Any]:
    """One part through the job's store, waited for and settled as the worker does."""
    sink = object_store.evidence_spill(job, max_bytes, store=store)
    entry: dict[str, Any] = {"spilled": [spill_part(sink, part, value)]}
    settle_refs([entry], sink.drain(5))
    sink.close()
    return entry["spilled"][0]


class TestTheStore:
    def test_a_part_is_written_under_the_job_s_prefix_by_its_digest(self) -> None:
        store = _Store()
        job = uuid.uuid4()

        ref = _kept(job, store, "answer", "the whole answer")

        digest = hashlib.sha256(b"the whole answer").hexdigest()
        assert ref == {
            "part": "answer",
            "bytes": 16,
            "sha256": digest,
            "key": f"evidence/{job}/{digest}",
        }
        assert store.objects[ref["key"]] == (b"the whole answer", "text/plain; charset=utf-8")
        assert store.exists, "the bucket is created the one way, lazily"

    def test_a_refused_write_is_a_stated_reference(self) -> None:
        ref = _kept("j", _Store(refuses=True), "structured", {"a": 1})

        assert "key" not in ref
        assert ref["error"] == "upload_failed (OSError)"
        assert ref["bytes"] == len(b'{"a": 1}')

    def test_the_last_structure_pass_keeps_what_it_drops(self) -> None:
        store = _Store()
        ledger: list[dict[str, Any]] = [
            {"id": "ev_0001", "agent": "a", "output": "y" * 80},
            {
                "id": "ev_0002",
                "agent": "a",
                "output": "prose",
                "structured": {"wide": "z" * 40},
                "structured_from_server": True,
            },
        ]
        sink = object_store.evidence_spill("job", store=store)
        fit_structures_to_budget(ledger, 100, spill=sink)
        settle_refs(ledger, sink.drain(5))

        (ref,) = ledger[1]["spilled"]
        assert ledger[1]["structured"] is None
        assert json.loads(store.objects[ref["key"]][0]) == {"wide": "z" * 40}
        row = _evidence_row(ledger[1], job_id=uuid.uuid4())
        assert row.spilled == [ref]

    def test_the_worker_gives_the_job_s_container_the_store_and_drains_it(self) -> None:
        run = inspect.getsource(analysis_worker.run_analysis)
        stored = inspect.getsource(analysis_worker._store_the_report)
        assert "set_evidence_spill(await object_store.job_evidence_spill(job_id))" in run
        assert "asyncio.to_thread(_spill.drain, object_store.EVIDENCE_DRAIN_SECONDS)" in stored
        assert stored.index("settle_refs(_dumps, _outcomes)") < stored.index("rows_to_store(")


class _Slow(_Store):
    def __init__(self, seconds: float) -> None:
        super().__init__()
        self.seconds = seconds

    def put_object(self, bucket: str, path: str, data: Any, length: int, content_type: str) -> None:
        import time

        time.sleep(self.seconds)
        super().put_object(bucket, path, data, length, content_type)


class _Unreachable(_Store):
    def __init__(self) -> None:
        super().__init__()
        self.tries = 0

    def put_object(self, bucket: str, path: str, data: Any, length: int, content_type: str) -> None:
        self.tries += 1
        raise ConnectionRefusedError("connection refused by minio.internal:9000")


class TestTheWritesRunOffTheLoop:
    def test_a_slow_store_never_stops_the_loop(self) -> None:
        import asyncio
        import time

        store = _Slow(0.5)
        sink = object_store.evidence_spill("job", store=store)

        async def run() -> tuple[int, float]:
            ticks = 0

            async def ticker() -> None:
                nonlocal ticks
                while True:
                    ticks += 1
                    await asyncio.sleep(0.01)

            task = asyncio.create_task(ticker())
            await asyncio.sleep(0.02)
            started = time.monotonic()
            for index in range(4):
                spill_part(sink, "answer", f"part {index}")
            handed = time.monotonic() - started
            await asyncio.sleep(0.2)
            task.cancel()
            return ticks, handed

        ticks, handed = asyncio.run(run())
        assert handed < 0.1, "put hands the bytes over and returns"
        assert ticks >= 10, "the loop kept turning while the store wrote"
        assert len(sink.drain(5)) == 4
        sink.close()

    def test_the_first_unreachable_store_refuses_every_later_part_at_once(self) -> None:
        store = _Unreachable()
        sink = object_store.evidence_spill("job", store=store)
        first = {"spilled": [spill_part(sink, "answer", "one")]}
        sink.drain(5)

        later = spill_part(sink, "output", "two")

        assert later == {
            "part": "output",
            "bytes": 3,
            "sha256": hashlib.sha256(b"two").hexdigest(),
            "error": "upload_failed (store unreachable)",
        }
        assert store.tries == 1, "nothing more is sent to a store marked down"
        settle_refs([first], sink.drain(5))
        assert first["spilled"][0]["error"] == "upload_failed (store unreachable)"
        assert "key" not in first["spilled"][0]
        sink.close()

    def test_a_part_still_writing_at_the_deadline_is_stated_not_finished(self) -> None:
        store = _Slow(1.0)
        sink = object_store.evidence_spill("job", store=store)
        entry = {"spilled": [spill_part(sink, "answer", "slow")]}

        settle_refs([entry], sink.drain(0.05))

        assert entry["spilled"][0]["error"] == "upload_failed (not finished)"
        assert "key" not in entry["spilled"][0]
        sink.close()
        # The late write still finishes, and its object is removed again.
        import threading

        for _ in range(150):
            if store.removed:
                break
            threading.Event().wait(0.02)
        assert store.objects == {}

    def test_a_part_past_the_backlog_bound_is_refused_at_once_as_busy(self) -> None:
        import threading

        release = threading.Event()

        class _Held(_Store):
            def put_object(self, *args: Any, **kwargs: Any) -> None:
                release.wait(5)
                super().put_object(*args, **kwargs)

        store = _Held()
        sink = object_store.evidence_spill("job", 100, store=store)
        assert sink.backlog_bytes == object_store.EVIDENCE_WRITERS * 100

        held = [spill_part(sink, "answer", f"{index}" * 100) for index in range(2)]
        busy = spill_part(sink, "output", "z" * 50)

        assert all("key" in ref for ref in held)
        assert busy["error"] == "upload_failed (store busy)" and "key" not in busy
        release.set()
        assert sink.drain(5) == {ref["sha256"]: None for ref in held}
        assert "key" in spill_part(sink, "output", "z" * 50), "room again once written"
        sink.drain(5)
        sink.close()

    def test_the_same_bytes_are_written_once_per_job(self) -> None:
        class _Counting(_Store):
            writes = 0

            def put_object(self, *args: Any, **kwargs: Any) -> None:
                type(self).writes += 1
                super().put_object(*args, **kwargs)

        store = _Counting()
        sink = object_store.evidence_spill("job", store=store)
        first = spill_part(sink, "answer", "same bytes")
        second = spill_part(sink, "output", "same bytes")
        sink.drain(5)

        assert first["key"] == second["key"]
        assert _Counting.writes == 1
        sink.close()

    def test_a_write_that_ends_after_the_drain_leaves_no_object(self) -> None:
        import threading

        started, release = threading.Event(), threading.Event()

        class _Late(_Store):
            def put_object(self, *args: Any, **kwargs: Any) -> None:
                started.set()
                release.wait(5)
                super().put_object(*args, **kwargs)

        store = _Late()
        sink = object_store.evidence_spill("job", store=store)
        running = {"spilled": [spill_part(sink, "answer", "running")]}
        started.wait(5)
        spill_part(sink, "output", "second")
        queued = {"spilled": [spill_part(sink, "structured", {"third": 3})]}

        outcomes = sink.drain(0.05)
        settle_refs([running, queued], outcomes)
        release.set()
        for _ in range(100):
            if not store.objects:
                break
            threading.Event().wait(0.02)

        assert running["spilled"][0]["error"] == "upload_failed (not finished)"
        assert queued["spilled"][0]["error"] == "upload_failed (not finished)"
        assert store.objects == {}, "no object outlives a reference that says not kept"

    def _gated(self) -> tuple[Any, Any]:
        import threading

        gate = threading.Event()

        class _Gated(_Store):
            def put_object(self, *args: Any, **kwargs: Any) -> None:
                gate.wait(5)
                super().put_object(*args, **kwargs)

        return gate, _Gated()

    def _wait_for(self, done: Any) -> None:
        import threading

        for _ in range(150):
            if done():
                return
            threading.Event().wait(0.02)

    def test_a_write_ending_during_the_drain_is_stated_and_removed_as_one(self) -> None:
        import threading

        gate, store = self._gated()
        sink = object_store.evidence_spill("job", 1000, store=store)
        entry = {"spilled": [spill_part(sink, "answer", "hello")]}
        threading.Event().wait(0.1)
        pool = sink._pool
        shutdown = pool.shutdown

        def ending_now(*args: Any, **kwargs: Any) -> None:
            gate.set()  # the write ends after the drain's snapshot, before its shutdown
            threading.Event().wait(0.2)
            shutdown(*args, **kwargs)

        pool.shutdown = ending_now
        settle_refs([entry], sink.drain(0.05))
        self._wait_for(lambda: store.removed)

        assert entry["spilled"][0]["error"] == "upload_failed (not finished)"
        assert store.objects == {}, "the object goes with the reference that says not kept"

    def test_a_late_write_never_removes_what_a_later_put_wrote_again(self) -> None:
        import threading

        gate, store = self._gated()
        sink = object_store.evidence_spill("job", 1000, store=store)
        first = {"spilled": [spill_part(sink, "answer", "again")]}
        threading.Event().wait(0.05)
        settle_refs([first], sink.drain(0.05))

        second = spill_part(sink, "output", "again")
        gate.set()
        assert sink.drain(5) == {second["sha256"]: None}
        threading.Event().wait(0.1)

        assert first["spilled"][0]["error"] == "upload_failed (not finished)"
        assert second["key"] in store.objects and store.removed == []
        sink.close()

    def test_a_write_cancelled_at_the_drain_gives_its_bytes_back(self) -> None:
        import threading

        gate, store = self._gated()
        sink = object_store.evidence_spill("job", 100, store=store)
        for index in range(3):
            spill_part(sink, "answer", f"{index}" * 40)
        threading.Event().wait(0.05)

        sink.drain(0.05)
        gate.set()
        self._wait_for(lambda: sink._queued == 0 and len(store.removed) == 2)

        assert sink._queued == 0, "the cancelled write's bytes are no longer counted"

    def test_the_writers_client_has_short_timeouts_and_one_retry(self) -> None:
        built = object_store._evidence_client()
        pool = built._http
        assert pool.connection_pool_kw["timeout"].connect_timeout == 3.0
        assert pool.connection_pool_kw["retries"].total == 1


class _Talkative(_Store):
    """A store whose failure text names its endpoint, its bucket and its key."""

    def put_object(self, bucket: str, path: str, data: Any, length: int, content_type: str) -> None:
        raise OSError(
            "S3 operation failed; host: minio.internal:9000, bucket: maljan-samples, "
            "access key: operator-key"
        )


class TestWhatIsServed:
    def test_a_failed_upload_serves_its_class_and_logs_the_whole_failure(self, caplog: Any) -> None:
        ref = _kept("job", _Talkative(), "answer", "text")

        row = _evidence_row({"id": "ev_0001", "tool": "t", "spilled": [ref]}, job_id=uuid.uuid4())
        row.id = uuid.uuid4()
        served = EvidenceEntryResponse.model_validate(row).model_dump_json()
        assert ref["error"] == "upload_failed (OSError)"
        for leaked in ("minio.internal", "9000", "maljan-samples", "operator-key", "host"):
            assert leaked not in served, leaked
        assert "minio.internal:9000" in caplog.text, "the whole failure is logged server-side"


class TestTheBound:
    def test_a_part_above_the_upload_limit_is_referenced_with_the_reason_and_not_written(
        self,
    ) -> None:
        store = _Store()

        over = _kept("job", store, "answer", "x" * 1025, max_bytes=1024)
        at = _kept("job", store, "output", "y" * 1024, max_bytes=1024)

        assert over == {"part": "answer", "error": "exceeds upload_max_bytes (1024 bytes)"}
        assert at["key"] in store.objects and len(store.objects) == 1

    def test_a_part_surely_over_the_bound_is_never_encoded(self) -> None:
        from maljan.schemas import evidence_spill

        encoded: list[str] = []
        real = evidence_spill.part_bytes

        def counting(part: str, value: Any) -> bytes:
            encoded.append(part)
            return real(part, value)

        with patch.object(evidence_spill, "part_bytes", counting):
            text = _kept("job", _Store(), "answer", "x" * 2048, max_bytes=1024)
            shape = _kept("job", _Store(), "structured", {"rows": ["y" * 600, "z" * 600]}, 1024)
            wide = _kept("job", _Store(), "output", "\u00e9" * 600, max_bytes=1024)

        assert text["error"] == shape["error"] == "exceeds upload_max_bytes (1024 bytes)"
        assert encoded == ["output"], "only a part the floor cannot decide is encoded"
        assert wide == {
            "part": "output",
            "bytes": 1200,
            "sha256": hashlib.sha256(("\u00e9" * 600).encode()).hexdigest(),
            "error": "exceeds upload_max_bytes (1024 bytes)",
        }

    def test_the_job_s_store_reads_the_operator_s_upload_limit(self) -> None:
        import asyncio

        from app.runtime_config import runtime_config

        async def setting(name: str) -> Any:
            assert name == "upload_max_bytes"
            return 4096

        with patch.object(runtime_config, "get", setting):
            sink = asyncio.run(object_store.job_evidence_spill("job"))

        assert (sink.max_bytes, sink.bound_by) == (4096, "upload_max_bytes")


class TestTheRemoval:
    def test_a_job_s_prefix_is_removed_whole_and_no_other(self) -> None:
        store = _Store()
        job, other = uuid.uuid4(), uuid.uuid4()
        for owner, text in ((job, "one"), (job, "two"), (other, "three")):
            _kept(owner, store, "answer", text)

        removed = object_store.remove_prefix(store, object_store.evidence_prefix(job))

        assert removed == 2
        assert [key.split("/")[1] for key in store.objects] == [str(other)]


class TestTheRow:
    def test_an_entry_with_no_references_writes_none(self) -> None:
        row = _evidence_row({"id": "ev_0001", "tool": "t"}, job_id=uuid.uuid4())
        assert row.spilled is None

    def test_an_older_row_reads_with_no_references(self) -> None:
        from app.models.evidence import EvidenceEntry

        row = EvidenceEntry(
            id=uuid.uuid4(),
            job_id=uuid.uuid4(),
            entry_id="ev_0001",
            stage="analysis",
            agent="static",
            tool="pe_info",
            ok=True,
            duration_ms=1,
            seq=1,
            args={},
            output="",
            spilled=None,
        )
        served = json.loads(EvidenceEntryResponse.model_validate(row).model_dump_json())
        assert "spilled" not in served


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("evidence_references_kept_parts", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(conn: Any, step: Any) -> None:
    mod = _load()
    context = MigrationContext.configure(conn)
    with Operations.context(context):
        mod.op = Operations(context)
        step(mod)


class TestTheRevision:
    def test_it_follows_the_unique_ids_revision(self) -> None:
        mod = _load()
        assert (mod.revision, mod.down_revision) == ("20261019000000", "20261018000000")

    def test_an_older_row_holds_no_references_and_the_downgrade_takes_the_column(self) -> None:
        engine = sa.create_engine("sqlite://")
        with engine.connect() as conn:
            conn.execute(
                sa.text("CREATE TABLE evidence_entries (id INTEGER PRIMARY KEY, tool TEXT)")
            )
            conn.execute(sa.text("INSERT INTO evidence_entries (tool) VALUES ('pe_info')"))

            _run(conn, lambda mod: mod.upgrade())
            assert conn.execute(sa.text("SELECT spilled FROM evidence_entries")).one() == (None,)

            _run(conn, lambda mod: mod.downgrade())
            columns = [c["name"] for c in sa.inspect(conn).get_columns("evidence_entries")]
            assert "spilled" not in columns


def test_the_objects_live_in_the_one_bucket() -> None:
    assert object_store.evidence_key("j", "d") == "evidence/j/d"
    assert object_store.evidence_prefix("j") == "evidence/j/"
    assert settings.minio_bucket


class _Svc:
    def __init__(self, owned: bool) -> None:
        self.owned = owned
        self.asked: list[tuple[Any, Any]] = []

    async def get_job(self, job_id: Any, user: Any) -> Any:
        self.asked.append((job_id, user))
        return object() if self.owned else None


class _Db:
    def __init__(self, row: Any) -> None:
        self.row = row

    async def execute(self, statement: Any) -> Any:
        from unittest.mock import MagicMock

        result = MagicMock()
        result.scalar_one_or_none.return_value = self.row
        return result


class _Readable(_Store):
    def get_object(self, bucket: str, path: str) -> Any:
        from unittest.mock import MagicMock

        blob = self.objects[path][0]
        response = MagicMock()
        response.stream.side_effect = lambda amt: (blob[i : i + 4] for i in range(0, len(blob), 4))
        self.response = response
        return response


class TestTheDownload:
    def _client(self, *, owned: bool, row: Any) -> Any:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.api.v1 import jobs
        from app.database import get_db
        from app.deps import get_current_user

        app = FastAPI()
        app.include_router(jobs.router, prefix="/api/v1")
        self.svc = _Svc(owned)
        self.user = SimpleNamespace(id=uuid.uuid4())
        app.dependency_overrides[get_db] = lambda: _Db(row)
        app.dependency_overrides[get_current_user] = lambda: self.user
        app.dependency_overrides[jobs._get_service] = lambda: self.svc
        return TestClient(app)

    def _kept(self, job: uuid.UUID, store: _Store) -> Any:
        from app.models.evidence import EvidenceEntry

        ref = _kept(job, store, "answer", "the whole answer")
        failed = {"part": "output", "bytes": 3, "sha256": "0" * 64, "error": "upload_failed (X)"}
        return EvidenceEntry(job_id=job, entry_id="ev_0007", spilled=[ref, failed])

    def test_the_owner_gets_the_bytes_with_their_digest(self) -> None:
        job, store = uuid.uuid4(), _Readable()
        client = self._client(owned=True, row=self._kept(job, store))

        with patch.object(object_store, "client", lambda: store):
            r = client.get(f"/api/v1/jobs/{job}/evidence/ev_0007/objects/answer")

        assert r.status_code == 200
        assert r.content == b"the whole answer"
        assert r.headers["content-type"].startswith("text/plain")
        assert r.headers["x-content-sha256"] == hashlib.sha256(b"the whole answer").hexdigest()
        assert r.headers["content-length"] == "16"
        store.response.stream.assert_called_once_with(object_store.EVIDENCE_CHUNK_BYTES)
        store.response.release_conn.assert_called_once()
        assert 'filename="ev_0007-answer.txt"' in r.headers["content-disposition"]
        assert self.svc.asked == [(job, self.user)], "ownership checked as the evidence page does"

    def test_another_user_s_job_is_not_found(self) -> None:
        job, store = uuid.uuid4(), _Readable()
        client = self._client(owned=False, row=self._kept(job, store))

        r = client.get(f"/api/v1/jobs/{job}/evidence/ev_0007/objects/answer")

        assert r.status_code == 404 and r.json()["detail"] == "Job not found"

    def test_a_part_never_kept_or_not_referenced_is_not_found_with_its_reason(self) -> None:
        job, store = uuid.uuid4(), _Readable()
        client = self._client(owned=True, row=self._kept(job, store))

        failed = client.get(f"/api/v1/jobs/{job}/evidence/ev_0007/objects/output")
        missing = client.get(f"/api/v1/jobs/{job}/evidence/ev_0007/objects/structured")

        assert failed.status_code == 404
        assert failed.json()["detail"] == "The part was not kept: upload_failed (X)"
        assert missing.status_code == 404

    def test_a_key_outside_the_job_s_prefix_is_never_read(self) -> None:
        from app.models.evidence import EvidenceEntry

        job = uuid.uuid4()
        row = EvidenceEntry(
            job_id=job,
            entry_id="ev_0007",
            spilled=[{"part": "answer", "key": "samples/aa/aa", "bytes": 1, "sha256": "a"}],
        )
        client = self._client(owned=True, row=row)

        r = client.get(f"/api/v1/jobs/{job}/evidence/ev_0007/objects/answer")

        assert r.status_code == 404

    def test_bytes_that_do_not_match_their_digest_are_refused(self) -> None:
        job, store = uuid.uuid4(), _Readable()
        row = self._kept(job, store)
        store.objects[row.spilled[0]["key"]] = (b"altered", "text/plain")
        client = self._client(owned=True, row=row)

        from app.api.v1.jobs import EvidenceDigestMismatch

        with (
            patch.object(object_store, "client", lambda: store),
            pytest.raises(EvidenceDigestMismatch),
        ):
            client.get(f"/api/v1/jobs/{job}/evidence/ev_0007/objects/answer")
        store.response.release_conn.assert_called_once()

    def test_a_store_that_cannot_hand_it_back_is_a_bad_gateway(self) -> None:
        job, store = uuid.uuid4(), _Readable()
        row = self._kept(job, store)
        store.objects.clear()
        client = self._client(owned=True, row=row)

        with patch.object(object_store, "client", lambda: store):
            r = client.get(f"/api/v1/jobs/{job}/evidence/ev_0007/objects/answer")

        assert r.status_code == 502


class TestTheStreamVerifies:
    def _response(self, blob: bytes, size: int) -> Any:
        from unittest.mock import MagicMock

        response = MagicMock()
        response.stream.return_value = (blob[i : i + size] for i in range(0, len(blob), size))
        return response

    def test_a_tampered_object_never_yields_its_final_chunk(self) -> None:
        from app.api.v1.jobs import EvidenceDigestMismatch, verified_chunks

        recorded = hashlib.sha256(b"aaaabbbbcccc").hexdigest()
        response = self._response(b"aaaabbbbXXXX", 4)
        sent: list[bytes] = []

        with pytest.raises(EvidenceDigestMismatch):
            for chunk in verified_chunks(response, recorded, "evidence/j/d"):
                sent.append(chunk)

        assert sent == [b"aaaa", b"bbbb"], "the last chunk is held back and never sent"
        response.release_conn.assert_called_once()

    def test_a_matching_object_is_sent_whole(self) -> None:
        from app.api.v1.jobs import verified_chunks

        blob = b"aaaabbbbcccc"
        sent = list(verified_chunks(self._response(blob, 4), hashlib.sha256(blob).hexdigest(), "k"))

        assert b"".join(sent) == blob
