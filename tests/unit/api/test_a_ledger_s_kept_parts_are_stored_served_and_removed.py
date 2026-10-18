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
from typing import Any
from unittest.mock import patch

import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

from app.config import settings
from app.schemas.evidence import EvidenceEntryResponse
from app.services import object_store
from app.worker import analysis_worker
from app.worker.analysis_worker import _evidence_row
from maljan.schemas.evidence import fit_structures_to_budget
from maljan.schemas.evidence_spill import spill_part

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


class TestTheStore:
    def test_a_part_is_written_under_the_job_s_prefix_by_its_digest(self) -> None:
        store = _Store()
        job = uuid.uuid4()
        with patch.object(object_store, "client", lambda: store):
            ref = spill_part(object_store.evidence_spill(job), "answer", "the whole answer")

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
        with patch.object(object_store, "client", lambda: _Store(refuses=True)):
            ref = spill_part(object_store.evidence_spill("j"), "structured", {"a": 1})

        assert "key" not in ref
        assert ref["error"] == "OSError: connection refused"
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
        with patch.object(object_store, "client", lambda: store):
            fit_structures_to_budget(ledger, 100, spill=object_store.evidence_spill("job"))

        (ref,) = ledger[1]["spilled"]
        assert ledger[1]["structured"] is None
        assert json.loads(store.objects[ref["key"]][0]) == {"wide": "z" * 40}
        row = _evidence_row(ledger[1], job_id=uuid.uuid4())
        assert row.spilled == [ref]

    def test_the_worker_gives_the_job_s_container_the_store_and_the_last_pass_too(self) -> None:
        run = inspect.getsource(analysis_worker.run_analysis)
        stored = inspect.getsource(analysis_worker._store_the_report)
        assert "app.container.set_evidence_spill(object_store.evidence_spill(job_id))" in run
        assert "spill=object_store.evidence_spill(job_id)" in stored


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
