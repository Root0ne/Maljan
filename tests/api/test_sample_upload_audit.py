"""Every successful upload leaves a row, including the ones that store nothing.

A2 re-verification (dev audit 2026-09-06): the audit call sat at the end of
``upload_sample``, and two of the route's three successful exits return before
it. Re-uploading your own sample (the per-user dedup path) and uploading bytes
another user had already pushed to MinIO both answered 201 and wrote nothing to
the trail -- so "who put this sample in the system" had an answer only for the
first uploader of a given hash.

Those two paths are exactly the ones worth recording: a re-upload is how a
sample re-enters an investigation, and the shared-storage path is one user
gaining access to another's bytes.
"""

from __future__ import annotations

import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_API = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api.v1 import samples as module  # noqa: E402
from app.database import get_db  # noqa: E402
from app.deps import get_current_user  # noqa: E402
from app.services import audit as audit_module  # noqa: E402

SHA256 = "e" * 64


class _Recorder:
    def __init__(self) -> None:
        self.rows: list[Any] = []

    def __call__(self) -> _Recorder:
        return self

    async def __aenter__(self) -> _Recorder:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    def add(self, row: Any) -> None:
        self.rows.append(row)

    async def commit(self) -> None:
        return None

    def one(self, action: str) -> Any:
        matches = [r for r in self.rows if r.action == action]
        assert matches, f"no audit row for {action!r}; got {[r.action for r in self.rows]}"
        assert len(matches) == 1, f"{len(matches)} rows for {action!r}"
        return matches[0]


@pytest.fixture
def rows(monkeypatch) -> _Recorder:
    recorder = _Recorder()
    monkeypatch.setattr(audit_module, "async_session_factory", recorder)
    return recorder


def _sample_row(user_id: uuid.UUID) -> MagicMock:
    return MagicMock(
        id=uuid.uuid4(),
        sha256=SHA256,
        md5="d" * 32,
        sha1="c" * 40,
        original_filename="thing.exe",
        file_size_bytes=2048,
        mime_type="application/x-dosexec",
        storage_path=f"samples/{SHA256[:2]}/{SHA256}",
        uploaded_by=user_id,
        created_at=datetime.now(UTC),
    )


def _upload(monkeypatch, db: MagicMock, user: MagicMock):
    monkeypatch.setattr(
        module, "_streaming_hashes", lambda file, dest, cap: (SHA256, "c" * 40, "d" * 32, 2048)
    )
    monkeypatch.setattr(module, "_detect_mime", lambda path: "application/x-dosexec")
    monkeypatch.setattr(module.runtime_config, "get", AsyncMock(return_value=100 * 1024 * 1024))
    monkeypatch.setattr(module, "_minio_client", lambda: MagicMock())

    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: user
    return TestClient(app).post(
        "/api/v1/samples/upload", files={"file": ("thing.exe", b"MZ" + b"\x00" * 64)}
    )


def test_re_uploading_your_own_sample_is_audited_as_a_duplicate(rows, monkeypatch):
    user = MagicMock(id=uuid.uuid4())
    existing = _sample_row(user.id)

    prior = MagicMock()
    prior.scalar_one_or_none.return_value = existing.id
    insert_conflict = MagicMock()
    insert_conflict.scalar_one_or_none.return_value = None
    lookup = MagicMock()
    lookup.scalar_one.return_value = existing

    db = MagicMock()
    db.execute = AsyncMock(side_effect=[prior, insert_conflict, lookup])
    db.flush = AsyncMock()
    db.refresh = AsyncMock()

    response = _upload(monkeypatch, db, user)
    assert response.status_code == 201, response.text

    row = rows.one("sample.upload")
    assert row.resource_type == "sample"
    assert row.resource_id == str(existing.id)
    assert row.user_id == user.id
    assert row.details["sha256"] == SHA256
    assert row.details["filename"] == "thing.exe"
    assert row.details["size_bytes"] == 2048
    assert row.details["deduplicated"] is True


def test_reusing_another_users_stored_bytes_is_audited_as_shared_storage(rows, monkeypatch):
    user = MagicMock(id=uuid.uuid4())
    fresh = _sample_row(user.id)

    prior = MagicMock()
    prior.scalar_one_or_none.return_value = uuid.uuid4()  # someone else's row
    inserted = MagicMock()
    inserted.scalar_one_or_none.return_value = fresh

    db = MagicMock()
    db.execute = AsyncMock(side_effect=[prior, inserted])
    db.flush = AsyncMock()
    db.refresh = AsyncMock()

    response = _upload(monkeypatch, db, user)
    assert response.status_code == 201, response.text

    row = rows.one("sample.upload")
    assert row.resource_id == str(fresh.id)
    assert row.details["shared_storage"] is True
    assert row.details["deduplicated"] is False
    assert row.details["sha256"] == SHA256


def test_a_first_upload_is_audited_without_either_flag(rows, monkeypatch):
    """The path that already worked keeps working, and says it stored the bytes."""
    user = MagicMock(id=uuid.uuid4())
    fresh = _sample_row(user.id)

    prior = MagicMock()
    prior.scalar_one_or_none.return_value = None
    inserted = MagicMock()
    inserted.scalar_one_or_none.return_value = fresh

    db = MagicMock()
    db.execute = AsyncMock(side_effect=[prior, inserted])
    db.flush = AsyncMock()
    db.refresh = AsyncMock()

    response = _upload(monkeypatch, db, user)
    assert response.status_code == 201, response.text

    row = rows.one("sample.upload")
    assert row.resource_id == str(fresh.id)
    assert row.details["deduplicated"] is False
    assert row.details["shared_storage"] is False
