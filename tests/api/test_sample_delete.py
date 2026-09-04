"""Deleting a sample also removes the sandbox reports it owned.

Fix round 1, Important 3: ``delete_sample`` had no test coverage at all before
this — every sandbox report's bytes routinely run to tens of megabytes and
carry extracted strings, C2 endpoints and network detail, so leaving them in
storage once the only row that could locate them is gone is a real forensic
leftover, not a someday cleanup item. This covers the new behavior: the
sample's own object-sharing logic (the ``others`` dedup check and the local
sample_files cleanup) is pre-existing, untouched by this fix, and out of
scope here.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

_API = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api.v1 import samples as module  # noqa: E402
from app.database import get_db  # noqa: E402
from app.deps import require_active_user  # noqa: E402


def _client(db: MagicMock, user: MagicMock) -> TestClient:
    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_active_user] = lambda: user
    return TestClient(app)


def test_deleting_a_sample_also_removes_its_sandbox_report_objects(monkeypatch):
    user = MagicMock(id=uuid.uuid4())
    sha256 = "a" * 64
    sample = MagicMock(
        id=uuid.uuid4(),
        sha256=sha256,
        storage_path=f"samples/{sha256[:2]}/{sha256}",
        uploaded_by=user.id,
    )
    report_paths = [
        f"sandbox-reports/{sha256[:2]}/{sha256}/r1.json",
        f"sandbox-reports/{sha256[:2]}/{sha256}/r2.json",
    ]

    sample_result = MagicMock()
    sample_result.scalar_one_or_none.return_value = sample
    no_active_jobs = MagicMock()
    no_active_jobs.scalar.return_value = 0
    report_paths_result = MagicMock()
    report_paths_result.scalars.return_value.all.return_value = list(report_paths)
    # Another user's row still shares these bytes: the sample's own object and
    # the local-file cleanup are pre-existing, gated behind this same check, and
    # are not what this test is proving.
    still_shared = MagicMock()
    still_shared.scalar.return_value = 1

    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=[sample_result, no_active_jobs, report_paths_result, None, still_shared]
    )
    db.delete = AsyncMock()
    db.flush = AsyncMock()

    minio = MagicMock()
    monkeypatch.setattr(module, "_minio_client", lambda: minio)

    r = _client(db, user).delete(f"/api/v1/samples/{sample.id}")

    assert r.status_code == 204
    removed = {call.args[1] for call in minio.remove_object.call_args_list}
    assert removed == set(report_paths)
    # The shared sample bytes themselves were not touched — that path is
    # unrelated to this fix.
    assert sample.storage_path not in removed


def test_deleting_a_sample_with_no_sandbox_reports_touches_storage_once(monkeypatch):
    """No reports attached: the new cleanup loop is simply a no-op, and the
    pre-existing single-object removal (this sample's own bytes, unshared) is
    unaffected."""
    user = MagicMock(id=uuid.uuid4())
    sha256 = "b" * 64
    sample = MagicMock(
        id=uuid.uuid4(),
        sha256=sha256,
        storage_path=f"samples/{sha256[:2]}/{sha256}",
        uploaded_by=user.id,
    )

    sample_result = MagicMock()
    sample_result.scalar_one_or_none.return_value = sample
    no_active_jobs = MagicMock()
    no_active_jobs.scalar.return_value = 0
    no_reports = MagicMock()
    no_reports.scalars.return_value.all.return_value = []
    not_shared = MagicMock()
    not_shared.scalar.return_value = 0

    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=[sample_result, no_active_jobs, no_reports, None, not_shared]
    )
    db.delete = AsyncMock()
    db.flush = AsyncMock()

    minio = MagicMock()
    monkeypatch.setattr(module, "_minio_client", lambda: minio)
    monkeypatch.setattr("app.worker.sample_files.remove_for_sha", lambda sha: [])

    r = _client(db, user).delete(f"/api/v1/samples/{sample.id}")

    assert r.status_code == 204
    minio.remove_object.assert_called_once_with(module.settings.minio_bucket, sample.storage_path)
