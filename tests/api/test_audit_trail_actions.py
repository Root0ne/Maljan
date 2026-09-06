"""Every action that creates or destroys evidence leaves an audit row.

A2 (dev audit 2026-09-06): only auth and settings wrote ``AuditLog`` rows, so
the trail said who logged in and what they configured but never who uploaded a
sample, who submitted or cancelled a job, or who attached and removed a
sandbox report -- the actions that put malware and its analysis into the
system in the first place.

Each row is written on a session of its own, the way ``auth`` has written its
rows since the 2026-07-26 audit, so a handled 4xx (which rolls the request's
own transaction back) still leaves the record behind, and a failing audit
write never turns that 4xx into a 500.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1 import jobs as jobs_module  # noqa: E402
from app.api.v1 import samples as samples_module  # noqa: E402
from app.api.v1 import sandbox_reports as reports_module  # noqa: E402
from app.database import get_db  # noqa: E402
from app.deps import get_current_user, require_active_user  # noqa: E402
from app.services import audit as audit_module  # noqa: E402
from fastapi import FastAPI
from fastapi.testclient import TestClient


class _Recorder:
    """Stands in for the independent session, keeping what was written."""

    def __init__(self) -> None:
        self.rows: list[Any] = []
        self.commits = 0

    def __call__(self) -> _Recorder:
        return self

    async def __aenter__(self) -> _Recorder:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False

    def add(self, row: Any) -> None:
        self.rows.append(row)

    async def commit(self) -> None:
        self.commits += 1

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


def _client(module, db, user, dependency=get_current_user) -> TestClient:
    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[dependency] = lambda: user
    return TestClient(app)


def test_submitting_a_job_is_audited_with_its_sample_and_profile(rows):
    user = MagicMock(id=uuid.uuid4())
    sample_id = uuid.uuid4()
    # Every JobResponse field needs a concrete value; a bare MagicMock does
    # not satisfy pydantic's uuid/str/dict validation.
    job = MagicMock(
        id=uuid.uuid4(),
        sample_id=sample_id,
        sample_sha256=None,
        sample_filename=None,
        status="pending",
        config={},
        created_at=datetime.now(UTC),
        started_at=None,
        completed_at=None,
        duration_seconds=None,
        error_message=None,
    )
    db = MagicMock()
    svc = MagicMock()
    svc.create_job = AsyncMock(return_value=job)

    app = FastAPI()
    app.include_router(jobs_module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[jobs_module._get_service] = lambda: svc
    client = TestClient(app)

    response = client.post(
        "/api/v1/jobs",
        json={
            "sample_id": str(sample_id),
            "config": {"llm_provider": "openai", "mock_mode": True, "api_key": "sk-secret"},
        },
    )
    assert response.status_code == 201, response.text

    row = rows.one("job.submit")
    assert row.resource_type == "job"
    assert row.resource_id == str(job.id)
    assert row.user_id == user.id
    assert row.details["sample_id"] == str(sample_id)
    assert row.details["llm_provider"] == "openai"
    # Only the keys this audit names travel; anything else an operator put in
    # the config stays out of the trail rather than being copied wholesale.
    assert "api_key" not in row.details


def test_cancelling_a_job_is_audited(rows):
    user = MagicMock(id=uuid.uuid4())
    job_id = uuid.uuid4()
    svc = MagicMock()
    svc.cancel_job = AsyncMock(return_value=None)

    app = FastAPI()
    app.include_router(jobs_module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[jobs_module._get_service] = lambda: svc
    response = TestClient(app).delete(f"/api/v1/jobs/{job_id}")
    assert response.status_code == 204, response.text

    row = rows.one("job.cancel")
    assert row.resource_type == "job"
    assert row.resource_id == str(job_id)
    assert row.user_id == user.id


def test_deleting_a_sample_is_audited(rows, monkeypatch):
    user = MagicMock(id=uuid.uuid4())
    sha256 = "c" * 64
    sample = MagicMock(
        id=uuid.uuid4(),
        sha256=sha256,
        storage_path=f"samples/{sha256[:2]}/{sha256}",
        uploaded_by=user.id,
        original_filename="thing.exe",
    )
    sample_result = MagicMock()
    sample_result.scalar_one_or_none.return_value = sample
    no_active_jobs = MagicMock()
    no_active_jobs.scalar.return_value = 0
    no_reports = MagicMock()
    no_reports.scalars.return_value.all.return_value = []
    still_shared = MagicMock()
    still_shared.scalar.return_value = 1

    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=[sample_result, no_active_jobs, no_reports, None, still_shared]
    )
    db.delete = AsyncMock()
    db.flush = AsyncMock()
    monkeypatch.setattr(samples_module, "_minio_client", lambda: MagicMock())

    response = _client(samples_module, db, user, require_active_user).delete(
        f"/api/v1/samples/{sample.id}"
    )
    assert response.status_code == 204, response.text

    row = rows.one("sample.delete")
    assert row.resource_type == "sample"
    assert row.resource_id == str(sample.id)
    assert row.details["sha256"] == sha256


def test_deleting_a_sandbox_report_is_audited(rows, monkeypatch):
    user = MagicMock(id=uuid.uuid4())
    sample = MagicMock(id=uuid.uuid4(), sha256="d" * 64, uploaded_by=user.id)
    report_id = uuid.uuid4()
    row_obj = MagicMock(id=report_id, storage_path="sandbox-reports/dd/x.json", format="cape2")

    load_result = MagicMock()
    load_result.scalar_one_or_none.return_value = sample
    report_result = MagicMock()
    report_result.scalar_one_or_none.return_value = row_obj

    db = MagicMock()
    db.execute = AsyncMock(side_effect=[load_result, report_result, None])
    db.flush = AsyncMock()
    monkeypatch.setattr(reports_module, "_minio_client", lambda: MagicMock())

    response = _client(reports_module, db, user, require_active_user).delete(
        f"/api/v1/samples/{sample.id}/sandbox-reports/{report_id}"
    )
    assert response.status_code == 204, response.text

    row = rows.one("sandbox_report.delete")
    assert row.resource_type == "sandbox_report"
    assert row.resource_id == str(report_id)
    assert row.details["sample_id"] == str(sample.id)


def test_an_audit_write_that_fails_never_breaks_the_request(rows, monkeypatch):
    """The whole point of the independent session: best effort, never fatal."""

    class _Broken:
        def __call__(self) -> _Broken:
            return self

        async def __aenter__(self) -> _Broken:
            raise RuntimeError("db down")

        async def __aexit__(self, *exc: Any) -> bool:
            return False

    monkeypatch.setattr(audit_module, "async_session_factory", _Broken())
    user = MagicMock(id=uuid.uuid4())
    job_id = uuid.uuid4()
    svc = MagicMock()
    svc.cancel_job = AsyncMock(return_value=None)

    app = FastAPI()
    app.include_router(jobs_module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[jobs_module._get_service] = lambda: svc
    assert TestClient(app).delete(f"/api/v1/jobs/{job_id}").status_code == 204
