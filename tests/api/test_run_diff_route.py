"""``GET /reports/diff``: two runs the caller may read, or the 404 of a single read."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.jobs import router as jobs_router
from app.api.v1.reports import router
from app.database import get_db
from app.deps import get_current_user
from app.services.report_service import ReportService, run_record


def _stored(verdict: str, sha: str = "a" * 64) -> Any:
    """A stored report row with its job and sample, with exactly the columns read."""
    sample = SimpleNamespace(sha256=sha, original_filename="invoice.exe")
    job = SimpleNamespace(sample=sample, duration_seconds=12.5)
    return SimpleNamespace(
        id=uuid.uuid4(),
        job_id=uuid.uuid4(),
        created_at=datetime(2026, 9, 20, tzinfo=UTC),
        verdict=verdict,
        overall_confidence=0.8,
        malware_category="loader",
        malware_report=None,
        run_summary={"verdict_reading": "stated"},
        stix_bundle=None,
        agent_findings=[
            SimpleNamespace(
                agent_name="static",
                status="complete",
                final_confidence=0.7,
                revision_rounds=1,
                claims=[{"claim": "x", "evidence_ref": "ev_0002"}],
            )
        ],
        job=job,
    )


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.include_router(jobs_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: MagicMock(id=uuid.uuid4())
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return TestClient(app)


def _url(a: Any, b: Any, by: str | None = None) -> str:
    return f"/api/v1/reports/diff?a={a}&b={b}" + (f"&by={by}" if by else "")


def test_two_readable_runs_answer_with_the_diff(client: TestClient) -> None:
    rows = [_stored("Malware"), _stored("Benign")]
    loader = AsyncMock(side_effect=rows)
    with patch.object(ReportService, "get_report_for_diff", loader):
        resp = client.get(_url(rows[0].id, rows[1].id))

    assert resp.status_code == 200
    body = resp.json()
    assert body["a"]["report_id"] == str(rows[0].id)
    assert body["same_sample"] is True
    verdict = next(s for s in body["sections"] if s["key"] == "verdict")
    assert verdict["counts"]["changed"] == 1
    analysts = next(s for s in body["sections"] if s["key"] == "analysts")
    assert analysts["rows"][0]["evidence"]["a"] == ["ev_0002"]


@pytest.mark.parametrize("missing", [0, 1])
def test_a_run_the_caller_cannot_read_is_a_404_like_a_single_read(
    client: TestClient, missing: int
) -> None:
    rows: list[Any] = [_stored("Malware"), _stored("Benign")]
    rows[missing] = None
    loader = AsyncMock(side_effect=rows)
    with patch.object(ReportService, "get_report_for_diff", loader):
        resp = client.get(_url(uuid.uuid4(), uuid.uuid4()))

    assert resp.status_code == 404
    assert resp.json() == {"detail": "Report not found"}


def test_job_ids_are_looked_up_as_job_ids(client: TestClient) -> None:
    loader = AsyncMock(side_effect=[_stored("Malware"), _stored("Malware")])
    a, b = uuid.uuid4(), uuid.uuid4()
    with patch.object(ReportService, "get_report_for_diff", loader):
        resp = client.get(_url(a, b, "job"))

    assert resp.status_code == 200
    assert [c.args[0] for c in loader.await_args_list] == [a, b]
    assert all(c.kwargs["by"] == "job" for c in loader.await_args_list)


def test_the_path_is_not_read_as_a_report_id(client: TestClient) -> None:
    resp = client.get("/api/v1/reports/diff")

    # A missing query parameter, not a malformed report id in the path.
    assert resp.status_code == 422
    assert {e["loc"][-1] for e in resp.json()["detail"]} == {"a", "b"}


def test_an_unknown_lookup_is_refused(client: TestClient) -> None:
    assert client.get(_url(uuid.uuid4(), uuid.uuid4(), "sample")).status_code == 422


def test_the_record_is_the_stored_values_unchanged() -> None:
    row = _stored("Malware")

    record = run_record(row)

    assert record.sample_sha256 == "a" * 64
    assert record.duration_seconds == 12.5
    assert record.agent_findings[0]["claims"] == [{"claim": "x", "evidence_ref": "ev_0002"}]
    assert record.run_summary is row.run_summary


def test_the_query_scopes_both_runs_to_the_caller() -> None:
    from sqlalchemy.dialects import postgresql

    db = MagicMock()
    result = MagicMock()
    result.scalar_one_or_none.return_value = None
    db.execute = AsyncMock(return_value=result)
    user = MagicMock(id=uuid.uuid4())
    svc = ReportService(db)

    import asyncio

    asyncio.run(svc.get_report_for_diff(uuid.uuid4(), user, by="job"))

    sql = str(
        db.execute.await_args.args[0].compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )
    assert f"analysis_jobs.created_by = '{user.id}'" in sql
    assert "analysis_reports.job_id = " in sql


def test_the_job_list_narrows_to_one_sample(client: TestClient) -> None:
    listing = AsyncMock(return_value={"items": [], "total": 0, "page": 1, "page_size": 20})
    sample = uuid.uuid4()
    with patch("app.api.v1.jobs.AnalysisService.list_jobs", listing):
        resp = client.get(f"/api/v1/jobs?sample_id={sample}&status=completed")

    assert resp.status_code == 200
    assert listing.await_args.kwargs["sample_id"] == sample
    assert listing.await_args.kwargs["status_filter"] == "completed"
