"""ARQ worker job lifecycle integration tests.

These tests exercise the run_analysis function with mocked DB/Redis
contexts to verify status transitions and event publishing without
needing a real ARQ worker process.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from app.worker.analysis_worker import WorkerSettings, run_analysis


@pytest_asyncio.fixture
async def mock_db_session() -> AsyncMock:
    """A mocked async DB session that supports async context manager."""
    session = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.flush = AsyncMock()
    # Ensure async with db_session() as db: returns the same session object
    session.__aenter__.return_value = session
    session.__aexit__.return_value = False
    return session


@pytest_asyncio.fixture
async def mock_ctx(mock_db_session: AsyncMock) -> dict[str, Any]:
    """Mock ARQ worker context with Redis and DB session."""
    redis = AsyncMock()
    redis.publish = AsyncMock()
    return {
        "redis": redis,
        "db_session": lambda: mock_db_session,
    }


def _make_job(
    job_id: str | None = None,
    status: str = "queued",
    sample_sha256: str = "a" * 64,
    config: dict | None = None,
) -> MagicMock:
    job = MagicMock()
    job.id = uuid.UUID(job_id or "12345678-1234-1234-1234-123456789abc")
    job.status = status
    job.sample_id = uuid.UUID("87654321-4321-4321-4321-210987654321")
    job.config = config
    job.started_at = None
    job.completed_at = None
    job.duration_seconds = None
    job.error_message = None
    return job


def _make_sample(
    sha256: str = "a" * 64,
    filename: str = "test.exe",
) -> MagicMock:
    sample = MagicMock()
    sample.id = uuid.UUID("87654321-4321-4321-4321-210987654321")
    sample.sha256 = sha256
    sample.original_filename = filename
    sample.storage_path = f"samples/{sha256[:2]}/{sha256}"
    return sample


@pytest.mark.asyncio
async def test_job_not_found(mock_ctx: dict[str, Any], mock_db_session: AsyncMock) -> None:
    """If job is missing from DB, return error status."""
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None

    async def _fake_execute(*args: Any, **kwargs: Any) -> MagicMock:
        return mock_result

    mock_db_session.execute = _fake_execute

    result = await run_analysis(mock_ctx, "12345678-1234-1234-1234-123456789abc")

    assert result["status"] == "error"
    assert result["message"] == "Job not found"


@pytest.mark.asyncio
async def test_job_already_cancelled(mock_ctx: dict[str, Any], mock_db_session: AsyncMock) -> None:
    """Cancelled jobs are skipped immediately."""
    job = _make_job(status="cancelled")
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = job

    async def _fake_execute(*args: Any, **kwargs: Any) -> MagicMock:
        return mock_result

    mock_db_session.execute = _fake_execute

    result = await run_analysis(mock_ctx, str(job.id))

    assert result["status"] == "cancelled"


@pytest.mark.asyncio
async def test_mock_pipeline_completes(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
) -> None:
    """A mock-mode job transitions running -> completed and saves a report."""
    job = _make_job()
    sample = _make_sample()

    def _make_result(obj: Any) -> MagicMock:
        m = MagicMock()
        # MagicMock creates MagicMock for any missing attr, so hasattr is unreliable.
        # Only treat as a job if status is explicitly set to a real string.
        status_val = getattr(obj, "status", None)
        if isinstance(status_val, str):
            m.scalar_one_or_none.return_value = obj
        else:
            m.scalar_one.return_value = obj
        return m

    exec_results = [_make_result(job), _make_result(sample)]
    call_count = 0

    async def _fake_execute(*args: Any, **kwargs: Any) -> MagicMock:
        nonlocal call_count
        res = exec_results[call_count]
        call_count += 1
        return res

    mock_db_session.execute = _fake_execute

    with patch.dict("os.environ", {"MALJAN_MOCK_MODE": "true"}, clear=False):
        result = await run_analysis(mock_ctx, str(job.id))

    assert result["status"] == "completed"
    assert result["verdict"] == "Malware"
    assert job.status == "completed"
    assert job.completed_at is not None
    assert mock_db_session.commit.call_count >= 2  # running + completed


@pytest.mark.asyncio
async def test_pipeline_failure_sets_failed_status(
    mock_ctx: dict[str, Any], mock_db_session: AsyncMock
) -> None:
    """If the pipeline raises, job status becomes failed."""
    job = _make_job()
    sample = _make_sample()

    def _make_result(obj: Any) -> MagicMock:
        m = MagicMock()
        status_val = getattr(obj, "status", None)
        if isinstance(status_val, str):
            m.scalar_one_or_none.return_value = obj
        else:
            m.scalar_one.return_value = obj
        return m

    exec_results = [_make_result(job), _make_result(sample)]
    call_count = 0

    async def _fake_execute(*args: Any, **kwargs: Any) -> MagicMock:
        nonlocal call_count
        res = exec_results[call_count]
        call_count += 1
        return res

    mock_db_session.execute = _fake_execute

    # Force MaljanApp to blow up by mocking the class where it is defined.
    with patch("maljan.app.MaljanApp") as mock_app_cls:
        mock_app_cls.side_effect = RuntimeError("Simulated pipeline crash")

        result = await run_analysis(mock_ctx, str(job.id))

    assert result["status"] == "failed"
    assert "Simulated pipeline crash" in result["error"]
    assert job.status == "failed"
    assert job.error_message is not None


# ---------------------------------------------------------------------------
# Worker settings sanity checks
# ---------------------------------------------------------------------------


def test_worker_settings_sanity() -> None:
    """Verify ARQ worker tuning values are production-ready."""
    assert WorkerSettings.max_jobs == 1
    assert WorkerSettings.job_timeout == 1800
    assert WorkerSettings.max_tries == 1
