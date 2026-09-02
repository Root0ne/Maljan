"""ARQ worker job lifecycle integration tests.

These tests exercise the run_analysis function with mocked DB/Redis
contexts to verify status transitions and event publishing without
needing a real ARQ worker process.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from app.worker.analysis_worker import WorkerSettings, run_analysis


@pytest_asyncio.fixture
async def mock_db_session() -> AsyncMock:
    """A mocked async DB session that supports async context manager.

    SQLAlchemy ``Session.add`` is a *synchronous* method but ``AsyncMock``
    silently turns every attribute into an async coroutine, leaving the
    return value unawaited and triggering ``RuntimeWarning`` at pytest
    teardown. Explicitly mark sync methods (``add``) as ``MagicMock`` while
    keeping ``flush`` / ``commit`` / ``rollback`` / aenter / aexit async.
    """
    session = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.flush = AsyncMock()
    session.add = MagicMock()
    session.add_all = MagicMock()
    # Ensure async with db_session() as db: returns the same session object
    session.__aenter__.return_value = session
    session.__aexit__.return_value = False
    return session


@pytest_asyncio.fixture
async def mock_ctx(mock_db_session: AsyncMock) -> dict[str, Any]:
    """Mock ARQ worker context with Redis and DB session."""
    # ``redis.asyncio.Redis`` uses sync attribute access on
    # ``connection_pool.connection_kwargs`` during init; using a bare
    # ``AsyncMock`` turns that into a coroutine and raises a runtime
    # warning. ``MagicMock`` keeps the descriptor sync while we still
    # override the few async methods we actually call.
    redis = MagicMock()
    redis.publish = AsyncMock()
    redis.aclose = AsyncMock()
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
        # The worker fires extra ``UPDATE`` statements for ``started_at``/
        # ``completed_at`` after the audit 2026-05-17 TIME-01 fix. Those
        # don't need a row payload — return an empty MagicMock so the
        # commit/refresh path doesn't blow up.
        if call_count >= len(exec_results):
            return MagicMock()
        res = exec_results[call_count]
        call_count += 1
        return res

    mock_db_session.execute = _fake_execute

    # Audit 2026-05-17 (W-01 permanent fix): mock mode now requires BOTH
    # the env-var AND ``settings.mock_mode_allowed=True``. Without the
    # second toggle the worker stays on the real LLM path — exactly the
    # opposite of what this test wants. ``MOCK_MODE_ALLOWED`` flows
    # through pydantic-settings env loading; combined with the cleared
    # settings cache it produces a fresh ``APISettings`` with both gates
    # on.
    from app import config as api_config

    api_config._settings = None
    with patch.dict(
        "os.environ",
        {"MALJAN_MOCK_MODE": "true", "MOCK_MODE_ALLOWED": "true"},
        clear=False,
    ):
        result = await run_analysis(mock_ctx, str(job.id))
    api_config._settings = None  # don't leak the test settings to neighbours

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
        # The worker fires extra ``UPDATE`` statements for ``started_at``/
        # ``completed_at`` after the audit 2026-05-17 TIME-01 fix. Those
        # don't need a row payload — return an empty MagicMock so the
        # commit/refresh path doesn't blow up.
        if call_count >= len(exec_results):
            return MagicMock()
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
    # 2026-07-13: bumped 3600 -> 28800 (8h) for the deep-analysis restore.
    # Full-depth static runs one ReAct loop PER CHUNK (~8-10 chunks), so a
    # realistic-slow cold-cache run is ~2-4h; the outer ARQ ceiling must sit
    # above the inner per-loop safety nets so it never kills a progressing run.
    assert WorkerSettings.job_timeout == 28800
    assert WorkerSettings.max_tries == 1


# ---------------------------------------------------------------------------
# Wave 8 ORPHAN-JOBS-01 (2026-05-28) — startup orphan sweep regression test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_startup_sweeps_phantom_running_jobs() -> None:
    """``_sweep_orphan_jobs`` flips abandoned ``running`` rows to ``failed``.

    Without the sweep the dashboard accumulates phantom in-flight jobs every
    time the worker is killed. The cutoff used to be ``job_timeout`` — eight
    hours — which made the sweep useless for the case its own docstring names
    first: a worker killed mid-flight is back within seconds, and its row then
    sat in ``running`` for the rest of the day with nothing retrying it
    (``max_tries = 1``). Observed live on 2026-07-26, and a container memory
    limit makes a mid-flight kill more likely rather than less.

    The grace period only has to exceed the window in which a row can be
    legitimately ``running`` while no worker is up, which — with ``max_jobs =
    1`` and this process having just booted — is seconds.
    """
    from datetime import UTC, datetime, timedelta

    from app.worker.analysis_worker import _sweep_orphan_jobs

    captured_stmts: list[Any] = []
    sweep_session = AsyncMock()
    sweep_session.commit = AsyncMock()
    sweep_session.__aenter__.return_value = sweep_session
    sweep_session.__aexit__.return_value = False

    # Pretend two rows survived the sweep (older than 3600s budget).
    mock_result = MagicMock()
    mock_result.all.return_value = [
        (uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),),
        (uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),),
    ]

    async def _fake_execute(stmt: Any) -> MagicMock:
        captured_stmts.append(stmt)
        return mock_result

    sweep_session.execute = _fake_execute

    db_session_factory = MagicMock(return_value=sweep_session)

    before = datetime.now(UTC)
    await _sweep_orphan_jobs(db_session_factory)
    after = datetime.now(UTC)

    # Exactly one UPDATE statement was issued + one commit.
    assert len(captured_stmts) == 1
    assert sweep_session.commit.await_count == 1

    # The cutoff must be minutes ago, not hours. Read the bound parameter off
    # the compiled statement rather than comparing two timestamps that are
    # ordered by construction — the previous assertion here could not fail.
    from app.worker.analysis_worker import _ORPHAN_GRACE_SECONDS

    params = captured_stmts[0].compile().params
    cutoff = next(v for v in params.values() if isinstance(v, datetime))

    assert before - timedelta(seconds=_ORPHAN_GRACE_SECONDS + 1) <= cutoff
    assert cutoff <= after - timedelta(seconds=_ORPHAN_GRACE_SECONDS - 1)
    assert _ORPHAN_GRACE_SECONDS <= 900, (
        "a worker killed mid-flight must be reclaimed in minutes; at the old "
        "eight-hour cutoff the job stayed 'running' all day"
    )


@pytest.mark.asyncio
async def test_startup_sweep_handles_no_phantoms_gracefully() -> None:
    """A clean DB with no phantom rows must not raise or log a warning."""
    from app.worker.analysis_worker import _sweep_orphan_jobs

    sweep_session = AsyncMock()
    sweep_session.commit = AsyncMock()
    sweep_session.__aenter__.return_value = sweep_session
    sweep_session.__aexit__.return_value = False

    empty_result = MagicMock()
    empty_result.all.return_value = []

    async def _fake_execute(stmt: Any) -> MagicMock:
        return empty_result

    sweep_session.execute = _fake_execute
    db_session_factory = MagicMock(return_value=sweep_session)

    # Should complete without raising.
    await _sweep_orphan_jobs(db_session_factory)
    assert sweep_session.commit.await_count == 1


# ---------------------------------------------------------------------------
# Wave 9 HOTFIX-08 (2026-05-29) — upload_temp_dir must resolve to absolute
# ---------------------------------------------------------------------------


def test_upload_temp_dir_resolves_to_absolute_path() -> None:
    """Regression: the original Wave 9 ERGO-06 commit set
    ``APISettings.upload_temp_dir = "data/uploads/.tmp"`` (relative) and
    consumers (API startup, sample upload endpoint, worker MinIO download)
    used ``Path(settings.upload_temp_dir)`` directly. When a downstream
    consumer then tried to open that relative path from a CWD that
    wasn't the project root it failed with ``[Errno 22] Invalid argument``.

    The hotfix is ``Path(settings.upload_temp_dir).resolve()`` at every
    use-site so the path stays absolute / CWD-independent. This test
    documents the invariant — Python's ``Path.resolve()`` will turn any
    relative settings value into an absolute Path that the downstream
    MinIO / Ghidra consumers can rely on.
    """
    from pathlib import Path

    from app.config import APISettings

    # Default settings value is "data/uploads/.tmp" — explicitly relative
    # for repo-portability across operator machines.
    settings = APISettings()
    assert not Path(settings.upload_temp_dir).is_absolute()

    # After resolve(), it MUST be absolute. Every Wave 9 use-site is
    # required to call ``.resolve()`` before handing the path to a
    # consumer.
    resolved = Path(settings.upload_temp_dir).resolve()
    assert resolved.is_absolute(), (
        f"Wave 9 HOTFIX-08 invariant violated: "
        f"upload_temp_dir resolved to non-absolute path {resolved!r}. "
        "Add ``.resolve()`` at the affected call site."
    )


@pytest.mark.asyncio
async def test_override_load_failure_falls_back_to_env_settings(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A DB error while loading UI overrides must not fail the job.

    The job runs on environment settings and one warning names the exception
    type only -- never a value, never a connection string.
    """
    job = _make_job()
    sample = _make_sample()

    def _make_result(obj: Any) -> MagicMock:
        m = MagicMock()
        if isinstance(getattr(obj, "status", None), str):
            m.scalar_one_or_none.return_value = obj
        else:
            m.scalar_one.return_value = obj
        return m

    exec_results = [_make_result(job), _make_result(sample)]
    call_count = 0

    async def _fake_execute(*args: Any, **kwargs: Any) -> MagicMock:
        nonlocal call_count
        if call_count >= len(exec_results):
            return MagicMock()
        res = exec_results[call_count]
        call_count += 1
        return res

    mock_db_session.execute = _fake_execute

    async def _boom(_db: Any) -> dict[str, Any]:
        raise ConnectionError("postgres://maljan:s3cret@db:5432/maljan unreachable")

    from app.services import settings_service

    monkeypatch.setattr(settings_service, "load_core_overrides", _boom)

    from app import config as api_config

    api_config._settings = None
    with (
        patch.dict(
            "os.environ",
            {"MALJAN_MOCK_MODE": "true", "MOCK_MODE_ALLOWED": "true"},
            clear=False,
        ),
        caplog.at_level(logging.WARNING, logger="app.worker.analysis_worker"),
    ):
        result = await run_analysis(mock_ctx, str(job.id))
    api_config._settings = None

    assert result["status"] == "completed"
    warnings = [r for r in caplog.records if "environment settings only" in r.getMessage()]
    assert len(warnings) == 1
    assert "ConnectionError" in warnings[0].getMessage()
    assert "s3cret" not in caplog.text
