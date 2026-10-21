"""ARQ worker job lifecycle integration tests.

These tests exercise the run_analysis function with mocked DB/Redis
contexts to verify status transitions and event publishing without
needing a real ARQ worker process.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from app.worker.analysis_worker import WorkerSettings, run_analysis
from tests.integration._session_probe import updates_in


def _dsn(scheme: str, userinfo: str, rest: str) -> str:
    """Assemble a credentialed URL at runtime so no literal DSN sits in the source
    (secret scanners flag ``scheme://user:pass@host`` even in a masking test)."""
    return f"{scheme}://{userinfo}@{rest}"


@pytest.fixture(autouse=True)
def _isolated_runtime_settings(monkeypatch: pytest.MonkeyPatch):
    """Keep these tests off the real runtime-settings singletons.

    ``runtime_config`` would otherwise try the real session factory on every
    ``run_analysis`` (and fall back on the connection error), and
    ``install_settings`` would leave the last job's Settings behind for the
    next test.

    ``api.mock_mode_allowed`` is set here rather than through the
    ``MOCK_MODE_ALLOWED`` env var some tests below still also set: Task 2
    moved that knob off ``APISettings`` entirely, so the env var has had no
    effect on it since, and the store override (what ``runtime_config.get``
    actually reads) is the only lever left. Every test in this module that
    requests mock mode via the job/env flag relies on this being True.
    """
    from app import runtime_config as rc
    from maljan.core.config import reset_settings_cache

    async def _mock_mode_allowed_override() -> dict[str, Any]:
        return {"api.mock_mode_allowed": True}

    monkeypatch.setattr(rc.runtime_config, "_overrides", _mock_mode_allowed_override)
    yield
    reset_settings_cache()


@pytest.fixture(autouse=True)
def _no_object_store(monkeypatch: pytest.MonkeyPatch):
    """The object store is out of reach here unless a test brings its own.

    These tests are about the job's lifecycle, not its bytes. Left to the
    host, the download succeeds on a developer machine and fails in CI, which
    makes every run take a different path through the worker and writes sample
    copies into whatever ``UPLOAD_TEMP_DIR`` points at. Refusing the
    connection is the shape CI exercises, and the two tests that need the
    bytes patch ``minio.Minio`` themselves, which wins while their block is
    open.
    """
    with patch("minio.Minio", side_effect=ConnectionError("no object store here")):
        yield


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


def _answer_reads(session: AsyncMock, answers: list[Any]) -> list[Any]:
    """Answer each read in turn, and keep every statement the run executed.

    The worker fires ``UPDATE`` statements between the reads and those need no
    row payload, so anything past the answers gets a bare ``MagicMock``. The
    list this returns is where a test reads the job's status changes from: the
    run writes them as statements now, against a row it does not keep loaded,
    because the session that read the job is closed before the pipeline runs.
    """
    recorded: list[Any] = []
    pending = list(answers)

    async def _execute(*args: Any, **kwargs: Any) -> MagicMock:
        if args:
            recorded.append(args[0])
        if pending:
            return pending.pop(0)
        return MagicMock()

    session.execute = _execute
    return recorded


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
async def test_job_not_found(
    mock_ctx: dict[str, Any], mock_db_session: AsyncMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If job is missing from DB, return error status."""
    from app.worker import analysis_worker

    monkeypatch.setattr(analysis_worker, "JOB_ROW_READ_PAUSES", (0.0, 0.0))
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

    recorded = _answer_reads(mock_db_session, [_make_result(job), _make_result(sample)])

    # Mock mode requires BOTH the
    # env/job flag AND ``api.mock_mode_allowed=True``. Without the second
    # toggle the worker stays on the real LLM path -- exactly the opposite of
    # what this test wants. The second toggle comes from the module's
    # autouse ``_isolated_runtime_settings`` fixture (Task 2 moved
    # ``mock_mode_allowed`` off ``APISettings`` into the settings store, so
    # an env var no longer reaches it); the leftover ``MOCK_MODE_ALLOWED``
    # env var below is inert and kept only for history.
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
    statuses = updates_in(recorded, "analysis_jobs")
    assert [u["status"] for u in statuses] == ["running", "completed"]
    completed_at = statuses[-1]["completed_at"]
    assert isinstance(completed_at, datetime)
    assert (datetime.now(UTC) - completed_at).total_seconds() < 60
    assert mock_db_session.commit.call_count >= 2  # running + completed


@pytest.mark.asyncio
async def test_report_less_pipeline_result_fails_the_job(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
) -> None:
    """A pipeline run that produced no report is a failed job, not a
    completed one with an empty report (L15, security hardening).

    ``report_node`` returns ``{"report_error": "<type>: <message>"}`` instead
    of a ``malware_report`` when the deterministic build raises; the worker
    must surface that message through the same failure path any other
    pipeline exception takes.
    """
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

    recorded = _answer_reads(mock_db_session, [_make_result(job), _make_result(sample)])

    from app import config as api_config

    api_config._settings = None
    with (
        patch.dict(
            "os.environ",
            {"MALJAN_MOCK_MODE": "true", "MOCK_MODE_ALLOWED": "true"},
            clear=False,
        ),
        patch(
            "maljan.app.MaljanApp.arun",
            new=AsyncMock(return_value={"report_error": "ValueError: boom"}),
        ),
    ):
        result = await run_analysis(mock_ctx, str(job.id))
    api_config._settings = None

    assert result["status"] == "failed"
    # The reason is the class of what was raised and the id of the log entry
    # holding the rest: ``error_message`` is a field of ``JobResponse``, and
    # the pipeline's own message can name a path or a connection string.
    assert result["error"].startswith("RuntimeError (error id ")
    assert "boom" not in result["error"]
    failed = [u for u in updates_in(recorded, "analysis_jobs") if u["status"] == "failed"]
    assert len(failed) == 1
    assert failed[0]["error_message"] == result["error"]
    assert isinstance(failed[0]["completed_at"], datetime)


@pytest.mark.asyncio
async def test_reporting_disabled_completes_without_a_malware_report(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing ``malware_report`` is not itself a failure.

    With ``reporting.enabled = False`` the graph routes judge -> END and the
    report node never runs at all (``pipeline/builder.py``,
    ``pipeline/state.py``) — ``malware_report`` stays ``None`` on every run
    of a job configured this way, and that is the documented, shipped
    behaviour (see ``tests/integration/test_report_pipeline.py::
    TestReportNodeDisabled``), not a report-less failure. The job must still
    complete.

    Task 3: ``build_job_settings`` is store-only, so ``reporting.enabled``
    can no longer be pinned via a ``REPORTING__ENABLED`` env var -- it has to
    arrive the way a real UI-saved override would, through
    ``load_core_overrides``.
    """
    from app.services import settings_service

    async def _reporting_disabled(_db: Any) -> dict[str, Any]:
        return {"reporting.enabled": False}

    monkeypatch.setattr(settings_service, "load_core_overrides", _reporting_disabled)
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

    recorded = _answer_reads(mock_db_session, [_make_result(job), _make_result(sample)])

    from app import config as api_config

    api_config._settings = None
    with (
        patch.dict(
            "os.environ",
            {"MALJAN_MOCK_MODE": "true"},
            clear=False,
        ),
        patch(
            "maljan.app.MaljanApp.arun",
            new=AsyncMock(
                return_value={
                    "final_decision": "Malware",
                    "judge_report": "legacy judge prose",
                }
            ),
        ),
    ):
        result = await run_analysis(mock_ctx, str(job.id))
    api_config._settings = None

    assert result["status"] == "completed"
    statuses = updates_in(recorded, "analysis_jobs")
    assert [u["status"] for u in statuses] == ["running", "completed"]
    assert "error_message" not in statuses[-1]


def _job_rows(job: Any, sample: Any) -> list[MagicMock]:
    rows = []
    for obj in (job, sample):
        m = MagicMock()
        if isinstance(getattr(obj, "status", None), str):
            m.scalar_one_or_none.return_value = obj
        else:
            m.scalar_one.return_value = obj
        rows.append(m)
    return rows


@pytest.mark.parametrize(
    ("stored", "named"),
    [
        ({"llm.max_spend_usd_per_job": -5.0}, "core.llm.max_spend_usd_per_job"),
        (
            {
                "mcp.servers": {
                    "custom": {
                        "enabled": True,
                        "transport": "stdio",
                        "command": "x",
                        "env_allow": 5,
                    }
                }
            },
            "core.mcp.servers",
        ),
        (
            {
                "mcp.servers": {
                    "custom": {
                        "enabled": True,
                        "transport": "stdio",
                        "command": "x",
                        "env_allow": ["DATABASE_URL"],
                    }
                }
            },
            "core.mcp.servers",
        ),
        ({"job_timeout": 0}, "core.job_timeout"),
    ],
)
@pytest.mark.asyncio
async def test_a_refused_stored_value_fails_the_job_by_name_and_runs_nothing(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
    stored: dict[str, Any],
    named: str,
) -> None:
    """No retry on the shipped defaults: the job fails, says which stored key
    and what to do, and the pipeline never starts."""
    from app.services import settings_service

    async def _stored(_db: Any) -> dict[str, Any]:
        return dict(stored)

    monkeypatch.setattr(settings_service, "load_core_overrides", _stored)
    job = _make_job()
    sample = _make_sample()
    recorded = _answer_reads(mock_db_session, _job_rows(job, sample))
    pipeline = AsyncMock(return_value={"final_decision": "Malware"})

    with patch("maljan.app.MaljanApp.arun", new=pipeline):
        result = await run_analysis(mock_ctx, str(job.id))

    assert result["status"] == "failed", result
    assert named in result["error"]
    assert "Fix it or reset it in the console" in result["error"]
    pipeline.assert_not_awaited()
    failed = [u for u in updates_in(recorded, "analysis_jobs") if u["status"] == "failed"]
    assert len(failed) == 1 and named in failed[0]["error_message"]
    published = " ".join(str(call.args) for call in mock_ctx["redis"].publish.await_args_list)
    assert '"error"' in published or "'error'" in published


@pytest.mark.asyncio
async def test_unreadable_stored_settings_fail_the_job_and_run_nothing(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A database that cannot give the stored settings fails the job: running
    on the shipped defaults would drop the operator's caps without a word."""
    from app.services import settings_service

    async def _unreadable(_db: Any) -> dict[str, Any]:
        raise ConnectionError("postgresql://maljan:hunter2@db:5432 refused")

    monkeypatch.setattr(settings_service, "load_core_overrides", _unreadable)
    job = _make_job()
    sample = _make_sample()
    recorded = _answer_reads(mock_db_session, _job_rows(job, sample))
    pipeline = AsyncMock(return_value={"final_decision": "Malware"})

    with patch("maljan.app.MaljanApp.arun", new=pipeline):
        result = await run_analysis(mock_ctx, str(job.id))

    assert result["status"] == "failed", result
    assert "The stored settings could not be read" in result["error"]
    assert "did not run on defaults" in result["error"]
    assert "once the database answers" in result["error"]
    assert "hunter2" not in result["error"]
    pipeline.assert_not_awaited()
    failed = [u for u in updates_in(recorded, "analysis_jobs") if u["status"] == "failed"]
    assert len(failed) == 1
    assert "The stored settings could not be read" in failed[0]["error_message"]
    published = [json.loads(call.args[1]) for call in mock_ctx["redis"].publish.await_args_list]
    assert any(event.get("type") == "error" for event in published)


@pytest.mark.asyncio
async def test_a_stored_secret_the_worker_cannot_decrypt_fails_the_job_naming_its_key(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The row used to be dropped and the job ran on the default in its place."""
    from app.services import settings_service
    from maljan.core.settings_overrides import StoredValueRefused

    async def _undecryptable(_db: Any) -> dict[str, Any]:
        raise StoredValueRefused({"llm.api_key": "the stored secret cannot be decrypted"})

    monkeypatch.setattr(settings_service, "load_core_overrides", _undecryptable)
    job = _make_job()
    _answer_reads(mock_db_session, _job_rows(job, _make_sample()))
    pipeline = AsyncMock(return_value={"final_decision": "Malware"})

    with patch("maljan.app.MaljanApp.arun", new=pipeline):
        result = await run_analysis(mock_ctx, str(job.id))

    assert result["status"] == "failed", result
    # The owner reads the job, so its message names no setting key.
    assert "api_key" not in result["error"]
    assert "did not run on a default" in result["error"]
    pipeline.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_secret_of_a_server_the_job_never_calls_does_not_stop_the_worker(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An orphan server's token that cannot be read is no reason to fail a job."""
    from app.services import settings_service
    from maljan.core.settings_overrides import StoredValueRefused

    calls: list[int] = []

    async def _read(_db: Any) -> dict[str, Any]:
        calls.append(1)
        if len(calls) == 1:
            raise StoredValueRefused({"mcp.servers.orphan.auth_token": "cannot be decrypted"})
        return {}

    monkeypatch.setattr(settings_service, "load_core_overrides", _read)
    job = _make_job()
    _answer_reads(mock_db_session, _job_rows(job, _make_sample()))
    pipeline = AsyncMock(return_value={"final_decision": "Malware"})

    with patch("maljan.app.MaljanApp.arun", new=pipeline):
        result = await run_analysis(mock_ctx, str(job.id))

    assert "cannot be decrypted" not in str(result.get("error", "")), result
    assert len(calls) >= 2


@pytest.mark.asyncio
async def test_the_workers_real_settings_read_refuses_an_undecryptable_secret_row(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
) -> None:
    """Through the real ``load_core_overrides`` and its context variable: no fake."""
    from types import SimpleNamespace

    from maljan.core import settings_secrets as box

    job = _make_job()
    rows = MagicMock()
    rows.scalars.return_value.all.return_value = [
        SimpleNamespace(key="core.llm.api_key", value="gAAAA-unreadable", is_secret=True)
    ]
    _answer_reads(mock_db_session, [*_job_rows(job, _make_sample()), MagicMock(), rows])
    pipeline = AsyncMock(return_value={"final_decision": "Malware"})

    with (
        patch.object(box, "decrypt", side_effect=box.SecretsUnavailable("rotated")),
        patch("maljan.app.MaljanApp.arun", new=pipeline),
    ):
        result = await run_analysis(mock_ctx, str(job.id))

    assert result["status"] == "failed", result
    # The owner reads the job, so its message names no setting key.
    assert "api_key" not in result["error"]
    pipeline.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_refused_job_option_fails_the_job_by_field_without_its_value(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
) -> None:
    """The other arm: a refusal that is no stored key also fails loudly, naming
    the field, never running on defaults and never quoting the value."""
    job = _make_job(config={"max_iterations": -7777})
    sample = _make_sample()
    _answer_reads(mock_db_session, _job_rows(job, sample))
    pipeline = AsyncMock(return_value={"final_decision": "Malware"})

    with patch("maljan.app.MaljanApp.arun", new=pipeline):
        result = await run_analysis(mock_ctx, str(job.id))

    assert result["status"] == "failed", result
    assert "negotiation.max_iterations" in result["error"]
    assert "-7777" not in result["error"]
    pipeline.assert_not_awaited()


def _database_error(secret: str) -> Exception:
    from sqlalchemy.exc import OperationalError

    return OperationalError("SELECT 1", {}, Exception(f"password {secret} was refused"))


def _connection_error(secret: str) -> Exception:
    return ConnectionRefusedError(f"db:5432 refused the login {secret}")


@pytest.mark.parametrize(
    ("unreadable", "named"),
    [(_database_error, "OperationalError"), (_connection_error, "ConnectionRefusedError")],
    ids=["database", "connection"],
)
@pytest.mark.asyncio
async def test_a_database_that_cannot_give_the_settings_is_named_with_its_error_class(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
    unreadable: Any,
    named: str,
) -> None:
    from app.services import settings_service
    from tests.credential_shapes import password

    secret = password(14)

    async def _unreadable(_db: Any) -> dict[str, Any]:
        raise unreadable(secret)

    monkeypatch.setattr(settings_service, "load_core_overrides", _unreadable)
    job = _make_job()
    _answer_reads(mock_db_session, _job_rows(job, _make_sample()))
    pipeline = AsyncMock(return_value={"final_decision": "Malware"})

    with patch("maljan.app.MaljanApp.arun", new=pipeline):
        result = await run_analysis(mock_ctx, str(job.id))

    assert result["status"] == "failed", result
    assert f"could not be read from the database ({named})" in result["error"]
    assert "once the database answers" in result["error"]
    assert secret not in result["error"]
    pipeline.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_settings_read_that_fails_for_another_reason_is_not_blamed_on_the_database(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Not an outage to wait out: the job fails by the error's class, the pipeline never starts."""
    from app.services import settings_service

    async def _unmergeable(_db: Any) -> dict[str, Any]:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(settings_service, "load_core_overrides", _unmergeable)
    job = _make_job()
    recorded = _answer_reads(mock_db_session, _job_rows(job, _make_sample()))
    pipeline = AsyncMock(return_value={"final_decision": "Malware"})

    with patch("maljan.app.MaljanApp.arun", new=pipeline):
        result = await run_analysis(mock_ctx, str(job.id))

    assert result["status"] == "failed", result
    assert result["error"].startswith("RecursionError (error id "), result["error"]
    assert "database" not in result["error"]
    pipeline.assert_not_awaited()
    failed = [u for u in updates_in(recorded, "analysis_jobs") if u["status"] == "failed"]
    assert len(failed) == 1 and failed[0]["error_message"].startswith("RecursionError")


@pytest.mark.asyncio
async def test_a_plain_settings_refusal_is_stated_by_its_class_never_its_text(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The refused value can be a stored secret; it reaches neither the job nor the log."""
    from app.worker import analysis_worker
    from tests.credential_shapes import password

    secret = password(16)

    def _refuses(overrides: Any, job_config: Any) -> Any:
        raise ValueError(f"the value {secret} is not one this field takes")

    monkeypatch.setattr(analysis_worker, "build_job_settings", _refuses)
    job = _make_job()
    _answer_reads(mock_db_session, _job_rows(job, _make_sample()))
    pipeline = AsyncMock(return_value={"final_decision": "Malware"})

    with (
        patch("maljan.app.MaljanApp.arun", new=pipeline),
        caplog.at_level(logging.INFO, logger="app.worker.analysis_worker"),
    ):
        result = await run_analysis(mock_ctx, str(job.id))

    assert result["status"] == "failed", result
    assert "The settings this job would run with are refused (ValueError)." in result["error"]
    assert "did not run on defaults" in result["error"]
    assert secret not in result["error"]
    stated = [r for r in caplog.records if "rather than running on defaults" in r.getMessage()]
    assert len(stated) == 1 and "ValueError" in stated[0].getMessage()
    # ``from None``: the refusal's own text is not chained onto the failure's
    # traceback, which the failure path logs whole.
    assert secret not in caplog.text
    pipeline.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_provider_with_no_role_block_is_refused_by_its_setting_with_why(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one refusal written here from setting names keeps its sentence."""
    from app.services import settings_service
    from maljan.llm import registry
    from maljan.llm.provider_base import _FACTS, LLMProvider

    class _Bare(LLMProvider):
        name = "bare"

        def __init__(self, config: Any) -> None:
            self._config = config

    async def _stored(_db: Any) -> dict[str, Any]:
        return {"llm.provider": "bare"}

    registry.discover_providers()
    registry.register_provider("bare")(_Bare)
    monkeypatch.setattr(settings_service, "load_core_overrides", _stored)
    job = _make_job()
    _answer_reads(mock_db_session, _job_rows(job, _make_sample()))
    pipeline = AsyncMock(return_value={"final_decision": "Malware"})
    try:
        with patch("maljan.app.MaljanApp.arun", new=pipeline):
            result = await run_analysis(mock_ctx, str(job.id))
    finally:
        registry._PROVIDER_REGISTRY.pop("bare", None)
        _FACTS.pop("bare", None)

    assert result["status"] == "failed", result
    assert result["error"].startswith(
        "The settings this job would run with are refused: llm.provider: the bare provider "
        "keeps no settings block"
    ), result["error"]
    pipeline.assert_not_awaited()


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

    recorded = _answer_reads(mock_db_session, [_make_result(job), _make_result(sample)])

    # Force MaljanApp to blow up by mocking the class where it is defined.
    with patch("maljan.app.MaljanApp") as mock_app_cls:
        mock_app_cls.side_effect = RuntimeError("Simulated pipeline crash")

        result = await run_analysis(mock_ctx, str(job.id))

    assert result["status"] == "failed"
    assert result["error"].startswith("RuntimeError (error id ")
    assert "Simulated pipeline crash" not in result["error"]
    failed = [u for u in updates_in(recorded, "analysis_jobs") if u["status"] == "failed"]
    assert len(failed) == 1
    assert isinstance(failed[0]["completed_at"], datetime)


@pytest.mark.asyncio
async def test_mock_mode_with_an_attached_report_fails_with_a_worded_message(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
) -> None:
    """A job carrying both ``mock_mode`` and ``sandbox_report_id`` must not
    surface a raw ``AttributeError``.

    ``build_job_settings`` forces ``sandbox.provider="upload"`` because a
    report is attached, but ``ServiceContainer.get_sandbox_provider()``'s own
    mock override runs after that and wins whenever the container's ``mock``
    flag is set, handing back a ``MockSandboxProvider`` — which has no
    ``set_pending_blob``. The worker must check
    ``capabilities.accepts_uploaded_report`` before calling it and fail with a
    legible, worded message instead of letting the attribute error escape to
    ``job.error_message`` where the user would see it. Task 20 (per-job
    override validation) is the real fix for the underlying combination; this
    is the defence in depth underneath it.
    """
    job = _make_job(
        config={
            "sandbox_report_id": "0b6c6e0e-0000-4000-8000-000000000000",
            "mock_mode": True,
        }
    )
    sample = _make_sample()

    report_row = MagicMock()
    report_row.id = uuid.UUID("0b6c6e0e-0000-4000-8000-000000000000")
    report_row.sample_id = sample.id
    report_row.storage_path = "sandbox-reports/0b/0b6c.../report.json"
    report_row.format = "cape2"

    def _make_result(obj: Any) -> MagicMock:
        m = MagicMock()
        status_val = getattr(obj, "status", None)
        if isinstance(status_val, str):
            m.scalar_one_or_none.return_value = obj
        else:
            m.scalar_one.return_value = obj
        return m

    report_result = MagicMock()
    report_result.scalar_one_or_none.return_value = report_row

    # Job, then sample, then the ``started_at`` UPDATE every job fires right
    # after, then ``load_core_overrides``'s own settings-table read (both
    # unused — a plain MagicMock's default empty ``__iter__`` is enough for
    # ``list(res.scalars().all())`` to come back ``[]``, same as every other
    # test in this file relies on for that call), then the sandbox-report row
    # lookup this task's own attach-path added.
    recorded = _answer_reads(
        mock_db_session,
        [
            _make_result(job),
            _make_result(sample),
            MagicMock(),
            MagicMock(),
            report_result,
        ],
    )

    from app import config as api_config

    api_config._settings = None
    with (
        patch.dict("os.environ", {"MOCK_MODE_ALLOWED": "true"}, clear=False),
        # Never actually reached once the capability guard fires first — mocked
        # anyway so a wrong fix ordering fails loudly instead of hitting MinIO.
        patch("app.api.v1.sandbox_reports.get_object", return_value=b"{}"),
    ):
        result = await run_analysis(mock_ctx, str(job.id))
    api_config._settings = None

    assert result["status"] == "failed"
    assert "AttributeError" not in result["error"]
    # The sentence this module wrote is what the operator reads, with the id
    # of the log entry that holds the rest. Only a ``StatedFailure`` keeps its
    # message; anything else would arrive as its class name alone.
    assert "cannot accept an uploaded report" in result["error"]
    assert "(error id " in result["error"]
    failed = [u for u in updates_in(recorded, "analysis_jobs") if u["status"] == "failed"]
    assert len(failed) == 1
    assert failed[0]["error_message"] == result["error"]


# ---------------------------------------------------------------------------
# L2 (live-run finding): an attached sandbox report whose own claimed hash
# disagreed with the sample at upload time must show up as a degradation —
# the upload endpoint's warning promises "The analysis will still run and
# will say so in its findings", but nothing threaded the stored
# ``sample_sha256_match`` flag into the run until this fix.
# ---------------------------------------------------------------------------


def _attached_report_exec_results(
    job: MagicMock, sample: MagicMock, report_row: MagicMock
) -> list[MagicMock]:
    def _make_result(obj: Any) -> MagicMock:
        m = MagicMock()
        status_val = getattr(obj, "status", None)
        if isinstance(status_val, str):
            m.scalar_one_or_none.return_value = obj
        else:
            m.scalar_one.return_value = obj
        return m

    report_result = MagicMock()
    report_result.scalar_one_or_none.return_value = report_row
    # Same sequence as test_mock_mode_with_an_attached_report_fails_with_a_
    # worded_message: job, sample, the started_at UPDATE, load_core_overrides'
    # own settings-table read, then this task's sandbox-report row lookup.
    # Anything after falls back to a bare MagicMock() in _fake_execute below.
    return [_make_result(job), _make_result(sample), MagicMock(), MagicMock(), report_result]


async def _run_with_attached_report(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
    job: MagicMock,
    sample: MagicMock,
    report_row: MagicMock,
) -> dict[str, Any]:
    exec_results = _attached_report_exec_results(job, sample, report_row)
    call_count = 0

    async def _fake_execute(*args: Any, **kwargs: Any) -> MagicMock:
        nonlocal call_count
        if call_count >= len(exec_results):
            return MagicMock()
        res = exec_results[call_count]
        call_count += 1
        return res

    mock_db_session.execute = _fake_execute

    from app import config as api_config

    api_config._settings = None
    with (
        # Real (non-mock) mode: mock mode's own container override always
        # hands back a MockSandboxProvider with no set_pending_blob, so an
        # attached-report job can only succeed off mock mode (see the
        # capability-guard test above). MaljanApp.arun is patched anyway, so
        # this never reaches a real LLM or sandbox call.
        patch.dict("os.environ", {}, clear=False),
        patch("app.api.v1.sandbox_reports.get_object", return_value=b"{}"),
        patch("minio.Minio", return_value=_FakeMinioClient()),
        patch(
            "maljan.app.MaljanApp.arun",
            new=AsyncMock(
                return_value={
                    "final_decision": "Suspicious",
                    "malware_report": {"degradation_reasons": []},
                }
            ),
        ),
    ):
        result = await run_analysis(mock_ctx, str(job.id))
    api_config._settings = None
    return result


@pytest.mark.asyncio
async def test_a_hash_mismatch_on_the_attached_report_is_recorded_as_a_degradation(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
) -> None:
    job = _make_job(config={"sandbox_report_id": "0b6c6e0e-0000-4000-8000-000000000000"})
    sample = _make_sample()

    report_row = MagicMock()
    report_row.id = uuid.UUID("0b6c6e0e-0000-4000-8000-000000000000")
    report_row.sample_id = sample.id
    report_row.storage_path = "sandbox-reports/0b/0b6c.../report.json"
    report_row.format = "cape2"
    report_row.sample_sha256_match = False

    result = await _run_with_attached_report(mock_ctx, mock_db_session, job, sample, report_row)

    assert result["status"] == "completed", result
    saved_report = mock_db_session.add.call_args[0][0]
    reason = "uploaded sandbox report's target hash differs from the sample"
    assert reason in saved_report.run_summary["degradation_reasons"]
    assert reason in saved_report.malware_report["degradation_reasons"]


@pytest.mark.asyncio
async def test_a_matching_attached_report_records_no_such_degradation(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
) -> None:
    job = _make_job(config={"sandbox_report_id": "0b6c6e0e-0000-4000-8000-000000000000"})
    sample = _make_sample()

    report_row = MagicMock()
    report_row.id = uuid.UUID("0b6c6e0e-0000-4000-8000-000000000000")
    report_row.sample_id = sample.id
    report_row.storage_path = "sandbox-reports/0b/0b6c.../report.json"
    report_row.format = "cape2"
    report_row.sample_sha256_match = True

    result = await _run_with_attached_report(mock_ctx, mock_db_session, job, sample, report_row)

    assert result["status"] == "completed", result
    saved_report = mock_db_session.add.call_args[0][0]
    reason = "uploaded sandbox report's target hash differs from the sample"
    assert reason not in (saved_report.run_summary.get("degradation_reasons") or [])
    assert reason not in (saved_report.malware_report.get("degradation_reasons") or [])


@pytest.mark.asyncio
async def test_an_attached_report_of_a_format_no_longer_declared_fails_in_words(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
) -> None:
    """The run reads the format the upload row recorded; one no longer declared
    stops the job with the reason rather than running without the evidence."""
    job = _make_job(config={"sandbox_report_id": "0b6c6e0e-0000-4000-8000-000000000000"})
    sample = _make_sample()

    report_row = MagicMock()
    report_row.id = uuid.UUID("0b6c6e0e-0000-4000-8000-000000000000")
    report_row.sample_id = sample.id
    report_row.storage_path = "sandbox-reports/0b/0b6c.../report.json"
    report_row.format = "retired_format"
    report_row.sample_sha256_match = True

    result = await _run_with_attached_report(mock_ctx, mock_db_session, job, sample, report_row)

    assert result["status"] == "failed", result
    assert "'retired_format', which is no longer declared" in result["error"]


@pytest.mark.asyncio
async def test_an_attached_report_of_a_format_no_longer_allowed_fails_in_words(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
) -> None:
    """A recorded format taken out of the allow list stops the job with the
    reason, as a removed declaration does, rather than running without it."""
    job = _make_job(config={"sandbox_report_id": "0b6c6e0e-0000-4000-8000-000000000000"})
    sample = _make_sample()

    report_row = MagicMock()
    report_row.id = uuid.UUID("0b6c6e0e-0000-4000-8000-000000000000")
    report_row.sample_id = sample.id
    report_row.storage_path = "sandbox-reports/0b/0b6c.../report.json"
    report_row.format = "cuckoo"
    report_row.sample_sha256_match = True

    async def _overrides(db: Any) -> dict[str, Any]:
        # The settings read still takes its place in the session's sequence.
        await db.execute(None)
        return {"sandbox.upload.allowed_formats": ["cape2"]}

    with patch("app.services.settings_service.load_core_overrides", new=_overrides):
        result = await _run_with_attached_report(mock_ctx, mock_db_session, job, sample, report_row)

    assert result["status"] == "failed", result
    assert "'cuckoo', which sandbox.upload.allowed_formats no longer accepts" in result["error"]


@pytest.mark.asyncio
async def test_a_provider_s_own_words_over_an_attached_report_are_stated_by_their_class(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A plug-in provider's refusal can quote a value: the job says its class, the log no text."""
    from maljan.providers.errors import ProviderError
    from maljan.providers.sandbox.upload import UploadSandboxProvider
    from tests.credential_shapes import password

    secret = password(12)

    def _refuses(self: Any, blob: bytes, **_: Any) -> None:
        raise ProviderError(f"the report store refused the password '{secret}'")

    job = _make_job(config={"sandbox_report_id": "0b6c6e0e-0000-4000-8000-000000000000"})
    sample = _make_sample()
    report_row = MagicMock()
    report_row.id = uuid.UUID("0b6c6e0e-0000-4000-8000-000000000000")
    report_row.sample_id = sample.id
    report_row.storage_path = "sandbox-reports/0b/0b6c.../report.json"
    report_row.format = "cape2"
    report_row.sample_sha256_match = True

    with (
        patch.object(UploadSandboxProvider, "set_pending_blob", _refuses),
        caplog.at_level(logging.INFO),
    ):
        result = await _run_with_attached_report(mock_ctx, mock_db_session, job, sample, report_row)

    assert result["status"] == "failed", result
    assert "could not read the attached sandbox report (ProviderError)" in result["error"]
    assert "did not run without it" in result["error"]
    assert secret not in result["error"]
    assert secret not in caplog.text


# ---------------------------------------------------------------------------
# H3 (security hardening): the worker's private sample copies (download +
# Ghidra mirror) are removed when the job ends, success or failure alike.
# ---------------------------------------------------------------------------


class _FakeMinioClient:
    """Stands in for the real MinIO client so the download step actually
    writes a file, letting the mirror step run for real too."""

    def fget_object(self, bucket: str, object_name: str, file_path: str) -> None:
        Path(file_path).write_bytes(b"MZfakebinary")


@pytest.mark.asyncio
async def test_worker_removes_private_sample_copies_after_success(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A completed job leaves neither the downloaded temp copy nor the
    Ghidra ``.work`` mirror behind."""
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

    _answer_reads(mock_db_session, [_make_result(job), _make_result(sample)])

    from app.worker import sample_files

    recorded: list[tuple[Any, str | None]] = []
    monkeypatch.setattr(
        sample_files,
        "release_copy",
        lambda path, *, job_id=None: recorded.append((path, job_id)),
    )

    from app import config as api_config

    api_config._settings = None
    with (
        patch.dict(
            "os.environ",
            {
                "MALJAN_MOCK_MODE": "true",
                "MOCK_MODE_ALLOWED": "true",
                "UPLOAD_TEMP_DIR": str(tmp_path / "tmp"),
                "SAMPLES_DIR": str(tmp_path / "samples"),
            },
            clear=False,
        ),
        patch("minio.Minio", return_value=_FakeMinioClient()),
    ):
        result = await run_analysis(mock_ctx, str(job.id))
    api_config._settings = None

    assert result["status"] == "completed"
    expected_temp = (tmp_path / "tmp" / f"{sample.sha256}.exe").resolve()
    expected_mirror = (tmp_path / "samples" / ".work" / f"{sample.sha256}.exe").resolve()
    called_paths = {Path(p).resolve() for p, _ in recorded if p is not None}
    assert expected_temp in called_paths
    assert expected_mirror in called_paths


@pytest.mark.asyncio
async def test_worker_removes_private_sample_copies_after_pipeline_failure(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A job that fails mid-pipeline (after the sample was already downloaded
    and mirrored) still has both private copies removed."""
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

    _answer_reads(mock_db_session, [_make_result(job), _make_result(sample)])

    from app.worker import sample_files

    recorded: list[tuple[Any, str | None]] = []
    monkeypatch.setattr(
        sample_files,
        "release_copy",
        lambda path, *, job_id=None: recorded.append((path, job_id)),
    )

    from app import config as api_config

    api_config._settings = None
    with (
        patch.dict(
            "os.environ",
            {
                "MALJAN_MOCK_MODE": "true",
                "MOCK_MODE_ALLOWED": "true",
                "UPLOAD_TEMP_DIR": str(tmp_path / "tmp"),
                "SAMPLES_DIR": str(tmp_path / "samples"),
            },
            clear=False,
        ),
        patch("minio.Minio", return_value=_FakeMinioClient()),
        # The download/mirror happen before ``app.arun`` is ever awaited, so
        # failing here (rather than in ``MaljanApp.__init__``, as the other
        # failure test does) is what actually exercises cleanup of real
        # on-disk copies rather than of two still-``None`` paths.
        patch(
            "maljan.app.MaljanApp.arun",
            new=AsyncMock(side_effect=RuntimeError("Simulated pipeline crash")),
        ),
    ):
        result = await run_analysis(mock_ctx, str(job.id))
    api_config._settings = None

    assert result["status"] == "failed"
    expected_temp = (tmp_path / "tmp" / f"{sample.sha256}.exe").resolve()
    expected_mirror = (tmp_path / "samples" / ".work" / f"{sample.sha256}.exe").resolve()
    called_paths = {Path(p).resolve() for p, _ in recorded if p is not None}
    assert expected_temp in called_paths
    assert expected_mirror in called_paths


# ---------------------------------------------------------------------------
# Worker settings sanity checks
# ---------------------------------------------------------------------------


def test_worker_settings_sanity() -> None:
    """Verify ARQ worker tuning values are production-ready."""
    from datetime import timedelta

    assert WorkerSettings.max_jobs == 1
    # No deadline arq can reach: a job's limit is ``core.job_timeout``, empty
    # by default, which the run enforces itself so a stopped job keeps what it
    # produced (``test_the_job_timeout_is_a_setting``).
    assert WorkerSettings.job_timeout == timedelta.max.total_seconds()
    assert WorkerSettings.max_tries == 1


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
async def test_override_load_failure_fails_the_job_and_logs_no_secret(
    mock_ctx: dict[str, Any],
    mock_db_session: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A DB error while loading the stored settings fails the job.

    Running on the shipped defaults would drop the operator's spend cap,
    server map and timeout without a word. One error names the exception type
    only -- never a value, never a connection string.
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

    _answer_reads(mock_db_session, [_make_result(job), _make_result(sample)])

    async def _boom(_db: Any) -> dict[str, Any]:
        raise ConnectionError(f"{_dsn('postgres', 'maljan:s3cret', 'db:5432/maljan')} unreachable")

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

    assert result["status"] == "failed"
    errors = [r for r in caplog.records if "rather than running on defaults" in r.getMessage()]
    assert len(errors) == 1
    assert "ConnectionError" in errors[0].getMessage()
    assert "s3cret" not in caplog.text
    assert "s3cret" not in result["error"]
