"""A job reaches its servers to list them only once it is known to run for real.

The worker reads what each server declared of its tools, kept, at the start of
every job (``served_declarations_store.prepare_job``), and lists each trusted
server nothing is kept for (``list_before_run``) only after the mock decision:
a mock run reaches no server of its own accord. Nothing here reaches a
service: the database is the tracking factory of ``_session_probe``, Redis a
stub, and the listing itself stands in.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.worker.analysis_worker import run_analysis
from tests.integration._session_probe import SessionFactory, fake_job, fake_sample, rows_for


class _Stop(Exception):
    """Ends a real run where the listing would be, before anything else is built."""


class _FakeMinioClient:
    def fget_object(self, bucket: str, object_name: str, file_path: str) -> None:
        Path(file_path).write_bytes(b"MZfakebinary")


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    from app import config as api_config
    from app import runtime_config as rc
    from maljan.core.config import reset_settings_cache

    async def _allowed() -> dict[str, Any]:
        return {"api.mock_mode_allowed": True}

    monkeypatch.setattr(rc.runtime_config, "_overrides", _allowed)
    api_config._settings = None
    with (
        patch("minio.Minio", return_value=_FakeMinioClient()),
        patch.dict(
            "os.environ",
            {"UPLOAD_TEMP_DIR": str(tmp_path / "tmp"), "SAMPLES_DIR": str(tmp_path / "samples")},
            clear=False,
        ),
    ):
        yield
    api_config._settings = None
    reset_settings_cache()


def _redis() -> MagicMock:
    redis = MagicMock()
    for name in ("publish", "aclose", "set", "delete"):
        setattr(redis, name, AsyncMock())
    redis.get = AsyncMock(return_value=None)
    return redis


async def _run(mock: bool, listed: list[Any]) -> dict[str, Any]:
    from app.services import served_declarations_store

    async def _list(db_session: Any, settings: Any) -> None:
        listed.append(settings)
        raise _Stop

    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))
    from tests.integration.test_worker_session_lifetime import _pipeline_result

    result = _pipeline_result()
    with (
        patch.dict("os.environ", {"MALJAN_MOCK_MODE": "true" if mock else "false"}),
        patch.object(served_declarations_store, "list_before_run", _list),
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(return_value=result)),
    ):
        return await run_analysis({"redis": _redis(), "db_session": factory}, str(job.id))


@pytest.mark.asyncio
async def test_a_mock_run_lists_no_server() -> None:
    listed: list[Any] = []
    result = await _run(True, listed)
    # It ran to its end, past where a run for real lists its servers.
    assert result["status"] == "completed", result
    assert listed == []


@pytest.mark.asyncio
async def test_a_run_for_real_lists_them_before_its_app_is_built() -> None:
    listed: list[Any] = []
    with patch("maljan.app.MaljanApp.__init__", side_effect=AssertionError("built first")):
        result = await _run(False, listed)
    assert len(listed) == 1
    # The listing stood in for the rest of the run: it stopped there.
    assert result["status"] == "failed"
