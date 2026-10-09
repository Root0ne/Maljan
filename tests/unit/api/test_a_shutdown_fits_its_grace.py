"""SIGTERM ends the analysis worker within the grace ``docker stop`` gives it.

The worker's shutdown is a sum of bounds — the pipeline's stop grace, keeping
the stopped run, the job teardown, the two connections and the exit guard —
and the compose file's ``stop_grace_period`` is that sum, so the stop reason
and the partial report are recorded before Docker kills the process. Keeping
the stopped run is the one step a shutdown added, and it is held to its grace.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml
from tests.integration._session_probe import SessionFactory, fake_job, fake_sample, rows_for

from app.worker import analysis_worker as worker_module

COMPOSE = Path(__file__).resolve().parents[3] / "docker" / "docker-compose.yml"


def _seconds(value: str) -> float:
    assert value.endswith("s"), value
    return float(value[:-1])


def test_docker_waits_as_long_as_the_worker_s_own_shutdown_bounds_add_up_to() -> None:
    services = yaml.safe_load(COMPOSE.read_text())["services"]
    grace = _seconds(str(services["backend-worker"]["stop_grace_period"]))
    assert grace == worker_module.shutdown_budget_seconds()
    assert worker_module.shutdown_budget_seconds() == 110


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    from app import config as api_config
    from app import runtime_config as rc
    from maljan.core.config import reset_settings_cache

    async def _allowed() -> dict[str, Any]:
        return {"api.mock_mode_allowed": True}

    monkeypatch.setattr(rc.runtime_config, "_overrides", _allowed)
    api_config._settings = None
    with (
        patch("minio.Minio", side_effect=ConnectionError("no object store here")),
        patch.dict(
            "os.environ",
            {"MALJAN_MOCK_MODE": "true", "UPLOAD_TEMP_DIR": str(tmp_path / "tmp")},
            clear=False,
        ),
    ):
        yield
    api_config._settings = None
    reset_settings_cache()


@pytest.mark.asyncio
async def test_a_keep_that_does_not_fit_is_abandoned_and_the_stop_still_recorded() -> None:
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))
    redis = MagicMock()
    redis.publish = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock()
    redis.delete = AsyncMock()
    running = asyncio.Event()

    async def _long_run(self: Any, **_: Any) -> dict[str, Any]:
        running.set()
        await asyncio.sleep(3600)
        return {}

    async def _slow_keep(*args: Any, **kwargs: Any) -> bool:
        await asyncio.sleep(3600)
        return True

    with (
        patch("maljan.app.MaljanApp.arun", new=_long_run),
        patch.object(worker_module, "keep_the_stopped_run", _slow_keep),
        patch.object(worker_module, "STOP_KEEP_GRACE", 0.05),
    ):
        task = asyncio.create_task(
            worker_module.run_analysis({"redis": redis, "db_session": factory}, str(job.id))
        )
        await running.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 30)

    from tests.integration._session_probe import updates_to

    [failed] = [u for u in updates_to(factory, "analysis_jobs") if u.get("status") == "failed"]
    assert failed["error_message"].startswith("Stopped because the worker running it shut down")
