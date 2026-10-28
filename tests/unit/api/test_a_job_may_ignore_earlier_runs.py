"""The job option ``ignore_earlier_runs`` reaches the run from every place a job is started (T-414).

The submit schema checks it, the audit row names it, the worker hands it to
the job's container from the job's own config and from nothing else, and the
command line takes it as ``--ignore-earlier-runs``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from tests.integration._session_probe import SessionFactory, fake_job, fake_sample, rows_for

from app.api.v1.jobs import _job_details
from app.schemas.job import JobCreateRequest
from app.worker import analysis_worker

BYTES = b"MZ synthetic sample bytes, never run\x00" * 64
INTAKE = hashlib.sha256(BYTES).hexdigest()
SAMPLE = "00000000-0000-0000-0000-000000000001"


class TestTheSubmitSchema:
    @pytest.mark.parametrize("value", [True, False])
    def test_a_boolean_is_accepted_and_kept(self, value: bool) -> None:
        body = JobCreateRequest(sample_id=SAMPLE, config={"ignore_earlier_runs": value})
        assert body.config == {"ignore_earlier_runs": value}

    # Strict: the route stores the config as sent and the worker reads only
    # ``True``, so a lax "true" or 1 would be accepted and leave the switch off.
    @pytest.mark.parametrize("value", [None, "sometimes", [True], "true", "yes", 1, 0])
    def test_anything_else_is_refused(self, value: Any) -> None:
        with pytest.raises(ValidationError):
            JobCreateRequest(sample_id=SAMPLE, config={"ignore_earlier_runs": value})

    def test_the_audit_row_names_it(self) -> None:
        assert _job_details(SAMPLE, {"ignore_earlier_runs": True})["ignore_earlier_runs"] is True
        assert "ignore_earlier_runs" not in _job_details(SAMPLE, {})


class TestTheWorker:
    @pytest.fixture(autouse=True)
    def _worker_dirs(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
        from unittest.mock import patch

        from app import config as api_config
        from app import runtime_config as rc
        from maljan.core.config import reset_settings_cache

        async def _mock_mode_allowed() -> dict[str, Any]:
            return {"api.mock_mode_allowed": True}

        monkeypatch.setattr(rc.runtime_config, "_overrides", _mock_mode_allowed)
        api_config._settings = None
        with patch.dict(
            "os.environ",
            {
                "MALJAN_MOCK_MODE": "true",
                "UPLOAD_TEMP_DIR": str(tmp_path / "tmp"),
                "SAMPLES_DIR": str(tmp_path / "samples"),
            },
            clear=False,
        ):
            yield
        api_config._settings = None
        reset_settings_cache()

    async def _switch_in_force(self, config: dict[str, Any] | None) -> Any:
        from unittest.mock import AsyncMock, MagicMock, patch

        from app.services import object_store

        def _download(_client: Any, _path: str, destination: str) -> None:
            Path(destination).write_bytes(BYTES)

        seen: dict[str, Any] = {}

        async def _arun(self_: Any, **_kwargs: Any) -> dict[str, Any]:
            seen["switch"] = self_.container.ignore_earlier_runs
            return {
                "final_decision": "Malware",
                "judge_report": "the judge answered",
                "malware_report": {"summary": {"verdict": "Malware"}},
                "isr_reports": {},
                "evidence_ledger": [],
            }

        job = fake_job(config=config)
        sample = fake_sample(job.sample_id, sha256=INTAKE)
        sample.file_size_bytes = len(BYTES)
        factory = SessionFactory(rows_for(job, sample))
        redis = MagicMock()
        for name in ("publish", "aclose", "set", "delete"):
            setattr(redis, name, AsyncMock())
        redis.get = AsyncMock(return_value=None)
        with (
            patch.object(object_store, "client", return_value=MagicMock()),
            patch.object(object_store, "download", side_effect=_download),
            patch("maljan.app.MaljanApp.arun", new=_arun),
        ):
            result = await analysis_worker.run_analysis(
                {"redis": redis, "db_session": factory}, str(job.id)
            )
        assert result["status"] == "completed"
        return seen["switch"]

    @pytest.mark.asyncio
    async def test_the_job_s_config_turns_it_on(self) -> None:
        assert await self._switch_in_force({"ignore_earlier_runs": True}) is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize("config", [None, {}, {"ignore_earlier_runs": False}])
    async def test_without_it_the_job_reads_its_earlier_runs(self, config: Any) -> None:
        assert await self._switch_in_force(config) is False


class TestTheCommandLine:
    @pytest.mark.parametrize(("argv", "expected"), [([], False), (["--ignore-earlier-runs"], True)])
    def test_the_option_reaches_the_app(
        self, monkeypatch: pytest.MonkeyPatch, argv: list[str], expected: bool
    ) -> None:
        from typer.testing import CliRunner

        from maljan import cli

        built: dict[str, Any] = {}

        class _App:
            def __init__(self, **kwargs: Any) -> None:
                built.update(kwargs)

            def run(self, **_kwargs: Any) -> dict[str, Any]:
                return {"stix_output": {}, "run_summary": None}

            def remember_the_run(self) -> bool:
                return False

        monkeypatch.setattr(cli, "MaljanApp", _App)
        monkeypatch.setattr(cli, "_release", lambda _app: None)

        result = CliRunner().invoke(cli.app, ["analyze", "sample_1", "--mock", *argv])

        assert built.get("ignore_earlier_runs") is expected, result.output
