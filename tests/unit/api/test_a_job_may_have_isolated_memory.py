"""The job option ``isolated_memory`` gives one job an owner of its own, in both workers (T-422).

The submit schema checks it, the audit row names it, and the analysis worker
and the enrichment of the job's report derive one owner from it: the job's
creator without it, byte for byte as before, and a key of the job's own with
it. It never reaches the job's settings, and the stored run summary says so.
"""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError
from tests.integration._session_probe import SessionFactory, fake_job, fake_sample, rows_for

from app.api.v1.jobs import _job_details
from app.schemas.job import JobCreateRequest
from app.worker import analysis_worker, enrich_worker
from app.worker.job_memory import ISOLATED_MEMORY_OPTION, job_memory_owner
from maljan.memory.long_term_memory import memory_owner_for

BYTES = b"MZ synthetic sample bytes, never run\x00" * 64
INTAKE = hashlib.sha256(BYTES).hexdigest()
SAMPLE = "00000000-0000-0000-0000-000000000001"
CREATOR = uuid.UUID("11111111-1111-1111-1111-111111111111")


class TestTheSubmitSchema:
    @pytest.mark.parametrize("value", [True, False])
    def test_a_boolean_is_accepted_and_kept(self, value: bool) -> None:
        body = JobCreateRequest(sample_id=SAMPLE, config={"isolated_memory": value})
        assert body.config == {"isolated_memory": value}

    # Strict: the workers read only ``True``, so a lax "true" or 1 would be
    # accepted and leave the job reading its owner's whole memory.
    @pytest.mark.parametrize("value", [None, "sometimes", [True], "true", "yes", 1, 0])
    def test_anything_else_is_refused(self, value: Any) -> None:
        with pytest.raises(ValidationError):
            JobCreateRequest(sample_id=SAMPLE, config={"isolated_memory": value})

    def test_the_audit_row_names_it(self) -> None:
        assert _job_details(SAMPLE, {"isolated_memory": True})["isolated_memory"] is True
        assert "isolated_memory" not in _job_details(SAMPLE, {})


class TestTheOwner:
    @pytest.mark.parametrize("created_by", [CREATOR, str(CREATOR), "user-alice", None])
    def test_off_it_is_exactly_today_s_owner(self, created_by: Any) -> None:
        assert memory_owner_for(created_by, uuid.uuid4(), False) == str(created_by)
        for config in (None, {}, {"isolated_memory": False}, {"profile": "p"}):
            assert job_memory_owner(created_by, uuid.uuid4(), config) == str(created_by)

    def test_on_each_job_has_a_key_of_its_own(self) -> None:
        one, two = uuid.uuid4(), uuid.uuid4()
        mine = memory_owner_for(CREATOR, one, True)
        assert mine == f"{CREATOR}/job/{one}"
        assert mine != memory_owner_for(CREATOR, two, True)
        assert mine != str(CREATOR)
        # The stores' owner/sample separator never appears in it.
        assert "\x1f" not in mine
        assert job_memory_owner(CREATOR, one, {ISOLATED_MEMORY_OPTION: True}) == mine

    @pytest.mark.parametrize("value", [None, "true", 1, 0, "yes"])
    def test_a_value_that_is_not_a_bool_is_refused(self, value: Any) -> None:
        with pytest.raises(TypeError):
            memory_owner_for(CREATOR, uuid.uuid4(), value)

    @pytest.mark.parametrize("job_id", [None, "", "  "])
    def test_an_isolated_job_without_an_id_is_refused(self, job_id: Any) -> None:
        with pytest.raises(ValueError):
            memory_owner_for(CREATOR, job_id, True)

    @pytest.mark.parametrize("value", ["true", 1, "yes"])
    def test_a_stored_value_that_is_not_true_is_not_the_switch(self, value: Any) -> None:
        assert job_memory_owner(CREATOR, uuid.uuid4(), {"isolated_memory": value}) == str(CREATOR)


class TestTheJobSettings:
    @pytest.mark.parametrize("value", [True, False])
    def test_the_option_never_reaches_the_settings(self, value: bool) -> None:
        without = analysis_worker.build_job_settings({}, {"profile": "default"})
        with_it = analysis_worker.build_job_settings(
            {}, {"profile": "default", "isolated_memory": value}
        )
        assert with_it.model_dump(mode="json") == without.model_dump(mode="json")
        assert analysis_worker.build_job_settings({}, {"isolated_memory": value}).model_dump(
            mode="json"
        ) == analysis_worker.build_job_settings({}, None).model_dump(mode="json")


class TestTheAnalysisWorker:
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

    async def _run(self, config: dict[str, Any] | None) -> tuple[Any, dict[str, Any]]:
        """The job, and its container's owner and switch, and what the job stored."""
        from unittest.mock import patch

        from app.services import object_store

        def _download(_client: Any, _path: str, destination: str) -> None:
            Path(destination).write_bytes(BYTES)

        seen: dict[str, Any] = {}

        async def _arun(self_: Any, **_kwargs: Any) -> dict[str, Any]:
            seen["owner"] = self_.container.memory_owner
            seen["isolated"] = self_.container.isolated_memory
            return {
                "final_decision": "Malware",
                "judge_report": "the judge answered",
                "malware_report": {"summary": {"verdict": "Malware"}, "run_summary": {"a": 1}},
                "run_summary": {"a": 1},
                "isr_reports": {},
                "evidence_ledger": [],
            }

        real_inputs = analysis_worker._report_inputs

        def _inputs(*args: Any, **kwargs: Any) -> Any:
            out = real_inputs(*args, **kwargs)
            seen["summary"] = out[1]
            seen["report_summary"] = (args[0].get("malware_report") or {}).get("run_summary")
            return out

        job = fake_job(config=config)
        job.created_by = CREATOR
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
            patch.object(analysis_worker, "_report_inputs", side_effect=_inputs),
        ):
            result = await analysis_worker.run_analysis(
                {"redis": redis, "db_session": factory}, str(job.id)
            )
        assert result["status"] == "completed"
        return job, seen

    @pytest.mark.asyncio
    @pytest.mark.parametrize("config", [None, {}, {"isolated_memory": False}])
    async def test_without_it_the_owner_is_today_s(self, config: Any) -> None:
        job, seen = await self._run(config)
        assert seen["owner"] == str(job.created_by) == str(CREATOR)
        assert seen["isolated"] is False
        assert "isolated_memory" not in seen["summary"]
        assert "isolated_memory" not in seen["report_summary"]

    @pytest.mark.asyncio
    async def test_with_it_the_job_has_its_own_and_the_summaries_say_so(self) -> None:
        job, seen = await self._run({"isolated_memory": True})
        assert seen["owner"] == f"{CREATOR}/job/{job.id}"
        assert seen["isolated"] is True
        assert seen["summary"]["isolated_memory"] is True
        assert seen["report_summary"]["isolated_memory"] is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "config", [None, {}, {"isolated_memory": False}, {"isolated_memory": True}]
    )
    async def test_the_enrichment_reads_the_owner_the_run_read(self, config: Any) -> None:
        job, seen = await self._run(config)
        row = MagicMock()
        row.first = MagicMock(return_value=(job.created_by, job.config))
        db = MagicMock()
        db.execute = AsyncMock(return_value=row)

        assert await enrich_worker._job_owner(db, job.id) == seen["owner"]


def _stored_state(container: Any) -> dict[str, Any]:
    """A run's state with the summary its judge built, which never says isolated_memory."""
    import time

    from maljan.pipeline.stopped_run import partial_report

    state: dict[str, Any] = {
        "file_hash": INTAKE,
        "file_name": "sample.exe",
        "run_started_at": time.time() - 5,
        "reports": {},
        "isr_reports": {},
        "evidence_ledger": [],
        "discussion_history": [],
        "degradation_reasons": [],
        "stage_results": {},
        "final_decision": "Malware",
        "run_summary": {"degraded_mode": False, "degradation_reasons": []},
    }
    state["malware_report"] = partial_report(state, container, note="the run failed")
    return state


def _isolated_container(isolated: bool) -> Any:
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    job = uuid.uuid4()
    return ServiceContainer(
        Settings(_env_file=None),
        mock=True,
        job_id=str(job),
        memory_owner=memory_owner_for(CREATOR, job, isolated),
        isolated_memory=isolated,
    )


def _kept_report(factory: SessionFactory) -> Any:
    from app.models.report import AnalysisReport

    added = [obj for session in factory.sessions for obj in session.added]
    [report] = [obj for obj in added if isinstance(obj, AnalysisReport)]
    return report


class TestEveryStoreSaysIt:
    """The report kept after a failure and the stopped run's say it as the completed run's do."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("isolated", [True, False])
    async def test_a_report_kept_after_a_failure(self, isolated: bool) -> None:
        from maljan.core.config import Settings

        container = _isolated_container(isolated)
        job = fake_job()
        factory = SessionFactory(rows_for(job, fake_sample(job.sample_id, sha256=INTAKE)))

        kept = await analysis_worker.keep_the_built_report(
            factory,
            job_uuid=job.id,
            job_id=str(job.id),
            built=_stored_state(container),
            note="the run failed after its report was built",
            transcript=[],
            core_settings=Settings(_env_file=None),
            override_keys=(),
            hash_mismatch_reason=None,
            container=container,
        )

        assert kept is True
        report = _kept_report(factory)
        assert (report.run_summary.get("isolated_memory") is True) is isolated
        assert (report.malware_report["run_summary"].get("isolated_memory") is True) is isolated
        if not isolated:
            assert "isolated_memory" not in report.run_summary

    @pytest.mark.asyncio
    @pytest.mark.parametrize("isolated", [True, False])
    async def test_a_stopped_run(self, isolated: bool) -> None:
        from types import SimpleNamespace

        from maljan.core.config import Settings

        container = _isolated_container(isolated)
        state = _stored_state(container)
        state.pop("malware_report")
        app = SimpleNamespace(container=container, built_report=None, latest_state=state)
        job = fake_job()
        factory = SessionFactory(rows_for(job, fake_sample(job.sample_id, sha256=INTAKE)))

        kept = await analysis_worker.keep_the_stopped_run(
            factory,
            job_uuid=job.id,
            job_id=str(job.id),
            app=app,
            note="Stopped by the operator.",
            transcript=[],
            core_settings=Settings(_env_file=None),
            override_keys=(),
            hash_mismatch_reason=None,
        )

        assert kept is True
        report = _kept_report(factory)
        assert (report.run_summary.get("isolated_memory") is True) is isolated
        if not isolated:
            assert "isolated_memory" not in report.run_summary
