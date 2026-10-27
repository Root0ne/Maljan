"""The copies of the sample a job hands out are hashed at its start and end; a change is said.

The intake digest was the only one ever taken: the worker's download, each
mirror it wrote for a server's mount and a download another job already held
were taken as those bytes. The worker now reads every copy once before the
pipeline starts and once when the run ends, before the store and the teardown.
A copy that does not read as the intake digest is recorded on the run summary
and said in the isolation part of the report, with which copy, what it read
and when; the run is stored as it would have been. A run stored before the
record existed renders as before. Synthetic bytes only.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from tests.integration._session_probe import SessionFactory, fake_job, fake_sample, rows_for

from app.worker import analysis_worker
from app.worker.analysis_worker import _report_inputs, keep_the_stopped_run
from app.worker.sample_integrity import SampleIntegrity, copies_of
from maljan.analysis.disclosure import disclosure_record
from maljan.analysis.isolation import isolation_lines
from maljan.analysis.sample_integrity import (
    AT_END,
    AT_START,
    RECORD_KEY,
    file_sha256,
    integrity_lines,
)
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers import MarkdownRenderer

BYTES = b"MZ synthetic sample bytes, never run\x00" * 64
INTAKE = hashlib.sha256(BYTES).hexdigest()


def _copies(tmp_path: Path) -> tuple[Path, Path]:
    download = tmp_path / "uploads" / f"{INTAKE}.exe"
    mirror = tmp_path / "samples" / "r2" / f"{INTAKE}.job-1.exe"
    for path in (download, mirror):
        path.parent.mkdir(parents=True)
        path.write_bytes(BYTES)
    return download, mirror


def _code(text: str) -> str:
    return f"`{text}`"


class TestOneReading:
    def test_a_regular_file_reads_as_its_sha256(self, tmp_path: Path) -> None:
        path = tmp_path / "copy"
        path.write_bytes(BYTES)
        assert file_sha256(path) == (INTAKE, "")

    def test_a_missing_copy_is_a_failed_reading_naming_no_path(self, tmp_path: Path) -> None:
        sha, why = file_sha256(tmp_path / "gone")
        assert sha == ""
        assert why == "FileNotFoundError"

    def test_a_link_in_a_copys_place_is_not_followed(self, tmp_path: Path) -> None:
        target = tmp_path / "elsewhere"
        target.write_bytes(BYTES)
        link = tmp_path / "copy"
        link.symlink_to(target)
        sha, why = file_sha256(link)
        assert sha == ""
        assert why

    def test_a_pipe_in_a_copys_place_is_not_read(self, tmp_path: Path) -> None:
        pipe = tmp_path / "copy"
        os.mkfifo(pipe)
        assert file_sha256(pipe) == ("", "not a regular file")


class TestTheCopies:
    def test_each_copy_once_named_by_its_directory_never_its_host_path(
        self, tmp_path: Path
    ) -> None:
        download, mirror = _copies(tmp_path)
        copies = copies_of(str(download), [mirror, mirror, download])
        assert [(copy, where) for copy, where, _ in copies] == [("download", ""), ("mirror", "r2")]

    def test_no_download_is_no_copy(self) -> None:
        assert copies_of(None, []) == []


class TestStartAndEnd:
    @pytest.mark.asyncio
    async def test_unchanged_copies_read_as_the_intake_digest_both_times(
        self, tmp_path: Path
    ) -> None:
        download, mirror = _copies(tmp_path)
        integrity = SampleIntegrity(INTAKE, copies_of(str(download), [mirror]))
        await integrity.started()
        record = await integrity.ended()
        assert record is not None
        assert record["changed"] is False
        assert [(r["copy"], r["at"]) for r in record["readings"]] == [
            ("download", AT_START),
            ("mirror", AT_START),
            ("download", AT_END),
            ("mirror", AT_END),
        ]
        assert all(r["sha256"] == INTAKE for r in record["readings"])

    @pytest.mark.asyncio
    async def test_a_mirror_written_during_the_run_is_seen_at_the_end(self, tmp_path: Path) -> None:
        download, mirror = _copies(tmp_path)
        integrity = SampleIntegrity(INTAKE, copies_of(str(download), [mirror]))
        await integrity.started()
        mirror.write_bytes(BYTES + b"patched by a tool server")
        record = await integrity.ended()
        assert record is not None
        assert record["changed"] is True
        [off] = [r for r in record["readings"] if r["sha256"] != INTAKE]
        assert (off["copy"], off["where"], off["at"]) == ("mirror", "r2", AT_END)
        assert off["sha256"] == hashlib.sha256(BYTES + b"patched by a tool server").hexdigest()
        assert off["seen_at"]

    @pytest.mark.asyncio
    async def test_with_the_intake_size_a_grown_mirror_is_a_change_without_a_read(
        self, tmp_path: Path
    ) -> None:
        download, mirror = _copies(tmp_path)
        integrity = SampleIntegrity(INTAKE, copies_of(str(download), [mirror]), size=len(BYTES))
        await integrity.started()
        mirror.write_bytes(BYTES + b"patched by a tool server")
        record = await integrity.ended()
        assert record is not None and record["changed"] is True
        [off] = [r for r in record["readings"] if r["sha256"] != INTAKE]
        assert (off["copy"], off["at"], off["sha256"]) == ("mirror", AT_END, "")
        assert off["error"] == f"size {len(BYTES) + 24} is not the intake size {len(BYTES)}"

    @pytest.mark.asyncio
    async def test_with_the_intake_size_same_length_other_bytes_read_as_their_digest(
        self, tmp_path: Path
    ) -> None:
        download, mirror = _copies(tmp_path)
        integrity = SampleIntegrity(INTAKE, copies_of(str(download), [mirror]), size=len(BYTES))
        await integrity.started()
        other = bytes(b ^ 0xFF for b in BYTES)
        mirror.write_bytes(other)
        record = await integrity.ended()
        assert record is not None
        [off] = [r for r in record["readings"] if r["sha256"] != INTAKE]
        assert off["sha256"] == hashlib.sha256(other).hexdigest()

    @pytest.mark.asyncio
    async def test_a_download_that_is_not_the_intake_bytes_is_seen_at_the_start(
        self, tmp_path: Path
    ) -> None:
        download, mirror = _copies(tmp_path)
        download.write_bytes(b"other bytes")
        integrity = SampleIntegrity(INTAKE, copies_of(str(download), [mirror]))
        await integrity.started()
        record = integrity.record()
        assert record is not None and record["changed"] is True
        assert [r["at"] for r in record["readings"] if r["sha256"] != INTAKE] == [AT_START]

    @pytest.mark.asyncio
    async def test_the_end_is_read_once_however_many_stores_ask(self, tmp_path: Path) -> None:
        download, mirror = _copies(tmp_path)
        integrity = SampleIntegrity(INTAKE, copies_of(str(download), [mirror]))
        await integrity.started()
        first = await integrity.ended()
        mirror.unlink()
        assert await integrity.ended() == first

    @pytest.mark.asyncio
    async def test_a_job_that_handed_out_no_copy_records_nothing(self) -> None:
        integrity = SampleIntegrity(INTAKE, [])
        await integrity.started()
        assert await integrity.ended() is None


def _isolation_part() -> dict[str, Any]:
    return {
        "worker": {"uid": 1000, "platform_names_in_env": []},
        "rows": [],
        "unsourced_reads": 0,
        "isolated": False,
        "isolated_by": "",
    }


def _disclosure() -> dict[str, Any]:
    record = disclosure_record(
        {"llm.provider": "openai", "llm.openai.base_url": "http://127.0.0.1:8080/v1"},
        tokens={"llm_calls": 0, "per_agent": {}},
        agents=[],
    )
    record["isolation"] = _isolation_part()
    return record


def _state() -> dict[str, Any]:
    summary = {"final_decision": "Malware", "disclosure": _disclosure()}
    payload = MalwareReport.model_validate(
        {
            "identity": {"hashes": {"sha256": INTAKE}},
            "verdict": "Malware",
            "run_summary": summary,
            "generated_at": "2026-10-01T00:00:00Z",
        }
    ).model_dump(mode="json")
    return {"run_summary": summary, "malware_report": payload}


async def _changed_record(tmp_path: Path) -> dict[str, Any]:
    download, mirror = _copies(tmp_path)
    integrity = SampleIntegrity(INTAKE, copies_of(str(download), [mirror]))
    await integrity.started()
    mirror.write_bytes(b"rewritten")
    record = await integrity.ended()
    assert record is not None
    return record


class TestTheStoredRun:
    @pytest.mark.asyncio
    async def test_the_record_is_a_run_fact_and_an_isolation_line(self, tmp_path: Path) -> None:
        record = await _changed_record(tmp_path)
        state = _state()
        _, summary = _report_inputs(
            state,
            core_settings=Settings(_env_file=None),
            override_keys=(),
            hash_mismatch_reason=None,
            sample_integrity=record,
        )
        assert summary[RECORD_KEY]["changed"] is True
        assert summary["disclosure"]["isolation"][RECORD_KEY] == record
        held = state["malware_report"]["run_summary"]
        assert held[RECORD_KEY] == record
        assert held["disclosure"]["isolation"][RECORD_KEY] == record
        # Not a degradation: the run is not failed or downgraded for it.
        assert record["readings"][0]["sha256"] == INTAKE
        assert not summary.get("degradation_reasons")
        json.dumps(summary)

        markdown = MarkdownRenderer().render(MalwareReport.model_validate(state["malware_report"]))
        assert f"did not read as its intake SHA-256 `{INTAKE}`" in markdown
        assert "The run was not failed for it" in markdown
        changed = hashlib.sha256(b"rewritten").hexdigest()
        assert f"The mirror in `r2` read `{changed}` when the run ended (" in markdown

    def test_a_run_without_the_record_renders_as_before(self) -> None:
        bare, given = _state(), _state()
        _, before = _report_inputs(
            bare,
            core_settings=Settings(_env_file=None),
            override_keys=(),
            hash_mismatch_reason=None,
        )
        _, after = _report_inputs(
            given,
            core_settings=Settings(_env_file=None),
            override_keys=(),
            hash_mismatch_reason=None,
            sample_integrity=None,
        )
        before.pop("settings_snapshot")
        after.pop("settings_snapshot")
        assert before == after
        assert RECORD_KEY not in after
        render = MarkdownRenderer().render
        assert render(MalwareReport.model_validate(bare["malware_report"])) == render(
            MalwareReport.model_validate(given["malware_report"])
        )
        assert isolation_lines(_isolation_part(), _code) == [
            "This run recorded no read of the sample's bytes, so nothing is said of it."
        ]

    def test_unchanged_copies_are_said_in_one_line(self) -> None:
        readings = [
            {"copy": "download", "where": "", "at": at, "sha256": INTAKE, "error": ""}
            for at in (AT_START, AT_END)
        ]
        lines = integrity_lines(
            {"expected_sha256": INTAKE, "readings": readings, "changed": False}, _code
        )
        assert lines == [
            "The sample the platform handed out (copy) was hashed when the job started and "
            f"when the run ended, and every reading was its intake SHA-256 `{INTAKE}`."
        ]

    def test_a_copy_that_could_not_be_read_says_why_and_when(self) -> None:
        readings = [
            {"copy": "download", "where": "", "at": AT_START, "sha256": INTAKE, "error": ""},
            {
                "copy": "download",
                "where": "",
                "at": AT_END,
                "sha256": "",
                "error": "FileNotFoundError",
                "seen_at": "2026-10-23T10:00:00+00:00",
            },
        ]
        lines = integrity_lines({"expected_sha256": INTAKE, "readings": readings}, _code)
        assert lines[-1] == (
            "The worker's copy was not hashed when the run ended "
            "(2026-10-23T10:00:00+00:00): FileNotFoundError."
        )


@pytest.mark.asyncio
async def test_a_stopped_run_is_stored_with_its_end_reading(tmp_path: Path) -> None:
    from app.models.report import AnalysisReport

    download, mirror = _copies(tmp_path)
    integrity = SampleIntegrity(INTAKE, copies_of(str(download), [mirror]))
    await integrity.started()
    download.write_bytes(b"swapped mid-run")
    container = ServiceContainer(Settings(_env_file=None), mock=True)
    state = {
        "file_hash": INTAKE,
        "file_name": "sample.exe",
        "run_started_at": time.time() - 5,
        "reports": {},
        "isr_reports": {},
        "evidence_ledger": [],
        "discussion_history": [],
        "degradation_reasons": [],
        "stage_results": {},
        "run_summary": {"degraded_mode": False, "degradation_reasons": []},
    }
    app = SimpleNamespace(container=container, built_report=None, latest_state=state)
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))

    kept = await keep_the_stopped_run(
        factory,
        job_uuid=job.id,
        job_id=str(job.id),
        app=app,
        note="Stopped by the operator.",
        transcript=[],
        core_settings=Settings(_env_file=None),
        override_keys=(),
        hash_mismatch_reason=None,
        sample_integrity=integrity,
    )

    assert kept is True
    added = [obj for session in factory.sessions for obj in session.added]
    [report] = [obj for obj in added if isinstance(obj, AnalysisReport)]
    stored = report.run_summary[RECORD_KEY]
    assert stored["changed"] is True
    assert [(r["copy"], r["at"]) for r in stored["readings"] if r["sha256"] != INTAKE] == [
        ("download", AT_END)
    ]
    assert report.malware_report["run_summary"][RECORD_KEY] == stored


def test_the_worker_reads_the_copies_before_the_pipeline_and_before_each_store() -> None:
    source = inspect.getsource(analysis_worker.run_analysis)
    started = source.index("await _integrity.started()")
    assert started < source.index("app.arun(")
    assert source.index("copies_of(temp_path, host_mirrors)") < started
    assert source.count("sample_integrity=_integrity") == 2
    assert "sample_integrity=await ended_record(_integrity)" in source
    # Before the teardown that removes the copies.
    assert source.rindex("ended_record(_integrity)") < source.index(
        "sample_files.release_copy(temp_path"
    )


class TestWhatIsNotRead:
    def test_a_copy_of_another_size_is_not_read(self, tmp_path: Path) -> None:
        sparse = tmp_path / "copy"
        with sparse.open("wb") as fh:
            fh.truncate(10 * 1024**4)
        # Removed at once: pytest keeps its last temp dirs, and a 10 TiB file
        # left there costs any host scanner that reads it hours of CPU.
        try:
            started = time.monotonic()
            sha, why = file_sha256(sparse, len(BYTES))
            assert time.monotonic() - started < 5
        finally:
            sparse.unlink()
        assert (sha, why) == ("", f"size {10 * 1024**4} is not the intake size {len(BYTES)}")

    def test_the_intake_size_reads_as_before(self, tmp_path: Path) -> None:
        path = tmp_path / "copy"
        path.write_bytes(BYTES)
        assert file_sha256(path, len(BYTES)) == (INTAKE, "")

    def test_a_link_in_place_of_the_copys_directory_is_not_followed(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        (real / "copy").write_bytes(BYTES)
        linked = tmp_path / "linked"
        linked.symlink_to(real, target_is_directory=True)
        sha, why = file_sha256(linked / "copy", len(BYTES))
        assert sha == ""
        assert why

    @pytest.mark.asyncio
    async def test_a_hard_link_put_in_a_copys_place_is_a_change(self, tmp_path: Path) -> None:
        download, mirror = _copies(tmp_path)
        integrity = SampleIntegrity(INTAKE, copies_of(str(download), [mirror]), size=len(BYTES))
        await integrity.started()
        other = tmp_path / "other"
        other.write_bytes(bytes(len(BYTES)))
        mirror.unlink()
        os.link(other, mirror)
        record = await integrity.ended()
        assert record is not None and record["changed"] is True
        [off] = [r for r in record["readings"] if r["sha256"] != INTAKE]
        assert (off["copy"], off["at"]) == ("mirror", AT_END)
        assert off["sha256"] == hashlib.sha256(bytes(len(BYTES))).hexdigest()


class TestAFailedReading:
    @pytest.mark.asyncio
    async def test_a_reading_that_raises_is_recorded_and_leaves_the_copies_alone(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.worker import sample_files
        from app.worker import sample_integrity as integrity_module

        download, mirror = _copies(tmp_path)
        copies = copies_of(str(download), [mirror])
        integrity = SampleIntegrity(INTAKE, copies, size=len(BYTES))

        def _raises(*_args: Any, **_kwargs: Any) -> tuple[str, str]:
            raise RuntimeError("the reader broke")

        monkeypatch.setattr(integrity_module, "file_sha256", _raises)
        await integrity.started()
        record = await integrity.ended()
        assert record is not None and record["changed"] is True
        assert {r["error"] for r in record["readings"]} == {"RuntimeError"}
        assert integrity.copies == copies
        assert download.read_bytes() == BYTES and mirror.read_bytes() == BYTES
        # The teardown removes each copy as it would have.
        assert sample_files.release_copy(download, job_id="") is True
        assert sample_files.release_copy(mirror, job_id="") is True
        assert not download.exists() and not mirror.exists()

    @pytest.mark.asyncio
    async def test_an_end_reading_whose_caller_is_cancelled_is_taken_whole_by_the_next(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio
        import threading

        from app.worker import sample_integrity as integrity_module

        download, mirror = _copies(tmp_path)
        integrity = SampleIntegrity(INTAKE, copies_of(str(download), [mirror]), size=len(BYTES))
        await integrity.started()
        entered, release = threading.Event(), threading.Event()
        real = integrity_module.file_sha256

        def _slow(*args: Any, **kwargs: Any) -> tuple[str, str]:
            entered.set()
            release.wait(5)
            return real(*args, **kwargs)

        monkeypatch.setattr(integrity_module, "file_sha256", _slow)
        first = asyncio.create_task(integrity.ended())
        await asyncio.to_thread(entered.wait, 5)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        # Nothing half-read is in the record while the reading runs.
        assert [r["at"] for r in integrity.readings] == [AT_START, AT_START]
        release.set()
        record = await integrity.ended()
        assert record is not None
        assert [r["at"] for r in record["readings"]] == [AT_START, AT_START, AT_END, AT_END]
        assert record["changed"] is False


def _disclosure_with_rows() -> dict[str, Any]:
    from maljan.analysis.isolation import isolation_part

    record = _disclosure()
    record["isolation"] = isolation_part(
        {"provider:triage": 1},
        0,
        {},
        worker={"uid": 1000, "platform_names_in_env": []},
        in_process={"provider:triage": "the triage pack"},
        route=lambda _source: ("", "", "", ""),
        needs_network=lambda _source: False,
    )
    assert record["isolation"]["rows"]
    return record


@pytest.mark.asyncio
async def test_a_report_kept_after_a_failure_carries_the_end_reading(tmp_path: Path) -> None:
    from app.models.report import AnalysisReport
    from app.worker.analysis_worker import keep_the_built_report
    from maljan.pipeline.stopped_run import partial_report

    download, mirror = _copies(tmp_path)
    integrity = SampleIntegrity(INTAKE, copies_of(str(download), [mirror]), size=len(BYTES))
    await integrity.started()
    changed = bytes(b ^ 0x01 for b in BYTES)
    mirror.write_bytes(changed)

    container = ServiceContainer(Settings(_env_file=None), mock=True)
    disclosure = _disclosure_with_rows()
    built: dict[str, Any] = {
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
        "run_summary": {
            "degraded_mode": False,
            "degradation_reasons": [],
            "disclosure": disclosure,
        },
    }
    report_dump = partial_report(built, container, note="the run failed after its report")
    report_dump["run_summary"] = {
        **(report_dump.get("run_summary") or {}),
        "disclosure": disclosure,
    }
    built["malware_report"] = report_dump
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id, sha256=INTAKE)))

    kept = await keep_the_built_report(
        factory,
        job_uuid=job.id,
        job_id=str(job.id),
        built=built,
        note="the run failed after its report was built",
        transcript=[],
        core_settings=Settings(_env_file=None),
        override_keys=(),
        hash_mismatch_reason=None,
        container=container,
        sample_integrity=integrity,
    )

    assert kept is True
    added = [obj for session in factory.sessions for obj in session.added]
    [report] = [obj for obj in added if isinstance(obj, AnalysisReport)]
    stored = report.run_summary[RECORD_KEY]
    assert stored["changed"] is True
    [off] = [r for r in stored["readings"] if r["sha256"] != INTAKE]
    assert (off["copy"], off["where"], off["at"]) == ("mirror", "r2", AT_END)
    assert report.run_summary["disclosure"]["isolation"][RECORD_KEY] == stored
    held = report.malware_report["run_summary"]
    assert held["disclosure"]["isolation"][RECORD_KEY] == stored
    assert held["disclosure"]["isolation"]["rows"]
    markdown = MarkdownRenderer().render(MalwareReport.model_validate(report.malware_report))
    assert f"The mirror in `r2` read `{hashlib.sha256(changed).hexdigest()}`" in markdown


class TestTheCompletedRun:
    """``run_analysis`` end to end, the graph stubbed: a copy changed during it is stored."""

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

    @pytest.mark.asyncio
    async def test_a_download_changed_during_the_run_is_stored_and_the_job_completes(
        self, tmp_path: Path
    ) -> None:
        from unittest.mock import AsyncMock, MagicMock, patch

        from app.models.report import AnalysisReport
        from app.services import object_store

        def _download(_client: Any, _path: str, destination: str) -> None:
            Path(destination).write_bytes(BYTES)

        handed: dict[str, str] = {}

        async def _arun(_self: Any, **kwargs: Any) -> dict[str, Any]:
            # A reader in the run writes over the copy it was handed.
            handed["path"] = str(kwargs["sample_path"])
            Path(kwargs["sample_path"]).write_bytes(bytes(len(BYTES)))
            return {
                "final_decision": "Malware",
                "judge_report": "the judge answered",
                "malware_report": {"summary": {"verdict": "Malware"}},
                "isr_reports": {},
                "evidence_ledger": [],
            }

        job = fake_job()
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
        [report] = [o for s in factory.sessions for o in s.added if isinstance(o, AnalysisReport)]
        stored = report.run_summary[RECORD_KEY]
        assert stored["expected_sha256"] == INTAKE
        assert stored["changed"] is True
        assert [(r["copy"], r["at"]) for r in stored["readings"] if r["sha256"] != INTAKE] == [
            ("download", AT_END)
        ]
        assert [r["at"] for r in stored["readings"] if r["copy"] == "download"] == [
            AT_START,
            AT_END,
        ]
        # The teardown still removed the copy afterwards.
        assert handed["path"] and not Path(handed["path"]).exists()
