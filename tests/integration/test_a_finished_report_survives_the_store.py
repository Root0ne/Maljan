"""A finished report reaches the store whatever Redis, the sample or the operator does.

Three ways a run that had finished lost its report or its status:

- A Redis connection that dropped made ``_publish_event`` raise, and the run
  awaited it before the store, so a finished report was thrown away; a raise
  after the completion was committed let the failure path turn ``completed``
  into ``failed``. Publishing is total now, a result the graph returned is kept
  on any later failure, and a completed row is never marked failed.
- A NUL (U+0000) in any sample-derived string made PostgreSQL refuse the whole
  report store, and a batch of events with it. Every stored string has it
  written out (``store_text``), before the ledger is digested, and the count is
  in the run summary.
- The completion update had no status filter, so an operator's cancel that
  landed while the report was being written was overwritten.

Nothing here reaches a service: the database is the tracking factory from
``_session_probe`` with the job row's WHERE clauses evaluated, and Redis is a
stub. What PostgreSQL refuses is checked the way it refuses it: no ``text``
value may hold U+0000 and no ``jsonb`` value may serialise to ``\\u0000``.
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
from sqlalchemy import inspect as sa_inspect

from app.models.evidence import EvidenceEntry
from app.models.job_event import JobEvent
from app.models.report import AgentMessage, AnalysisReport
from app.services import ledger_chain, ledger_verify, store_text
from app.services.audit_chain import AuditChainCheck
from app.services.ledger_verify import JobAudit
from app.worker import analysis_worker as worker_module
from app.worker.analysis_worker import (
    POST_GRAPH_STEP,
    _JobEventBuffer,
    _publish_event,
    _store_the_report,
    mark_job_failed,
    run_analysis,
)
from maljan.core.config import Settings
from maljan.schemas.evidence import LedgerEntry
from tests.integration._session_probe import (
    JobRow,
    Recorded,
    SessionFactory,
    fake_job,
    fake_sample,
    rows_for,
)

KEY = ledger_chain.derive_key("nul-store-test-material")
NUL = "\x00"
LONE = "\ud800"
SURROGATES = (0xD800, 0xDFFF)


# ── the harness ─────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _isolated_runtime_settings(monkeypatch: pytest.MonkeyPatch):
    from app import runtime_config as rc
    from maljan.core.config import reset_settings_cache

    async def _mock_mode_allowed_override() -> dict[str, Any]:
        return {"api.mock_mode_allowed": True}

    monkeypatch.setattr(rc.runtime_config, "_overrides", _mock_mode_allowed_override)
    yield
    reset_settings_cache()


@pytest.fixture(autouse=True)
def _no_object_store(tmp_path: Path):
    from app import config as api_config

    api_config._settings = None
    with (
        patch("minio.Minio", side_effect=ConnectionError("no object store here")),
        patch.dict(
            "os.environ",
            {
                "MALJAN_MOCK_MODE": "true",
                "UPLOAD_TEMP_DIR": str(tmp_path / "tmp"),
                "SAMPLES_DIR": str(tmp_path / "samples"),
            },
            clear=False,
        ),
    ):
        yield
    api_config._settings = None


@pytest_asyncio.fixture
async def redis_stub() -> MagicMock:
    redis = MagicMock()
    redis.publish = AsyncMock()
    redis.aclose = AsyncMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock()
    redis.delete = AsyncMock()
    return redis


class _CountedRow(JobRow):
    """The job row, with the driver's ``rowcount`` for each update it answers."""

    def __init__(self, job: Any) -> None:
        super().__init__(job)
        self.matched: dict[int, int] = {}

    def __call__(self, record: Recorded, statement: Any) -> None:
        if getattr(statement, "is_update", False) and statement.table.name == "analysis_jobs":
            from sqlalchemy.orm.evaluator import _EvaluatorCompiler

            from app.models.job import AnalysisJob

            matches = _EvaluatorCompiler(AnalysisJob).process(statement.whereclause)
            self.matched[id(statement)] = 1 if matches(self.row) else 0
        super().__call__(record, statement)

    def rows(self, base: Any) -> Any:
        def answer(statement: Any) -> Any:
            result = base(statement)
            if id(statement) in self.matched:
                result.rowcount = self.matched[id(statement)]
            descriptions = getattr(statement, "column_descriptions", None) or []
            if descriptions and descriptions[0].get("name") == "status":
                # ``select(AnalysisJob.status)``: what the row says now.
                result.scalar_one_or_none.return_value = self.row.status
            return result

        return answer


def _factory(job: Any) -> tuple[SessionFactory, _CountedRow]:
    row = _CountedRow(job)
    # The worker turns the row ``running`` before the pipeline starts.
    row.row.status = "running"
    return SessionFactory(row.rows(rows_for(job, fake_sample(job.sample_id))), on_execute=row), row


def _pipeline_result(**extra: Any) -> dict[str, Any]:
    return {
        "final_decision": "Malware",
        "judge_report": "the judge answered",
        "malware_report": {"summary": {"verdict": "Malware"}},
        "isr_reports": {},
        "evidence_ledger": [],
        **extra,
    }


def _stored(factory: SessionFactory, kind: type) -> list[Any]:
    return [o for s in factory.sessions for o in s.added if isinstance(o, kind)]


def _published_types(redis: MagicMock) -> list[str]:
    return [json.loads(call.args[1])["type"] for call in redis.publish.call_args_list]


async def _run(factory: SessionFactory, redis: MagicMock, job: Any) -> dict[str, Any]:
    return await run_analysis({"redis": redis, "db_session": factory}, str(job.id))


def _refused_by_postgres(value: Any) -> bool:
    """Whether PostgreSQL would refuse ``value`` in a ``text`` or ``jsonb`` column.

    A NUL or a lone surrogate anywhere in a string, a JSON key included.
    """
    if isinstance(value, str):
        return any(ch == NUL or SURROGATES[0] <= ord(ch) <= SURROGATES[1] for ch in value)
    if isinstance(value, dict):
        return any(_refused_by_postgres(k) or _refused_by_postgres(v) for k, v in value.items())
    if isinstance(value, list | tuple):
        return any(_refused_by_postgres(v) for v in value)
    return False


def _too_long(rows: list[Any]) -> list[str]:
    """Every string column longer than its ``String(n)`` width."""
    return [
        f"{type(row).__name__}.{attr.key}"
        for row in rows
        for attr in sa_inspect(row).mapper.column_attrs
        if isinstance(getattr(row, attr.key, None), str)
        and isinstance(getattr(attr.columns[0].type, "length", None), int)
        and len(getattr(row, attr.key)) > attr.columns[0].type.length
    ]


def _refused_columns(rows: list[Any]) -> list[str]:
    return [
        f"{type(row).__name__}.{attr.key}"
        for row in rows
        for attr in sa_inspect(row).mapper.column_attrs
        if _refused_by_postgres(getattr(row, attr.key, None))
    ]


# ── SW-H1: a dropped Redis never costs a finished report ────────────


@pytest.mark.asyncio
async def test_a_publish_that_raises_is_logged_and_never_raises(caplog: Any) -> None:
    redis = MagicMock()
    redis.incr = AsyncMock(return_value=1)
    redis.publish = AsyncMock(side_effect=ConnectionError("Connection closed by server."))
    with caplog.at_level(logging.WARNING):
        await _publish_event(redis, str(uuid.uuid4()), "phase_change", {"phase": "reporting"})
    assert any(
        "Could not publish the phase_change event" in r.getMessage()
        and "ConnectionError" in r.getMessage()
        for r in caplog.records
    )


@pytest.mark.parametrize(
    ("event", "nth"),
    [
        ("status_change", 0),
        ("phase_change", 0),  # analyzing, before the graph
        ("phase_change", 1),  # negotiation, after it
        ("phase_change", 2),  # reporting, just before the store
        ("completed", 0),  # after the completion is committed
    ],
)
@pytest.mark.asyncio
async def test_a_publish_raising_at_each_point_still_stores_and_completes(
    redis_stub: MagicMock, event: str, nth: int
) -> None:
    job = fake_job()
    factory, row = _factory(job)
    seen: dict[str, int] = {}

    async def _publish(channel: str, message: str) -> None:
        kind = json.loads(message)["type"]
        index = seen.get(kind, 0)
        seen[kind] = index + 1
        if kind == event and index == nth:
            raise ConnectionError("Connection closed by server.")

    redis_stub.publish = AsyncMock(side_effect=_publish)
    with patch("maljan.app.MaljanApp.arun", new=AsyncMock(return_value=_pipeline_result())):
        result = await _run(factory, redis_stub, job)

    assert result["status"] == "completed"
    assert row.row.status == "completed"
    [report] = _stored(factory, AnalysisReport)
    assert report.incomplete_reason is None
    assert seen.get(event, 0) > nth, "the failing publish was reached"


@pytest.mark.asyncio
async def test_redis_down_for_the_whole_run_still_stores_and_completes(
    redis_stub: MagicMock,
) -> None:
    job = fake_job()
    factory, row = _factory(job)
    redis_stub.publish = AsyncMock(side_effect=ConnectionError("Connection refused."))
    with patch("maljan.app.MaljanApp.arun", new=AsyncMock(return_value=_pipeline_result())):
        result = await _run(factory, redis_stub, job)
    assert result["status"] == "completed"
    assert row.row.status == "completed"
    assert len(_stored(factory, AnalysisReport)) == 1


@pytest.mark.asyncio
async def test_a_failure_after_the_completion_never_marks_the_job_failed(
    redis_stub: MagicMock, caplog: Any
) -> None:
    job = fake_job()
    factory, row = _factory(job)
    with (
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(return_value=_pipeline_result())),
        patch("maljan.app.MaljanApp.remember_the_run", side_effect=OSError("store gone")),
        caplog.at_level(logging.ERROR),
    ):
        result = await _run(factory, redis_stub, job)

    assert result["status"] == "completed"
    assert "error_after_completion" in result
    assert row.row.status == "completed"
    assert row.row.error_message is None
    assert "error" not in _published_types(redis_stub)
    assert any("stays completed" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_mark_job_failed_leaves_a_completed_row_alone_and_says_so(caplog: Any) -> None:
    job = fake_job(status="completed")
    factory, row = _factory(job)
    row.row.status = "completed"
    with caplog.at_level(logging.WARNING):
        assert await mark_job_failed(factory, job.id, reason="RuntimeError", error_id="e1")
    assert row.row.status == "completed"
    assert any("was not marked failed" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_a_failure_between_the_graph_and_the_store_keeps_the_report(
    redis_stub: MagicMock,
) -> None:
    job = fake_job()
    factory, row = _factory(job)
    with (
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(return_value=_pipeline_result())),
        patch.object(worker_module, "enrichment_plan", side_effect=RuntimeError("plan")),
    ):
        result = await _run(factory, redis_stub, job)

    assert result["status"] == "failed"
    assert row.row.status == "failed"
    [report] = _stored(factory, AnalysisReport)
    assert report.verdict == "Malware"
    assert POST_GRAPH_STEP in report.incomplete_reason
    assert report.malware_report["degraded_mode"] is True


@pytest.mark.asyncio
async def test_an_absent_analysis_is_still_not_kept(redis_stub: MagicMock) -> None:
    job = fake_job()
    factory, row = _factory(job)
    absent = {"final_decision": "Suspicious", "isr_reports": {}, "evidence_ledger": []}
    with patch("maljan.app.MaljanApp.arun", new=AsyncMock(return_value=absent)):
        result = await _run(factory, redis_stub, job)
    assert result["status"] == "failed"
    assert _stored(factory, AnalysisReport) == []


# ── SW-L1: a cancel during persistence stands ───────────────────────


def _row_moves_while_building(row: _CountedRow, status: str, message: str | None = None) -> Any:
    """``_report_inputs``, with the job row moved on while the report is built."""
    build = worker_module._report_inputs

    def _moved(*args: Any, **kwargs: Any) -> Any:
        row.row.status = status
        row.row.error_message = message
        return build(*args, **kwargs)

    return patch.object(worker_module, "_report_inputs", new=_moved)


@pytest.mark.asyncio
async def test_a_cancel_during_persistence_is_not_overwritten(
    redis_stub: MagicMock, caplog: Any
) -> None:
    job = fake_job()
    factory, row = _factory(job)
    with (
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(return_value=_pipeline_result())),
        _row_moves_while_building(row, "cancelled", "Cancelled by the operator."),
        patch("maljan.app.MaljanApp.remember_the_run") as remembered,
        caplog.at_level(logging.WARNING),
    ):
        result = await _run(factory, redis_stub, job)

    assert row.row.status == "cancelled"
    assert result["status"] == "not_running_at_completion"
    assert result["row_status"] == "cancelled"
    [report] = _stored(factory, AnalysisReport)
    assert result["report_id"] == str(report.id)
    assert report.incomplete_reason == worker_module.stored_after_note("cancelled")
    assert report.incomplete_reason.startswith("Stored after the job was cancelled")
    assert report.run_summary["degradation_reasons"][-1] == report.incomplete_reason
    types = _published_types(redis_stub)
    assert "completed" not in types
    [moved] = [
        json.loads(c.args[1])["data"]
        for c in redis_stub.publish.call_args_list
        if json.loads(c.args[1])["type"] == "status_change"
        and json.loads(c.args[1])["data"].get("report_id")
    ]
    assert moved["status"] == "cancelled" and moved["report_id"] == str(report.id)
    remembered.assert_not_called()
    assert any("was cancelled when its report was stored" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_a_job_the_sweep_took_during_a_redis_outage_still_completes(
    redis_stub: MagicMock, caplog: Any
) -> None:
    job = fake_job()
    factory, row = _factory(job)
    with (
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(return_value=_pipeline_result())),
        _row_moves_while_building(row, "failed", worker_module._SWEPT_NO_OWNER),
        caplog.at_level(logging.WARNING),
    ):
        result = await _run(factory, redis_stub, job)

    assert result["status"] == "completed"
    assert row.row.status == "completed"
    assert row.row.error_message is None
    [report] = _stored(factory, AnalysisReport)
    assert report.incomplete_reason is None
    assert any("marked failed by the orphan sweep" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_a_job_failed_for_another_reason_is_not_completed(redis_stub: MagicMock) -> None:
    job = fake_job()
    factory, row = _factory(job)
    with (
        patch("maljan.app.MaljanApp.arun", new=AsyncMock(return_value=_pipeline_result())),
        _row_moves_while_building(row, "failed", "something else"),
    ):
        result = await _run(factory, redis_stub, job)
    assert result["row_status"] == "failed"
    assert row.row.status == "failed" and row.row.error_message == "something else"


@pytest.mark.asyncio
async def test_a_lost_completion_acknowledgement_keeps_the_complete_report(
    redis_stub: MagicMock, monkeypatch: Any
) -> None:
    """The commit landed and only its answer was lost: no incomplete copy supersedes it."""
    from tests.integration import _session_probe

    job = fake_job()
    factory, row = _factory(job)
    commit = _session_probe.TrackedSession.commit
    lost: list[bool] = []

    async def _commit_then_lose_the_answer(self: Any) -> None:
        await commit(self)
        if row.row.status == "completed" and not lost:
            lost.append(True)
            raise ConnectionError("connection lost after COMMIT")

    monkeypatch.setattr(_session_probe.TrackedSession, "commit", _commit_then_lose_the_answer)
    with patch("maljan.app.MaljanApp.arun", new=AsyncMock(return_value=_pipeline_result())):
        result = await _run(factory, redis_stub, job)

    assert lost == [True]
    assert result["status"] == "completed"
    assert row.row.status == "completed"
    [report] = _stored(factory, AnalysisReport)
    assert report.incomplete_reason is None
    assert "error" not in _published_types(redis_stub)


@pytest.mark.asyncio
async def test_the_api_refuses_to_cancel_a_job_that_completed_meanwhile() -> None:
    """``cancel_job`` read ``running``; the worker completed the row before the write."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.v1 import jobs as jobs_module
    from app.database import get_db
    from app.deps import get_current_user
    from app.services import analysis_service as svc_mod

    user = MagicMock(id=uuid.uuid4())
    job = MagicMock(id=uuid.uuid4(), status="running")
    read = MagicMock()
    read.scalar_one_or_none.return_value = job
    moved_on = MagicMock(rowcount=0)
    db = MagicMock()
    db.execute = AsyncMock(side_effect=[read, moved_on])
    db.flush = AsyncMock()

    async def _refresh(obj: Any) -> None:
        obj.status = "completed"

    db.refresh = AsyncMock(side_effect=_refresh)
    app = FastAPI()
    app.include_router(jobs_module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: user
    with patch.object(svc_mod.aioredis, "from_url") as redis_from_url:
        response = TestClient(app).delete(f"/api/v1/jobs/{job.id}")

    assert response.status_code == 409, response.text
    assert "'completed'" in response.json()["detail"]
    assert job.status == "completed"
    redis_from_url.assert_not_called()
    db.flush.assert_not_called()
    update_statement = db.execute.call_args_list[1].args[0]
    where = str(update_statement.whereclause.compile(compile_kwargs={"literal_binds": True}))
    assert "'pending'" in where and "'running'" in where


# ── SW-H2: a NUL never refuses the store ───────────────────────────


def _nul_entry(seq: int) -> dict[str, Any]:
    dump = LedgerEntry(
        id=f"ev_{seq:04d}",
        tool="pe_info",
        seq=seq,
        output=f"CompanyName=Acme{NUL}Corp {seq}",
        started_at=1.7e9 + seq,
    ).model_dump(mode="json")
    dump["structured"] = {"version_info": {f"Company{NUL}Name": f"Acme{NUL}Corp"}}
    dump["args"] = {"path": f"C:\\x{NUL}.exe"}
    if seq == 1:
        # Cut to the column's 100 characters by the row builder, then longer
        # once its NUL is written out.
        dump["agent"] = "a" * 99 + NUL
    return dump


# Each NUL the store below is handed: two entries of three (output, a structure
# key and value, an argument), the report payload, the agent prose, the run
# summary and the transcript's text and report.
_NULS_HANDED = 2 * 4 + 1 + 1 + 1 + 2
# Besides them: the agent name cut to its width, and a key that collides once
# written out.
_NULS_ALL = _NULS_HANDED + 2


def _nul_state() -> dict[str, Any]:
    return {
        "final_decision": "Malware",
        "evidence_ledger": [_nul_entry(1), _nul_entry(2)],
        "malware_report": {
            "version_info": f"Acme{NUL}Corp",
            "decoded": f"x{LONE}y",
            "keys": {f"k{NUL}": 1, f"k{store_text.NUL_WRITTEN}": 2},
        },
        "reports": {"static": f"the string Acme{NUL}Corp"},
        "isr_reports": {},
    }


async def _store_with_nul(monkeypatch: Any, key: Any = KEY) -> tuple[SessionFactory, Any]:
    monkeypatch.setattr(ledger_chain, "platform_key_status", lambda: (key, None))
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))
    transcript = [
        {"seq": 1, "speaker": "static", "text": f"quote {NUL} here", "report": {"s": NUL}}
    ]
    async with factory() as db:
        report = await _store_the_report(
            db,
            job_uuid=job.id,
            job_id=str(job.id),
            pipeline_result=_nul_state(),
            stix_bundle=None,
            run_summary={"note": f"seen{NUL}"},
            transcript=transcript,
            core_settings=Settings(_env_file=None),
        )
    return factory, report


@pytest.mark.asyncio
async def test_nul_in_evidence_transcript_and_report_is_written_out(
    monkeypatch: Any, caplog: Any
) -> None:
    with caplog.at_level(logging.WARNING):
        factory, report = await _store_with_nul(monkeypatch)

    added = [o for s in factory.sessions for o in s.added]
    assert _stored(factory, EvidenceEntry) and _stored(factory, AgentMessage)
    assert _refused_columns(added) == []
    [entry, _] = _stored(factory, EvidenceEntry)
    assert entry.output == f"CompanyName=Acme{store_text.NUL_WRITTEN}Corp 1"
    assert entry.structured == {
        "version_info": {
            f"Company{store_text.NUL_WRITTEN}Name": f"Acme{store_text.NUL_WRITTEN}Corp"
        }
    }
    [message] = _stored(factory, AgentMessage)
    assert message.text == f"quote {store_text.NUL_WRITTEN} here"
    assert report.malware_report["version_info"] == f"Acme{store_text.NUL_WRITTEN}Corp"
    assert report.malware_report["decoded"] == "x\\xd800y"
    written_key = f"k{store_text.NUL_WRITTEN}"
    assert report.malware_report["keys"] == {
        written_key: 1,
        store_text.COLLISION_KEY.format(key=written_key, n=2): 2,
    }, "both values are kept"
    assert _too_long(added) == []
    assert entry.agent == ("a" * 99 + store_text.NUL_WRITTEN)[:100]
    assert report.run_summary[store_text.RUN_SUMMARY_KEY] == {
        "nul": _NULS_ALL,
        "surrogate": 1,
        "collided_keys": 1,
        "recut": 1,
        "written_as": store_text.NUL_WRITTEN,
        "events": 0,
    }
    assert any("PostgreSQL refuses in what it stores" in r.getMessage() for r in caplog.records)


def test_the_written_form_is_the_packs_own() -> None:
    from maljan.utils.written_forms import pack_escaped

    assert store_text.NUL_WRITTEN == pack_escaped(NUL) == "\\x00"


@pytest.mark.asyncio
async def test_a_sanitised_ledger_verifies_against_its_seal(monkeypatch: Any) -> None:
    factory, report = await _store_with_nul(monkeypatch)
    rows = _stored(factory, EvidenceEntry)
    assert _refused_columns([*rows, report]) == [], "the seal covers the written-out values"
    seal = report.ledger_seal
    assert seal["report_sha256"] == ledger_chain.report_digest(report)
    stored_rows = [
        ledger_chain.entry_fields(r) | {"digest": r.digest, "chain": r.chain} for r in rows
    ]
    stored_report = {
        attr.key: getattr(report, attr.key) for attr in sa_inspect(report).mapper.column_attrs
    }
    stored_report["id"] = str(report.id)
    stored_report["job_id"] = str(report.job_id)
    audit = JobAudit(
        check=AuditChainCheck(rows=1, head_seq=1, rotated_at_seq=1, verified=[1]),
        seals=[{"report_id": str(report.id), "seal": ledger_chain.core_of(seal)}],
    )
    verdict = ledger_verify.verify_ledger(
        report.job_id, stored_rows, report=stored_report, audit=audit, keys={KEY.key_id: KEY}
    )
    assert verdict["status"] == ledger_verify.VERIFIED, verdict


@pytest.mark.asyncio
async def test_a_clean_store_records_nothing_new(monkeypatch: Any) -> None:
    monkeypatch.setattr(ledger_chain, "platform_key_status", lambda: (KEY, None))
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))
    async with factory() as db:
        report = await _store_the_report(
            db,
            job_uuid=job.id,
            job_id=str(job.id),
            pipeline_result=_pipeline_result(),
            stix_bundle=None,
            run_summary={"evidence": {"entries": 0}},
            transcript=[{"seq": 1, "text": "plain"}],
            core_settings=Settings(_env_file=None),
        )
    assert store_text.RUN_SUMMARY_KEY not in report.run_summary


@pytest.mark.asyncio
async def test_nul_in_an_event_batch_is_written_out_and_said(caplog: Any) -> None:
    job_id = str(uuid.uuid4())
    factory = SessionFactory(rows_for(None, None))
    buffer = _JobEventBuffer(job_id, factory)  # type: ignore[arg-type]
    now = datetime.now(UTC).isoformat()
    await buffer.add(1, "agent_message", {"text": f"a{NUL}b", f"k{NUL}": [NUL]}, now)
    await buffer.add(2, "phase_change", {"phase": "reporting"}, now)
    with caplog.at_level(logging.WARNING):
        await buffer.flush()

    events = _stored(factory, JobEvent)
    assert len(events) == 2
    assert _refused_columns(events) == []
    assert events[0].payload == {
        "text": f"a{store_text.NUL_WRITTEN}b",
        f"k{store_text.NUL_WRITTEN}": [store_text.NUL_WRITTEN],
    }
    assert events[1].payload == {"phase": "reporting"}
    assert any("3 refused character(s) in 2 event(s)" in r.getMessage() for r in caplog.records)


def test_a_clean_value_comes_back_as_the_same_object() -> None:
    value = {"a": ["b", {"c": "d"}], "e": 1.5, "f": None}
    cleaned, found = store_text.without_nul(value)
    assert found == 0 and cleaned is value


@pytest.mark.asyncio
async def test_the_live_feed_and_the_table_carry_one_written_out_payload() -> None:
    job_id = str(uuid.uuid4())
    factory = SessionFactory(rows_for(None, None))
    redis = MagicMock()
    redis.incr = AsyncMock(return_value=1)
    redis.publish = AsyncMock()
    redis.xadd = AsyncMock()
    redis.expire = AsyncMock()
    worker_module._start_event_feed(job_id, factory)  # type: ignore[arg-type]
    try:
        await _publish_event(redis, job_id, "agent_message", {"text": f"a{NUL}b{LONE}c"})
        assert worker_module._EVENT_REPLACED[job_id] == 2
    finally:
        await worker_module._stop_event_feed(job_id)
    assert job_id not in worker_module._EVENT_REPLACED

    sent = json.loads(redis.publish.call_args.args[1])["data"]
    [stored] = _stored(factory, JobEvent)
    assert sent == stored.payload
    assert sent["text"] == f"a{store_text.NUL_WRITTEN}b\\xd800c"


@pytest.mark.asyncio
async def test_the_feed_s_replacements_are_counted_in_the_run_summary(monkeypatch: Any) -> None:
    monkeypatch.setattr(ledger_chain, "platform_key_status", lambda: (KEY, None))
    job = fake_job()
    monkeypatch.setitem(worker_module._EVENT_REPLACED, str(job.id), 2)
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))
    async with factory() as db:
        report = await _store_the_report(
            db,
            job_uuid=job.id,
            job_id=str(job.id),
            pipeline_result=_pipeline_result(),
            stix_bundle=None,
            run_summary={},
            transcript=[],
            core_settings=Settings(_env_file=None),
        )
    assert report.run_summary[store_text.RUN_SUMMARY_KEY]["events"] == 2
    assert report.ledger_seal["report_sha256"] == ledger_chain.report_digest(report)


# ── against a real PostgreSQL, when one is reachable ───────────────

# How long the real-database check waits for a connection before it skips.
PG_CONNECT_SECONDS = 3


async def _postgres() -> Any:
    """A connection to the configured database, or a skip that says why not."""
    import asyncio

    asyncpg = pytest.importorskip("asyncpg")
    from app.config import get_settings

    dsn = get_settings().database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
    try:
        return await asyncio.wait_for(asyncpg.connect(dsn), timeout=PG_CONNECT_SECONDS)
    except Exception as exc:  # noqa: BLE001 — any failure to reach it is a skip
        pytest.skip(
            f"no PostgreSQL reachable at the configured DATABASE_URL ({type(exc).__name__})"
        )


@pytest.mark.asyncio
async def test_postgres_refuses_the_raw_values_and_stores_the_written_out_ones() -> None:
    import asyncpg

    conn = await _postgres()
    try:
        await conn.execute(
            "CREATE TEMP TABLE f4_store_probe (agent varchar(100), output text, structured jsonb)"
        )
        insert = "INSERT INTO f4_store_probe (agent, output, structured) VALUES ($1, $2, $3::jsonb)"
        refused: list[tuple[str, str, str, str]] = [
            ("text NUL", "a", f"x{NUL}y", "{}"),
            ("jsonb NUL", "a", "x", json.dumps({"k": f"x{NUL}"})),
            ("text surrogate", "a", f"x{LONE}y", "{}"),
            ("jsonb surrogate", "a", "x", json.dumps({"k": f"x{LONE}"}, ensure_ascii=False)),
            ("varchar overflow", "a" * 103, "x", "{}"),
        ]
        for label, agent, output, structured in refused:
            try:
                await conn.execute(insert, agent, output, structured)
            except (asyncpg.PostgresError, UnicodeEncodeError):
                continue
            pytest.fail(f"PostgreSQL accepted the raw {label}")

        entry = LedgerEntry(id="ev_0001", tool="pe_info", seq=1, output="o").model_dump(mode="json")
        entry |= {
            "agent": "a" * 99 + NUL,
            "output": f"Acme{NUL}Corp {LONE}",
            "structured": {f"Company{NUL}": f"x{LONE}", "Company\\x00": 1},
        }
        row = worker_module._evidence_row(entry, job_id=uuid.uuid4())
        tally = store_text.sanitise_row(row)
        assert (tally.nul, tally.surrogate, tally.collided_keys, tally.recut) == (3, 2, 1, 1)
        await conn.execute(insert, row.agent, row.output, json.dumps(row.structured))
        back = await conn.fetchrow("SELECT agent, output, structured FROM f4_store_probe")
        assert back["agent"] == row.agent and len(back["agent"]) == 100
        assert back["output"] == row.output
        assert json.loads(back["structured"]) == row.structured
    finally:
        await conn.close()
