"""A follow-up question is kept as a record beside the report, and goes onto the audit chain.

``services.follow_up.store`` writes the follow-up row, the calls' usage as the
job's ``model_usage`` events (numbered after the job's last event) and, with
the chain key, a keyed record of the follow-up that a chained
``report.follow_up`` audit row holds: the stored report's digest it was
answered from, the report's seal and last amendment, the digest of the question
and answer. The stored report is never changed. Without the key the follow-up
is kept unchained and says why. ``prepare`` refuses a job that has not finished
and one that stored nothing to answer from; ``answer`` builds the reporter as
the report stage does and records its calls under ``follow-up``.
"""

from __future__ import annotations

import copy
import importlib.util
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from langchain_core.messages import AIMessage
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.compiler import compiles

from app.models.follow_up import JobFollowUp
from app.models.job_event import JobEvent
from app.models.report import AnalysisReport
from app.services import audit_chain, follow_up, ledger_chain
from maljan.reporting.models import QuestionAnswer

KEY = ledger_chain.derive_key("follow-up-test-material")
# The chained append itself, kept before a test replaces it to capture its calls.
REAL_APPEND = audit_chain.append
NOW = datetime(2026, 10, 23, 9, 0, tzinfo=UTC)
_REV = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261029000000_job_follow_ups.py"
)


@compiles(postgresql.JSONB, "sqlite")
def _json(element, compiler, **kw):  # noqa: ANN001, ANN202
    return "JSON"


@compiles(postgresql.INET, "sqlite")
def _inet(element, compiler, **kw):  # noqa: ANN001, ANN202
    return "TEXT"


def _sealed_report() -> AnalysisReport:
    job_id = uuid.uuid4()
    payload = {"verdict": "Malicious"}
    report = AnalysisReport(job_id=job_id, verdict="Malicious", malware_report=payload)
    report.run_summary = {"evidence": {"entries": 1}}
    report.id = uuid.uuid4()
    seal = ledger_chain.seal(
        job_id,
        [],
        ledger_chain.genesis(job_id, KEY),
        report_sha256=ledger_chain.report_digest(report),
        sealed_at=NOW,
        key=KEY,
        report_id=report.id,
    )
    report.ledger_seal = seal
    report.malware_report = ledger_chain.with_seal(payload, seal)
    report.run_summary = ledger_chain.with_seal(report.run_summary, seal)
    return report


class _Result:
    def __init__(self, value: Any = None) -> None:
        self.value = value

    def scalar(self) -> Any:
        return self.value

    def scalar_one_or_none(self) -> Any:
        return self.value

    def mappings(self) -> list[dict[str, Any]]:
        return list(self.value or [])


class _Session:
    """What ``store`` and ``prepare`` touch: reads answered in order, writes recorded."""

    def __init__(self, report: Any, *results: Any) -> None:
        self.report = report
        self.results = list(results)
        self.statements: list[Any] = []
        self.added: list[Any] = []

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> _Result:
        self.statements.append(statement)
        return _Result(self.results.pop(0) if self.results else None)

    async def get(self, *args: Any, **kwargs: Any) -> Any:
        return self.report

    def add(self, row: Any) -> None:
        self.added.append(row)

    async def flush(self) -> None:
        return None


def _prepared(report: AnalysisReport) -> follow_up.Prepared:
    return follow_up.Prepared(
        job_id=report.job_id,
        report_id=report.id,
        report_sha256=ledger_chain.report_digest(report),
        seal=report.ledger_seal,
        last_amendment=None,
        run=None,
        settings=None,
        model_source="the reporter's model this run's settings snapshot recorded",
    )


def _answered(**over: Any) -> follow_up.Answered:
    answer = QuestionAnswer(
        question="Does it beacon?",
        outcome="established",
        answer="It does [ev_0001].",
        evidence_ids=["ev_0001"],
    )
    fields: dict[str, Any] = {
        "answer": answer,
        "model": "openai gpt-test",
        "usage": [{"agent": "reporter", "model": "gpt-test", "call": "follow-up"}] * 2,
        "notes": [],
    }
    fields.update(over)
    return follow_up.Answered(**fields)


@pytest.fixture
def appended(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    async def _append(db: Any, **kwargs: Any) -> object:
        calls.append(kwargs)
        return object()

    async def _reserved(job_id: Any, count: int, **kwargs: Any) -> int:
        return 8

    monkeypatch.setattr(audit_chain, "append", _append)
    monkeypatch.setattr(ledger_chain, "platform_key_status", lambda: (KEY, None))
    monkeypatch.setattr(follow_up, "reserve_seqs", _reserved)
    return calls


class TestTheRecord:
    def test_it_names_the_report_digest_the_seal_and_the_last_amendment_keyed(self) -> None:
        record = ledger_chain.follow_up_record(
            follow_up_id="f",
            report_id="r",
            report_sha256="a" * 64,
            seal_record={"digest": "seal"},
            last_amendment={"digest": "amend"},
            answer_sha256="b" * 64,
            at=NOW,
            key=KEY,
        )

        assert record["kind"] == "follow_up"
        assert (record["report_sha256"], record["seal_digest"], record["amendment_digest"]) == (
            "a" * 64,
            "seal",
            "amend",
        )
        assert record["key_id"] == KEY.key_id
        assert record["digest"] == ledger_chain.record_digest(record, KEY)
        changed = {**record, "report_sha256": "c" * 64}
        assert ledger_chain.record_digest(changed, KEY) != record["digest"]

    def test_the_answer_digest_moves_with_the_answer(self) -> None:
        one = ledger_chain.follow_up_digest({"question": "q", "answer": {"answer": "a"}})
        two = ledger_chain.follow_up_digest({"question": "q", "answer": {"answer": "b"}})

        assert len(one) == 64 and one != two


class TestTheStore:
    @pytest.mark.asyncio
    async def test_the_follow_up_its_usage_and_its_audit_row_are_written_and_the_report_kept(
        self, appended: list[dict[str, Any]]
    ) -> None:
        report = _sealed_report()
        before = copy.deepcopy((report.malware_report, report.run_summary, report.ledger_seal))
        db = _Session(report, None, 7)

        row = await follow_up.store(db, _prepared(report), _answered(), " Does it\n beacon? ")

        assert (report.malware_report, report.run_summary, report.ledger_seal) == before
        assert isinstance(row, JobFollowUp) and row in db.added
        assert row.question == "Does it beacon?"
        assert row.outcome == "established"
        assert row.answer["evidence_ids"] == ["ev_0001"]
        assert row.report_sha256 == ledger_chain.report_digest(report)
        assert row.record["seal_digest"] == report.ledger_seal["digest"]
        assert row.record["report_sha256"] == row.report_sha256
        assert row.record["follow_up_id"] == str(row.id)
        assert row.notes == []
        events = [r for r in db.added if isinstance(r, JobEvent)]
        assert [(e.seq, e.type, e.payload["seq"]) for e in events] == [
            (8, "model_usage", 8),
            (9, "model_usage", 9),
        ]
        assert events[0].payload["call"] == "follow-up"
        [call] = appended
        assert call["action"] == audit_chain.REPORT_FOLLOW_UP == "report.follow_up"
        assert call["resource_type"] == "job"
        assert call["resource_id"] == str(report.job_id)
        assert call["details"] == {
            "report_id": str(report.id),
            "follow_up_id": str(row.id),
            "record": row.record,
        }

    @pytest.mark.asyncio
    async def test_the_job_row_is_locked_before_anything_is_numbered(
        self, appended: list[dict[str, Any]]
    ) -> None:
        db = _Session(_sealed_report(), None, 0)

        await follow_up.store(db, _prepared(db.report), _answered(), "q")

        first = db.statements[0]
        assert first._for_update_arg is not None
        assert "analysis_jobs" in str(first)

    @pytest.mark.asyncio
    async def test_without_the_key_it_is_kept_unchained_and_says_why(
        self, appended: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            ledger_chain, "platform_key_status", lambda: (None, "no settings encryption key")
        )
        db = _Session(_sealed_report(), None, None)

        row = await follow_up.store(db, _prepared(db.report), _answered(usage=[]), "q")

        assert row.record is None
        assert row.notes == ["this follow-up is not on the audit chain: no settings encryption key"]
        assert appended == []
        assert not [r for r in db.added if isinstance(r, JobEvent)]

    @pytest.mark.asyncio
    async def test_an_audit_row_that_does_not_land_is_said(
        self, appended: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _lost(db: Any, **kwargs: Any) -> None:
            return None

        monkeypatch.setattr(audit_chain, "append", _lost)
        db = _Session(_sealed_report(), None, None)

        row = await follow_up.store(db, _prepared(db.report), _answered(), "q")

        assert row.record is not None
        assert "did not land" in row.notes[-1]

    @pytest.mark.asyncio
    async def test_a_report_deleted_while_answering_is_refused(
        self, appended: list[dict[str, Any]]
    ) -> None:
        prepared = _prepared(_sealed_report())
        db = _Session(None, None)

        with pytest.raises(follow_up.FollowUpRefused) as refused:
            await follow_up.store(db, prepared, _answered(), "q")

        assert refused.value.status_code == 409
        assert db.added == []
        assert appended == []


class TestTheChain:
    @pytest.mark.asyncio
    async def test_the_follow_up_row_chains_after_the_seal_and_a_changed_record_is_found(
        self, appended: list[dict[str, Any]]
    ) -> None:
        from tests.unit.api.test_the_seal_is_on_the_audit_chain import _ChainSession

        report = _sealed_report()
        await follow_up.store(_Session(report, None, None), _prepared(report), _answered(), "q")
        [asked] = appended
        chain = _ChainSession()
        await REAL_APPEND(
            chain,
            action=audit_chain.LEDGER_SEAL,
            resource_type="job",
            resource_id=str(report.job_id),
            details={"seal": report.ledger_seal},
            key=KEY,
        )
        await REAL_APPEND(chain, **asked)

        check = audit_chain.verify_audit_chain(chain.rows, {KEY.key_id: KEY}, chain.head)
        assert (check.rows, check.broken_at) == (2, None)
        assert chain.rows[1].action == "report.follow_up"
        assert chain.rows[1].details["record"]["report_sha256"] == ledger_chain.report_digest(
            report
        )

        chain.rows[1].details = {
            **chain.rows[1].details,
            "record": {**asked["details"]["record"], "report_sha256": "0" * 64},
        }
        check = audit_chain.verify_audit_chain(chain.rows, {KEY.key_id: KEY}, chain.head)
        assert check.broken_at == 2


class TestThePreparation:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", ["pending", "running"])
    async def test_a_job_that_has_not_finished_is_refused_before_anything_is_read(
        self, status: str
    ) -> None:
        db = _Session(None)
        job = type("Job", (), {"id": uuid.uuid4(), "status": status, "config": {}})()

        with pytest.raises(follow_up.FollowUpRefused) as refused:
            await follow_up.prepare(db, job)

        assert refused.value.status_code == 409
        assert f"has not finished (it is {status})" in refused.value.detail
        assert db.statements == []

    @pytest.mark.asyncio
    async def test_a_finished_job_without_a_report_is_refused(self) -> None:
        job = type("Job", (), {"id": uuid.uuid4(), "status": "failed", "config": {}})()

        with pytest.raises(follow_up.FollowUpRefused) as refused:
            await follow_up.prepare(_Session(None, None), job)

        assert refused.value.status_code == 409
        assert "without storing a report" in refused.value.detail

    @pytest.mark.asyncio
    async def test_a_report_without_the_structured_payload_is_refused(self) -> None:
        job = type("Job", (), {"id": uuid.uuid4(), "status": "completed", "config": {}})()
        legacy = AnalysisReport(job_id=job.id, verdict="Malicious", malware_report=None)

        with pytest.raises(follow_up.FollowUpRefused) as refused:
            await follow_up.prepare(_Session(None, legacy), job)

        assert refused.value.status_code == 422

    @pytest.mark.asyncio
    async def test_a_finished_job_is_read_back_with_the_runs_reporter_model(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tests.unit.reporting.test_a_follow_up_is_answered_from_the_stored_run import (
            _findings,
            _payload,
            _rows,
        )

        from app import runtime_config as rc
        from app.services import settings_service
        from maljan.core.model_assignments import model_label_for
        from maljan.reporting.follow_up import RUN_MODEL

        async def _overrides(db: Any) -> dict[str, Any]:
            return {"llm.provider": "openai"}

        async def _get(key: str) -> Any:
            return False

        monkeypatch.setattr(settings_service, "load_core_overrides", _overrides)
        monkeypatch.setattr(rc.runtime_config, "get", _get)
        job = type("Job", (), {"id": uuid.uuid4(), "status": "completed", "config": {}})()
        report = _sealed_report()
        report.malware_report = ledger_chain.with_seal(_payload(), report.ledger_seal)
        report.run_summary = {
            "settings_snapshot": {"llm.provider": "anthropic", "llm.anthropic.judge_model": "c-run"}
        }
        db = _Session(None, report, _rows(), _findings())

        prepared = await follow_up.prepare(db, job)

        assert prepared.report_sha256 == ledger_chain.report_digest(report)
        assert prepared.seal == report.ledger_seal
        assert [e.id for e in prepared.run.ledger] == ["ev_0001", "ev_0002"]
        assert prepared.model_source == RUN_MODEL
        assert "c-run" in model_label_for(prepared.settings, "reporter", role="judge")
        assert prepared.mock is False

    @pytest.mark.asyncio
    async def test_every_ledger_row_the_database_returns_reaches_the_model(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        from tests.unit.reporting.test_a_follow_up_is_answered_from_the_stored_run import (
            _findings,
            _payload,
        )

        from app.models.evidence import EvidenceEntry
        from app.services import settings_service
        from maljan.core.container import ServiceContainer
        from maljan.reporting.narrative_agent import NarrativeAgent

        async def _overrides(db: Any) -> dict[str, Any]:
            return {}

        # Each row as the database returns it: every column of the table, and
        # NULL in each one that admits it.
        filled = {"entry_id": "", "stage": "analysis", "agent": "static", "tool": "strings",
                  "ok": True, "output": "beacons to example.test", "seq": 0, "duration_ms": 0,
                  "waited_ms": 0, "args_repaired": False, "truncated": False,
                  "chars_dropped": 0}  # fmt: skip
        columns = EvidenceEntry.__table__.columns
        rows = [
            {
                **{c.name: None for c in columns if c.nullable},
                **filled,
                "id": str(uuid.uuid4()),
                "entry_id": f"ev_000{seq}",
                "seq": seq,
            }
            for seq in (1, 2, 3)
        ]
        required = {c.name for c in columns if not c.nullable}
        assert required <= {*filled, "id", "job_id", "created_at", "updated_at"}
        answer = {
            "answers": [
                {"question": 1, "outcome": "established", "answer": "Yes [ev_0003].",
                 "evidence_ids": ["ev_0003"]}
            ]
        }  # fmt: skip
        built: list[NarrativeAgent] = []
        packed: list[list[str]] = []

        def _reporter(self: ServiceContainer) -> NarrativeAgent:
            agent = NarrativeAgent(
                llm=_Reply(json.dumps(answer)),  # type: ignore[arg-type]
                token_ledger=self._token_ledger,
                model_label="openai gpt-test",
            )
            built.append(agent)
            return agent

        async def _close(self: ServiceContainer) -> None:
            return None

        def _pack(state: Any, *args: Any, **kwargs: Any) -> str:
            packed.append([str(e.id) for e in state["evidence_ledger"]])
            return "PACK"

        monkeypatch.setattr(settings_service, "load_core_overrides", _overrides)
        monkeypatch.setattr(ServiceContainer, "get_narrative_agent", _reporter)
        monkeypatch.setattr(ServiceContainer, "aclose", _close)
        monkeypatch.setattr(follow_up, "_learn_reporter_windows", lambda settings: None)
        monkeypatch.setattr("maljan.pipeline.nodes.pack_text", _pack)
        job = type("Job", (), {"id": uuid.uuid4(), "status": "completed", "config": {}})()
        report = _sealed_report()
        report.malware_report = ledger_chain.with_seal(_payload(), report.ledger_seal)

        prepared = await follow_up.prepare(_Session(None, report, rows, _findings()), job)
        done = await follow_up.answer(prepared, "Does it beacon?")

        ids = ["ev_0001", "ev_0002", "ev_0003"]
        assert [e.id for e in prepared.run.ledger] == ids
        assert packed == [ids]
        assert len(built[0].ledger_reads) == len(ids)
        assert done.answer.outcome == "established"
        assert not any("ledger row" in note for note in done.notes)

    @pytest.mark.asyncio
    async def test_a_refused_stored_setting_is_a_422_that_names_no_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tests.unit.reporting.test_a_follow_up_is_answered_from_the_stored_run import (
            _findings,
            _payload,
            _rows,
        )

        from app.services import settings_service
        from maljan.core import settings_overrides

        async def _overrides(db: Any) -> dict[str, Any]:
            return {"llm.openai.api_key": "a-value"}

        def _refuse(*args: Any, **kwargs: Any) -> Any:
            raise settings_overrides.StoredValueRefused({"llm.openai.api_key": "a-value refused"})

        monkeypatch.setattr(settings_service, "load_core_overrides", _overrides)
        monkeypatch.setattr(settings_overrides, "settings_from_store", _refuse)
        job = type("Job", (), {"id": uuid.uuid4(), "status": "completed", "config": {}})()
        report = _sealed_report()
        report.malware_report = ledger_chain.with_seal(_payload(), report.ledger_seal)

        with pytest.raises(follow_up.FollowUpRefused) as refused:
            await follow_up.prepare(_Session(None, report, _rows(), _findings()), job)

        assert refused.value.status_code == 422
        assert "api_key" not in refused.value.detail
        assert "a-value" not in refused.value.detail


class _Reply:
    """A model whose one answer carries the usage a provider reports."""

    def __init__(self, content: str) -> None:
        self.content = content

    async def ainvoke(self, *args: Any, **kwargs: Any) -> AIMessage:
        return AIMessage(
            content=self.content,
            usage_metadata={"input_tokens": 120, "output_tokens": 30, "total_tokens": 150},
        )


class TestTheAnswer:
    @staticmethod
    def _prepared(mock: bool) -> follow_up.Prepared:
        from tests.unit.reporting.test_a_follow_up_is_answered_from_the_stored_run import (
            _findings,
            _payload,
            _rows,
        )

        from maljan.core.settings_overrides import build_settings
        from maljan.reporting.follow_up import stored_run

        return follow_up.Prepared(
            job_id=uuid.uuid4(),
            report_id=uuid.uuid4(),
            report_sha256="a" * 64,
            seal=None,
            last_amendment=None,
            run=stored_run(_payload(), _rows(), _findings()),
            settings=build_settings({}),
            model_source="m",
            mock=mock,
        )

    @pytest.mark.asyncio
    async def test_a_mock_job_has_no_report_model_and_the_question_is_not_determinable(
        self,
    ) -> None:
        done = await follow_up.answer(self._prepared(mock=True), "Does it beacon?")

        assert done.answer.outcome == "not_determinable"
        assert done.answer.checks == ["no report model ran in this run"]
        assert done.usage == []

    @pytest.mark.asyncio
    async def test_the_reporter_is_the_containers_and_its_calls_are_recorded_as_usage(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        from maljan.core.container import ServiceContainer
        from maljan.reporting.narrative_agent import NarrativeAgent

        answer = {
            "answers": [
                {"question": 1, "outcome": "established", "answer": "Yes [ev_0001].",
                 "evidence_ids": ["ev_0001"]}
            ]
        }  # fmt: skip
        built: list[Any] = []

        def _reporter(self: ServiceContainer) -> NarrativeAgent:
            agent = NarrativeAgent(
                llm=_Reply(json.dumps(answer)),  # type: ignore[arg-type]
                token_ledger=self._token_ledger,
                model_label="openai gpt-test",
            )
            built.append(self)
            return agent

        closed: list[Any] = []

        async def _close(self: ServiceContainer) -> None:
            closed.append(self)

        monkeypatch.setattr(ServiceContainer, "get_narrative_agent", _reporter)
        monkeypatch.setattr(ServiceContainer, "aclose", _close)
        monkeypatch.setattr(follow_up, "_learn_reporter_windows", lambda settings: None)
        monkeypatch.setattr("maljan.pipeline.nodes.pack_text", lambda *a, **k: "PACK")

        done = await follow_up.answer(self._prepared(mock=False), "Does it beacon?")

        assert done.answer.outcome == "established"
        assert done.model == "openai gpt-test"
        assert [(u["agent"], u["call"]) for u in done.usage] == [("reporter", "follow-up")]
        assert closed == built
        assert built[0].job_id.startswith("follow-up-")


def test_the_table_is_created_as_the_model_declares_it_and_dropped_again() -> None:
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    spec = importlib.util.spec_from_file_location("job_follow_ups", _REV)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert (mod.revision, mod.down_revision) == ("20261029000000", "20261028000000")
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        for table in ("analysis_jobs", "analysis_reports", "users"):
            conn.execute(sa.text(f"CREATE TABLE {table} (id TEXT PRIMARY KEY)"))
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()
            columns = {c["name"] for c in sa.inspect(conn).get_columns("job_follow_ups")}
            assert columns == {c.name for c in JobFollowUp.__table__.columns}
            keys = {
                (fk["referred_table"], fk["options"].get("ondelete"))
                for fk in sa.inspect(conn).get_foreign_keys("job_follow_ups")
            }
            assert keys == {
                ("analysis_jobs", "CASCADE"),
                ("analysis_reports", "CASCADE"),
                ("users", "SET NULL"),
            }
            mod.downgrade()
            assert "job_follow_ups" not in sa.inspect(conn).get_table_names()


class TestTheNumbering:
    """The follow-up's usage records take their numbers from the job's event counter."""

    class _Tables:
        """An ``async_sessionmaker`` whose session answers the job's highest stored ``seq``."""

        def __init__(self, highest: int | None) -> None:
            self.highest = highest

        def __call__(self) -> Any:
            highest = self.highest

            class _Db:
                async def __aenter__(self) -> Any:
                    return self

                async def __aexit__(self, *exc: Any) -> bool:
                    return False

                async def execute(self, *args: Any, **kwargs: Any) -> _Result:
                    return _Result(highest)

                async def commit(self) -> None:
                    return None

            return _Db()

    @pytest.mark.asyncio
    async def test_a_later_publish_never_takes_a_number_the_follow_up_took(self) -> None:
        import fakeredis

        from app.worker import analysis_worker

        job_id = uuid.uuid4()
        redis_conn = fakeredis.FakeAsyncRedis()
        await redis_conn.set(f"analysis:{job_id}:seq", 40)

        first = await follow_up.reserve_seqs(
            job_id, 2, redis_conn=redis_conn, session_factory=self._Tables(40)
        )
        later = await analysis_worker._next_seq(redis_conn, str(job_id))

        assert first == 41
        assert later == 43

    @pytest.mark.asyncio
    async def test_an_expired_counter_is_continued_from_the_table_first(self) -> None:
        import fakeredis

        job_id = uuid.uuid4()
        redis_conn = fakeredis.FakeAsyncRedis()

        first = await follow_up.reserve_seqs(
            job_id, 3, redis_conn=redis_conn, session_factory=self._Tables(40)
        )

        assert first == 41
        assert int(await redis_conn.get(f"analysis:{job_id}:seq")) == 43

    @pytest.mark.asyncio
    async def test_without_the_counter_the_table_numbers_them_and_it_is_said(
        self, appended: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def _away(job_id: Any, count: int, **kwargs: Any) -> None:
            return None

        monkeypatch.setattr(follow_up, "reserve_seqs", _away)
        db = _Session(_sealed_report(), None, 7)

        row = await follow_up.store(db, _prepared(db.report), _answered(), "q")

        events = [r for r in db.added if isinstance(r, JobEvent)]
        assert [e.seq for e in events] == [8, 9]
        assert row.notes == [follow_up.NUMBERED_FROM_THE_TABLE]

    @pytest.mark.asyncio
    async def test_the_numbers_are_taken_before_the_job_row_is_locked(
        self, appended: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = _Session(_sealed_report(), None, None)
        seen: list[int] = []

        async def _reserved(job_id: Any, count: int, **kwargs: Any) -> int:
            seen.append(len(db.statements))
            return 21

        monkeypatch.setattr(follow_up, "reserve_seqs", _reserved)

        await follow_up.store(db, _prepared(db.report), _answered(), "q")
        given = _Session(_sealed_report(), None, None)
        await follow_up.store(given, _prepared(given.report), _answered(), "q", first=5)

        assert seen == [0], "the counter was asked under the job row's lock"
        assert [e.seq for e in db.added if isinstance(e, JobEvent)] == [21, 22]
        assert [e.seq for e in given.added if isinstance(e, JobEvent)] == [5, 6]
        assert seen == [0], "a number the caller took is not taken again"

    def test_the_counters_client_waits_a_bounded_time(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import asyncio

        import redis.asyncio as aioredis

        made: list[dict[str, Any]] = []

        class _Down:
            async def exists(self, key: str) -> bool:
                raise ConnectionError("down")

            async def incrby(self, key: str, count: int) -> int:
                raise ConnectionError("down")

            async def aclose(self) -> None:
                return None

        def _from_url(url: str, **kwargs: Any) -> _Down:
            made.append(kwargs)
            return _Down()

        monkeypatch.setattr(aioredis, "from_url", _from_url)

        assert asyncio.run(follow_up.reserve_seqs(uuid.uuid4(), 2)) is None
        assert made == [
            {
                "socket_timeout": follow_up.COUNTER_TIMEOUT,
                "socket_connect_timeout": follow_up.COUNTER_TIMEOUT,
            }
        ]


class TestTheModelChosen:
    @staticmethod
    def _job(config: dict[str, Any] | None = None) -> Any:
        return type("Job", (), {"id": uuid.uuid4(), "status": "completed", "config": config})()

    @staticmethod
    def _stored(monkeypatch: pytest.MonkeyPatch) -> Any:
        from tests.unit.reporting.test_a_follow_up_is_answered_from_the_stored_run import (
            _findings,
            _payload,
            _rows,
        )

        from app.services import settings_service

        async def _overrides(db: Any) -> dict[str, Any]:
            return {"llm.provider": "openai"}

        monkeypatch.setattr(settings_service, "load_core_overrides", _overrides)
        report = _sealed_report()
        report.malware_report = ledger_chain.with_seal(_payload(), report.ledger_seal)
        return _Session(None, report, _rows(), _findings())

    @pytest.mark.asyncio
    async def test_a_job_that_ran_as_a_mock_is_answered_as_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app import runtime_config as rc

        async def _not_allowed(key: str) -> Any:
            return False

        monkeypatch.setattr(rc.runtime_config, "get", _not_allowed)

        prepared = await follow_up.prepare(
            self._stored(monkeypatch), self._job({"mock_mode": True})
        )

        assert prepared.mock is True

    @pytest.mark.asyncio
    async def test_a_recorded_model_that_will_not_build_falls_back_to_the_current_and_says_why(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core.model_assignments import model_label_for
        from maljan.reporting import follow_up as core
        from maljan.reporting.follow_up import UNBUILT_MODEL

        def _half_blank(overrides: Any, snapshot: Any, current: Any = None) -> Any:
            return {**overrides, "llm.agents": {"reporter": {"provider": "openai"}}}, "run"

        monkeypatch.setattr(core, "reporter_overrides", _half_blank)

        prepared = await follow_up.prepare(self._stored(monkeypatch), self._job())

        assert prepared.model_source == UNBUILT_MODEL.format(error="ValidationError")
        assert "gpt-4o" in model_label_for(prepared.settings, "reporter", role="judge")


class TestTheVerification:
    @staticmethod
    def _chained(appended: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [call["details"] for call in appended]

    @staticmethod
    def _row(row: JobFollowUp) -> dict[str, Any]:
        return {c.name: getattr(row, c.name) for c in JobFollowUp.__table__.columns}

    @pytest.mark.asyncio
    async def test_an_untouched_follow_up_matches_its_chained_record(
        self, appended: list[dict[str, Any]]
    ) -> None:
        from app.services.ledger_verify import check_follow_ups

        db = _Session(_sealed_report(), None, None)
        row = await follow_up.store(db, _prepared(db.report), _answered(), "q")

        found = check_follow_ups([self._row(row)], self._chained(appended), {KEY.key_id: KEY})

        assert (found.checks, found.problems) == (
            ["1 follow-up(s) match their chained records"],
            [],
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "edit",
        [
            {"question": "Another question?"},
            {"model": "another model"},
            {"answer": {"outcome": "established", "answer": "rewritten"}},
        ],
    )
    async def test_an_edited_question_answer_or_model_is_caught(
        self, appended: list[dict[str, Any]], edit: dict[str, Any]
    ) -> None:
        from app.services.ledger_verify import (
            _with_follow_ups,
            check_follow_ups,
        )

        db = _Session(_sealed_report(), None, None)
        row = await follow_up.store(db, _prepared(db.report), _answered(), "q")
        stored = {**self._row(row), **edit}

        found = check_follow_ups([stored], self._chained(appended), {KEY.key_id: KEY})
        verdict = _with_follow_ups(
            {
                "status": "verified",
                "reason": "",
                "first_broken_seq": None,
                "checks": [],
                "notes": [],
            },
            found,
        )

        assert found.problems == [
            f"follow-up {row.id} differs from its record: its question, answer or model changed"
        ]
        assert verdict["status"] == "broken"
        assert "does not match its chained record" in verdict["reason"]

    @pytest.mark.asyncio
    async def test_a_record_rewritten_on_the_row_alone_is_caught(
        self, appended: list[dict[str, Any]]
    ) -> None:
        from app.services.ledger_verify import check_follow_ups

        db = _Session(_sealed_report(), None, None)
        row = await follow_up.store(db, _prepared(db.report), _answered(), "q")
        stored = self._row(row)
        stored["question"] = "Rewritten?"
        stored["record"] = ledger_chain.follow_up_record(
            follow_up_id=row.id,
            report_id=row.report_id,
            report_sha256=row.report_sha256,
            seal_record=db.report.ledger_seal,
            last_amendment=None,
            answer_sha256=ledger_chain.follow_up_digest(
                {"question": "Rewritten?", "answer": row.answer, "model": row.model}
            ),
            at=NOW,
            key=KEY,
        )

        found = check_follow_ups([stored], self._chained(appended), {KEY.key_id: KEY})

        assert found.problems == [
            f"follow-up {row.id}'s record differs from the one its chained audit row holds"
        ]

    def test_an_unchained_follow_up_is_said_not_checked(self) -> None:
        from app.services.ledger_verify import check_follow_ups

        found = check_follow_ups([{"id": "f", "record": None}], [], {KEY.key_id: KEY})

        assert found.problems == []
        assert "is not checked" in found.notes[0]

    @pytest.mark.asyncio
    async def test_a_chained_follow_up_whose_row_is_gone_breaks_while_its_report_is_stored(
        self, appended: list[dict[str, Any]]
    ) -> None:
        from app.services.ledger_verify import check_follow_ups

        db = _Session(_sealed_report(), None, None)
        row = await follow_up.store(db, _prepared(db.report), _answered(), "q")
        chained = self._chained(appended)

        removed = check_follow_ups([], chained, {KEY.key_id: KEY}, [str(row.report_id)])
        with_its_report = check_follow_ups([], chained, {KEY.key_id: KEY}, [])

        assert removed.problems == [
            f"follow-up {row.id} is on the audit chain and its row is gone while the report it "
            "was answered from is stored"
        ]
        assert with_its_report.problems == []
        assert "the report it was answered from is gone too" in with_its_report.notes[0]

    @pytest.mark.asyncio
    async def test_the_jobs_verification_reads_its_follow_ups_and_breaks_on_an_edit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from tests.unit.api.test_a_ledger_is_verified_against_its_seal import (
            KEY as VERIFY_KEY,
        )
        from tests.unit.api.test_a_ledger_is_verified_against_its_seal import (
            _AsyncConnection,
            _audit_row,
            _report_row,
            _seal_into,
        )

        from app.models.audit import AuditChainHead, AuditLog
        from app.models.evidence import EvidenceEntry
        from app.services import ledger_verify
        from app.worker.analysis_worker import _evidence_row
        from maljan.schemas.evidence import LedgerEntry

        monkeypatch.setattr(ledger_chain, "platform_key_status", lambda: (VERIFY_KEY, None))
        job_id = uuid.uuid4()
        rows = [
            _evidence_row(
                LedgerEntry(id="ev_0001", tool="pe_info", seq=1, output="x").model_dump(
                    mode="json"
                ),
                job_id=job_id,
                written_at=NOW,
            )
        ]
        report = _report_row(job_id)
        seal = _seal_into(report, job_id, rows, ledger_chain.chain_rows(job_id, rows, VERIFY_KEY))
        asked = {"question": "Does it beacon?", "answer": {"outcome": "partial"}, "model": "m"}
        follow_up_id = uuid.uuid4()
        record = ledger_chain.follow_up_record(
            follow_up_id=follow_up_id,
            report_id=report["id"],
            report_sha256="a" * 64,
            seal_record=seal,
            last_amendment=None,
            answer_sha256=ledger_chain.follow_up_digest(asked),
            at=NOW,
            key=VERIFY_KEY,
        )
        sealed = _audit_row(
            1, None, job_id, audit_chain.LEDGER_SEAL, {"report_id": report["id"], "seal": seal}
        )
        chained = _audit_row(
            2,
            sealed["chain"],
            job_id,
            audit_chain.REPORT_FOLLOW_UP,
            {"report_id": report["id"], "follow_up_id": str(follow_up_id), "record": record},
        )
        engine = sa.create_engine("sqlite://")
        with engine.begin() as conn:
            for model in (EvidenceEntry, AnalysisReport, AuditLog, AuditChainHead, JobFollowUp):
                model.__table__.create(conn)
            for row in rows:
                values = {c.name: getattr(row, c.name) for c in EvidenceEntry.__table__.columns}
                conn.execute(
                    EvidenceEntry.__table__.insert().values(
                        **values | {"id": uuid.uuid4(), "updated_at": NOW}
                    )
                )
            conn.execute(
                AnalysisReport.__table__.insert().values(
                    **report | {"id": uuid.UUID(report["id"]), "job_id": job_id},
                    created_at=NOW,
                    updated_at=NOW,
                )
            )
            for audit_row in (sealed, chained):
                conn.execute(AuditLog.__table__.insert().values(**audit_row))
            conn.execute(
                AuditChainHead.__table__.insert().values(
                    name=audit_chain.HEAD_NAME,
                    chain_seq=2,
                    chain=chained["chain"],
                    key_id=VERIFY_KEY.key_id,
                    rotated_at_seq=1,
                    mac=audit_chain.head_mac(2, chained["chain"], 1, VERIFY_KEY),
                )
            )
            table = JobFollowUp.__table__
            conn.execute(
                table.insert().values(
                    id=follow_up_id,
                    job_id=job_id,
                    report_id=uuid.UUID(report["id"]),
                    outcome="partial",
                    model_source="s",
                    report_sha256="a" * 64,
                    record=record,
                    notes=[],
                    answered_at=NOW,
                    created_at=NOW,
                    updated_at=NOW,
                    **asked,
                )
            )
            db = _AsyncConnection(conn)

            verdict = await ledger_verify.verify_job(db, job_id)
            assert verdict["status"] == "verified", verdict
            assert "1 follow-up(s) match their chained records" in verdict["checks"]

            conn.execute(table.update().values(question="Was it edited?"))
            verdict = await ledger_verify.verify_job(db, job_id)
            assert verdict["status"] == "broken"
            assert "follow-up" in verdict["reason"] and "changed" in verdict["reason"]
