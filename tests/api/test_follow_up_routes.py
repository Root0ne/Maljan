"""A finished job can be asked a follow-up question; a job that has not finished cannot.

``POST /jobs/{id}/follow-ups`` reads the stored run, ends its transaction,
asks the reporter's model and writes the answer in a new one; ``GET`` lists the
job's follow-ups. Both are the job owner's alone, checked the way every job
route checks it (``AnalysisService.get_job``): another account's job is not
found. A job still pending or running is a 409 that says why.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.v1.jobs import _get_service, router
from app.database import Base, get_db
from app.deps import get_current_user
from app.models.follow_up import JobFollowUp
from app.models.job import AnalysisJob
from app.models.job_event import JobEvent
from app.models.report import AnalysisReport
from app.models.sample import Sample
from app.models.user import User
from app.services import follow_up
from maljan.reporting.models import QuestionAnswer

OWNER = uuid.uuid4()


class _Session:
    """The bits of ``AsyncSession`` the routes touch, with a transaction flag."""

    def __init__(self) -> None:
        self.in_transaction = False
        self.commits = 0
        self.rollbacks = 0

    async def commit(self) -> None:
        self.in_transaction = False
        self.commits += 1

    async def rollback(self) -> None:
        self.in_transaction = False
        self.rollbacks += 1

    async def close(self) -> None:
        self.in_transaction = False


class _Jobs:
    """``AnalysisService`` as the routes use it: a job is found for its owner only."""

    def __init__(self, job: Any) -> None:
        self.job = job

    async def get_job(self, job_id: uuid.UUID, user: Any) -> Any:
        if self.job is None or self.job.id != job_id or user.id != self.job.created_by:
            return None
        return self.job


def _job(status: str = "completed") -> Any:
    return MagicMock(id=uuid.uuid4(), status=status, created_by=OWNER, config={})


def _row(job_id: uuid.UUID, question: str = "Does it beacon?") -> Any:
    answer = QuestionAnswer(question=question, outcome="not_determinable", checks=["why"])
    return MagicMock(
        id=uuid.uuid4(),
        job_id=job_id,
        report_id=uuid.uuid4(),
        question=question,
        outcome="not_determinable",
        answer=answer.model_dump(mode="json"),
        model="openai gpt-test",
        model_source="the current report model",
        report_sha256="a" * 64,
        record=None,
        notes=["this follow-up is not on the audit chain: no key"],
        answered_at=datetime(2026, 10, 23, tzinfo=UTC),
    )


@pytest.fixture
def session() -> _Session:
    return _Session()


def _client(session: _Session, job: Any, user_id: uuid.UUID = OWNER) -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: MagicMock(id=user_id)
    app.dependency_overrides[get_db] = lambda: session
    app.dependency_overrides[_get_service] = lambda: _Jobs(job)
    return TestClient(app)


@pytest.mark.parametrize("status", ["pending", "running"])
def test_a_job_that_has_not_finished_is_a_409_that_says_why(
    session: _Session, status: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _never(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("nothing is asked of a job that has not finished")

    monkeypatch.setattr(follow_up, "answer", _never)
    job = _job(status)

    res = _client(session, job).post(f"/api/v1/jobs/{job.id}/follow-ups", json={"question": "q"})

    assert res.status_code == 409
    assert f"has not finished (it is {status})" in res.json()["detail"]


def test_another_accounts_job_is_not_found_for_asking_or_listing(
    session: _Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _never(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("another account's job is never read")

    monkeypatch.setattr(follow_up, "prepare", _never)
    monkeypatch.setattr(follow_up, "list_for", _never)
    job = _job()
    client = _client(session, job, user_id=uuid.uuid4())

    asked = client.post(f"/api/v1/jobs/{job.id}/follow-ups", json={"question": "q"})
    listed = client.get(f"/api/v1/jobs/{job.id}/follow-ups")

    assert (asked.status_code, listed.status_code) == (404, 404)


def test_a_blank_question_is_refused(session: _Session) -> None:
    job = _job()

    res = _client(session, job).post(f"/api/v1/jobs/{job.id}/follow-ups", json={"question": " \n "})

    assert res.status_code == 422


def test_a_report_deleted_while_answering_is_a_409_and_nothing_is_kept(
    session: _Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _prepare(db: Any, found: Any) -> str:
        return "prepared"

    async def _answer(prepared: Any, question: str) -> follow_up.Answered:
        answer = QuestionAnswer(question=question, outcome="not_determinable")
        return follow_up.Answered(answer=answer, model="m")

    async def _store(*args: Any, **kwargs: Any) -> Any:
        raise follow_up.FollowUpRefused(409, "the report was deleted")

    monkeypatch.setattr(follow_up, "prepare", _prepare)
    monkeypatch.setattr(follow_up, "answer", _answer)
    monkeypatch.setattr(follow_up, "store", _store)
    job = _job()

    res = _client(session, job).post(f"/api/v1/jobs/{job.id}/follow-ups", json={"question": "q"})

    assert res.status_code == 409
    assert session.rollbacks == 1


def test_the_follow_ups_are_listed_oldest_first(
    session: _Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    job = _job()
    rows = [_row(job.id, "first?"), _row(job.id, "second?")]

    async def _list(db: Any, job_id: uuid.UUID) -> list[Any]:
        assert job_id == job.id
        return rows

    monkeypatch.setattr(follow_up, "list_for", _list)

    res = _client(session, job).get(f"/api/v1/jobs/{job.id}/follow-ups")

    assert res.status_code == 200
    assert [f["question"] for f in res.json()["follow_ups"]] == ["first?", "second?"]


# ── Against a real database session ──────────────────────────────────
#
# The job is read by the real ``AnalysisService`` and the follow-up written by
# the real service over SQLAlchemy's ORM ``Session`` on an in-memory SQLite
# database. The async driver for SQLite (``aiosqlite``) is not a dependency of
# this repository, so ``AsyncSession`` itself is not used: a thin adapter awaits
# the synchronous session's calls, and ``Session.in_transaction()`` is what the
# transaction check reads.


@compiles(postgresql.JSONB, "sqlite")
def _jsonb(element, compiler, **kw):  # noqa: ANN001, ANN202
    return "JSON"


@compiles(postgresql.INET, "sqlite")
def _inet(element, compiler, **kw):  # noqa: ANN001, ANN202
    return "TEXT"


class _Awaited:
    """An ORM ``Session``'s calls, awaited as ``AsyncSession``'s are."""

    def __init__(self, session: Session) -> None:
        self.session = session

    async def execute(self, statement: Any, *args: Any, **kwargs: Any) -> Any:
        return self.session.execute(statement, *args, **kwargs)

    async def get(self, *args: Any, **kwargs: Any) -> Any:
        return self.session.get(*args, **kwargs)

    def add(self, row: Any) -> None:
        self.session.add(row)

    async def flush(self) -> None:
        self.session.flush()

    async def commit(self) -> None:
        self.session.commit()

    async def rollback(self) -> None:
        self.session.rollback()

    async def close(self) -> None:
        return None


def _user(email: str) -> User:
    return User(id=uuid.uuid4(), email=email, hashed_password="x", full_name=email, role="analyst")


@pytest.fixture
def stored(monkeypatch: pytest.MonkeyPatch) -> Any:
    from app.services import settings_service
    from tests.unit.reporting.test_a_follow_up_is_answered_from_the_stored_run import _payload

    async def _overrides(db: Any) -> dict[str, Any]:
        return {}

    async def _reserved(job_id: Any, count: int, **kwargs: Any) -> int:
        return 1

    monkeypatch.setattr(settings_service, "load_core_overrides", _overrides)
    monkeypatch.setattr(follow_up, "reserve_seqs", _reserved)
    monkeypatch.setattr(
        "app.services.ledger_chain.platform_key_status", lambda: (None, "no key in this test")
    )
    engine = sa.create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    # Every table the models declare: the ORM loads a job's relationships too.
    Base.metadata.create_all(engine)
    session = Session(engine, expire_on_commit=False)
    owner, other = _user("owner@example.test"), _user("other@example.test")
    sample = Sample(
        id=uuid.uuid4(),
        sha256="d" * 64,
        original_filename="sample.exe",
        file_size_bytes=1,
        storage_path="x",
        uploaded_by=owner.id,
    )
    job = AnalysisJob(
        id=uuid.uuid4(), sample_id=sample.id, created_by=owner.id, status="completed", config={}
    )
    report = AnalysisReport(job_id=job.id, verdict="Malware", malware_report=_payload())
    report.run_summary = {}
    session.add_all([owner, other, sample, job, report])
    session.commit()
    return SimpleNamespace(session=session, owner=owner, other=other, job=job, report=report)


def _real_client(stored: Any, user: User) -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = lambda: _Awaited(stored.session)
    return TestClient(app)


def test_another_users_job_is_not_found_by_the_real_service(stored: Any) -> None:
    client = _real_client(stored, stored.other)

    asked = client.post(f"/api/v1/jobs/{stored.job.id}/follow-ups", json={"question": "q"})
    listed = client.get(f"/api/v1/jobs/{stored.job.id}/follow-ups")

    assert (asked.status_code, listed.status_code) == (404, 404)
    assert stored.session.query(JobFollowUp).count() == 0


def test_the_owner_is_answered_with_no_transaction_open_while_the_model_answers(
    stored: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    held: list[bool] = []

    async def _answer(prepared: Any, question: str) -> follow_up.Answered:
        held.append(stored.session.in_transaction())
        answer = QuestionAnswer(question=question, outcome="not_determinable", checks=["why"])
        return follow_up.Answered(answer=answer, model="openai gpt-test", usage=[{"call": "x"}])

    monkeypatch.setattr(follow_up, "answer", _answer)
    client = _real_client(stored, stored.owner)

    res = client.post(f"/api/v1/jobs/{stored.job.id}/follow-ups", json={"question": "Q?"})
    listed = client.get(f"/api/v1/jobs/{stored.job.id}/follow-ups")

    assert res.status_code == 201, res.text
    assert held == [False], "a transaction was held across the model's answer"
    assert [f["question"] for f in listed.json()["follow_ups"]] == ["Q?"]
    assert listed.json()["follow_ups"][0]["notes"] == [
        "this follow-up is not on the audit chain: no key in this test"
    ]
    assert stored.session.query(JobEvent).filter_by(type="model_usage").count() == 1
    assert stored.session.get(AnalysisReport, stored.report.id).malware_report == (
        stored.report.malware_report
    )


def test_ledger_rows_with_null_columns_reach_the_question_as_the_database_returns_them(
    stored: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.models.evidence import EvidenceEntry

    # NULL in every nullable column of the table, as a row whose entry carried
    # nothing there, or one older than the column, is stored.
    nullable = [c.name for c in EvidenceEntry.__table__.columns if c.nullable]
    stored.session.add_all(
        [
            EvidenceEntry(
                **{name: None for name in nullable},
                job_id=stored.job.id,
                entry_id=f"ev_000{seq}",
                seq=seq,
                agent="static",
                tool="strings",
                output="beacons to example.test",
            )
            for seq in (1, 2)
        ]
    )
    stored.session.commit()
    read: list[Any] = []

    async def _answer(prepared: Any, question: str) -> follow_up.Answered:
        read.append(prepared.run)
        answer = QuestionAnswer(
            question=question, outcome="established", answer="Yes [ev_0002].",
            evidence_ids=["ev_0002"],
        )  # fmt: skip
        return follow_up.Answered(answer=answer, model="openai gpt-test", notes=prepared.run.notes)

    monkeypatch.setattr(follow_up, "answer", _answer)
    client = _real_client(stored, stored.owner)

    res = client.post(f"/api/v1/jobs/{stored.job.id}/follow-ups", json={"question": "Q?"})

    assert res.status_code == 201, res.text
    assert {"started_at", "ran_on", "args_nulls_withheld", "structured_from_server"} <= set(
        nullable
    )
    (run,) = read
    assert [e.id for e in run.ledger] == ["ev_0001", "ev_0002"]
    assert not any("ledger" in note for note in res.json()["notes"])
