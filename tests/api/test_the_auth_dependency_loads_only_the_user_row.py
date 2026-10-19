"""The auth dependency loads the caller's row and nothing of its history (AUD-30).

``User``'s relationships were ``lazy="selectin"``, so resolving the caller of
any authenticated request also loaded every sample, job, report (multi-MB
JSONB), transcript, audit row and API key the account ever made: thirteen
SELECTs for a user with history, growing with it. Here the statements issued
by ``get_current_user`` are counted on a real ORM session for a user with a
short and a long history, and must be the same single SELECT of ``users``.

The ORM runs on an in-memory SQLite engine (stdlib, no service needed) behind
a thin async adapter, so the loader strategies under test are SQLAlchemy's
own; only the column types Postgres has and SQLite lacks are rendered as
their SQLite equivalents for table creation.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import create_engine, event
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import deps
from app.auth.jwt import create_access_token, session_claims
from app.database import Base
from app.deps import hash_api_key
from app.models.audit import APIKey, AuditLog
from app.models.job import AnalysisJob
from app.models.report import AgentFinding, AnalysisReport
from app.models.sample import Sample
from app.models.user import User, UserRole


@compiles(JSONB, "sqlite")
def _jsonb_on_sqlite(_type: Any, _compiler: Any, **_kw: Any) -> str:
    return "JSON"


@compiles(INET, "sqlite")
def _inet_on_sqlite(_type: Any, _compiler: Any, **_kw: Any) -> str:
    return "TEXT"


# ``audit_log.created_at`` defaults server-side to the Postgres literal ``now()``.
_NOW = datetime(2026, 10, 19, tzinfo=UTC)


class _AsyncSessionOverSync:
    """The one ``AsyncSession`` method the auth dependency awaits, over a sync session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    async def execute(self, statement: Any) -> Any:
        return self._session.execute(statement)


def _seed(session: Session, history: int) -> User:
    user = User(
        email=f"analyst-{history}@example.test",
        hashed_password="not-a-hash",
        full_name="Analyst",
        role=UserRole.ANALYST,
        is_active=True,
        token_generation=0,
    )
    session.add(user)
    session.flush()
    for index in range(history):
        sample = Sample(
            sha256=f"{index:064x}",
            original_filename=f"s{index}.bin",
            file_size_bytes=1,
            storage_path=f"samples/{index}",
            uploaded_by=user.id,
            metadata_json={"index": index},
        )
        session.add(sample)
        session.flush()
        job = AnalysisJob(sample_id=sample.id, created_by=user.id, status="completed")
        session.add(job)
        session.flush()
        report = AnalysisReport(job_id=job.id, verdict="malicious", malware_report={"i": index})
        session.add(report)
        session.flush()
        session.add(AgentFinding(report_id=report.id, agent_name="a", domain="static"))
        session.add(AuditLog(user_id=user.id, action="sample.upload", created_at=_NOW))
        session.add(
            APIKey(
                user_id=user.id,
                key_hash=f"hash-{history}-{index}",
                key_prefix="mk_",
                name=f"key {index}",
            )
        )
    session.commit()
    return user


def _statements_resolving(
    history: int, credential: str, monkeypatch: pytest.MonkeyPatch
) -> list[str]:
    monkeypatch.setattr(deps.settings, "auth_disabled", False)
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    statements: list[str] = []
    with Session(engine) as session:
        user = _seed(session, history)
        token = create_access_token(session_claims(user))
        raw_key = f"probe-key-{history}"
        session.add(
            APIKey(user_id=user.id, key_hash=hash_api_key(raw_key), key_prefix="mk_", name="p")
        )
        session.commit()
        user_id = user.id
        session.expunge_all()

        @event.listens_for(engine, "before_cursor_execute")
        def _count(_conn: Any, _cursor: Any, statement: str, *_args: Any) -> None:
            statements.append(statement)

        resolved = asyncio.run(
            deps.get_current_user(
                credentials=(
                    HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
                    if credential == "bearer"
                    else None
                ),
                api_key=raw_key if credential == "api_key" else None,
                db=_AsyncSessionOverSync(session),  # type: ignore[arg-type]
            )
        )
        assert resolved.id == user_id
    engine.dispose()
    return statements


# The rows a credential is resolved from: the account, and for an API key the
# key row first. Nothing of the account's history.
_RESOLVED_FROM = {"bearer": ["users"], "api_key": ["api_keys", "users"]}


@pytest.mark.parametrize("credential", sorted(_RESOLVED_FROM))
def test_the_caller_is_resolved_from_its_own_rows_whatever_its_history(
    credential: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    short = _statements_resolving(1, credential, monkeypatch)
    long = _statements_resolving(25, credential, monkeypatch)

    assert len(short) == len(long), (short, long)
    tables = _RESOLVED_FROM[credential]
    assert len(long) == len(tables), long
    for statement, table in zip(long, tables, strict=True):
        assert f"FROM {table}" in statement, statement


@pytest.mark.parametrize("relationship_name", ["samples", "jobs", "audit_logs", "api_keys"])
def test_reading_a_history_relationship_off_a_loaded_user_is_refused_aloud(
    relationship_name: str,
) -> None:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        user_id = _seed(session, 2).id
        session.expunge_all()
        user = session.get(User, user_id)
        assert user is not None
        # A route that needs the history queries it, bounded; touching the
        # relationship raises rather than loading it whole behind the caller.
        with pytest.raises(InvalidRequestError):
            getattr(user, relationship_name)
    engine.dispose()


def test_the_history_relationships_are_never_loaded_eagerly() -> None:
    for name in ("samples", "jobs", "audit_logs", "api_keys"):
        assert User.__mapper__.relationships[name].lazy == "raise", name
