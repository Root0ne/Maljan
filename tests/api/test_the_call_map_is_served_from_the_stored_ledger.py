"""``GET /jobs/{id}/evidence/call-map`` derives the call map from the stored rows (T-485).

The job's ledger rows are written the way the worker writes them, read back by
the real ``AnalysisService`` over an in-memory SQLite session, and the map is
the one ``maljan.reporting.call_map`` draws from the same entries. Nothing is
written; another account's job is not found.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.v1.jobs import router
from app.database import Base, get_db
from app.deps import get_current_user
from app.models.evidence import EvidenceEntry
from app.models.job import AnalysisJob
from app.models.sample import Sample
from app.worker.analysis_worker import _evidence_row
from maljan.reporting.call_map import call_map
from maljan.schemas.evidence import LedgerEntry
from tests.api.test_follow_up_routes import _Awaited, _user

BASE = 0x2470000
_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}


def _lifted(entry_id: str, seq: int, address: int, body: str) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        seq=seq,
        tool="lift_routine",
        agent="reader_one",
        args={"address": hex(address)},
        output=f"int FUN_{address:x}(int a)\n{{\n{body}\n}}\n",
        facts=_DECOMPILE,
    )


GATE, CHECK = BASE + 0x5A10, BASE + 0x5A38
LEDGER = [
    _lifted("ev_0001", 1, GATE, f"  if (FUN_{CHECK:x}(a) == 0) return 0;"),
    _lifted("ev_0002", 2, CHECK, "  return a;"),
]


@pytest.fixture
def stored() -> Any:
    engine = sa.create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
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
    session.add_all([owner, other, sample, job])
    session.add_all([_evidence_row(e.model_dump(mode="json"), job_id=job.id) for e in LEDGER])
    session.commit()
    return SimpleNamespace(session=session, owner=owner, other=other, job=job)


def _client(stored: Any, user: Any) -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = lambda: _Awaited(stored.session)
    return TestClient(app)


def test_the_owner_gets_the_map_the_stored_entries_draw(stored: Any) -> None:
    before = stored.session.execute(sa.select(sa.func.count()).select_from(EvidenceEntry)).scalar()

    res = _client(stored, stored.owner).get(f"/api/v1/jobs/{stored.job.id}/evidence/call-map")

    assert res.status_code == 200
    body = res.json()
    assert body == {"job_id": str(stored.job.id), **call_map(LEDGER)}
    gate = next(f for f in body["functions"] if f["address"] == hex(GATE))
    assert gate["calls"] == [hex(CHECK)] and gate["listed_in"] == ["ev_0001"]
    assert all(f["read"] for f in body["functions"])
    after = stored.session.execute(sa.select(sa.func.count()).select_from(EvidenceEntry)).scalar()
    assert before == after == 2


def test_another_users_job_is_not_found(stored: Any) -> None:
    res = _client(stored, stored.other).get(f"/api/v1/jobs/{stored.job.id}/evidence/call-map")
    assert res.status_code == 404 and res.json()["detail"] == "Job not found"


def test_a_job_that_read_no_code_has_an_empty_map(stored: Any) -> None:
    stored.session.execute(sa.delete(EvidenceEntry))
    stored.session.commit()

    res = _client(stored, stored.owner).get(f"/api/v1/jobs/{stored.job.id}/evidence/call-map")

    assert res.status_code == 200
    assert res.json() == {
        "job_id": str(stored.job.id),
        "image_base": None,
        "functions": [],
        "roots": [],
    }
