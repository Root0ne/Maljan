"""The evidence endpoint: owner-only, filtered, paged, in call order.

There is no async database driver in the unit environment, so the route is
called directly against a session stub that records the statements it is
handed. That is the right level for what is being checked here — who may read
a job's ledger, and what the query asks for — and leaves the SQL semantics to
the migration test.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi import HTTPException

from app.api.v1.jobs import get_job_evidence
from app.models.evidence import EvidenceEntry


class _Result:
    def __init__(self, scalar: Any = None, rows: list[Any] | None = None) -> None:
        self._scalar = scalar
        self._rows = rows or []

    def scalar_one(self) -> Any:
        return self._scalar

    def scalars(self) -> _Result:
        return self

    def all(self) -> list[Any]:
        return self._rows


class _Session:
    """Answers the count first and the page second, recording both."""

    def __init__(self, total: int, rows: list[Any]) -> None:
        self.statements: list[Any] = []
        self._answers = [_Result(scalar=total), _Result(rows=rows)]

    async def execute(self, statement: Any) -> _Result:
        self.statements.append(statement)
        return self._answers.pop(0)


class _Service:
    def __init__(self, job: Any) -> None:
        self._job = job

    async def get_job(self, job_id: uuid.UUID, user: Any) -> Any:
        return self._job


def _entry(seq: int, agent: str = "static", tool: str = "pe_info") -> EvidenceEntry:
    return EvidenceEntry(
        id=uuid.uuid4(),
        job_id=uuid.uuid4(),
        entry_id=f"ev_{seq:04d}",
        stage="analysis",
        agent=agent,
        server=None,
        tool=tool,
        ok=True,
        duration_ms=3,
        seq=seq,
        args={"path": "/samples/evil.exe"},
        output='{"machine": 332}',
        structured={"machine": 332},
    )


class _User:
    id = uuid.uuid4()


@pytest.mark.asyncio
async def test_a_job_the_caller_does_not_own_is_not_found():
    with pytest.raises(HTTPException) as excinfo:
        await get_job_evidence(
            job_id=uuid.uuid4(),
            agent=None,
            tool=None,
            page=1,
            page_size=50,
            user=_User(),
            svc=_Service(None),
            db=_Session(0, []),
        )
    assert excinfo.value.status_code == 404


@pytest.mark.asyncio
async def test_the_page_carries_the_entries_and_the_total():
    job_id = uuid.uuid4()
    session = _Session(7, [_entry(1), _entry(2)])
    page = await get_job_evidence(
        job_id=job_id,
        agent=None,
        tool=None,
        page=1,
        page_size=2,
        user=_User(),
        svc=_Service(object()),
        db=session,
    )
    assert page.job_id == job_id
    assert page.total == 7
    assert [e.entry_id for e in page.entries] == ["ev_0001", "ev_0002"]
    assert page.entries[0].structured == {"machine": 332}


@pytest.mark.asyncio
async def test_the_filters_and_the_offset_reach_the_query():
    session = _Session(0, [])
    await get_job_evidence(
        job_id=uuid.uuid4(),
        agent="static",
        tool="pe_info",
        page=3,
        page_size=25,
        user=_User(),
        svc=_Service(object()),
        db=session,
    )
    page_query = str(session.statements[1].compile(compile_kwargs={"literal_binds": True}))
    assert "evidence_entries.agent = 'static'" in page_query
    assert "evidence_entries.tool = 'pe_info'" in page_query
    assert "ORDER BY evidence_entries.seq" in page_query
    assert "LIMIT 25" in page_query
    assert "OFFSET 50" in page_query

    count_query = str(session.statements[0].compile(compile_kwargs={"literal_binds": True}))
    assert "count(*)" in count_query
    assert "evidence_entries.agent = 'static'" in count_query
