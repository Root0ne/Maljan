"""Through the worker, one user's job never reads another user's long-term memory.

The worker hands the pipeline the job's owner (``AnalysisJob.created_by``);
the case a completed job leaves is filed under that owner, and a later job
reads its own owner's cases alone.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.worker.analysis_worker import run_analysis
from maljan.app import MaljanApp
from maljan.core.container import ServiceContainer
from maljan.memory import embeddings
from maljan.memory.in_memory_store import InMemoryStore
from maljan.memory.long_term_memory import StoredCase, memory_owner_of, recall
from tests.integration.test_worker_job_lifecycle import (  # noqa: F401 — fixtures
    _answer_reads,
    _isolated_runtime_settings,
    _make_job,
    _make_sample,
    _no_object_store,
    mock_ctx,
    mock_db_session,
)

TEXT = "ransomware encrypts files and deletes shadow copies T1486 T1490"
ALICE = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")
BOB = uuid.UUID("bbbbbbbb-0000-0000-0000-000000000002")


class _Model:
    """A deterministic stand-in for the embedding model."""

    def embed(self, texts: list[str], batch_size: int | None = None) -> Any:
        for text in texts:
            vector = embeddings._bow_projection(text)
            yield MagicMock(tolist=lambda v=vector: list(v))


def _result(obj: Any) -> MagicMock:
    m = MagicMock()
    if isinstance(getattr(obj, "status", None), str):
        m.scalar_one_or_none.return_value = obj
    else:
        m.scalar_one.return_value = obj
    return m


async def _run_as(ctx: dict[str, Any], session: AsyncMock, owner: uuid.UUID, arun: Any) -> Any:
    from app import config as api_config

    job = _make_job()
    job.created_by = owner
    _answer_reads(session, [_result(job), _result(_make_sample())])
    api_config._settings = None
    with (
        patch.dict("os.environ", {"MALJAN_MOCK_MODE": "true"}, clear=False),
        patch("maljan.app.MaljanApp.arun", new=arun),
    ):
        result = await run_analysis(ctx, str(job.id))
    api_config._settings = None
    return result


@pytest.mark.asyncio
async def test_two_users_jobs_never_read_each_other_s_memory(
    mock_ctx: dict[str, Any],  # noqa: F811
    mock_db_session: AsyncMock,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: _Model())
    shared = InMemoryStore()
    monkeypatch.setattr(ServiceContainer, "get_memory_store", lambda self: shared)
    original = MaljanApp.arun
    owners: list[str | None] = []
    read: list[list[str]] = []

    async def _remembers(self: Any, **kwargs: Any) -> dict[str, Any]:
        result = await original(self, **kwargs)
        owners.append(self.container.memory_owner)
        self.container.pending_memory_case = StoredCase(
            sample_id="a" * 64, summary_text=TEXT, technique_ids=["T1486"]
        )
        return result

    async def _recalls(self: Any, **kwargs: Any) -> dict[str, Any]:
        cases = recall(shared, TEXT, top_k=5, owner=memory_owner_of(self.container))
        read.append([c.sample_id for c in cases])
        return await original(self, **kwargs)

    assert (await _run_as(mock_ctx, mock_db_session, ALICE, _remembers))["status"] == "completed"
    assert owners == [str(ALICE)]
    assert [(c.sample_id, c.owner) for c, _v, _b in shared._cases] == [("a" * 64, str(ALICE))]

    await _run_as(mock_ctx, mock_db_session, BOB, _recalls)
    await _run_as(mock_ctx, mock_db_session, ALICE, _recalls)
    assert read == [[], ["a" * 64]], "Bob's job reads nothing of Alice's; Alice's reads hers"
