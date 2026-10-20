"""The enrichment's similar samples are the job owner's; a job whose owner is unread gets none."""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.worker import enrich_worker


@pytest.mark.asyncio
async def test_the_owner_is_the_job_s_creator() -> None:
    owner = uuid.uuid4()
    db = MagicMock()
    db.scalar = AsyncMock(return_value=owner)
    assert await enrich_worker._job_owner(db, uuid.uuid4()) == str(owner)


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", [None, RuntimeError("db gone")])
async def test_an_owner_that_cannot_be_read_is_none(answer: Any) -> None:
    db = MagicMock()
    db.scalar = (
        AsyncMock(side_effect=answer)
        if isinstance(answer, Exception)
        else AsyncMock(return_value=answer)
    )
    assert await enrich_worker._job_owner(db, uuid.uuid4()) is None


@pytest.mark.asyncio
async def test_the_orchestrator_hands_the_owner_to_the_similar_samples(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.enrichment import orchestrator
    from maljan.memory.in_memory_store import InMemoryStore
    from maljan.memory.long_term_memory import StoredCase

    store = InMemoryStore()
    store._cases.append(
        (StoredCase(sample_id="theirs", summary_text="x", owner="user-bob"), [1.0], "m")
    )
    asked: list[Any] = []

    def _populate(report: Any, memory_store: Any, *, top_k: int = 5, owner: Any = None) -> Any:
        asked.append((memory_store, owner))
        return report

    monkeypatch.setattr(orchestrator, "populate_similar_samples", _populate)
    await orchestrator.enrich_malware_report({}, memory_store=store, memory_owner="user-alice")
    assert asked == [(store, "user-alice")]
