"""What the judge decides to remember is written once, and only for a job that completes.

That is the long-term-memory case and the function hashes filed under the
judge's family in the attribution corpus.

The judge used to write the case from inside its node: a job that then failed
still taught the next run its verdict, and a judge that ran twice wrote it
twice. The judge now builds the case and holds it on the container; the worker
writes it after the job is recorded as completed.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.worker.analysis_worker import run_analysis
from maljan.app import MaljanApp
from maljan.core.container import ServiceContainer
from tests.integration._session_probe import updates_in
from tests.integration.test_worker_job_lifecycle import (  # noqa: F401 — fixtures
    _answer_reads,
    _isolated_runtime_settings,
    _make_job,
    _make_sample,
    _no_object_store,
    mock_ctx,
    mock_db_session,
)

CASE = SimpleNamespace(sample_id="a" * 64, malware_category="loader", technique_ids=["T1105"])


FUNCTIONS = [("h1", "sub_401000"), ("h2", "sub_402000")]


class _Store:
    """The memory store and the function-hash store, recording what each is given."""

    def __init__(self) -> None:
        self.stored: list[Any] = []
        self.filed: list[tuple[str, str, list[tuple[str, str]]]] = []
        # What the console had been told when the write happened.
        self.published_before: list[str] = []
        self.redis: Any = None

    def _published(self) -> list[str]:
        if self.redis is None:
            return []
        return [str(call.args[1]) for call in self.redis.publish.call_args_list]

    def store(self, case: Any) -> None:
        self.published_before = self._published()
        self.stored.append(case)

    def upsert_sample(self, sample_id: str, family: str, functions: Any) -> int:
        self.filed.append((sample_id, family, list(functions)))
        return len(functions)


def _hold(container: Any, store: _Store) -> None:
    """What the judge holds for a run whose family was grounded."""
    container.pending_memory_case = CASE
    container.pending_function_hashes = (store, "a" * 64, "loader", FUNCTIONS)


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> _Store:
    shared = _Store()
    monkeypatch.setattr(ServiceContainer, "get_memory_store", lambda self: shared)
    return shared


def _reads(job: Any, sample: Any) -> list[Any]:
    def _result(obj: Any) -> MagicMock:
        m = MagicMock()
        if isinstance(getattr(obj, "status", None), str):
            m.scalar_one_or_none.return_value = obj
        else:
            m.scalar_one.return_value = obj
        return m

    return [_result(job), _result(sample)]


async def _run(ctx: dict[str, Any], job: Any, arun: Any) -> dict[str, Any]:
    from app import config as api_config

    api_config._settings = None
    with (
        patch.dict("os.environ", {"MALJAN_MOCK_MODE": "true"}, clear=False),
        patch("maljan.app.MaljanApp.arun", new=arun),
    ):
        result = await run_analysis(ctx, str(job.id))
    api_config._settings = None
    return result


@pytest.mark.asyncio
async def test_a_job_that_fails_after_its_judge_leaves_no_case_and_no_corpus_write(
    mock_ctx: dict[str, Any],  # noqa: F811
    mock_db_session: AsyncMock,  # noqa: F811
    store: _Store,
) -> None:
    job = _make_job()
    recorded = _answer_reads(mock_db_session, _reads(job, _make_sample()))

    async def _judge_then_fail(self: Any, **_: Any) -> dict[str, Any]:
        _hold(self.container, store)
        self.failed_step = "node report"
        raise RuntimeError("after the judge")

    result = await _run(mock_ctx, job, _judge_then_fail)

    assert result["status"] == "failed"
    assert [u["status"] for u in updates_in(recorded, "analysis_jobs")] == ["running", "failed"]
    assert store.stored == []
    assert store.filed == []


@pytest.mark.asyncio
async def test_a_completed_job_writes_its_case_and_its_corpus_once(
    mock_ctx: dict[str, Any],  # noqa: F811
    mock_db_session: AsyncMock,  # noqa: F811
    store: _Store,
) -> None:
    job = _make_job()
    recorded = _answer_reads(mock_db_session, _reads(job, _make_sample()))
    store.redis = mock_ctx["redis"]
    original = MaljanApp.arun

    async def _completes(self: Any, **kwargs: Any) -> dict[str, Any]:
        result = await original(self, **kwargs)
        _hold(self.container, store)
        return result

    result = await _run(mock_ctx, job, _completes)

    assert result["status"] == "completed"
    assert [u["status"] for u in updates_in(recorded, "analysis_jobs")] == [
        "running",
        "completed",
    ]
    assert store.stored == [CASE]
    assert store.filed == [("a" * 64, "loader", FUNCTIONS)]
    # Announced first: a slow store never holds the completion back.
    assert any('"completed"' in message for message in store.published_before)


def test_the_case_is_written_once_and_a_failing_store_costs_nothing(
    store: _Store,
) -> None:
    from maljan.core.config import Settings

    container = ServiceContainer(Settings(_env_file=None), mock=True)
    assert container.remember_the_run() is False
    container.pending_memory_case = CASE
    assert container.remember_the_run() is True
    assert container.remember_the_run() is False
    assert store.stored == [CASE]

    def _refuses(case: Any) -> None:
        raise ConnectionError("no store")

    store.store = _refuses  # type: ignore[method-assign]
    container.pending_memory_case = CASE
    assert container.remember_the_run() is False
    assert container.pending_memory_case is None
