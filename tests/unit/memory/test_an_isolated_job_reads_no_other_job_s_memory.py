"""A job with isolated memory reads nothing another job stored, for any sample (T-422).

A benchmark series runs under one account, and every cross-sample reader (the
judge's similar cases, the attribution's similar samples, the function-hash
families) is scoped by the owner alone: run k read what runs 1..k-1 stored for
the other samples. A job submitted with ``isolated_memory`` has an owner of
its own (``long_term_memory.memory_owner_for``), so ``recall``,
``match_functions`` and ``earlier_case`` read nothing for it under the same
owner rule, and its own case is filed under its job, never replacing the
account's. A job under the same account without the option reads as before.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.analysis.run_summary import (
    ISOLATED_MEMORY_KEY,
    RunSummaryBuilder,
    with_isolated_memory,
)
from maljan.memory import embeddings
from maljan.memory.function_hash_store import FunctionHashStore
from maljan.memory.in_memory_store import InMemoryStore
from maljan.memory.long_term_memory import (
    StoredCase,
    earlier_case,
    match_functions,
    memory_owner_for,
    memory_owner_of,
    recall,
)

ALICE = "11111111-1111-1111-1111-111111111111"
JOB_A, JOB_B, JOB_C, JOB_D = (f"0000000{n}-0000-0000-0000-000000000000" for n in range(1, 5))
X, Y = "aa" * 32, "bb" * 32
TEXT = "[STATIC] injects into explorer.exe and beacons over HTTPS T1055 T1071.001"


@pytest.fixture(autouse=True)
def fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: False)


def _case(sample: str, techniques: list[str]) -> StoredCase:
    return StoredCase(sample_id=sample, summary_text=TEXT, technique_ids=techniques)


def _container(store: Any, job: str, *, isolated: bool) -> Any:
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    container = ServiceContainer(
        Settings(_env_file=None),
        mock=True,
        job_id=job,
        memory_owner=memory_owner_for(ALICE, job, isolated),
        isolated_memory=isolated,
    )
    container.get_memory_store = lambda: store  # type: ignore[method-assign]
    return container


def _local_index() -> FunctionHashStore:
    from qdrant_client import QdrantClient

    return FunctionHashStore(
        url="http://qdrant.test:6333", collection="fh", client=QdrantClient(location=":memory:")
    )


def _job_a_stored(store: Any, index: FunctionHashStore) -> None:
    """Job A, under Alice without the option, completed on sample X."""
    container = _container(store, JOB_A, isolated=False)
    container.pending_memory_case = _case(X, ["T1055"])
    assert container.remember_the_run() is True
    index.upsert_sample(X, "FamilyA", [("h1", "f1")], owner=memory_owner_of(container))


def _reads(store: Any, index: FunctionHashStore, container: Any, sample: str) -> tuple:
    owner = memory_owner_of(container)
    return (
        recall(store, TEXT, top_k=5, exclude_sample_id=sample, owner=owner),
        match_functions(index, ["h1"], exclude_sample_id=sample, owner=owner),
        earlier_case(store, X, owner=owner),
    )


class TestAnIsolatedJobReadsNothingOfAnotherJob:
    def test_job_b_on_another_sample_reads_nothing_job_a_stored(self) -> None:
        store, index = InMemoryStore(), _local_index()
        _job_a_stored(store, index)

        similar, families, earlier = _reads(
            store, index, _container(store, JOB_B, isolated=True), Y
        )

        assert similar == []
        assert families == []
        assert earlier is None

    def test_a_job_without_it_under_the_same_account_still_reads_job_a(self) -> None:
        store, index = InMemoryStore(), _local_index()
        _job_a_stored(store, index)

        similar, families, earlier = _reads(
            store, index, _container(store, JOB_C, isolated=False), Y
        )

        assert [c.sample_id for c in similar] == [X]
        assert [m.family for m in families] == ["FamilyA"]
        assert earlier is not None and earlier.technique_ids == ["T1055"]


class TestAnIsolatedJobFilesItsOwnCaseUnderItself:
    @pytest.mark.parametrize("backend", ["memory", "qdrant"])
    def test_it_never_replaces_the_account_s_case_and_no_later_job_reads_it(
        self, backend: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        if backend == "qdrant":
            import qdrant_client

            from maljan.memory.qdrant_store import QdrantStore
            from tests.unit.memory.test_memory_is_one_owner_s_and_one_space import _Model

            # A durable store keeps the model's embedding space alone.
            monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: _Model())
            client = qdrant_client.QdrantClient(location=":memory:")
            monkeypatch.setattr(qdrant_client, "QdrantClient", lambda **_kw: client)
            store: Any = QdrantStore(url="http://qdrant.test:6333", collection="cases")
        else:
            store = InMemoryStore()
        index = _local_index()
        _job_a_stored(store, index)

        b = _container(store, JOB_B, isolated=True)
        b.pending_memory_case = _case(X, ["T1486"])
        assert b.remember_the_run() is True

        # Alice's case of X is still job A's; job B's sits beside it under its own key.
        assert earlier_case(store, X, owner=ALICE).technique_ids == ["T1055"]
        assert earlier_case(store, X, owner=memory_owner_of(b)).technique_ids == ["T1486"]
        assert store.count() == 2
        # Neither another isolated job nor the account reads job B's case as its own.
        d = _container(store, JOB_D, isolated=True)
        assert earlier_case(store, X, owner=memory_owner_of(d)) is None
        assert recall(store, TEXT, top_k=5, owner=memory_owner_of(d)) == []
        assert all(c.technique_ids == ["T1055"] for c in recall(store, TEXT, top_k=5, owner=ALICE))


class TestTheRunSummary:
    def test_off_the_summary_is_unchanged(self) -> None:
        plain = RunSummaryBuilder(start_time=0.0).build()
        off = RunSummaryBuilder(start_time=0.0).set_isolated_memory(False).build()
        plain.timestamp = off.timestamp = 0.0
        plain.elapsed_seconds = off.elapsed_seconds = 0.0

        assert off.to_dict() == plain.to_dict()
        assert ISOLATED_MEMORY_KEY not in off.to_dict()
        assert off.to_markdown() == plain.to_markdown()

    def test_on_the_dict_says_so(self) -> None:
        summary = RunSummaryBuilder(start_time=0.0).set_isolated_memory(True).build()

        assert summary.to_dict()[ISOLATED_MEMORY_KEY] is True

    def test_a_stored_summary_is_marked_only_when_isolated(self) -> None:
        assert with_isolated_memory({"a": 1}, False) == {"a": 1}
        assert with_isolated_memory({"a": 1}, True) == {"a": 1, ISOLATED_MEMORY_KEY: True}

    @pytest.mark.parametrize("isolated", [True, False])
    def test_a_run_stopped_before_its_judge_says_so_too(self, isolated: bool) -> None:
        from maljan.pipeline.stopped_run import stopped_run_summary

        state = {"file_hash": X, "evidence_ledger": [], "degradation_reasons": []}
        container = _container(InMemoryStore(), JOB_B, isolated=isolated)

        summary = stopped_run_summary(state, container, note="stopped")

        if isolated:
            assert summary[ISOLATED_MEMORY_KEY] is True
        else:
            assert ISOLATED_MEMORY_KEY not in summary

    def test_the_app_hands_the_switch_to_its_container(self) -> None:
        from maljan.app import MaljanApp

        assert MaljanApp(mock=True).container.isolated_memory is False
        assert MaljanApp(mock=True).container.memory_owner is None
        owner = memory_owner_for(ALICE, JOB_B, True)
        isolated = MaljanApp(mock=True, memory_owner=owner, isolated_memory=True).container
        assert isolated.isolated_memory is True
        assert isolated.memory_owner == owner

    def test_without_an_owner_the_switch_is_not_claimed(self) -> None:
        from maljan.app import MaljanApp

        # The job reads the whole unscoped memory: its summary must not say isolated.
        container = MaljanApp(mock=True, isolated_memory=True).container
        assert container.memory_owner is None
        assert container.isolated_memory is False
