"""Memory filed under per-job owner keys can be purged by owner prefix, and nothing else is.

A job with memory of its own files its case and function hashes under an
owner key of its own, below its account's (``<account>/job/<job id>``), and
nothing reads them again. An admin purges them by owner prefix, from the
in-memory store, from Qdrant and from the function-hash collection beside it,
with a dry run that counts. The prefix is read a path segment at a time: an
account's own memory, another account whose key begins with the same
characters and every unscoped entry are never touched.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.memory import embeddings
from maljan.memory.function_hash_store import FunctionHashStore
from maljan.memory.in_memory_store import InMemoryStore
from maljan.memory.long_term_memory import (
    ISOLATED_JOB_SCOPE,
    OWNER_PATH_SEPARATOR,
    StoredCase,
    isolated_jobs_prefix,
    memory_owner_for,
    owner_prefix_key,
    owner_prefix_segments,
    owner_under,
)
from maljan.memory.memory_repair import OwnerPurgeFailed, purge_owned_points
from maljan.memory.qdrant_store import OWNER_KEY, QdrantStore

UID = "3f1c2b9e-6a1d-4f7e-9b2a-0c8d7e6f5a41"
JOBS = f"{UID}/job/"
# Owners one account's purge of its job memory must leave: the account's own
# key, a key that merely begins with the same characters, a sibling path, and
# another account whose id begins with this one's.
KEPT = [UID, f"{UID}/jobs", f"{UID}/jobx/1", f"{UID}0/job/1", f"{UID[:8]}/job/1"]
PURGED = [f"{UID}/job/1", f"{UID}/job/2"]
TEXT = "ransomware encrypts files deletes shadow copies T1486 T1490"


def _case(sample: str, owner: str | None) -> StoredCase:
    return StoredCase(sample_id=sample, summary_text=TEXT, technique_ids=["T1486"], owner=owner)


class _Vector:
    def __init__(self, values: list[float]) -> None:
        self._values = values

    def tolist(self) -> list[float]:
        return list(self._values)


class _Model:
    def embed(self, texts: list[str], batch_size: int | None = None) -> Any:
        for text in texts:
            yield _Vector(embeddings._bow_projection(text))


@pytest.fixture(autouse=True)
def model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: _Model())


@pytest.fixture
def qdrant(monkeypatch: pytest.MonkeyPatch) -> QdrantStore:
    import qdrant_client
    from qdrant_client import QdrantClient

    client = QdrantClient(location=":memory:")
    monkeypatch.setattr(qdrant_client, "QdrantClient", lambda **_kw: client)
    return QdrantStore(
        url="http://qdrant.test:6333",
        collection="cases",
        function_hash_collection="hashes",
    )


def _fill(store: Any) -> None:
    for index, owner in enumerate([*KEPT, *PURGED, None]):
        store.store(_case(f"s{index}", owner))


def _owners(store: QdrantStore, collection: str) -> list[str | None]:
    points, _ = store._client.scroll(collection_name=collection, limit=100, with_payload=True)
    return sorted((p.payload or {}).get(OWNER_KEY) or "" for p in points)


class TestTheRule:
    @pytest.mark.parametrize("owner", PURGED)
    def test_a_job_owner_is_under_its_account_s_job_prefix(self, owner: str) -> None:
        assert owner_under(owner, JOBS)
        assert owner_under(owner, JOBS.rstrip("/"))

    @pytest.mark.parametrize("owner", [*KEPT, None, ""])
    def test_no_other_owner_is(self, owner: str | None) -> None:
        assert not owner_under(owner, JOBS)

    def test_one_job_is_its_own_prefix(self) -> None:
        assert owner_under(PURGED[0], PURGED[0])
        assert not owner_under(f"{PURGED[0]}0", PURGED[0])

    def test_a_trailing_separator_means_strictly_below(self) -> None:
        assert owner_under("u1/x", "u1/")
        assert not owner_under("u1", "u1/")
        assert owner_under("u1", "u1")
        assert owner_under("u1/x", "u1")
        assert not owner_under(f"{UID}/job", JOBS)
        assert owner_under(f"{UID}/job", JOBS.rstrip("/"))

    @pytest.mark.parametrize("prefix", ["", " ", "/", "//", None, "u1//job", "u1//", "/u1"])
    def test_a_prefix_naming_no_owner_path_names_nothing(self, prefix: str | None) -> None:
        assert owner_prefix_key(prefix) is None
        assert not owner_under(PURGED[0], prefix)
        assert not owner_under("u1/job/1", prefix)

    def test_an_account_id_in_upper_case_is_read_as_filed(self) -> None:
        assert owner_prefix_key(f"{UID.upper()}/job/") == JOBS
        assert owner_prefix_key(JOBS.upper()) == f"{UID}/JOB/"
        assert owner_under(f"{UID}/JOB/1", JOBS.upper())
        assert not owner_under(PURGED[0], JOBS.upper())  # only the id is case-folded

    def test_the_segments_are_counted(self) -> None:
        assert owner_prefix_segments(UID) == 1
        assert owner_prefix_segments(f"{UID}/") == 1
        assert owner_prefix_segments(JOBS) == 2
        assert owner_prefix_segments("/") == 0


class TestAnIsolatedJobsMemory:
    """The keys an isolated job files under are the ones the job prefix purges."""

    JOB = "6f1d2c3b-0a9e-4d8c-b7a6-5f4e3d2c1b0a"

    def test_the_job_prefix_names_the_isolated_job_s_key_and_not_the_account_s(self) -> None:
        isolated = memory_owner_for(UID, self.JOB, True)

        assert isolated_jobs_prefix(UID) == f"{UID}/job/"
        assert owner_under(isolated, f"{UID}/job/")
        assert not owner_under(memory_owner_for(UID, self.JOB, False), f"{UID}/job/")
        assert OWNER_PATH_SEPARATOR == ISOLATED_JOB_SCOPE[0] == ISOLATED_JOB_SCOPE[-1]

    def test_an_isolated_job_s_case_is_purged_and_the_account_s_is_kept(self) -> None:
        store = InMemoryStore()
        store.store(_case("s1", memory_owner_for(UID, self.JOB, True)))
        store.store(_case("s1", memory_owner_for(UID, self.JOB, False)))

        assert store.purge_owners(f"{UID}/job/") == {"cases": 1, "function_hashes": 0}

        assert [str(case.owner) for case, _vec, _by in store._cases] == [UID]


class TestTheInMemoryStore:
    def test_a_dry_run_counts_and_keeps(self) -> None:
        store = InMemoryStore()
        _fill(store)

        assert store.purge_owners(JOBS, dry_run=True) == {"cases": 2, "function_hashes": 0}
        assert store.count() == len(KEPT) + len(PURGED) + 1

    def test_only_the_job_owners_go(self) -> None:
        store = InMemoryStore()
        _fill(store)

        assert store.purge_owners(JOBS) == {"cases": 2, "function_hashes": 0}

        left = sorted(str(case.owner) for case, _vec, _by in store._cases)
        assert left == sorted([*KEPT, "None"])

    def test_a_prefix_naming_no_owner_is_refused(self) -> None:
        store = InMemoryStore()
        _fill(store)

        with pytest.raises(ValueError):
            store.purge_owners("/")
        assert store.count() == len(KEPT) + len(PURGED) + 1


class TestQdrant:
    def _hashes(self, store: QdrantStore) -> FunctionHashStore:
        hashes = store.function_hash_store()
        assert hashes is not None
        for index, owner in enumerate([*KEPT, *PURGED, None]):
            hashes.upsert_sample(f"s{index}", "Emotet", [(f"h{index}", "f")], owner=owner)
        return hashes

    def test_a_dry_run_counts_both_kinds_and_keeps(self, qdrant: QdrantStore) -> None:
        _fill(qdrant)
        self._hashes(qdrant)

        assert qdrant.purge_owners(JOBS, dry_run=True) == {"cases": 2, "function_hashes": 2}
        assert len(_owners(qdrant, "cases")) == len(KEPT) + len(PURGED) + 1
        assert len(_owners(qdrant, "hashes")) == len(KEPT) + len(PURGED) + 1

    def test_only_the_job_owners_go_from_both_collections(self, qdrant: QdrantStore) -> None:
        _fill(qdrant)
        self._hashes(qdrant)

        assert qdrant.purge_owners(JOBS) == {"cases": 2, "function_hashes": 2}

        expected = sorted([*KEPT, ""])
        assert _owners(qdrant, "cases") == expected
        assert _owners(qdrant, "hashes") == expected

    def test_the_function_hash_store_alone(self, qdrant: QdrantStore) -> None:
        hashes = self._hashes(qdrant)

        assert hashes.purge_owners(JOBS, dry_run=True) == 2
        assert hashes.purge_owners(JOBS) == 2
        assert hashes.purge_owners(JOBS) == 0
        assert _owners(qdrant, "hashes") == sorted([*KEPT, ""])

    def test_an_empty_store_purges_nothing(self, qdrant: QdrantStore) -> None:
        assert qdrant.purge_owners(JOBS) == {"cases": 0, "function_hashes": 0}

    def test_a_failure_is_raised_not_answered_as_zero(
        self, qdrant: QdrantStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _fill(qdrant)

        def _broken(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("scroll failed")

        monkeypatch.setattr(qdrant._client, "scroll", _broken)
        with pytest.raises(OwnerPurgeFailed) as failed:
            qdrant.purge_owners(JOBS)
        assert isinstance(failed.value.__cause__, RuntimeError)
        assert failed.value.counts == {"cases": 0, "function_hashes": 0}

    def test_a_failure_in_the_function_hashes_says_what_each_kind_lost(
        self, qdrant: QdrantStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _fill(qdrant)
        self._hashes(qdrant)
        delete = qdrant._client.delete

        def _delete(*args: Any, **kwargs: Any) -> Any:
            if kwargs.get("collection_name") == "hashes":
                raise RuntimeError("delete failed")
            return delete(*args, **kwargs)

        monkeypatch.setattr(qdrant._client, "delete", _delete)
        with pytest.raises(OwnerPurgeFailed) as failed:
            qdrant.purge_owners(JOBS)

        assert failed.value.counts == {"cases": 2, "function_hashes": 0}
        assert _owners(qdrant, "cases") == sorted([*KEPT, ""])


class TestManyPoints:
    """More owned points than one scroll page (256) holds: every page is read and deleted."""

    def _collection(self, n: int) -> Any:
        from qdrant_client import QdrantClient
        from qdrant_client.models import Distance, PointStruct, VectorParams

        client = QdrantClient(location=":memory:")
        client.create_collection("x", vectors_config=VectorParams(size=1, distance=Distance.DOT))
        owners = [f"{UID}/job/{i}" if i % 2 else (UID if i % 3 else None) for i in range(n)]
        client.upsert(
            "x",
            [
                PointStruct(id=i, vector=[1.0], payload={OWNER_KEY: o} if o else {})
                for i, o in enumerate(owners)
            ],
        )
        return client, sum(1 for o in owners if owner_under(o, JOBS))

    def test_every_page_is_counted_and_deleted(self) -> None:
        client, expected = self._collection(700)

        assert expected > 256
        assert purge_owned_points(client, "x", JOBS, dry_run=True) == expected
        assert purge_owned_points(client, "x", JOBS, dry_run=False) == expected
        assert client.count("x").count == 700 - expected
        assert purge_owned_points(client, "x", JOBS, dry_run=True) == 0

    def test_a_failed_page_names_the_ids_already_deleted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client, expected = self._collection(700)
        delete = client.delete
        calls: list[int] = []

        def _delete(*args: Any, **kwargs: Any) -> Any:
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError("delete failed")
            return delete(*args, **kwargs)

        monkeypatch.setattr(client, "delete", _delete)
        with pytest.raises(OwnerPurgeFailed) as failed:
            purge_owned_points(client, "x", JOBS, dry_run=False)

        assert len(failed.value.deleted["x"]) == 256
        assert client.count("x").count == 700 - 256
