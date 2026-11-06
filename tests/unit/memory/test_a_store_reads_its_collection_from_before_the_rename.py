"""A memory store reads the collection a deployment held before the product's rename (T-576).

The upgrade script aliases the new default collection names to the old
collections; a store counts an alias as the collection it names. Where no
alias was made, a store whose collection is absent reads its twin under the
previous name instead of creating an empty collection beside it. The memory
repair finds the marker an earlier release wrote, under the old names.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from malspark.core.previous_name import CURRENT_NAME, PREVIOUS_NAME
from malspark.memory import embeddings, memory_repair
from malspark.memory.function_hash_store import FunctionHashStore
from malspark.memory.long_term_memory import StoredCase, match_functions

NEW_HASHES = f"{CURRENT_NAME}_function_hashes_v1"
OLD_HASHES = f"{PREVIOUS_NAME}_function_hashes_v1"
NEW_CASES = f"{CURRENT_NAME}_cases_v2"
OLD_CASES = f"{PREVIOUS_NAME}_cases_v2"


def _client() -> Any:
    from qdrant_client import QdrantClient

    return QdrantClient(location=":memory:")


def _alias(client: Any, collection: str, alias: str) -> None:
    from qdrant_client.models import CreateAlias, CreateAliasOperation

    client.update_collection_aliases(
        change_aliases_operations=[
            CreateAliasOperation(
                create_alias=CreateAlias(collection_name=collection, alias_name=alias)
            )
        ]
    )


def _names(client: Any) -> set[str]:
    return {c.name for c in client.get_collections().collections}


def _old_hashes(client: Any) -> None:
    earlier = FunctionHashStore(url="http://qdrant.test:6333", collection=OLD_HASHES, client=client)
    earlier.upsert_sample("s1", "FamilyA", [("h1", "f1"), ("h2", "f2")], owner="alice")


def _families(index: FunctionHashStore) -> list[str]:
    return sorted({m.family for m in match_functions(index, ["h1", "h2"], owner="alice")})


def test_the_function_hash_store_reads_through_an_alias_and_creates_nothing() -> None:
    client = _client()
    _old_hashes(client)
    _alias(client, OLD_HASHES, NEW_HASHES)
    index = FunctionHashStore(url="http://qdrant.test:6333", collection=NEW_HASHES, client=client)

    assert index._collection_exists()
    assert _families(index) == ["FamilyA"]
    index.upsert_sample("s2", "FamilyB", [("h3", "f3")], owner="alice")
    assert _names(client) == {OLD_HASHES}, "no collection is created under the alias name"
    assert index.count() == 3


def test_without_an_alias_the_function_hash_store_reads_its_previous_twin(caplog: Any) -> None:
    client = _client()
    _old_hashes(client)
    index = FunctionHashStore(url="http://qdrant.test:6333", collection=NEW_HASHES, client=client)

    with caplog.at_level(logging.WARNING):
        assert _families(index) == ["FamilyA"]
        index.upsert_sample("s2", "FamilyB", [("h3", "f3")], owner="alice")
    assert _names(client) == {OLD_HASHES}, "no empty twin beside the old collection"
    switched = [r for r in caplog.records if "is absent" in r.getMessage()]
    assert len(switched) == 1 and OLD_HASHES in switched[0].getMessage(), "named once"


def test_a_fresh_deployment_creates_its_collection_under_the_new_name() -> None:
    client = _client()
    index = FunctionHashStore(url="http://qdrant.test:6333", collection=NEW_HASHES, client=client)
    index.upsert_sample("s1", "FamilyA", [("h1", "f1")], owner="alice")
    assert _names(client) == {NEW_HASHES}


class _Model:
    def embed(self, texts: list[str], batch_size: int | None = None) -> Any:
        from tests.unit.memory.test_memory_is_one_owner_s_and_one_space import _Vector

        for text in texts:
            bow = embeddings._bow_projection(text)
            yield _Vector(bow[1:] + bow[:1])


@pytest.fixture
def cases_client(monkeypatch: pytest.MonkeyPatch) -> Any:
    import qdrant_client

    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: _Model())
    client = _client()
    monkeypatch.setattr(qdrant_client, "QdrantClient", lambda **_kw: client)
    return client


def _case() -> StoredCase:
    return StoredCase(
        sample_id="x", summary_text="a loader that injects", technique_ids=["T1055"], owner="alice"
    )


@pytest.mark.parametrize("aliased", [True, False])
def test_the_case_store_reads_the_collection_from_before_the_rename(
    cases_client: Any, aliased: bool
) -> None:
    from malspark.memory.qdrant_store import QdrantStore

    earlier = QdrantStore(url="http://qdrant.test:6333", collection=OLD_CASES)
    earlier.store(_case())
    if aliased:
        _alias(cases_client, OLD_CASES, NEW_CASES)

    store = QdrantStore(url="http://qdrant.test:6333", collection=NEW_CASES)
    assert store.count() == 1
    assert "exists" in store.readiness()
    assert NEW_CASES not in _names(cases_client)


def test_the_repair_counts_aliases_as_collections() -> None:
    client = _client()
    _old_hashes(client)
    _alias(client, OLD_HASHES, NEW_HASHES)
    assert memory_repair.aliases(client) == {NEW_HASHES}
    assert memory_repair._collections(client) == {OLD_HASHES, NEW_HASHES}


def test_the_repair_finds_the_marker_an_earlier_release_wrote(monkeypatch: Any) -> None:
    from qdrant_client.models import Distance, PointStruct, VectorParams

    assert memory_repair.REPAIR_COLLECTION == f"{PREVIOUS_NAME}_memory_repairs"
    assert memory_repair._previous(NEW_CASES) == OLD_CASES
    assert memory_repair._previous("custom") == "custom"
    monkeypatch.setattr(embeddings, "active_backend", lambda: "model")
    monkeypatch.setattr(embeddings, "model_backend_id", lambda: "model")
    client = _client()
    client.create_collection(
        memory_repair.REPAIR_COLLECTION, vectors_config=VectorParams(size=1, distance=Distance.DOT)
    )
    earlier = memory_repair._marker_id(OLD_CASES, OLD_HASHES)
    client.upsert(
        collection_name=memory_repair.REPAIR_COLLECTION,
        points=[PointStruct(id=earlier, vector=[1.0], payload={})],
    )
    relabelled: list[str] = []
    monkeypatch.setattr(
        memory_repair, "_relabel_cases", lambda _c, name: relabelled.append(name) or 0
    )

    assert memory_repair.repair_once(client, NEW_CASES, NEW_HASHES) == memory_repair.ALREADY_DONE
    assert relabelled == [], "the repair does not run again"
