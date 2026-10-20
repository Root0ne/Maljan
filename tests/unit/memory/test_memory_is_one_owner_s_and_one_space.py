"""Long-term memory is read by its owner alone, in one embedding space, and filed only on Malware.

Three defects the memory had, and the rules that replace them:

- The memory was global: another owner's sample sha256, family and claim
  text reached a run's judge prompt, its tools and its report. A job with an
  owner now reads and writes that owner's entries alone; a job with none
  reads and writes the unscoped ones; an entry stored before owners were
  recorded is unscoped, so it keeps being read by unscoped jobs and never
  reaches an owned one.
- A bag-of-words fallback vector was stored beside the model's in the same
  collection and compared with it. Every point now carries its backend; a
  durable store refuses a fallback vector, a fallback query finds nothing,
  and a point stored before the backend was recorded is read as the model's
  and ranked on its text embedded again.
- Every function hash of a sample was filed under the judge's free-text
  family whatever the verdict. Only a Malware verdict's family is filed, the
  report node drops what the report does not publish, families are grouped
  under one spelling, and a hash filed under several families no longer
  raises any of them.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from maljan.analysis.function_hash_attribution import aggregate_matches
from maljan.core.exceptions import MemoryStoreError
from maljan.memory import embeddings
from maljan.memory.function_hash_store import FunctionHashStore, FunctionMatch
from maljan.memory.in_memory_store import InMemoryStore
from maljan.memory.long_term_memory import (
    NO_MEMORY,
    StoredCase,
    family_key,
    match_functions,
    memory_owner_of,
    recall,
)
from maljan.memory.qdrant_store import BACKEND_KEY, OWNER_KEY, QdrantStore, _stable_id

ALICE, BOB = "user-alice", "user-bob"
TEXT = "ransomware encrypts files deletes shadow copies T1486 T1490"


class _Vector:
    def __init__(self, values: list[float]) -> None:
        self._values = values

    def tolist(self) -> list[float]:
        return list(self._values)


class _Model:
    """A stand-in for the embedding model: deterministic, and labelled as the model."""

    def embed(self, texts: list[str], batch_size: int | None = None) -> Any:
        for text in texts:
            # Shifted, so a model vector and a bag-of-words vector of one text differ.
            bow = embeddings._bow_projection(text)
            yield _Vector(bow[1:] + bow[:1])


@pytest.fixture
def model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: _Model())


@pytest.fixture
def fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: False)


def _local_client() -> Any:
    from qdrant_client import QdrantClient

    return QdrantClient(location=":memory:")


@pytest.fixture
def qdrant(monkeypatch: pytest.MonkeyPatch) -> QdrantStore:
    import qdrant_client

    client = _local_client()
    monkeypatch.setattr(qdrant_client, "QdrantClient", lambda **_kw: client)
    return QdrantStore(url="http://qdrant.test:6333", collection="cases")


def _case(sample: str, owner: str | None = None, text: str = TEXT) -> StoredCase:
    return StoredCase(sample_id=sample, summary_text=text, technique_ids=["T1486"], owner=owner)


def _legacy_point(store: QdrantStore, sample: str, vector: list[float]) -> None:
    """A point as a store before this change wrote it: no owner, no backend."""
    from qdrant_client.models import PointStruct

    store._client.upsert(
        collection_name=store._collection,
        points=[
            PointStruct(
                id=_stable_id(sample),
                vector=vector,
                payload={"sample_id": sample, "summary_text": TEXT, "technique_ids": []},
            )
        ],
        wait=True,
    )


# ── one embedding space ───────────────────────────────────────────────────


def test_encode_names_what_made_each_vector(model: None) -> None:
    assert embeddings.encode_with_backend(TEXT)[1] == embeddings.model_backend_id()


def test_a_failed_model_call_is_named_the_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Broken:
        def embed(self, *_a: Any, **_k: Any) -> Any:
            raise RuntimeError("onnx")

    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: _Broken())
    vector, backend = embeddings.encode_with_backend(TEXT)
    assert backend == embeddings.FALLBACK_BACKEND
    assert vector == embeddings._bow_projection(TEXT)


def test_a_durable_store_refuses_a_fallback_vector(qdrant: QdrantStore, fallback: None) -> None:
    with pytest.raises(MemoryStoreError, match="one embedding space"):
        qdrant.store(_case("s1"))
    assert qdrant.count() == 0


def test_the_model_s_points_carry_their_backend_and_are_found(
    qdrant: QdrantStore, model: None
) -> None:
    qdrant.store(_case("s1"))
    (point,), _ = qdrant._client.scroll(collection_name="cases", with_payload=True)
    assert point.payload[BACKEND_KEY] == embeddings.model_backend_id()
    assert [c.sample_id for c in recall(qdrant, TEXT)] == ["s1"]


def test_a_fallback_query_finds_nothing(
    qdrant: QdrantStore, model: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    qdrant.store(_case("s1"))
    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: False)
    assert recall(qdrant, TEXT) == []


def test_a_point_from_before_the_backend_was_recorded_is_read_and_reranked(
    qdrant: QdrantStore, model: None
) -> None:
    from qdrant_client.models import Distance, VectorParams

    qdrant._ensure_collection(VectorParams, Distance)
    # Written by the fallback before backends were recorded: its stored vector
    # is not the model's, its text is.
    _legacy_point(qdrant, "old", embeddings._bow_projection(TEXT))
    qdrant.store(_case("new", text="a benign installer writes a shortcut"))
    found = recall(qdrant, TEXT, top_k=2)
    assert [c.sample_id for c in found] == ["old", "new"], "ranked on the model's reading"


def test_the_in_memory_store_never_compares_two_spaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryStore()
    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: False)
    store.store(_case("s1"))
    assert store._cases[0][2] == embeddings.FALLBACK_BACKEND
    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: _Model())
    assert [c.sample_id for c in recall(store, TEXT)] == ["s1"]
    # Embedded again by the model, and kept.
    assert store._cases[0][2] == embeddings.model_backend_id()
    assert math.isclose(
        sum(a * b for a, b in zip(store._cases[0][1], embeddings.encode(TEXT), strict=True)), 1.0
    )


# ── one owner's memory ────────────────────────────────────────────────────


@pytest.mark.parametrize("backend", ["qdrant", "memory"])
def test_an_owner_reads_only_its_own_cases(backend: str, qdrant: QdrantStore, model: None) -> None:
    store: Any = qdrant if backend == "qdrant" else InMemoryStore()
    store.store(_case("shared-sample", owner=ALICE))
    store.store(_case("bob-only", owner=BOB))
    store.store(_case("shared-sample", owner=BOB, text=TEXT + " bob's words"))

    alice = recall(store, TEXT, top_k=5, owner=ALICE)
    assert [(c.sample_id, c.owner) for c in alice] == [("shared-sample", ALICE)]
    bob = recall(store, TEXT, top_k=5, owner=BOB)
    assert sorted((c.sample_id, c.owner) for c in bob) == [
        ("bob-only", BOB),
        ("shared-sample", BOB),
    ]
    assert "bob's words" not in alice[0].summary_text, "one owner's write never replaces another's"
    assert recall(store, TEXT, top_k=5) == [], "an unscoped job reads no owner's case"


@pytest.mark.parametrize("backend", ["qdrant", "memory"])
def test_an_unscoped_job_keeps_reading_the_unscoped_memory(
    backend: str, qdrant: QdrantStore, model: None
) -> None:
    store: Any = qdrant if backend == "qdrant" else InMemoryStore()
    store.store(_case("s1"))
    assert [c.sample_id for c in recall(store, TEXT)] == ["s1"]
    assert recall(store, TEXT, owner=ALICE) == []


def test_a_case_from_before_owners_is_unscoped(qdrant: QdrantStore, model: None) -> None:
    from qdrant_client.models import Distance, VectorParams

    qdrant._ensure_collection(VectorParams, Distance)
    _legacy_point(qdrant, "old", embeddings.encode(TEXT))
    assert [c.sample_id for c in recall(qdrant, TEXT)] == ["old"]
    assert recall(qdrant, TEXT, owner=ALICE) == [], "fails closed for an owned job"
    # And an unscoped re-analysis replaces it in place, as before.
    qdrant.store(_case("old"))
    assert qdrant.count() == 1


def test_an_owner_s_point_carries_it(qdrant: QdrantStore, model: None) -> None:
    qdrant.store(_case("s1", owner=ALICE))
    (point,), _ = qdrant._client.scroll(collection_name="cases", with_payload=True)
    assert point.payload[OWNER_KEY] == ALICE


class _NoOwners:
    """A backend written before owners: no ``keeps_owners``, no ``owner`` argument."""

    def __init__(self) -> None:
        self.cases = [_case("s1")]

    def retrieve(self, query: str, top_k: int = 3) -> list[StoredCase]:
        return list(self.cases)

    def match(self, hashes: list[str], exclude_sample_id: str | None = None) -> list[Any]:
        return [FunctionMatch("h1", "FamilyA", "s1", "f1")]


def test_a_backend_that_keeps_no_owners_is_never_read_for_an_owner() -> None:
    old = _NoOwners()
    assert [c.sample_id for c in recall(old, TEXT, exclude_sample_id="other")] == ["s1"]
    assert recall(old, TEXT, owner=ALICE) == []
    assert len(match_functions(old, ["h1"])) == 1
    assert match_functions(old, ["h1"], owner=ALICE) == []


def test_the_job_s_owner_is_read_from_its_container_only_as_text() -> None:
    assert memory_owner_of(SimpleNamespace(memory_owner=f" {ALICE} ")) == ALICE
    assert memory_owner_of(SimpleNamespace(memory_owner="")) is None
    assert memory_owner_of(SimpleNamespace(memory_owner=None)) is None
    from unittest.mock import MagicMock

    assert memory_owner_of(None) is NO_MEMORY
    assert memory_owner_of(SimpleNamespace()) is NO_MEMORY
    assert memory_owner_of(MagicMock()) is NO_MEMORY


@pytest.mark.parametrize("backend", ["qdrant", "memory"])
def test_no_container_reads_nothing_not_the_unscoped_pool(
    backend: str, qdrant: QdrantStore, model: None
) -> None:
    store: Any = qdrant if backend == "qdrant" else InMemoryStore()
    store.store(_case("s1"))
    assert recall(store, TEXT, owner=memory_owner_of(None)) == []
    assert match_functions(_NoOwners(), ["h1"], owner=memory_owner_of(None)) == []


def _container(owner: str | None, store: Any) -> Any:
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    container = ServiceContainer(Settings(_env_file=None), mock=True, memory_owner=owner)
    container.get_memory_store = lambda: store  # type: ignore[method-assign]
    return container


def test_the_container_files_the_case_under_the_job_s_owner(model: None) -> None:
    store = InMemoryStore()
    container = _container(ALICE, store)
    container.pending_memory_case = _case("s1")
    assert container.remember_the_run() is True
    assert [c.owner for c, _v, _b in store._cases] == [ALICE]


def test_an_owned_job_writes_nothing_to_a_backend_without_owners() -> None:
    class _Unscoped:
        stored: list[Any] = []

        def store(self, case: Any) -> None:
            self.stored.append(case)

    store = _Unscoped()
    container = _container(ALICE, store)
    container.pending_memory_case = _case("s1")
    assert container.remember_the_run() is False
    assert store.stored == []


def test_function_hashes_are_one_owner_s(model: None) -> None:
    index = FunctionHashStore(
        url="http://qdrant.test:6333", collection="fh", client=_local_client()
    )
    index.upsert_sample("a-sample", "FamilyA", [("h1", "f1")], owner=ALICE)
    index.upsert_sample("b-sample", "FamilyB", [("h1", "f1")], owner=BOB)
    index.upsert_sample("u-sample", "FamilyU", [("h1", "f1")])

    def families(owner: str | None) -> list[str]:
        return [m.family for m in match_functions(index, ["h1"], owner=owner)]

    assert families(ALICE) == ["FamilyA"]
    assert families(BOB) == ["FamilyB"]
    assert families(None) == ["FamilyU"]


def test_the_knowledge_tool_matches_the_owner_s_samples_only() -> None:
    from maljan.tools import knowledge

    index = FunctionHashStore(
        url="http://qdrant.test:6333", collection="fh", client=_local_client()
    )
    index.upsert_sample("a-sample", "FamilyA", [("h1", "f1")], owner=ALICE)
    assert knowledge.function_matches(["h1"], index, owner=BOB) == {"matches": []}
    (row,) = knowledge.function_matches(["h1"], index, owner=ALICE)["matches"]
    assert row["sample_id"] == "a-sample"


# ── the function-hash corpus ──────────────────────────────────────────────


def test_one_family_written_three_ways_is_one_family() -> None:
    assert family_key("Agent Tesla") == family_key("agent-tesla") == family_key("AgentTesla")
    matches = [
        FunctionMatch("h1", "AgentTesla", "s1", "f1"),
        FunctionMatch("h2", "Agent Tesla", "s2", "f2"),
        FunctionMatch("h3", "agent-tesla", "s3", "f3"),
        FunctionMatch("h4", "AgentTesla", "s4", "f4"),
    ]
    (row,) = aggregate_matches(matches)
    assert row.family == "AgentTesla", "shown as most prior samples wrote it"
    assert (row.shared_functions, row.distinctive_functions) == (4, 4)
    assert row.sample_ids == ["s1", "s2", "s3", "s4"]


def test_a_hash_filed_under_several_families_raises_none_of_them() -> None:
    matches = [
        # A library routine every family links in.
        FunctionMatch("lib", "FamilyA", "a1", "memcpy_like"),
        FunctionMatch("lib", "FamilyB", "b1", "memcpy_like"),
        FunctionMatch("lib", "FamilyC", "c1", "memcpy_like"),
        FunctionMatch("a-own", "FamilyA", "a1", "decrypt_config"),
    ]
    rows = {r.family: r for r in aggregate_matches(matches)}
    assert rows["FamilyA"].distinctive_functions == 1
    assert rows["FamilyA"].confidence == 0.6
    assert rows["FamilyB"].distinctive_functions == 0
    assert rows["FamilyB"].confidence == 0.5, "the floor: nothing says it is this family"
    assert next(iter(rows)) == "FamilyA", "ranked by what only it shares"


def test_the_corpus_files_the_family_key_and_reads_points_without_one() -> None:
    from qdrant_client.models import PointStruct

    index = FunctionHashStore(
        url="http://qdrant.test:6333", collection="fh", client=_local_client()
    )
    assert index.upsert_sample("s1", "Agent Tesla", [("h1", "f1")]) == 1
    assert index.upsert_sample("s2", "  ", [("h1", "f1")]) == 0, "no family, nothing filed"
    index._client.upsert(
        collection_name="fh",
        points=[
            PointStruct(
                id=7,
                vector=[1.0],
                payload={"func_hash": "h1", "family": "AGENT-TESLA", "sample_id": "old"},
            )
        ],
        wait=True,
    )
    found = match_functions(index, ["h1"])
    assert {m.family_key for m in found} == {"agenttesla"}
    (row,) = aggregate_matches(found)
    assert row.sample_ids == ["old", "s1"]


class _Container:
    def __init__(self, family: str) -> None:
        self.released: list[str] = []
        self.pending_function_hashes: Any = ("store", "sha", family, [("h1", "f1")])

    def drop_function_hashes(self, reason: str) -> None:
        self.released.append(reason)
        self.pending_function_hashes = None


def _report(verdict: str, family: str | None, source: str | None = "judge") -> Any:
    return SimpleNamespace(
        verdict=verdict,
        attribution=SimpleNamespace(family=family, family_source=source),
    )


@pytest.mark.parametrize(
    ("report", "kept"),
    [
        (_report("Malware", "agent tesla"), True),
        (_report("Suspicious", "AgentTesla"), False),
        (_report("Malware", "Formbook"), False),
        (_report("Malware", None), False),
        (_report("Malware", "AgentTesla", source="sandbox"), False),
    ],
)
def test_the_report_node_files_only_the_published_family(report: Any, kept: bool) -> None:
    from maljan.pipeline.nodes import _file_only_the_published_family

    container = _Container("AgentTesla")
    _file_only_the_published_family(container, report)
    assert (container.pending_function_hashes is not None) is kept
    assert bool(container.released) is not kept


def test_a_completed_job_s_functions_are_matched_by_the_next_sample(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.memory import store_factory

    monkeypatch.setattr(store_factory, "release_function_hash_store", lambda _store: None)
    index = FunctionHashStore(
        url="http://qdrant.test:6333", collection="fh", client=_local_client()
    )
    container = _container(None, None)
    # As the static provider answers them: (name, hash).
    container.hold_function_hashes(index, "first", "FamilyA", [("decrypt_config", "h-dec")])
    assert container.remember_the_run() is True
    (found,) = match_functions(index, ["h-dec"], exclude_sample_id="second")
    assert (found.func_hash, found.func_name, found.family) == (
        "h-dec",
        "decrypt_config",
        "FamilyA",
    )


def test_the_container_lets_go_of_a_dropped_write(monkeypatch: pytest.MonkeyPatch) -> None:
    from maljan.memory import store_factory

    released: list[Any] = []
    monkeypatch.setattr(store_factory, "release_function_hash_store", released.append)
    container = _container(None, None)
    container.pending_function_hashes = ("the-store", "sha", "FamilyA", [])
    container.drop_function_hashes("not published")
    assert container.pending_function_hashes is None
    assert released == ["the-store"]
    assert container.remember_the_run() is False


def _formbook_and_a_stray_xloader() -> list[FunctionMatch]:
    """Three FormBook samples filing ten hashes, and one XLoader sample filing the same ten."""
    matches = [
        FunctionMatch(f"h{i}", "FormBook", f"fb{n}", f"f{i}") for i in range(10) for n in range(3)
    ]
    return matches + [FunctionMatch(f"h{i}", "XLoader", "xl0", f"f{i}") for i in range(10)]


def test_one_stray_sample_does_not_drop_the_family_seen_in_several() -> None:
    rows = {r.family: r for r in aggregate_matches(_formbook_and_a_stray_xloader())}
    assert (rows["FormBook"].distinctive_functions, rows["FormBook"].confidence) == (10, 0.95)
    assert (rows["XLoader"].distinctive_functions, rows["XLoader"].confidence) == (0, 0.5)


def test_junk_samples_on_other_hashes_do_not_flip_a_family() -> None:
    junk = [FunctionMatch(f"j{k}", "XLoader", f"junk{k}", "x") for k in range(4)]
    rows = {r.family: r for r in aggregate_matches(_formbook_and_a_stray_xloader() + junk)}
    assert rows["FormBook"].confidence == 0.95
    assert rows["XLoader"].distinctive_functions == 4, "its own junk hashes, nothing of FormBook's"


def test_a_library_routine_shared_one_to_one_counts_for_neither() -> None:
    matches = [FunctionMatch(f"a{i}", "A", f"a{i}", "f") for i in range(5)]
    matches += [FunctionMatch("L", "A", "a0", "memcpy"), FunctionMatch("L", "C", "c0", "memcpy")]
    rows = {r.family: r for r in aggregate_matches(matches)}
    assert (rows["A"].shared_functions, rows["A"].distinctive_functions) == (6, 5)
    assert rows["C"].distinctive_functions == 0


def test_two_single_sample_families_on_one_hash_hold_no_majority() -> None:
    matches = [FunctionMatch("h", "FamilyA", "a", "f"), FunctionMatch("h", "FamilyB", "b", "f")]
    assert [r.distinctive_functions for r in aggregate_matches(matches)] == [0, 0]


@pytest.mark.parametrize("placeholder", ["Unknown", "none", "N/A", " "])
def test_a_placeholder_family_is_never_filed(placeholder: str) -> None:
    index = FunctionHashStore(
        url="http://qdrant.test:6333", collection="fh", client=_local_client()
    )
    assert index.upsert_sample("s1", placeholder, [("h1", "f1")]) == 0
    assert match_functions(index, ["h1"]) == []


# ── the one-time repair ───────────────────────────────────────────────────


def _repair_fixture(qdrant: QdrantStore) -> Any:
    from qdrant_client.models import Distance, PointStruct, VectorParams

    from maljan.memory.function_hash_store import _point_id

    qdrant._ensure_collection(VectorParams, Distance)
    query = embeddings.encode(TEXT)
    # The relevant old case holds a vector far from the query; old noise near it.
    _legacy_point(qdrant, "relevant", [-x for x in query])
    for i in range(3):
        qdrant._client.upsert(
            collection_name="cases",
            points=[
                PointStruct(
                    id=_stable_id(f"noise{i}"),
                    vector=[x + 0.001 * i for x in query],
                    payload={"sample_id": f"noise{i}", "summary_text": "keylogger clipboard"},
                )
            ],
            wait=True,
        )
    qdrant._function_hash_collection = "fh"
    index = qdrant.function_hash_store()
    # Filed through the gate before the repair runs: kept as it is.
    index.upsert_sample("gated", "FamilyG", [("h-gated", "g_main")])
    # As the old writer filed them: ungated, and the name where the hash belongs.
    old = [("s1", "FamilyA", "decrypt_config", "h-dec"), ("s2", "Unknown", "main", "h-main")]
    qdrant._client.upsert(
        collection_name="fh",
        points=[
            PointStruct(
                id=_point_id(sid, name),
                vector=[1.0],
                payload={"func_hash": name, "family": fam, "sample_id": sid, "func_name": h},
            )
            for sid, fam, name, h in old
        ],
        wait=True,
    )
    return index


def test_the_repair_relabels_old_vectors_and_deletes_ungated_hashes_once(
    qdrant: QdrantStore, model: None
) -> None:
    from qdrant_client.models import FieldCondition, Filter, MatchValue

    from maljan.memory.memory_repair import ALREADY_DONE, repair_memory

    index = _repair_fixture(qdrant)
    gated = Filter(must=[FieldCondition(key="sample_id", match=MatchValue(value="gated"))])
    (gated_before,), _ = qdrant._client.scroll(
        collection_name="fh", scroll_filter=gated, with_payload=True
    )
    assert recall(qdrant, TEXT, top_k=1)[0].sample_id != "relevant", "the defect, before"
    said = repair_memory(qdrant)
    assert (
        said
        == "repaired: 4 case vector(s) labelled, 2 function hash(es) filed before the gate deleted"
    )
    points, _ = qdrant._client.scroll(collection_name="cases", with_payload=True, limit=50)
    assert all(p.payload[BACKEND_KEY] == embeddings.model_backend_id() for p in points)
    assert recall(qdrant, TEXT, top_k=1)[0].sample_id == "relevant"
    assert match_functions(index, ["h-dec", "h-main", "decrypt_config", "main"]) == []
    (kept,) = match_functions(index, ["h-gated"])
    assert (kept.family, kept.func_name) == ("FamilyG", "g_main")
    fh, _ = qdrant._client.scroll(collection_name="fh", with_payload=True, limit=50)
    assert [(p.id, p.payload) for p in fh] == [(gated_before.id, gated_before.payload)]
    assert repair_memory(qdrant) == ALREADY_DONE


def test_the_relabel_never_overwrites_a_restored_case_nor_revives_a_purged_one(
    qdrant: QdrantStore, model: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.memory.memory_repair import repair_memory

    _repair_fixture(qdrant)
    real = embeddings.encode_batch_with_backend

    def _meanwhile(texts: list[str]) -> Any:
        # While the page is embedded: one case stored again, one purged.
        qdrant.store(_case("relevant", text="restored with its own text"))
        from qdrant_client.models import PointIdsList

        qdrant._client.delete(
            collection_name="cases",
            points_selector=PointIdsList(points=[_stable_id("noise0")]),
            wait=True,
        )
        return real(texts)

    monkeypatch.setattr(embeddings, "encode_batch_with_backend", _meanwhile)
    repair_memory(qdrant)
    monkeypatch.setattr(embeddings, "encode_batch_with_backend", real)
    points, _ = qdrant._client.scroll(
        collection_name="cases", with_payload=True, with_vectors=True, limit=50
    )
    by_sample = {p.payload["sample_id"]: p for p in points}
    assert "noise0" not in by_sample, "a purged case is not brought back"
    restored = by_sample["relevant"]
    assert restored.payload["summary_text"] == "restored with its own text"
    expected = embeddings.encode("restored with its own text")
    assert max(abs(a - b) for a, b in zip(restored.vector, expected, strict=True)) < 1e-5


def test_without_the_model_the_repair_waits_and_leaves_no_marker(
    qdrant: QdrantStore, model: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.memory.memory_repair import REPAIR_COLLECTION, SKIPPED_NO_MODEL, repair_memory

    _repair_fixture(qdrant)
    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: False)
    assert repair_memory(qdrant) == SKIPPED_NO_MODEL
    names = {c.name for c in qdrant._client.get_collections().collections}
    assert REPAIR_COLLECTION not in names
    assert repair_memory(InMemoryStore()).startswith("nothing to repair")


# ── adopting the ownerless memory leaves one point per sample ─────────────


def _points(store: QdrantStore) -> list[Any]:
    return list(store._client.scroll(store._collection, limit=100, with_payload=True)[0])


def test_adoption_leaves_one_point_per_sample_and_a_later_store_overwrites_it(
    model: None, qdrant: QdrantStore
) -> None:
    qdrant.store(_case("both"))
    _legacy_point(qdrant, "only-ownerless", embeddings.encode_with_backend(TEXT)[0])
    qdrant.store(_case("both", owner=ALICE, text=TEXT + " newer"))

    counts = qdrant.adopt_unowned(ALICE)
    assert (counts["cases"], counts["dropped_cases"]) == (1, 1)
    points = _points(qdrant)
    assert sorted(p.payload["sample_id"] for p in points) == ["both", "only-ownerless"]
    assert all(p.payload[OWNER_KEY] == ALICE for p in points)
    # The owner's newer copy won over the ownerless one.
    assert (
        next(p for p in points if p.payload["sample_id"] == "both")
        .payload["summary_text"]
        .endswith("newer")
    )
    assert [c.sample_id for c in qdrant.retrieve(TEXT, top_k=10, owner=ALICE)].count("both") == 1
    assert qdrant.retrieve(TEXT, top_k=10, owner=None) == []

    # Idempotent, and a re-store replaces the adopted point in place.
    assert qdrant.adopt_unowned(ALICE)["cases"] == 0
    qdrant.store(_case("only-ownerless", owner=ALICE, text="rewritten"))
    assert len(_points(qdrant)) == 2


def _fh(client: Any) -> list[Any]:
    return list(client.scroll("fh", limit=100, with_payload=True)[0])


def _hash_index() -> tuple[Any, FunctionHashStore]:
    client = _local_client()
    return client, FunctionHashStore(url="http://qdrant.test:6333", collection="fh", client=client)


def test_a_sample_whose_owner_holds_hashes_keeps_none_of_the_ownerless_ones(model: None) -> None:
    from maljan.memory.memory_repair import adopt_unowned

    client, index = _hash_index()
    index.upsert_sample("s1", "FamilyU", [("h1", "f1"), ("h2", "f2")])
    index.upsert_sample("s1", "FamilyA", [("h1", "f1")], owner=ALICE)
    index.upsert_sample("s2", "FamilyU", [("h9", "f9")])
    out = adopt_unowned(client, "cases", "fh", ALICE)
    # s1 is kept from the owner's side alone (h2 is dropped too); s2 is adopted.
    assert (out["function_hashes"], out["dropped_function_hashes"]) == (1, 2)
    points = _fh(client)
    assert {(p.payload["sample_id"], p.payload["func_hash"]) for p in points} == {
        ("s1", "h1"),
        ("s2", "h9"),
    }
    assert all(p.payload["owner"] == ALICE for p in points)
    assert {p.payload["family"] for p in points if p.payload["sample_id"] == "s1"} == {"FamilyA"}
    again = adopt_unowned(client, "cases", "fh", ALICE)
    assert again["function_hashes"] == again["dropped_function_hashes"] == 0
    index.upsert_sample("s2", "FamilyB", [("h9", "f9")], owner=ALICE)
    assert len(_fh(client)) == 2


def _case_at(sample: str, when: datetime, owner: str | None = None, text: str = TEXT) -> StoredCase:
    return StoredCase(
        sample_id=sample, summary_text=text, technique_ids=[], owner=owner, created_at=when
    )


def test_the_newer_case_wins_and_a_newer_ownerless_one_replaces_the_owners_hashes(
    model: None, qdrant: QdrantStore
) -> None:
    from maljan.memory.memory_repair import adopt_unowned

    old, new = datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 6, 1, tzinfo=UTC)
    qdrant.store(_case_at("ownerless-newer", new))
    qdrant.store(_case_at("ownerless-newer", old, ALICE, "owners old text"))
    qdrant.store(_case_at("owner-newer", old))
    qdrant.store(_case_at("owner-newer", new, ALICE, "owners new text"))
    qdrant.store(_case_at("tie", old))
    qdrant.store(_case_at("tie", old, ALICE, "owners tie text"))
    # An owner's point with no created_at counts as older than any dated one.
    qdrant.store(_case_at("dateless-owner", old))
    qdrant.store(_case_at("dateless-owner", old, ALICE, "owners dateless text"))
    qdrant._client.delete_payload(
        qdrant._collection,
        keys=["created_at"],
        points=[_stable_id(f"{ALICE}\x1fdateless-owner")],
    )
    client = qdrant._client
    index = FunctionHashStore(url="http://qdrant.test:6333", collection="fh", client=client)
    index.upsert_sample("ownerless-newer", "FamilyU", [("h1", "f1")])
    index.upsert_sample("ownerless-newer", "FamilyA", [("hX", "fX")], owner=ALICE)

    out = adopt_unowned(client, qdrant._collection, "fh", ALICE)
    texts = {p.payload["sample_id"]: p.payload["summary_text"] for p in _points(qdrant)}
    assert texts["ownerless-newer"] == TEXT
    assert texts["owner-newer"] == "owners new text"
    assert texts["tie"] == "owners tie text"
    assert texts["dateless-owner"] == TEXT
    assert len(_points(qdrant)) == 4
    assert (out["cases"], out["dropped_cases"]) == (2, 2)
    # The replaced case's sample takes the ownerless hashes and loses the owner's stale ones.
    assert {p.payload["func_hash"] for p in _fh(client)} == {"h1"}


def test_the_owner_point_is_read_again_before_the_write(model: None, qdrant: QdrantStore) -> None:
    from maljan.memory import memory_repair

    old, new = datetime(2026, 1, 1, tzinfo=UTC), datetime(2026, 6, 1, tzinfo=UTC)
    qdrant.store(_case_at("raced", old))
    real = memory_repair._ownerless_pages

    def pages(client: Any, collection: str) -> Any:
        for page in real(client, collection):
            # The owner files a newer copy after the page was read, before it is written.
            qdrant.store(_case_at("raced", new, ALICE, "owners newer text"))
            yield page

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(memory_repair, "_ownerless_pages", pages)
        out = qdrant.adopt_unowned(ALICE)
    (point,) = _points(qdrant)
    assert point.payload["summary_text"] == "owners newer text"
    assert (out["cases"], out["dropped_cases"]) == (0, 1)


def test_a_point_with_no_sample_id_is_skipped_and_counted(model: None, qdrant: QdrantStore) -> None:
    from qdrant_client.models import PointStruct

    qdrant.store(_case("keyed"))
    qdrant._client.upsert(
        qdrant._collection,
        points=[
            PointStruct(
                id=7,
                vector=embeddings.encode_with_backend(TEXT)[0],
                payload={"summary_text": TEXT},
            )
        ],
        wait=True,
    )
    out = qdrant.adopt_unowned(ALICE)
    assert (out["cases"], out["skipped_cases"]) == (1, 1)
    assert [p.id for p in _points(qdrant) if OWNER_KEY not in p.payload] == [7]
    assert qdrant.adopt_unowned(ALICE)["skipped_cases"] == 1


def test_a_failure_part_way_carries_the_partial_counts(model: None, qdrant: QdrantStore) -> None:
    from maljan.memory.memory_repair import AdoptionFailed

    qdrant.store(_case("one"))
    real = qdrant._client.upsert

    def down(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("down")

    qdrant._client.upsert = down
    with pytest.raises(AdoptionFailed) as exc:
        qdrant.adopt_unowned(ALICE)
    assert isinstance(exc.value.__cause__, RuntimeError)
    assert exc.value.counts["cases"] == 0
    qdrant._client.upsert = real
    assert qdrant.adopt_unowned(ALICE)["cases"] == 1


def test_a_rerun_after_a_failure_mid_sample_adopts_every_remaining_hash(model: None) -> None:
    from maljan.memory import memory_repair
    from maljan.memory.memory_repair import AdoptionFailed, adopt_unowned

    client, index = _hash_index()
    index.upsert_sample("s1", "FamilyU", [("h1", "f1"), ("h2", "f2"), ("h3", "f3")])
    real = client.upsert
    calls = {"n": 0}

    def flaky(*args: Any, **kwargs: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("down")
        return real(*args, **kwargs)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(memory_repair, "_PAGE", 1)
        client.upsert = flaky
        with pytest.raises(AdoptionFailed) as exc:
            adopt_unowned(client, "cases", "fh", ALICE)
        assert exc.value.counts["function_hashes"] == 1
        client.upsert = real
        out = adopt_unowned(client, "cases", "fh", ALICE)
    assert out["dropped_function_hashes"] == 0
    points = _fh(client)
    assert sorted(p.payload["func_hash"] for p in points) == ["h1", "h2", "h3"]
    assert all(p.payload["owner"] == ALICE for p in points)
    # The owner's own later store writes no marker, so it counts as theirs from then on.
    index.upsert_sample("s1", "FamilyB", [("h1", "f1")], owner=ALICE)
    assert "adopted" not in next(p for p in _fh(client) if p.payload["func_hash"] == "h1").payload
