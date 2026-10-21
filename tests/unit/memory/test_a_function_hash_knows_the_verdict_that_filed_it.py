"""Each filed function hash names the verdicts that filed it, so an edit can take one back."""

from __future__ import annotations

from typing import Any

from maljan.memory.function_hash_store import FunctionHashStore
from maljan.memory.long_term_memory import match_functions


def _index() -> FunctionHashStore:
    from qdrant_client import QdrantClient

    return FunctionHashStore(
        url="http://qdrant.test:6333", collection="fh", client=QdrantClient(location=":memory:")
    )


def _families(index: FunctionHashStore, owner: str | None) -> list[str]:
    return [m.family for m in match_functions(index, ["h1", "h2"], owner=owner)]


def _filers(index: FunctionHashStore) -> dict[str, list[str]]:
    points, _ = index._client.scroll(collection_name="fh", limit=100, with_payload=True)
    return {
        f"{p.payload['sample_id']}:{p.payload['func_hash']}": p.payload.get("filers")
        for p in points
    }


def test_unfiling_a_verdict_removes_only_its_hashes() -> None:
    index = _index()
    index.upsert_sample("s1", "FamilyA", [("h1", "f1")], owner="alice", filed_by="job-1")
    index.upsert_sample("s2", "FamilyB", [("h2", "f2")], owner="alice", filed_by="job-2")
    index.upsert_sample("s3", "FamilyC", [("h1", "f1")], owner="bob", filed_by="job-1")
    index.upsert_sample("s4", "FamilyD", [("h1", "f1")], owner="alice")  # filed before filers

    assert index.unfile("job-1", owner="alice") == 1
    assert sorted(_families(index, "alice")) == ["FamilyB", "FamilyD"]
    assert _families(index, "bob") == ["FamilyC"], "another owner's points are never touched"
    assert index.unfile("job-1", owner="alice") == 0
    assert index.unfile("", owner="alice") == 0


def test_two_jobs_filing_the_same_sample_keep_one_point_until_both_are_taken_back() -> None:
    index = _index()
    index.upsert_sample("s1", "FamilyA", [("h1", "f1")], owner="alice", filed_by="job-1")
    index.upsert_sample("s1", "FamilyA", [("h1", "f1")], owner="alice", filed_by="job-2")
    index.upsert_sample("s1", "FamilyA", [("h1", "f1")], owner="alice", filed_by="job-2")
    assert list(_filers(index).values()) == [["job-1", "job-2"]]

    assert index.unfile("job-1", owner="alice") == 1
    assert _families(index, "alice") == ["FamilyA"], "job-2 still vouches for it"
    assert list(_filers(index).values()) == [["job-2"]]

    assert index.unfile("job-2", owner="alice") == 1
    assert _families(index, "alice") == []
    assert _filers(index) == {}


def test_the_filers_field_is_indexed() -> None:
    calls: list[Any] = []
    index = _index()
    real = index._client.create_payload_index

    def spy(**kwargs: Any) -> Any:
        calls.append(kwargs["field_name"])
        return real(**kwargs)

    index._client.create_payload_index = spy  # type: ignore[method-assign]
    index.upsert_sample("s1", "FamilyA", [("h1", "f1")], filed_by="job-1")
    assert calls == ["func_hash", "filers"]
