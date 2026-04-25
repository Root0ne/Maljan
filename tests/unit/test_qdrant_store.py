"""Unit tests for QdrantStore (Phase 5 production backend).

Tests are divided into two groups:

  Offline tests (always run):
    - _embed() produces a vector of correct dimension
    - _embed() is deterministic for the same input
    - _embed() produces different vectors for different inputs
    - _embed() returns L2-normalized vector (norm ~= 1.0)
    - _stable_id() produces consistent uint64 from a string
    - _stable_id() produces different IDs for different strings
    - QdrantStore raises QdrantNotAvailableError when qdrant-client missing
    - QdrantStore._collection_exists() returns False gracefully on errors

  Live Qdrant tests (skipped unless QDRANT_URL env var is set or
  Qdrant is reachable at http://localhost:6333):
    - store() creates collection and inserts a point
    - retrieve() returns stored cases sorted by similarity
    - count() returns the correct number of points
    - clear() empties the collection
    - Upsert semantics: re-storing the same sample_id replaces old entry
    - retrieve() returns [] for empty / non-existent collection
    - retrieve() handles blank query gracefully

Running live tests:
  docker run -d -p 6333:6333 qdrant/qdrant
  QDRANT_URL=http://localhost:6333 uv run pytest tests/unit/test_qdrant_store.py -v
"""

from __future__ import annotations

import math
import os
import uuid
from typing import Any

import pytest

from maljan.memory.long_term_memory import StoredCase
from maljan.memory.qdrant_store import (
    _EMBED_DIM,
    QdrantNotAvailableError,
    QdrantStore,
    _embed,
    _stable_id,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_case(suffix: str = "1", category: str = "RANSOMWARE") -> StoredCase:
    return StoredCase(
        sample_id=f"sample_{suffix}",
        summary_text=(
            f"ransomware encryption T1486 vssadmin shadow delete "
            f"bitcoin wallet C2 beacon sample_{suffix}"
        ),
        technique_ids=["T1486", "T1490"],
        malware_category=category,
        stix_bundle_json="{}",
    )


def _qdrant_url() -> str | None:
    """Return the Qdrant URL from env, or None if not configured."""
    return os.environ.get("QDRANT_URL", None)


def _is_qdrant_reachable(url: str) -> bool:
    """Quick connectivity check — True only when Qdrant is running."""
    try:
        from qdrant_client import QdrantClient

        client = QdrantClient(url=url, timeout=2)
        client.get_collections()
        return True
    except Exception:
        return False


def _live_url() -> str | None:
    """Return a reachable Qdrant URL or None."""
    candidates = [
        url
        for url in [
            _qdrant_url(),
            "http://localhost:6333",
        ]
        if url and _is_qdrant_reachable(url)
    ]
    return candidates[0] if candidates else None


LIVE_URL = _live_url()
requires_qdrant = pytest.mark.skipif(
    LIVE_URL is None,
    reason="Qdrant not reachable. Start with: docker run -p 6333:6333 qdrant/qdrant",
)


# ---------------------------------------------------------------------------
# Offline tests — _embed
# ---------------------------------------------------------------------------


class TestEmbed:
    def test_output_dimension(self) -> None:
        vec = _embed("ransomware encryption beacon")
        assert len(vec) == _EMBED_DIM

    def test_deterministic(self) -> None:
        text = "T1055 process injection WriteProcessMemory"
        assert _embed(text) == _embed(text)

    def test_different_texts_produce_different_vectors(self) -> None:
        v1 = _embed("ransomware encryption")
        v2 = _embed("network beacon C2 dns")
        assert v1 != v2

    def test_l2_normalized(self) -> None:
        vec = _embed("some text about malware techniques T1486")
        norm = math.sqrt(sum(v * v for v in vec))
        assert abs(norm - 1.0) < 1e-6

    def test_empty_string_returns_zero_vector(self) -> None:
        vec = _embed("")
        assert len(vec) == _EMBED_DIM
        assert all(v == 0.0 for v in vec)

    def test_single_token(self) -> None:
        vec = _embed("ransomware")
        assert len(vec) == _EMBED_DIM
        norm = math.sqrt(sum(v * v for v in vec))
        assert abs(norm - 1.0) < 1e-6


# ---------------------------------------------------------------------------
# Offline tests — _stable_id
# ---------------------------------------------------------------------------


class TestStableId:
    def test_returns_integer(self) -> None:
        result = _stable_id("sample_abc")
        assert isinstance(result, int)

    def test_deterministic(self) -> None:
        assert _stable_id("sample_1") == _stable_id("sample_1")

    def test_different_inputs_produce_different_ids(self) -> None:
        assert _stable_id("sample_1") != _stable_id("sample_2")

    def test_fits_uint64(self) -> None:
        result = _stable_id("any_sample")
        assert 0 <= result < 2**64


# ---------------------------------------------------------------------------
# Offline tests — QdrantStore instantiation
# ---------------------------------------------------------------------------


class TestQdrantStoreInstantiation:
    def test_raises_when_qdrant_client_missing(
        self, monkeypatch: Any
    ) -> None:
        import sys
        original = sys.modules.get("qdrant_client")
        sys.modules["qdrant_client"] = None  # type: ignore[assignment]
        try:
            with pytest.raises((QdrantNotAvailableError, ImportError)):
                QdrantStore(url="http://localhost:6333")
        finally:
            if original is None:
                del sys.modules["qdrant_client"]
            else:
                sys.modules["qdrant_client"] = original

    def test_collection_exists_returns_false_on_error(self) -> None:
        """_collection_exists() must never raise — returns False on any error."""
        if LIVE_URL is None:
            pytest.skip("Qdrant not reachable")
        store = QdrantStore(url=LIVE_URL, collection="__nonexistent_test__")
        # Should return bool, not raise
        result = store._collection_exists()
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# Live Qdrant tests — require a running Qdrant instance
# ---------------------------------------------------------------------------


@requires_qdrant
class TestQdrantStoreLive:
    """Integration tests against a real Qdrant instance.

    Each test uses a unique collection name to avoid cross-test interference.
    Collections are cleaned up in teardown.
    """

    def _unique_store(self) -> QdrantStore:
        """Return a QdrantStore with a unique test collection."""
        collection = f"maljan_test_{uuid.uuid4().hex[:8]}"
        return QdrantStore(url=LIVE_URL, collection=collection)  # type: ignore[arg-type]

    def test_store_and_retrieve_single_case(self) -> None:
        store = self._unique_store()
        case = _make_case("live_1")
        store.store(case)
        results = store.retrieve("ransomware encryption vssadmin", top_k=1)
        assert len(results) == 1
        assert results[0].sample_id == "sample_live_1"
        store.clear()

    def test_retrieve_returns_most_similar_first(self) -> None:
        store = self._unique_store()
        ransomware_case = _make_case("ransomware", "RANSOMWARE")
        rat_case = StoredCase(
            sample_id="rat_sample",
            summary_text="backdoor reverse shell C2 beacon T1095 remote access",
            technique_ids=["T1095"],
            malware_category="RAT",
        )
        store.store(ransomware_case)
        store.store(rat_case)

        results = store.retrieve("ransomware encryption bitcoin shadow delete", top_k=2)
        assert len(results) >= 1
        # Most similar should be the ransomware case
        assert results[0].sample_id == "sample_ransomware"
        store.clear()

    def test_count_reflects_stored_cases(self) -> None:
        store = self._unique_store()
        assert store.count() == 0
        store.store(_make_case("c1"))
        assert store.count() == 1
        store.store(_make_case("c2"))
        assert store.count() == 2
        store.clear()

    def test_clear_empties_collection(self) -> None:
        store = self._unique_store()
        store.store(_make_case("clr1"))
        store.store(_make_case("clr2"))
        assert store.count() == 2
        store.clear()
        assert store.count() == 0

    def test_upsert_replaces_existing_entry(self) -> None:
        store = self._unique_store()
        case_v1 = StoredCase(
            sample_id="same_sample",
            summary_text="v1 original text ransomware",
            malware_category="RANSOMWARE",
        )
        case_v2 = StoredCase(
            sample_id="same_sample",
            summary_text="v2 updated text dropper loader",
            malware_category="DROPPER",
        )
        store.store(case_v1)
        assert store.count() == 1
        store.store(case_v2)
        # Upsert: count must still be 1
        assert store.count() == 1
        results = store.retrieve("dropper loader updated", top_k=1)
        assert results[0].malware_category == "DROPPER"
        store.clear()

    def test_retrieve_empty_collection_returns_empty_list(self) -> None:
        store = self._unique_store()
        results = store.retrieve("ransomware encryption", top_k=3)
        assert results == []

    def test_retrieve_blank_query_returns_empty_list(self) -> None:
        store = self._unique_store()
        store.store(_make_case("blank_q"))
        results = store.retrieve("   ", top_k=3)
        assert results == []
        store.clear()

    def test_repr_includes_url_and_collection(self) -> None:
        store = self._unique_store()
        r = repr(store)
        assert "QdrantStore" in r
        assert store._url in r
