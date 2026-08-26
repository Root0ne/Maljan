"""Unit tests for the family-fingerprint semantic index (family-feature RAG).

Uses the deterministic BoW fallback embedding (fastembed not required), so cosine
ranking is assertable with well-separated family vocabularies.
"""

from __future__ import annotations

import json

from maljan.memory.family_fingerprint_index import (
    FamilyFingerprintIndex,
    load_family_index,
    reset_cache,
)

_FAMILIES = [
    {
        "family_id": "AsyncRAT",
        "description": "capabilities: process_injection x3, network x2; "
        "suspicious imports: VirtualAllocEx, CreateRemoteThread, WriteProcessMemory",
        "malware_category": "rat",
        "sample_count": 12,
    },
    {
        "family_id": "GandCrab",
        "description": "capabilities: crypto x4, filesystem x3; "
        "suspicious imports: CryptEncrypt, CryptGenKey, FindFirstFileW; "
        "high-entropy sections: .text~7.8",
        "malware_category": "ransomware",
        "sample_count": 9,
    },
]


class TestBuildAndSearch:
    def test_build_counts(self) -> None:
        idx = FamilyFingerprintIndex.from_records(_FAMILIES)
        assert len(idx) == 2

    def test_search_ranks_matching_family_first(self) -> None:
        idx = FamilyFingerprintIndex.from_records(_FAMILIES)
        # A profile dominated by injection/network terms must surface AsyncRAT.
        q = (
            "capabilities: process_injection x2, network x1; "
            "suspicious imports: CreateRemoteThread, WriteProcessMemory"
        )
        res = idx.search(q, top_k=2, min_score=0.0)
        assert res[0].family == "AsyncRAT"
        assert res[0].score >= res[-1].score  # sorted descending

    def test_min_score_filters(self) -> None:
        idx = FamilyFingerprintIndex.from_records(_FAMILIES)
        # An unrelated query scores low against both -> high floor empties it.
        res = idx.search("benign calculator gui windowing toolkit", top_k=5, min_score=0.95)
        assert res == []

    def test_top_k_caps(self) -> None:
        idx = FamilyFingerprintIndex.from_records(_FAMILIES)
        res = idx.search("crypto filesystem ransomware encrypt", top_k=1, min_score=0.0)
        assert len(res) == 1

    def test_empty_query_or_index(self) -> None:
        assert FamilyFingerprintIndex().search("anything", top_k=3, min_score=0.0) == []
        idx = FamilyFingerprintIndex.from_records(_FAMILIES)
        assert idx.search("   ", top_k=3, min_score=0.0) == []

    def test_records_without_description_skipped(self) -> None:
        idx = FamilyFingerprintIndex.from_records(
            [{"family_id": "X", "description": ""}, _FAMILIES[0]]
        )
        assert len(idx) == 1


class TestLoadFamilyIndex:
    def setup_method(self) -> None:
        reset_cache()

    def test_missing_catalog_returns_none(self, tmp_path) -> None:
        assert load_family_index(str(tmp_path / "nope.json")) is None

    def test_empty_path_returns_none(self) -> None:
        assert load_family_index("") is None

    def test_malformed_catalog_returns_none(self, tmp_path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("{not valid json", encoding="utf-8")
        assert load_family_index(str(p)) is None

    def test_no_families_returns_none(self, tmp_path) -> None:
        p = tmp_path / "empty.json"
        p.write_text(json.dumps({"schema": "x", "families": []}), encoding="utf-8")
        assert load_family_index(str(p)) is None

    def test_valid_catalog_loads_and_searches(self, tmp_path) -> None:
        p = tmp_path / "fp.json"
        p.write_text(json.dumps({"families": _FAMILIES}), encoding="utf-8")
        idx = load_family_index(str(p))
        assert idx is not None and len(idx) == 2
        # Cached: a second load returns the same object.
        assert load_family_index(str(p)) is idx
