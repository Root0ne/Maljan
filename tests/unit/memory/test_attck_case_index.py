"""Unit tests for the ATT&CK case-prior semantic index (§4 U2).

Uses the deterministic BoW fallback embedding (fastembed not required), so cosine
ranking and technique aggregation are assertable with well-separated case vocabularies.
"""

from __future__ import annotations

import json

from maljan.memory.attck_case_index import (
    AttckCaseIndex,
    load_attck_case_index,
    reset_cache,
)

_CASES = [
    {
        "sample_id": "aaa",
        "summary_text": "process injection CreateRemoteThread WriteProcessMemory "
        "VirtualAllocEx beacon network connection remote server",
        "technique_ids": ["T1055", "T1071"],
        "malware_category": "rat",
    },
    {
        "sample_id": "bbb",
        "summary_text": "injection inject into explorer.exe CreateRemoteThread "
        "process hollowing network beacon",
        "technique_ids": ["T1055", "T1071", "T1095"],
        "malware_category": "rat",
    },
    {
        "sample_id": "ccc",
        "summary_text": "file encryption ransomware CryptEncrypt CryptGenKey "
        "scramble disk ransom note shadow copy delete",
        "technique_ids": ["T1486", "T1490"],
        "malware_category": "ransomware",
    },
]


class TestBuildAndSearch:
    def test_build_counts(self) -> None:
        idx = AttckCaseIndex.from_records(_CASES)
        assert len(idx) == 3

    def test_search_ranks_matching_case_first(self) -> None:
        idx = AttckCaseIndex.from_records(_CASES)
        q = "process injection CreateRemoteThread WriteProcessMemory beacon network"
        res = idx.search(q, top_k=3, min_score=0.0)
        assert res[0].sample_id in {"aaa", "bbb"}  # injection cases, not ransomware
        assert res[0].score >= res[-1].score  # sorted descending

    def test_min_score_filters(self) -> None:
        idx = AttckCaseIndex.from_records(_CASES)
        res = idx.search("benign calculator gui windowing toolkit", top_k=5, min_score=0.95)
        assert res == []

    def test_empty_query_or_index(self) -> None:
        assert AttckCaseIndex().search("anything", top_k=3, min_score=0.0) == []
        idx = AttckCaseIndex.from_records(_CASES)
        assert idx.search("   ", top_k=3, min_score=0.0) == []

    def test_records_without_summary_skipped(self) -> None:
        idx = AttckCaseIndex.from_records([{"sample_id": "x", "summary_text": ""}, _CASES[0]])
        assert len(idx) == 1


class TestRecommendTechniques:
    def test_aggregates_support_across_neighbours(self) -> None:
        idx = AttckCaseIndex.from_records(_CASES)
        q = "process injection CreateRemoteThread WriteProcessMemory beacon network"
        cands = idx.recommend_techniques(q, top_k=3, min_score=0.0, max_techniques=8)
        ids = [c.technique_id for c in cands]
        # T1055 appears in both injection cases -> highest support, ranked first.
        assert ids[0] == "T1055"
        top = next(c for c in cands if c.technique_id == "T1055")
        assert top.support >= 2
        # Candidates sorted by (support, score) descending.
        supports = [c.support for c in cands]
        assert supports == sorted(supports, reverse=True)

    def test_max_techniques_caps(self) -> None:
        idx = AttckCaseIndex.from_records(_CASES)
        cands = idx.recommend_techniques(
            "injection network beacon encryption ransomware",
            top_k=3,
            min_score=0.0,
            max_techniques=2,
        )
        assert len(cands) <= 2

    def test_high_floor_yields_no_candidates(self) -> None:
        idx = AttckCaseIndex.from_records(_CASES)
        cands = idx.recommend_techniques(
            "totally unrelated text", top_k=3, min_score=0.99, max_techniques=8
        )
        assert cands == []

    def test_dedup_within_case(self) -> None:
        # A single neighbour listing a technique twice still contributes support 1.
        idx = AttckCaseIndex.from_records(
            [{"sample_id": "d", "summary_text": "alpha beta gamma", "technique_ids": ["T1", "T1"]}]
        )
        cands = idx.recommend_techniques(
            "alpha beta gamma", top_k=1, min_score=0.0, max_techniques=8
        )
        assert len(cands) == 1
        assert cands[0].support == 1


class TestLoadAttckCaseIndex:
    def setup_method(self) -> None:
        reset_cache()

    def test_missing_corpus_returns_none(self, tmp_path) -> None:
        assert load_attck_case_index(str(tmp_path / "nope.json")) is None

    def test_empty_path_returns_none(self) -> None:
        assert load_attck_case_index("") is None

    def test_malformed_corpus_returns_none(self, tmp_path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("{not valid json", encoding="utf-8")
        assert load_attck_case_index(str(p)) is None

    def test_no_cases_returns_none(self, tmp_path) -> None:
        p = tmp_path / "empty.json"
        p.write_text(json.dumps({"schema": "x", "cases": []}), encoding="utf-8")
        assert load_attck_case_index(str(p)) is None

    def test_valid_corpus_loads_and_caches(self, tmp_path) -> None:
        p = tmp_path / "corpus.json"
        p.write_text(json.dumps({"cases": _CASES}), encoding="utf-8")
        idx = load_attck_case_index(str(p))
        assert idx is not None and len(idx) == 3
        assert load_attck_case_index(str(p)) is idx  # cached
