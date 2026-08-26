"""Unit tests for the ATT&CK case-prior RAG orchestration (§4 U2)."""

from __future__ import annotations

from maljan.analysis.attck_case_rag import (
    build_attck_case_hint,
    retrieve_techniques,
    to_report_dicts,
)
from maljan.memory.attck_case_index import TechniqueCandidate


class TestBuildAttckCaseHint:
    def test_empty_no_hint(self) -> None:
        assert build_attck_case_hint([]) == ""

    def test_renders_candidates_as_evidence(self) -> None:
        hint = build_attck_case_hint(
            [
                TechniqueCandidate("T1055", 3, 0.81),
                TechniqueCandidate("T1071", 2, 0.62),
            ]
        )
        assert "CANDIDATE ATT&CK TECHNIQUES" in hint
        assert "T1055" in hint and "0.81" in hint
        assert "3 similar case" in hint  # support surfaced
        assert "NOT a verdict" in hint  # framed as evidence, LLM decides


class TestToReportDicts:
    def test_row_shape(self) -> None:
        rows = to_report_dicts([TechniqueCandidate("T1055", 3, 0.812345)])
        assert rows == [
            {
                "technique_id": "T1055",
                "support": 3,
                "similarity": 0.812,
                "match_method": "attck-case-rag",
                "source": "maljan-attck-case-corpus",
            }
        ]

    def test_empty(self) -> None:
        assert to_report_dicts([]) == []


class TestRetrieveTechniques:
    def test_none_index_failsafe(self) -> None:
        assert retrieve_techniques("q", None, top_k=5, min_score=0.3, max_techniques=8) == []

    def test_empty_query_failsafe(self) -> None:
        class _Idx:
            def recommend_techniques(self, *_a, **_k):  # pragma: no cover - must not run
                raise AssertionError("should not retrieve on empty query")

        assert retrieve_techniques("  ", _Idx(), top_k=5, min_score=0.3, max_techniques=8) == []

    def test_retrieval_error_failsafe(self) -> None:
        class _Boom:
            def recommend_techniques(self, *_a, **_k):
                raise RuntimeError("boom")

        assert retrieve_techniques("q", _Boom(), top_k=5, min_score=0.3, max_techniques=8) == []

    def test_delegates_to_index(self) -> None:
        sentinel = [TechniqueCandidate("T1055", 2, 0.5)]

        class _Idx:
            def recommend_techniques(self, query, *, top_k, min_score, max_techniques):
                assert query == "q" and top_k == 2 and min_score == 0.4 and max_techniques == 3
                return sentinel

        assert (
            retrieve_techniques("q", _Idx(), top_k=2, min_score=0.4, max_techniques=3) is sentinel
        )
