"""Unit tests for the family-feature RAG orchestration (profile / hint / dicts)."""

from __future__ import annotations

from maljan.analysis.family_feature_rag import (
    build_family_fingerprint_text,
    build_rag_hint,
    build_sample_profile_text,
    retrieve_candidates,
    to_report_dicts,
)
from maljan.memory.family_fingerprint_index import FamilyCandidate
from maljan.reporting.models import ImportRow, PESection, StaticAnalysis


def _static(**kw) -> StaticAnalysis:
    return StaticAnalysis(**kw)


class TestBuildSampleProfileText:
    def test_capabilities_and_imports(self) -> None:
        static = _static(
            imports=[
                ImportRow(
                    dll="k.dll",
                    function="VirtualAllocEx",
                    is_suspicious=True,
                    category="process_injection",
                ),
                ImportRow(
                    dll="k.dll",
                    function="CreateRemoteThread",
                    is_suspicious=True,
                    category="process_injection",
                ),
                ImportRow(dll="ws.dll", function="connect", is_suspicious=True, category="network"),
                ImportRow(dll="k.dll", function="lstrlen", is_suspicious=False),
            ],
            packer_hint="UPX",
        )
        text = build_sample_profile_text(static)
        assert "capabilities:" in text
        assert "process_injection x2" in text
        assert "network x1" in text
        assert "VirtualAllocEx" in text
        assert "packer: UPX" in text
        assert "lstrlen" not in text  # non-suspicious imports excluded

    def test_high_entropy_sections(self) -> None:
        static = _static(
            sections=[
                PESection(name=".text", virtual_address="0x1000", entropy=7.8, is_suspicious=True),
                PESection(name=".data", virtual_address="0x2000", entropy=3.1),
            ]
        )
        text = build_sample_profile_text(static)
        assert "high-entropy sections:" in text
        assert ".text~7.8" in text
        assert ".data" not in text  # low-entropy section omitted

    def test_empty_static_is_empty_text(self) -> None:
        assert build_sample_profile_text(_static()) == ""

    def test_suspicious_imports_deduped_and_capped(self) -> None:
        imports = [
            ImportRow(dll="k", function=f"Susp{i % 3}", is_suspicious=True, category="execution")
            for i in range(20)
        ]
        text = build_sample_profile_text(_static(imports=imports))
        # Only 3 distinct names despite 20 rows.
        assert text.count("Susp") == 3


class TestBuildFamilyFingerprintText:
    def test_aggregates_common_phrases(self) -> None:
        profiles = [
            "capabilities: process_injection x2, network x1; suspicious imports: VirtualAllocEx",
            "capabilities: process_injection x3; suspicious imports: VirtualAllocEx, connect",
            "capabilities: process_injection x1; suspicious imports: VirtualAllocEx",
        ]
        fp = build_family_fingerprint_text(profiles)
        # VirtualAllocEx appears in all 3 -> kept; rendered text non-empty.
        assert "VirtualAllocEx" in fp

    def test_empty(self) -> None:
        assert build_family_fingerprint_text([]) == ""


class TestBuildRagHint:
    def test_empty_no_hint(self) -> None:
        assert build_rag_hint([]) == ""

    def test_renders_candidates_as_evidence(self) -> None:
        hint = build_rag_hint(
            [
                FamilyCandidate("AsyncRAT", 0.81, "rat", 12),
                FamilyCandidate("njRAT", 0.62, "rat", 8),
            ]
        )
        assert "CANDIDATE FAMILIES" in hint
        assert "AsyncRAT" in hint and "0.81" in hint
        assert "NOT a verdict" in hint  # framed as evidence, LLM decides


class TestToReportDicts:
    def test_row_shape(self) -> None:
        rows = to_report_dicts([FamilyCandidate("AsyncRAT", 0.812345, "rat", 12)])
        assert rows == [
            {
                "family": "AsyncRAT",
                "similarity": 0.812,
                "malware_category": "rat",
                "sample_count": 12,
                "match_method": "family-feature-rag",
                "source": "maljan-family-fingerprints",
            }
        ]

    def test_empty(self) -> None:
        assert to_report_dicts([]) == []


class TestRetrieveCandidates:
    def test_none_index_failsafe(self) -> None:
        assert retrieve_candidates("some profile", None, top_k=5, min_score=0.3) == []

    def test_empty_profile_failsafe(self) -> None:
        class _Idx:
            def search(self, *_a, **_k):  # pragma: no cover - must not be called
                raise AssertionError("should not search on empty profile")

        assert retrieve_candidates("   ", _Idx(), top_k=5, min_score=0.3) == []

    def test_search_error_failsafe(self) -> None:
        class _Boom:
            def search(self, *_a, **_k):
                raise RuntimeError("boom")

        assert retrieve_candidates("p", _Boom(), top_k=5, min_score=0.3) == []

    def test_delegates_to_index(self) -> None:
        sentinel = [FamilyCandidate("X", 0.5, "", 1)]

        class _Idx:
            def search(self, profile, *, top_k, min_score):
                assert profile == "p" and top_k == 2 and min_score == 0.4
                return sentinel

        assert retrieve_candidates("p", _Idx(), top_k=2, min_score=0.4) is sentinel
