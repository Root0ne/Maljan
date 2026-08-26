"""Unit tests for the deterministic function-hash attribution helpers.

Covers the pure pieces (payload extraction, family aggregation, hint render,
report-row projection, confidence ladder). The networked
``fetch_bulk_function_hashes`` is exercised via integration, not here.
"""

from __future__ import annotations

import json

from maljan.analysis.function_hash_attribution import (
    FamilyHashAttribution,
    _extract_functions,
    aggregate_matches,
    build_attribution_hint,
    to_report_dicts,
)
from maljan.memory.function_hash_store import FunctionMatch


def _m(func_hash: str, family: str, sample_id: str, func_name: str = "") -> FunctionMatch:
    return FunctionMatch(
        func_hash=func_hash, family=family, sample_id=sample_id, func_name=func_name
    )


class TestExtractFunctions:
    def test_top_level_functions_list(self) -> None:
        data = {"program": "x", "functions": [{"name": "a", "hash": "h1"}]}
        out = _extract_functions(data)
        assert out == [{"name": "a", "hash": "h1"}]

    def test_raw_list(self) -> None:
        data = [{"hash": "h1"}, {"hash": "h2"}]
        assert _extract_functions(data) == data

    def test_nested_under_result(self) -> None:
        data = {"result": {"functions": [{"hash": "h1"}]}}
        assert _extract_functions(data) == [{"hash": "h1"}]

    def test_json_string_input(self) -> None:
        data = json.dumps({"functions": [{"hash": "h1"}]})
        assert _extract_functions(data) == [{"hash": "h1"}]

    def test_error_payload_yields_empty(self) -> None:
        assert _extract_functions({"error": "boom"}) == []

    def test_garbage_yields_empty(self) -> None:
        assert _extract_functions("not json") == []
        assert _extract_functions(None) == []
        assert _extract_functions(42) == []

    def test_non_dict_entries_filtered(self) -> None:
        data = {"functions": [{"hash": "h1"}, "junk", 7]}
        assert _extract_functions(data) == [{"hash": "h1"}]


class TestAggregate:
    def test_empty(self) -> None:
        assert aggregate_matches([]) == []

    def test_distinct_hash_count_per_family(self) -> None:
        # Same hash stored by two different prior samples must count ONCE.
        matches = [
            _m("h1", "Emotet", "sampleA", "decrypt"),
            _m("h1", "Emotet", "sampleB", "decrypt"),
            _m("h2", "Emotet", "sampleA", "c2_loop"),
        ]
        [res] = aggregate_matches(matches)
        assert res.family == "Emotet"
        assert res.shared_functions == 2  # h1, h2 — not 3
        assert res.sample_ids == ["sampleA", "sampleB"]
        assert "decrypt" in res.example_functions

    def test_ranking_by_shared_functions(self) -> None:
        matches = [
            _m("h1", "Qbot", "s1"),
            _m("h2", "Emotet", "s2"),
            _m("h3", "Emotet", "s2"),
            _m("h4", "Emotet", "s2"),
        ]
        results = aggregate_matches(matches)
        assert [r.family for r in results] == ["Emotet", "Qbot"]
        assert results[0].shared_functions == 3

    def test_max_families_cap(self) -> None:
        matches = [_m(f"h{i}", f"fam{i}", "s") for i in range(10)]
        results = aggregate_matches(matches, max_families=3)
        assert len(results) == 3

    def test_blank_family_defaults_unknown(self) -> None:
        [res] = aggregate_matches([_m("h1", "", "s1")])
        assert res.family == "UNKNOWN"

    def test_match_missing_hash_ignored(self) -> None:
        assert aggregate_matches([_m("", "Emotet", "s1")]) == []


class TestConfidence:
    def test_single_function_is_weak(self) -> None:
        assert FamilyHashAttribution("X", shared_functions=1).confidence == 0.6

    def test_grows_monotonically(self) -> None:
        c1 = FamilyHashAttribution("X", shared_functions=1).confidence
        c3 = FamilyHashAttribution("X", shared_functions=3).confidence
        assert c3 > c1
        assert c3 == 0.8

    def test_capped_below_one(self) -> None:
        assert FamilyHashAttribution("X", shared_functions=50).confidence == 0.95


class TestBuildHint:
    def test_empty_results_is_blank(self) -> None:
        assert build_attribution_hint([]) == ""

    def test_hint_mentions_family_and_count(self) -> None:
        results = aggregate_matches(
            [_m("h1", "Emotet", "s1", "decrypt"), _m("h2", "Emotet", "s1", "c2")]
        )
        hint = build_attribution_hint(results)
        assert "ATTRIBUTION PRIOR" in hint
        assert "Emotet" in hint
        assert "2 shared function" in hint
        # Must steer the model to corroborate, not to assert on the hash alone.
        assert "CONFIRM" in hint or "confirm" in hint


class TestToReportDicts:
    def test_row_shape(self) -> None:
        results = aggregate_matches([_m("h1", "Emotet", "s1", "decrypt")])
        [row] = to_report_dicts(results)
        assert row["family"] == "Emotet"
        assert row["match_method"] == "function-hash"
        assert row["source"] == "ghidra-mcp"
        assert row["shared_functions"] == 1
        assert row["sample_ids"] == ["s1"]
        assert 0.0 < row["confidence"] <= 0.95
