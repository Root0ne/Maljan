"""A tool answer holding signature-rule matches is read as rule matches, declared or not (T-508).

A stored run's operator tool, declared with no kind, answered with the
matches of its own rule set (two rules, three rows, nested in a report), and
nothing read them as rule matches: only the declared rule scan beside it (0
matches of 31 rules) was. A tool declaring the ``signature_rules`` kind is
read where it says; a tool declaring no kind is read by its answer's shape
alone, whatever its name or its server's: a match list whose rows each name
their rule, or a list or map of rules under a key naming matched rules. A
list of rules with no word of matching over it, an empty list nothing says is
a rule scan, a row naming no rule, and a tool declaring another kind are never
read as matches; "0 matches" stays a fact where the answer says it is a rule
scan.

Every value is synthetic.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from tests.linear_cost import assert_scales

from maljan.core.rule_matches import rule_matches_of, shaped_rule_matches
from maljan.schemas.evidence import LedgerEntry

_DECLARED = {
    "v": 1,
    "kind": "signature_rules",
    "rows": "/matches/*",
    "values": {"rule": "/rule"},
    "display_name": "Rule scan",
}
# What a stored run's undeclared operator tool carried: no kind.
_NO_KIND = {"v": 1, "kind": "", "discloses_sample": True}
# The shape of that tool's answer: its matches nested in a report, one map
# per matched row, the rule's name holding what it matched.
_NESTED_REPORT: dict[str, Any] = {
    "ok": True,
    "stdout": "rule matching ...",
    "reports": {
        "windows_report.json": {
            "categories": {"Process": ["CreateMutexW"]},
            "matched_rules": [
                {"rule_alpha": [{"offset": "0xcd72", "matched_pattern": "CreateMutex"}]},
                {"rule_alpha": [{"offset": "0xcd72", "matched_pattern": "CreateMutex"}]},
                {"Poly_Constant": [{"offset": "0x5f0c", "matched_pattern": "b' \\x83'"}]},
            ],
            "mitre_attack": {},
        }
    },
}


def _entry(structured: Any = None, facts: Any = None, **kw: Any) -> LedgerEntry:
    fields: dict[str, Any] = {
        "id": "ev_0042",
        "tool": "inspect_file",
        "server": "operator_server",
        "structured": structured,
        "facts": _NO_KIND if facts is None else facts,
    }
    fields.update(kw)
    return LedgerEntry(**fields)


class TestADeclaredRuleTool:
    def test_its_rows_are_read_where_it_declares(self) -> None:
        answer = {"matches": [{"rule": "a"}, {"rule": "b"}], "rule_count": 31}
        held = rule_matches_of(_entry(answer, _DECLARED, tool="yara_like", server="pipeline"))
        assert held is not None and held.declared
        assert held.rules == ("a", "b")
        assert held.rule_count == 31
        assert held.source == "Rule scan"

    def test_no_match_of_its_rules_stays_a_fact(self) -> None:
        held = rule_matches_of(_entry({"matches": [], "rule_count": 31}, _DECLARED))
        assert held is not None
        assert held.rules == () and held.rule_count == 31

    def test_rows_declared_elsewhere_are_read_there(self) -> None:
        facts = {**_DECLARED, "rows": "/result/hits/*", "values": {"rule": "/id"}}
        answer = {"result": {"hits": [{"id": "r1"}, {"id": "r2"}]}}
        held = rule_matches_of(_entry(answer, facts))
        assert held is not None and held.rules == ("r1", "r2")

    def test_a_tool_declared_as_another_kind_is_never_read_here(self) -> None:
        facts = {"v": 1, "kind": "strings", "rows": "/strings/*"}
        assert rule_matches_of(_entry(_NESTED_REPORT, facts)) is None


class TestAnUndeclaredTool:
    def test_the_stored_run_s_nested_report_is_read(self) -> None:
        held = rule_matches_of(_entry(_NESTED_REPORT))
        assert held is not None and not held.declared
        assert held.rules == ("rule_alpha", "rule_alpha", "Poly_Constant")
        assert held.rule_count is None
        assert (held.entry_id, held.tool, held.server) == (
            "ev_0042",
            "inspect_file",
            "operator_server",
        )

    @pytest.mark.parametrize(
        ("answer", "rules"),
        [
            ({"matches": [{"rule": "a", "strings": []}, {"rule": "b"}]}, ["a", "b"]),
            ({"results": {"hits": [{"rule_name": "a", "namespace": "default"}]}}, ["a"]),
            ({"ruleMatches": [{"ruleName": "a"}]}, ["a"]),
            ({"matched_rules": {"a": [{"offset": 1}], "b": []}}, ["a", "b"]),
            ({"matched_rules": ["a", "ns:b"]}, ["a", "ns:b"]),
            ({"files": [{"path": "x", "matches": [{"rule": "a"}]}]}, ["a"]),
            ({"matched_rules": []}, []),
            ({"matches": [], "rule_count": 12}, []),
        ],
    )
    def test_a_rule_match_shape_is_read(self, answer: Any, rules: list[str]) -> None:
        assert shaped_rule_matches(answer) is not None
        held = rule_matches_of(_entry(answer))
        assert held is not None and list(held.rules) == rules

    def test_the_rules_run_are_read_beside_the_match_list(self) -> None:
        held = rule_matches_of(_entry({"matches": [{"rule": "a"}], "total_rules": 7}))
        assert held is not None and held.rule_count == 7

    @pytest.mark.parametrize(
        "answer",
        [
            # A listing of the rules a tool holds is no match.
            {"rules": [{"rule": "a"}, {"rule": "b"}]},
            {"available_rules": ["a", "b"]},
            {"loaded_rules": {"a": [], "b": []}},
            # An empty list nothing says is a rule scan.
            {"matches": []},
            {"hits": []},
            # A match list whose rows name no rule: a string search.
            {"matches": [{"string": "abc", "offset": 4}]},
            {"matches": ["abc", "def"]},
            # One row naming no rule leaves the list unread.
            {"matches": [{"rule": "a"}, {"string": "abc"}]},
            # A key naming matches, not rules, holding names alone.
            {"hits": {"a": [], "b": []}},
            # A capability list: no word of matching over it.
            {"capabilities": [{"rule": "a", "namespace": "x", "match_count": 2}]},
            # A rule-named key holding no rule names.
            {"matched_rules": [{"count": 3}]},
            {"matched_rules": {"count": 3}},
            {"matched_rules": ["not a rule name!"]},
            # A count of matches is no list of them.
            {"match_count": 3, "rule_count": 31},
        ],
    )
    def test_no_other_shape_is_read_as_a_match(self, answer: Any) -> None:
        assert shaped_rule_matches(answer) is None
        assert rule_matches_of(_entry(answer)) is None

    def test_the_reading_is_by_shape_never_by_name(self) -> None:
        named = [("scan_rules", "rules_server"), ("anything", "elsewhere")]
        for tool, server in named:
            held = rule_matches_of(_entry(_NESTED_REPORT, tool=tool, server=server))
            assert held is not None
            assert held.rules == ("rule_alpha", "rule_alpha", "Poly_Constant")
            assert rule_matches_of(_entry({"rules": ["a"]}, tool=tool, server=server)) is None

    def test_an_entry_with_no_facts_and_no_source_is_read_by_its_shape(self) -> None:
        entry = LedgerEntry(id="ev_0001", tool="never_shipped", structured=_NESTED_REPORT)
        held = rule_matches_of(entry)
        assert held is not None and len(held.rules) == 3

    def test_an_answer_stored_as_text_is_read(self) -> None:
        entry = _entry(None, output=json.dumps(_NESTED_REPORT))
        held = rule_matches_of(entry)
        assert held is not None and len(held.rules) == 3

    def test_a_failed_call_or_a_repeat_holds_no_match(self) -> None:
        assert rule_matches_of(_entry(_NESTED_REPORT, ok=False)) is None
        assert rule_matches_of(_entry(_NESTED_REPORT, repeated_of="ev_0001")) is None

    def test_an_answer_that_is_not_json_holds_no_match(self) -> None:
        assert rule_matches_of(_entry(None, output="matched_rules: rule_alpha")) is None


def test_the_reading_is_linear_in_the_answer() -> None:
    def build(size: int) -> dict[str, Any]:
        rows = [{"rule": f"r{i}", "strings": [{"offset": i}]} for i in range(size)]
        noise = {f"k{i}": {"v": [i, {"w": i}]} for i in range(size)}
        return {"noise": noise, "result": {"matches": rows}, "rule_count": size}

    found = shaped_rule_matches(build(400))
    assert found is not None and len(found[0]) == 400
    assert_scales(build, 400, shaped_rule_matches)


def test_a_deep_or_huge_answer_is_read_within_its_bound() -> None:
    deep: Any = {"matches": [{"rule": "deep"}]}
    for _ in range(40):
        deep = {"inner": deep}
    assert shaped_rule_matches(deep) is None
    wide = {"rows": [{"x": i} for i in range(50_000)], "matched_rules": ["a"]}
    assert shaped_rule_matches(wide) == (["a"], None)
