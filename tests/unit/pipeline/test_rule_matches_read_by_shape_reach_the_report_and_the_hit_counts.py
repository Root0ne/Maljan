"""The rule matches an undeclared tool's answer holds reach the report and the hit counts (T-509).

The generic rule-match reader (``core.rule_matches``, T-508) read an
undeclared tool's matches for the debate's fact alone: the report's rule
tables and the pipeline's rule-hit counts read declared kinds only, so a
stored run's operator tool whose answer named the rules that matched the
sample was in neither. Now a tool that declares no kind and answers with a
match list is drawn in a table of its own, every row of which names its tool
and says it was read by the answer's shape, and the distinct rules it names
count toward ``rule_hits`` and under ``rule_matches_by_shape``. A shape names
no kind, so an event rule's, an indicator list's or a technique catalogue's
rows read this way never count as signature hits (``yara_hits``,
``hits["signature_rules"]``), and never join a declared kind's table. A run
whose tools are all declared is drawn and counted as before.

Every value is synthetic.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest

from maljan.core.rule_matches import BY_SHAPE_KEY
from maljan.pipeline.conditions import (
    SIGNATURE_RULES,
    StageContext,
    TriageFacts,
    evaluate,
    rule_match_hits,
)
from maljan.reporting.ledger_report import (
    SHAPE_READ_LABEL,
    SHAPE_RULE_COLUMNS,
    SHAPE_RULE_SECTION,
    build_sections,
    section_key_of_kind,
)
from maljan.schemas.evidence import LedgerEntry, build_entry

_NO_KIND = {"v": 1, "kind": ""}
# An undeclared tool's answer: its matches nested in a report, one map per
# matched string, the rule's name holding what it matched (two rules, three rows).
_NESTED_REPORT: dict[str, Any] = {
    "reports": {
        "file_report.json": {
            "matched_rules": [
                {"rule_alpha": [{"offset": "0x10"}]},
                {"rule_alpha": [{"offset": "0x20"}]},
                {"rule_beta": [{"offset": "0x30"}]},
            ]
        }
    }
}
# Rows an event-rule, an indicator or a technique tool could answer with:
# each names its rule under a key naming matches, so the shape reads them.
_EVENT_LIKE = {"matches": [{"rule": "Suspicious Shell Spawn", "level": "high"}]}
_INDICATOR_LIKE = {"matched_rules": ["ioc_domain_list"]}
_TECHNIQUE_LIKE = {"rule_hits": [{"rule_name": "attack.t1059"}]}


def _entry(entry_id: str, structured: Any, *, facts: Any = None, **kw: Any) -> LedgerEntry:
    fields: dict[str, Any] = {
        "id": entry_id,
        "tool": "inspect_file",
        "server": "operator_server",
        "structured": structured,
        "facts": _NO_KIND if facts is None else facts,
    }
    fields.update(kw)
    return LedgerEntry(**fields)


@pytest.fixture
def shipped() -> Iterator[None]:
    """The real ``Settings()`` and the shipped server map, installed for the test."""
    from maljan.core import declared_reading
    from maljan.core.config import Settings, get_settings, install_settings

    previous = get_settings()
    install_settings(Settings())
    declared_reading.forget()
    try:
        yield
    finally:
        install_settings(previous)
        declared_reading.forget()


def _pack_rule_scan(entry_id: str, rules: list[str]) -> LedgerEntry:
    """The triage pack's declared rule scan, recorded as the pack records it."""
    return build_entry(
        entry_id=entry_id,
        seq=int(entry_id[-4:]),
        agent="pipeline",
        tool="yara_scan",
        args={"path": "/samples/x.bin"},
        server="pipeline",
        output=json.dumps({"matches": [{"rule": r} for r in rules], "rule_count": 31}),
        source="pack",
        stage="triage_pack",
    )


def _undeclared(entry_id: str, answer: Any, server: str) -> LedgerEntry:
    """A tool no declaration names, on a shipped server an agent is bound to."""
    return build_entry(
        entry_id=entry_id,
        seq=int(entry_id[-4:]),
        agent="static",
        tool="inspect_file_never_declared",
        args={"path": "/samples/x.bin"},
        server=server,
        output=json.dumps(answer),
        source=f"mcp:{server}",
    )


def _static_server() -> str:
    from maljan.agents.composition import servers_bound_to
    from maljan.core.config import Settings

    return sorted(servers_bound_to(Settings(), "static"))[0]


class TestOverTheShippedSettings:
    def test_the_declared_scan_counts_as_before_and_the_shaped_answer_beside_it(
        self, shipped: None
    ) -> None:
        server = _static_server()
        declared = _pack_rule_scan("ev_0001", ["sig_a", "sig_b"])
        shaped = _undeclared("ev_0002", _NESTED_REPORT, server)
        assert declared.facts.get("kind") == SIGNATURE_RULES
        assert not shaped.facts.get("kind")

        alone, alone_total = rule_match_hits([declared])
        counted, total = rule_match_hits([declared, shaped])
        # The declared scan's counts are its own, unchanged by the shaped answer.
        assert counted[SIGNATURE_RULES] == alone[SIGNATURE_RULES] == 2
        assert counted.get("yara") == alone.get("yara") == 2
        # Two distinct rules in three rows, under the shape key and the server's.
        assert counted[BY_SHAPE_KEY] == 2
        assert counted[server] == 2
        assert total == alone_total + 2

    def test_the_report_draws_both_tables_and_labels_every_shaped_row(self, shipped: None) -> None:
        server = _static_server()
        declared = _pack_rule_scan("ev_0001", ["sig_a", "sig_b"])
        shaped = _undeclared("ev_0002", _NESTED_REPORT, server)
        alone = {s.key: s for s in build_sections([declared])}
        both = {s.key: s for s in build_sections([declared, shaped])}

        signature = section_key_of_kind(SIGNATURE_RULES)
        assert both[signature].model_dump() == alone[signature].model_dump()
        assert SHAPE_RULE_SECTION not in alone

        table = both[SHAPE_RULE_SECTION]
        assert table.columns == SHAPE_RULE_COLUMNS
        tool = f"inspect_file_never_declared ({server})"
        assert table.rows == [
            ["rule_alpha", tool, SHAPE_READ_LABEL],
            ["rule_beta", tool, SHAPE_READ_LABEL],
        ]
        assert table.evidence_ids == ["ev_0002"]
        # The answer is still drawn in its own generic block, as it was.
        assert any("ev_0002" in s.evidence_ids for k, s in both.items() if k.startswith("tool_"))

    def test_the_markdown_report_names_the_shaped_rules_among_the_rule_hits(
        self, shipped: None
    ) -> None:
        from maljan.reporting.renderers.markdown import _RULE_SECTIONS, MarkdownRenderer
        from tests.unit.reporting.test_builder import _build

        assert SHAPE_RULE_SECTION in _RULE_SECTIONS
        server = _static_server()
        report = _build(
            ledger=[
                _pack_rule_scan("ev_0001", ["sig_a"]),
                _undeclared("ev_0002", _NESTED_REPORT, server),
            ]
        )
        text = MarkdownRenderer().render(report)
        assert "Rule matches read by their answer's shape" in text
        assert "rule_alpha" in text and SHAPE_READ_LABEL in text


class TestAShapeNamesNoKind:
    @pytest.mark.parametrize("answer", [_EVENT_LIKE, _INDICATOR_LIKE, _TECHNIQUE_LIKE])
    def test_its_rows_never_count_as_signature_hits(self, answer: dict[str, Any]) -> None:
        counted, total = rule_match_hits([_entry("ev_0003", answer)])
        assert total == 1 and counted[BY_SHAPE_KEY] == 1
        assert SIGNATURE_RULES not in counted
        facts = TriageFacts().with_hits(counted, total)
        assert facts.yara_hits == 0
        context = StageContext(triage=facts)
        assert evaluate('triage.hits["signature_rules"] > 0', context) is False
        assert evaluate(f'triage.hits["{BY_SHAPE_KEY}"] > 0', context) is True
        assert evaluate("triage.rule_hits > 0", context) is True

    @pytest.mark.parametrize("answer", [_EVENT_LIKE, _INDICATOR_LIKE, _TECHNIQUE_LIKE])
    def test_its_rows_never_join_a_declared_kind_s_table(self, answer: dict[str, Any]) -> None:
        sections = {s.key: s for s in build_sections([_entry("ev_0003", answer)])}
        assert section_key_of_kind(SIGNATURE_RULES) not in sections
        assert section_key_of_kind("event_rules") not in sections
        assert all(row[2] == SHAPE_READ_LABEL for row in sections[SHAPE_RULE_SECTION].rows)


class TestWhatIsNotRead:
    def test_a_tool_declaring_another_kind_is_neither_drawn_nor_counted(self) -> None:
        entry = _entry("ev_0004", _EVENT_LIKE, facts={"v": 1, "kind": "strings"})
        assert rule_match_hits([entry]) == ({}, 0)
        assert SHAPE_RULE_SECTION not in {s.key for s in build_sections([entry])}

    def test_a_failed_call_and_a_repeat_are_not_counted(self) -> None:
        failed = _entry("ev_0005", _NESTED_REPORT, ok=False)
        repeat = _entry("ev_0006", _NESTED_REPORT, repeated_of="ev_0002")
        assert rule_match_hits([failed, repeat]) == ({}, 0)

    def test_an_empty_match_list_draws_no_row_and_counts_nothing(self) -> None:
        entry = _entry("ev_0007", {"matched_rules": [], "rule_count": 12})
        assert rule_match_hits([entry]) == ({}, 0)
        assert SHAPE_RULE_SECTION not in {s.key for s in build_sections([entry])}

    def test_a_list_of_rules_with_no_word_of_matching_is_no_match(self) -> None:
        entry = _entry("ev_0008", {"rules": ["rule_alpha", "rule_beta"]})
        assert rule_match_hits([entry]) == ({}, 0)
        assert SHAPE_RULE_SECTION not in {s.key for s in build_sections([entry])}


class TestTheStateLedgerReadsAlike:
    def test_a_stored_row_counts_as_its_entry_does(self) -> None:
        entry = _entry("ev_0009", _NESTED_REPORT)
        assert rule_match_hits([entry.model_dump()]) == rule_match_hits([entry])

    def test_a_forged_rule_name_is_cleaned_in_the_table(self) -> None:
        forged = "evil\n| injected | row"
        sections = {
            s.key: s for s in build_sections([_entry("ev_0010", {"matches": [{"rule": forged}]})])
        }
        (row,) = sections[SHAPE_RULE_SECTION].rows
        assert "\n" not in row[0] and "|" not in row[0]

    def test_an_output_nested_past_the_decoder_is_read_as_no_answer(self) -> None:
        deep = "[" * 50_000 + "]" * 50_000
        entry = _entry("ev_0011", None, output=deep)
        assert rule_match_hits([entry]) == ({}, 0)
        assert SHAPE_RULE_SECTION not in {s.key for s in build_sections([entry])}
