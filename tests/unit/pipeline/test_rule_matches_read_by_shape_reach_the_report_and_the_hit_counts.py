"""The rule matches an undeclared tool's answer holds reach the report and one hit count (T-509).

The generic rule-match reader (``core.rule_matches``, T-508) read an
undeclared tool's matches for the debate's fact alone: the report's rule
tables and the pipeline's rule-hit counts read declared kinds only, so a
stored run's operator tool whose answer named the rules that matched the
sample was in neither. Now a tool that declares no kind and answers with a
match list is drawn in an evidence table of its own, titled as read by the
answer's shape, each row naming its tool, and the distinct rules it names
are counted under ``hits["rule_matches_by_shape"]`` alone.

A shape names no kind, and reads an indicator list or a technique catalogue
as it reads rules (a format rule fires on most files of its format), so
these rows count toward nothing else: not ``rule_hits``, not a kind's key
(``yara_hits``, ``hits["signature_rules"]``), not the answering server's
key. Nor are they a detection: the table is in no declared kind's table and
in none of the report's rule-hit lists (Static's Rule hits, §10.1 and the
analyst report's §8.2). A run whose tools are all declared is drawn and
counted as before.

Every test runs over the real ``Settings()`` and the shipped server map.
Every value is synthetic.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Any

import pytest

from malspark.core.rule_matches import BY_SHAPE_KEY
from malspark.pipeline.conditions import (
    SIGNATURE_RULES,
    StageContext,
    TriageFacts,
    evaluate,
    rule_match_hits,
)
from malspark.reporting.ledger_report import (
    SHAPE_RULE_COLUMNS,
    SHAPE_RULE_SECTION,
    SHAPE_RULE_TITLE,
    build_sections,
    section_key_of_kind,
)
from malspark.schemas.evidence import LedgerEntry, build_entry

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


@pytest.fixture(autouse=True)
def shipped() -> Iterator[None]:
    """The real ``Settings()`` and the shipped server map, installed for every test."""
    from malspark.core import declared_reading
    from malspark.core.config import Settings, get_settings, install_settings

    previous = get_settings()
    install_settings(Settings())
    declared_reading.forget()
    try:
        yield
    finally:
        install_settings(previous)
        declared_reading.forget()


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
    from malspark.agents.composition import servers_bound_to
    from malspark.core.config import Settings

    return sorted(servers_bound_to(Settings(), "static"))[0]


def _both() -> list[LedgerEntry]:
    return [
        _pack_rule_scan("ev_0001", ["sig_a", "sig_b"]),
        _undeclared("ev_0002", _NESTED_REPORT, _static_server()),
    ]


class TestTheCounts:
    def test_the_declared_scan_counts_as_before_and_the_shaped_answer_under_its_key_alone(
        self,
    ) -> None:
        declared, shaped = _both()
        assert declared.facts.get("kind") == SIGNATURE_RULES
        assert not shaped.facts.get("kind")

        alone = rule_match_hits([declared])
        counted, total = rule_match_hits([declared, shaped])
        # Two distinct rules in three rows, under the shape key and nowhere else.
        assert counted == {**alone[0], BY_SHAPE_KEY: 2}
        assert total == alone[1] == 2
        assert _static_server() not in counted

    @pytest.mark.parametrize("answer", [_EVENT_LIKE, _INDICATOR_LIKE, _TECHNIQUE_LIKE])
    def test_a_shaped_row_never_counts_as_a_rule_hit_or_a_signature_hit(
        self, answer: dict[str, Any]
    ) -> None:
        counted, total = rule_match_hits([_entry("ev_0003", answer)])
        assert counted == {BY_SHAPE_KEY: 1} and total == 0
        facts = TriageFacts().with_hits(counted, total)
        assert facts.yara_hits == 0 and facts.rule_hits == 0
        context = StageContext(triage=facts)
        assert evaluate("triage.rule_hits > 0", context) is False
        assert evaluate('triage.hits["signature_rules"] > 0', context) is False
        assert evaluate(f'triage.hits["{BY_SHAPE_KEY}"] > 0', context) is True

    def test_a_stored_row_counts_as_its_entry_does(self) -> None:
        entry = _entry("ev_0009", _NESTED_REPORT)
        assert rule_match_hits([entry.model_dump()]) == rule_match_hits([entry])


class TestTheReport:
    def test_the_declared_table_is_drawn_as_before_and_the_shaped_rows_in_their_own(
        self,
    ) -> None:
        declared, shaped = _both()
        alone = {s.key: s for s in build_sections([declared])}
        both = {s.key: s for s in build_sections([declared, shaped])}

        signature = section_key_of_kind(SIGNATURE_RULES)
        assert both[signature].model_dump() == alone[signature].model_dump()
        assert SHAPE_RULE_SECTION not in alone

        table = both[SHAPE_RULE_SECTION]
        assert table.title == SHAPE_RULE_TITLE
        assert "no declaration" in table.title
        assert table.columns == SHAPE_RULE_COLUMNS == ["Rule", "Tool"]
        tool = f"inspect_file_never_declared ({_static_server()})"
        assert table.rows == [["rule_alpha", tool], ["rule_beta", tool]]
        assert table.evidence_ids == ["ev_0002"]
        # The answer is still drawn in its own generic block, as it was.
        assert any("ev_0002" in s.evidence_ids for k, s in both.items() if k.startswith("tool_"))

    @pytest.mark.parametrize("answer", [_EVENT_LIKE, _INDICATOR_LIKE, _TECHNIQUE_LIKE])
    def test_a_shaped_row_never_joins_a_declared_kind_s_table(self, answer: dict[str, Any]) -> None:
        sections = {s.key: s for s in build_sections([_entry("ev_0003", answer)])}
        assert section_key_of_kind(SIGNATURE_RULES) not in sections
        assert section_key_of_kind("event_rules") not in sections
        assert len(sections[SHAPE_RULE_SECTION].rows) == 1

    def test_a_forged_rule_name_is_cleaned_in_the_table(self) -> None:
        forged = "evil\n| injected | row"
        sections = {
            s.key: s for s in build_sections([_entry("ev_0010", {"matches": [{"rule": forged}]})])
        }
        (row,) = sections[SHAPE_RULE_SECTION].rows
        assert "\n" not in row[0] and "|" not in row[0]


def _block(text: str, start: str, end: str) -> str:
    """The text from the line holding ``start`` up to the next line matching ``end``."""
    at = text.index(start)
    found = re.compile(end, re.M).search(text, at + len(start))
    return text[at : found.start() if found else len(text)]


class TestNoRuleHitListNamesTheShapedRows:
    """The table is evidence: no list of the rules that matched the sample names its rows."""

    def _report(self) -> Any:
        from malspark.reporting.models import StaticAnalysis
        from tests.unit.reporting.test_builder import _build

        report = _build(ledger=_both())
        assert SHAPE_RULE_SECTION in {s.key for s in report.sections}
        # A static block, so Static's Rule hits is drawn.
        return report.model_copy(update={"static": report.static or StaticAnalysis()})

    def test_not_in_static_rule_hits_nor_in_10_1(self) -> None:
        from malspark.reporting.renderers.markdown import _RULE_SECTIONS, MarkdownRenderer

        assert SHAPE_RULE_SECTION not in _RULE_SECTIONS
        text = MarkdownRenderer().render(self._report())
        hits = _block(text, "### Rule hits", r"^#{2,3} ")
        matched = _block(text, "Rules that matched this sample", r"^#{2,4} ")
        for block in (hits, matched):
            assert "sig_a" in block
            assert "rule_alpha" not in block and SHAPE_RULE_TITLE not in block
        # The table is still drawn, as evidence, in Appendix A.
        appendix = _block(text, "## Appendix A.", r"^## ")
        assert SHAPE_RULE_TITLE in appendix and "rule_alpha" in appendix

    def test_not_in_the_analyst_report_s_8_2(self) -> None:
        from malspark.reporting.renderers.layout import ANALYST
        from malspark.reporting.renderers.markdown import MarkdownRenderer

        text = MarkdownRenderer(layout=ANALYST).render(self._report())
        detection = _block(text, "### 8.2 Detection rules", r"^#{2,3} ")
        assert "sig_a" in detection
        assert "rule_alpha" not in detection and SHAPE_RULE_TITLE not in detection


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

    def test_an_output_nested_past_the_decoder_is_read_as_no_answer(self) -> None:
        deep = "[" * 50_000 + "]" * 50_000
        entry = _entry("ev_0011", None, output=deep)
        assert rule_match_hits([entry]) == ({}, 0)
        assert SHAPE_RULE_SECTION not in {s.key for s in build_sections([entry])}
