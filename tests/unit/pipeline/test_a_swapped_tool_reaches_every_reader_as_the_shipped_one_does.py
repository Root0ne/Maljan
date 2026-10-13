"""A swapped or added matcher reaches every reader the shipped one does, named only by itself.

* Function-claim grounding reads an index row's rules under either name, so a
  swapped or mixed matcher's rule grounds a claim as the shipped matcher's
  does, and a long row counts them without naming a matcher that did not run.
* The declared-fact reader and the generic line show only rows that are
  objects, name a row only by a naming value (else ``name=value``), never
  print a value that is not a scalar, and count no row with no readable name
  as a capability.
* With no answer of the kind, the answers keep the shipped tool's names only
  where the effective list still runs that tool.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from maljan.core import config as config_module
from maljan.core import declared_reading
from maljan.core.config import MCPServerConfig, Settings
from maljan.core.pack_steps import effective_steps, runs_shipped
from maljan.pipeline import function_claims, triage_pack
from maljan.pipeline.triage_pack import PIPELINE, ServerAnswer
from maljan.schemas.evidence import LedgerEntry
from maljan.tools import artefact_index

from .test_the_pack_runs_its_declared_steps import (
    RULEMATCH,
    RULEMATCH_ANSWER,
    _Calls,
    _line,
    _only,
    _pack,
    _sample,
    _tools,  # noqa: F401 — the autouse stand-ins for capa and FLOSS
)
from .test_the_pack_says_only_what_the_tool_that_ran_answered import (
    RECOVER,
    SWAPPED_DECODER,
    SWAPPED_MATCHER,
)


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[Settings]:
    held = Settings(_env_file=None)
    held.mcp.servers["rules"] = MCPServerConfig.model_validate(RULEMATCH)
    held.mcp.servers["recover"] = MCPServerConfig.model_validate(RECOVER)
    monkeypatch.setattr(config_module, "_settings_instance", held)
    declared_reading.forget()
    yield held
    declared_reading.forget()


def _index_rows(result: Any) -> list[dict[str, Any]]:
    return list((_only(result, "function_index").structured or {}).get("rows") or [])


def _ruled(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if artefact_index.rule_cells(row)]


@pytest.mark.usefixtures("settings")
class TestFunctionClaimsReadEveryMatchersRules:
    def _texts(self, rows: list[dict[str, Any]]) -> set[str]:
        return {text for row in rows for text in function_claims._row_held(row).texts}

    def test_a_swapped_matcher_s_rules_ground_a_claim(self, tmp_path: Path) -> None:
        result = _pack(
            _sample(tmp_path),
            steps=[SWAPPED_MATCHER],
            server_step=_Calls({"capa": RULEMATCH_ANSWER}),
        )
        rows = _ruled(_index_rows(result))
        assert rows and all("rules" in row and "capa" not in row for row in rows)
        assert {"hash data with crc32", "contains a loop"} <= self._texts(rows)

    def test_a_matcher_beside_the_shipped_one_grounds_a_claim(self, tmp_path: Path) -> None:
        step = {"id": "rm", "server": "rules", "tool": "match", "after": "capa"}
        result = _pack(
            _sample(tmp_path), steps=[step], server_step=_Calls({"rm": RULEMATCH_ANSWER})
        )
        rows = _ruled(_index_rows(result))
        assert rows and all("rules" in row for row in rows)
        assert "contains a loop" in self._texts(rows)

    def test_the_shipped_matcher_s_rules_ground_a_claim_as_before(self, tmp_path: Path) -> None:
        rows = _ruled(_index_rows(_pack(_sample(tmp_path))))
        assert rows and all("capa" in row for row in rows)
        assert "hash data with crc32" in self._texts(rows)

    def _counted(self, field_name: str) -> str:
        cells = [{"rule": f"rule {i} " + "x" * 200, "sources": ["ev_0002"]} for i in range(40)]
        row = {"offset": "0x1100", field_name: cells}
        return function_claims._row_words(row, "ev_0009", artefact_index.row_parts)

    def test_a_long_row_counts_a_swapped_matcher_s_rules_neutrally(self) -> None:
        words = self._counted("rules")
        assert words.startswith("40 rules (ev_0009)")
        assert "capa" not in words

    def test_a_long_row_counts_the_shipped_matcher_s_rules_as_before(self) -> None:
        assert self._counted("capa").startswith("40 capa rules (ev_0009)")


def _entry(structured: Any, facts: dict[str, Any]) -> LedgerEntry:
    return LedgerEntry(
        id="ev_0001",
        agent=PIPELINE,
        server="rules",
        tool="match",
        output="the matcher answered",
        structured=structured,
        facts={"v": 1, **facts},
        pack_step={"v": 1, "id": "capa", "renderer": "capability_rules"},
    )


RULES = {
    "kind": "capability_rules",
    "rows": "/hits/*",
    "places": {"addresses": "/at"},
    "values": {"rule": "/name"},
}
NAMESPACES_ONLY = {**RULES, "values": {"ns": "/ns"}}
GENERIC = {
    "kind": "inventory",
    "rows": "/hits/*",
    "places": {"at": "/at"},
    "values": {"rule": "/name"},
}


class TestDeclaredRowsAreReadSafely:
    def test_rows_that_are_not_objects_are_not_counted(self) -> None:
        mixed = {"hits": ["a string", 3, None, {"name": "real", "at": ["0x10"]}]}
        line = triage_pack.render_pack([_entry(mixed, RULES)], 0)
        assert "1 capabilities (real @ 0x10)" in line

    def test_an_answer_of_only_such_rows_is_not_read_as_none_matched(self) -> None:
        line = triage_pack.render_pack([_entry({"hits": ["a", 3, None]}, RULES)], 0)
        assert line == "[ev_0001] match: the matcher answered"

    def test_a_name_that_is_not_a_scalar_is_never_printed_as_code(self) -> None:
        answer = {"hits": [{"name": {"nested": 1}, "at": 7}]}
        line = triage_pack.render_pack([_entry(answer, RULES)], 0)
        assert "{" not in line and "nested" not in line
        assert line == "[ev_0001] match: 1 row of kind capability_rules (@ 7)"

    def test_a_row_with_no_readable_name_is_no_empty_capability(self) -> None:
        line = triage_pack.render_pack([_entry({"hits": [{"name": "", "at": []}]}, RULES)], 0)
        assert line == "[ev_0001] match: 1 row of kind capability_rules"
        assert "()" not in line and "capabilities" not in line

    def test_only_named_rows_are_counted_as_capabilities(self) -> None:
        answer = {"hits": [{"name": "", "at": ["0x30"]}, {"name": "real", "at": ["0x10"]}]}
        line = triage_pack.render_pack([_entry(answer, RULES)], 0)
        assert "1 capabilities (real @ 0x10)" in line
        assert "0x30" not in line and "( @" not in line

    def test_a_declaration_with_no_naming_value_says_what_each_value_is(self) -> None:
        answer = {"hits": [{"ns": "data-manipulation/checksum/crc32", "at": ["0x1200"]}]}
        line = triage_pack.render_pack([_entry(answer, NAMESPACES_ONLY)], 0)
        assert "(ns=data-manipulation/checksum/crc32 @ 0x1200)" in line

    def test_the_generic_line_reads_the_same_way(self) -> None:
        answer = {"hits": ["x", {"name": {"a": 1}, "at": [{"b": 2}, "0x20"]}, {"name": "kept"}]}
        entry = _entry(answer, GENERIC).model_copy(update={"pack_step": None})
        line = triage_pack.render_pack([entry], 0)
        assert line == "[ev_0001] match: 2 rows of kind inventory (@ 0x20, kept)"

    def test_the_generic_line_of_only_rows_that_are_not_objects_is_the_answer(self) -> None:
        entry = _entry({"hits": ["x", 1]}, GENERIC).model_copy(update={"pack_step": None})
        assert triage_pack.render_pack([entry], 0) == "[ev_0001] match: the matcher answered"


def _failing(step: Any, values: Any, left: Any) -> ServerAnswer:
    return ServerAnswer(
        tool=step.called, args={}, server=step.server, output="", ok=False, error="boom"
    )


@pytest.mark.usefixtures("settings")
class TestNoAnswerKeepsTheShippedNamesOnlyWhereTheShippedToolRuns:
    def test_a_swapped_decoder_that_failed_leaves_the_neutral_names(self, tmp_path: Path) -> None:
        result = _pack(
            _sample(tmp_path), steps=[SWAPPED_MATCHER, SWAPPED_DECODER], server_step=_failing
        )
        assert not _only(result, "recover").ok
        data = _only(result, "decode_string_blobs").structured or {}
        assert data["decoder_rows_compared"] == 0
        assert data["also_recovered_by_decoder"] == 0
        assert not any("floss" in key for key in data)
        assert "Recover" in _line(result, _only(result, "decode_string_blobs"))

    def test_the_shipped_list_keeps_the_shipped_names(self) -> None:
        assert runs_shipped("emulated_strings") and runs_shipped("capability_rules")
        assert artefact_index.rules_field(triage_pack._from_shipped([], "capability_rules")) == (
            "capa"
        )

    def test_a_list_that_swapped_or_dropped_the_tool_does_not(self) -> None:
        swapped = effective_steps([SWAPPED_MATCHER, SWAPPED_DECODER])
        assert not runs_shipped("capability_rules", swapped)
        assert not runs_shipped("emulated_strings", swapped)
        dropped = effective_steps([{"id": "capa", "enabled": False}])
        assert not runs_shipped("capability_rules", dropped)
        assert runs_shipped("emulated_strings", dropped)
        index = triage_pack.index_inputs([], swapped)
        assert index.rules_under == "rules"
        assert triage_pack._rules_mark((), swapped) == "rules"
