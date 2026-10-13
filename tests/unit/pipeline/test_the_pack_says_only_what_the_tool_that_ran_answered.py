"""A step swapped for another tool is shown, keyed and named by that tool, not the one it replaced.

* A renderer reads a swapped tool's answer through its declared facts: a rule
  matcher declared ``capability_rules`` with two rules shows two rules, with a
  renderer declared or without one, each where it matched.
* A renderer that cannot read another tool's answer is never handed one: the
  line is the generic one.
* The answers the model reads name the tool that ran: the function index's
  rows, the constant scan's marks and the static decoder's comparison carry the
  shipped tool's name only when that tool answered, else a neutral name.
* A long list of steps started beside the pack holds only the threads still
  working.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from maljan.analysis import evidence_roots
from maljan.core import config as config_module
from maljan.core.config import MCPServerConfig, Settings
from maljan.pipeline import triage_pack
from maljan.pipeline.triage_pack import PIPELINE, ServerAnswer
from maljan.schemas.evidence import LedgerEntry
from maljan.tools import artefact_index, crypto_constants, string_blobs

from .test_the_pack_runs_its_declared_steps import (
    INVENTORY,
    RULEMATCH,
    RULEMATCH_ANSWER,
    _Calls,
    _line,
    _only,
    _pack,
    _sample,
    _tools,  # noqa: F401 — the autouse stand-ins for capa and FLOSS
)

RECOVER = {
    "command": "invented-recover",
    "enabled": True,
    "tool_facts": {
        "recover": {
            "kind": "emulated_strings",
            "rows": "/strings/*",
            "arguments": {"path": "file"},
            "display_name": "Recover",
        }
    },
}
RECOVER_ANSWER = {
    "strings": [
        {
            "string": "a text no blob holds",
            "kind": "decoded",
            "function_rva": "0x1100",
            "called_at_rva": "0x1180",
        }
    ]
}
SWAPPED_MATCHER = {"id": "capa", "server": "rules", "tool": "match"}
SWAPPED_DECODER = {"id": "floss", "server": "recover", "tool": "recover"}


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    held = Settings(_env_file=None)
    held.mcp.servers["inventory"] = MCPServerConfig.model_validate(INVENTORY)
    held.mcp.servers["rules"] = MCPServerConfig.model_validate(RULEMATCH)
    held.mcp.servers["recover"] = MCPServerConfig.model_validate(RECOVER)
    monkeypatch.setattr(config_module, "_settings_instance", held)
    return held


def _swapped(tmp_path: Path, *steps: dict[str, Any]) -> Any:
    answers = {"capa": RULEMATCH_ANSWER, "floss": RECOVER_ANSWER}
    return _pack(_sample(tmp_path), steps=list(steps), server_step=_Calls(answers))


@pytest.mark.usefixtures("settings")
class TestASwappedMatchersLine:
    TWO_RULES = (
        "RuleMatch: 2 capabilities (hash data with CRC32 @ 0x1200, contains a loop @ 0x1100); "
        "each rule @ the offsets from the image base where it matched"
    )

    def test_its_declared_renderer_shows_its_rules_not_none(self, tmp_path: Path) -> None:
        result = _swapped(tmp_path, {**SWAPPED_MATCHER, "renderer": "capability_rules"})
        match = _only(result, "match")
        assert _line(result, match) == f"[{match.id}] {self.TWO_RULES}"

    def test_with_no_renderer_its_line_says_as_much_as_the_shipped_one(
        self, tmp_path: Path
    ) -> None:
        plain = _pack(_sample(tmp_path))
        capa = _line(plain, _only(plain, "capa"))
        result = _swapped(tmp_path, SWAPPED_MATCHER)
        match = _only(result, "match")
        line = _line(result, match)
        assert line == f"[{match.id}] {self.TWO_RULES}"
        # The shipped line's shape: a count, each rule where it matched.
        assert capa.split(": ", 1)[1].startswith("1 capabilities (hash data with CRC32 @ 0x1200)")

    def test_the_techniques_it_asserts_are_shown(self, settings: Settings, tmp_path: Path) -> None:
        from maljan.core import declared_reading

        facts = {
            **RULEMATCH["tool_facts"]["match"],
            "asserts_techniques": True,
            "techniques": [{"path": "/attack/*"}],
        }
        settings.mcp.servers["rules"] = MCPServerConfig.model_validate(
            {**RULEMATCH, "tool_facts": {"match": facts}}
        )
        declared_reading.forget()
        answer = json.loads(json.dumps(RULEMATCH_ANSWER))
        answer["hits"][0]["attack"] = ["T1027"]
        try:
            result = _pack(
                _sample(tmp_path), steps=[SWAPPED_MATCHER], server_step=_Calls({"capa": answer})
            )
        finally:
            declared_reading.forget()
        line = _line(result, _only(result, "match"))
        assert line.endswith(", ATT&CK T1027 (rule-asserted)")

    def test_an_answer_whose_declaration_names_no_rows_gets_the_generic_line(self) -> None:
        entry = LedgerEntry(
            id="ev_0001",
            agent=PIPELINE,
            server="rules",
            tool="match",
            output="two rules matched",
            structured={"capabilities": [{"rule": "a"}, {"rule": "b"}]},
            facts={"v": 1, "kind": "capability_rules"},
            pack_step={"v": 1, "id": "capa", "renderer": "capability_rules"},
        )
        assert triage_pack.render_pack([entry], 0) == "[ev_0001] match: two rules matched"

    def test_a_renderer_that_cannot_read_another_tool_s_answer_is_never_handed_one(self) -> None:
        # A stamp this version refuses on save, read back from a stored ledger.
        entry = LedgerEntry(
            id="ev_0001",
            agent=PIPELINE,
            server="headers",
            tool="read",
            output="sections listed",
            structured={"sections": [{"name": ".text"}]},
            pack_step={"v": 1, "id": "pe_info", "renderer": "pe_header"},
        )
        assert triage_pack.render_pack([entry], 0) == "[ev_0001] read: sections listed"


@pytest.mark.usefixtures("settings")
class TestTheAnswersNameTheToolThatRan:
    def test_the_index_rows_and_the_constant_marks_name_no_matcher_that_did_not_run(
        self, tmp_path: Path
    ) -> None:
        result = _swapped(tmp_path, SWAPPED_MATCHER)
        match = _only(result, "match")
        index = _only(result, "function_index").structured or {}
        assert index["rule_sources"] == {match.id: "RuleMatch"}
        assert all("capa" not in row for row in index["rows"])
        constants = _only(result, crypto_constants.TOOL)
        (found,) = (constants.structured or {})["found"]
        assert found["rules"] == [{"rule": "hash data with CRC32", "at": "0x1200"}]
        assert "capa" not in found
        assert "agrees with RuleMatch at 0x1200" in _line(result, constants)

    def test_the_shipped_matcher_keeps_the_names_its_answers_always_had(
        self, tmp_path: Path
    ) -> None:
        result = _pack(_sample(tmp_path))
        index = _only(result, "function_index").structured or {}
        assert "rule_sources" not in index
        assert all("rules" not in row and "capa" in row for row in index["rows"])
        (found,) = (_only(result, crypto_constants.TOOL).structured or {})["found"]
        assert "capa" in found and "rules" not in found

    def test_the_static_decoder_names_no_emulator_that_did_not_run(self, tmp_path: Path) -> None:
        result = _swapped(tmp_path, SWAPPED_DECODER)
        assert _only(result, "recover").ok
        blobs = _only(result, "decode_string_blobs")
        data = blobs.structured or {}
        assert data["decoder_rows_compared"] == 1
        assert data["also_recovered_by_decoder"] == 0
        assert not any("floss" in key for key in data)
        assert "also recovered by Recover" in _line(result, blobs)

    def test_with_the_shipped_emulator_the_decoder_keeps_its_fields(self, tmp_path: Path) -> None:
        data = _only(_pack(_sample(tmp_path)), "decode_string_blobs").structured or {}
        assert {"floss_rows_compared", "also_recovered_by_floss"} <= set(data)


class TestEveryReaderTakesEitherName:
    ROW = {"function_rva": "0x1100", "called_at_rva": "0x1180"}

    def test_the_decoder_row_and_its_count(self) -> None:
        for word in ("floss", "decoder"):
            row = {"text": "t", word: self.ROW}
            assert string_blobs.decoder_row(row) == self.ROW
            assert string_blobs.also_recovered({f"also_recovered_by_{word}": 3}) == 3

    def test_the_decoded_blobs_line(self) -> None:
        for word in ("floss", "decoder"):
            data = {
                "results": [{"text": "t", "rva": "0x3000", "scheme": "xor", word: self.ROW}],
                "total": 1,
                f"also_recovered_by_{word}": 1,
            }
            line = triage_pack._decoded_blobs(data)
            assert "1 also recovered by" in line
            assert "routine 0x1100, call site 0x1180" in line

    def test_an_index_row_s_rules(self) -> None:
        for field_name in ("capa", "rules"):
            row = {field_name: [{"rule": "r", "sources": ["ev_0002"]}]}
            parts = artefact_index.row_parts(row, "ev_0009", {"ev_0002": "Matcher"})
            assert parts.startswith("Matcher: r (ev_0002)")

    def test_a_pass_row_s_marks(self) -> None:
        for field_name in ("capa", "rules"):
            row = {"algorithm": "CRC32", "what": "table", field_name: [{"rule": "r", "at": "0x1"}]}
            assert "agrees with" in triage_pack._constant_item(row)

    def test_the_evidence_roots_join_a_decoder_row_under_either_name(self) -> None:
        def joined(word: str) -> Any:
            entry = LedgerEntry(
                id="ev_0003",
                agent=PIPELINE,
                server=PIPELINE,
                tool="decode_string_blobs",
                args={"path": "/s.exe"},
                output="{}",
                structured={"results": [{"text": "t", "rva": "0x3000", word: self.ROW}]},
            )
            files = evidence_roots._Files([entry])
            return evidence_roots._joins([entry], files).blob_calls

        assert joined("decoder") == joined("floss") != set()


@pytest.mark.usefixtures("settings")
class TestStepsStartedBesideThePack:
    def test_a_long_chain_holds_only_the_threads_still_working(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(triage_pack, "available_memory_bytes", lambda: 10**13)
        monkeypatch.setattr(triage_pack, "cgroup_headroom_bytes", lambda: None)
        peak = [0]

        def call(step: Any, values: Any, left: Any) -> ServerAnswer:
            peak[0] = max(peak[0], threading.active_count())
            return ServerAnswer(
                tool=step.called,
                args={},
                server=step.server,
                output='{"rows": [1]}',
                started_at=time.time(),
            )

        n = 2000
        steps = [
            {
                "id": f"s{i}",
                "server": "inventory",
                "tool": "count_sections",
                "starts_after": f"s{i - 1}" if i else "hashes",
                "peak_mb": 1,
            }
            for i in range(n)
        ]
        before = threading.active_count()
        result = _pack(_sample(tmp_path), steps=steps, server_step=call, memory_floor_bytes=0)
        assert len([e for e in result.entries if e.tool == "count_sections"]) == n
        assert peak[0] - before < 16, peak[0]
        assert all(result.to_state()[f"s{i}"] == "beside the pack" for i in (0, n - 1))


def test_every_reading_by_declaration_is_a_declared_fact_renderer() -> None:
    from maljan.core.pack_steps import DECLARED_FACT_RENDERERS

    assert set(triage_pack._DECLARED_SHAPES) == set(DECLARED_FACT_RENDERERS)
