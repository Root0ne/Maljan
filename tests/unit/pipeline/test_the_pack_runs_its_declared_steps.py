"""The triage pack is a declared step list: any server's tool can be a step, and a later
step reads an earlier answer by its kind.

The shipped list (``core.pack_steps``) is today's pack: the same steps in the
same order, each with its own in-process implementation and renderer. An
operator's ``triage.steps`` laid over it adds a step, drops one or swaps one:

* an invented tool on an invented server added as a step is called through the
  server step call, recorded under that server at its place, stamped with its
  step, cited by its id and shown by the generic line with its label;
* the shipped rule matcher swapped for an invented one declared
  ``capability_rules`` gives the function index its rules and its function
  starts, the readings of the bytes their starts, the constant scan its
  agreement and the pack's text its name;
* a dropped matcher leaves the index naming the kind it lacks;
* a step named as one of the pack state's own keys runs as any other, and its
  schedule is held apart, so no fact or count is replaced.
"""

from __future__ import annotations

import asyncio
import json
import struct
import time
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.core import config as config_module
from maljan.core.config import MCPServerConfig, Settings, TriageConfig
from maljan.core.container import ServiceContainer
from maljan.core.pack_steps import PACK_RENDERERS, default_steps, effective_steps
from maljan.pipeline import triage_pack
from maljan.pipeline.nodes import _server_step_call
from maljan.pipeline.triage_pack import (
    PIPELINE,
    CapaSettings,
    PackInputs,
    ServerAnswer,
    pack_block,
    pack_entries,
    run_pack,
)
from maljan.providers.static import capa_yara
from maljan.schemas.evidence import EvidenceCounter, LedgerEntry
from maljan.tools import crypto_constants, emulated_strings, rules

from ..tools.synthetic_pe import TEXT_RVA, SyntheticPE

ROUTINE = TEXT_RVA + 0x200
SECOND = TEXT_RVA + 0x100

# Today's pack, step by step, in its order.
SHIPPED_IDS = [
    "identify_file",
    "hashes",
    "signing_info",
    "pe_info",
    "elf_info",
    "macho_info",
    "apk_info",
    "document_info",
    "archive_list",
    "strings",
    "iocs_from_file",
    "yara_scan",
    "capa",
    "sigma_match_sandbox",
    "api_capability",
    "lolbin_lookup",
    "sandbox_status",
    "sandbox_processes",
    "sandbox_network",
    "sandbox_signatures",
    "sandbox_dropped_files",
    "sandbox_channels",
    "pcap_summary",
    "reputation",
    "function_matches",
    "floss",
    "resolve_api_hashes",
    "decode_string_blobs",
    "resolved_api_capability",
    "find_crypto_constants",
    "anti_analysis_scan",
    "function_index",
    "unpack_upx",
    "sandbox_sections",
    "sandbox_api_capability",
    "find_directed_text",
    "behaviour_code_links",
]
# The shipped steps of a server's tool, beside the format readers, and YARA-X's
# right after the shipped YARA scan: each is off while its server is not
# switched on (``pack_steps.steps_on_servers``).
SHIPPED_SERVER_STEPS = [
    "die_scan",
    "dotnet_types",
    "go_symbols",
    "ole_vba",
    "office_dde",
    "rtf_objects",
    "js_deobfuscate",
    "container_extract",
    "android_classes",
]
_AFTER_THE_READERS = SHIPPED_IDS.index("archive_list") + 1
_AFTER_YARA = SHIPPED_IDS.index("yara_scan") + 1

INVENTORY = {
    "command": "invented-inventory",
    "enabled": True,
    "tool_facts": {
        "count_sections": {
            "kind": "section_table",
            "rows": "/sections/*",
            "places": {"rva": "/at"},
            "values": {"text": "/name"},
            "arguments": {"path": "target"},
        }
    },
}
RULEMATCH = {
    "command": "invented-rules",
    "enabled": True,
    "tool_facts": {
        "match": {
            "kind": "capability_rules",
            "rows": "/hits/*",
            "places": {"addresses": "/at"},
            "values": {"rule": "/name", "namespace": "/ns"},
            "function_starts": "/functions",
            "arguments": {"path": "file"},
            "display_name": "RuleMatch",
        }
    },
}
INVENTORY_ANSWER = {"sections": [{"name": ".text", "at": "0x1000"}, {"name": ".data"}]}
RULEMATCH_ANSWER = {
    "functions": [hex(TEXT_RVA), hex(SECOND), hex(ROUTINE)],
    "hits": [
        {
            "name": "hash data with CRC32",
            "ns": "data-manipulation/checksum/crc32",
            "at": [hex(ROUTINE)],
        },
        {"name": "contains a loop", "ns": "anti-analysis", "at": [hex(SECOND)]},
    ],
}


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    held = Settings(_env_file=None)
    held.mcp.servers["inventory"] = MCPServerConfig.model_validate(INVENTORY)
    held.mcp.servers["rules"] = MCPServerConfig.model_validate(RULEMATCH)
    monkeypatch.setattr(config_module, "_settings_instance", held)
    return held


@pytest.fixture(autouse=True)
def _tools(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """capa answers with a rule at the routine; FLOSS is not installed here."""
    asked: list[str] = []

    def capa(path: str, **_: Any) -> dict[str, Any]:
        asked.append(path)
        return {
            "capabilities": [
                {
                    "namespace": "data-manipulation/checksum/crc32",
                    "rule": "hash data with CRC32",
                    "attck": [],
                    "addresses": [hex(ROUTINE)],
                }
            ],
            "function_starts": [hex(TEXT_RVA), hex(ROUTINE)],
        }

    monkeypatch.setattr(rules, "capa", capa)
    monkeypatch.setattr(emulated_strings, "floss_unavailable", lambda environ=None: "not here")
    return asked


def _sample(tmp_path: Path) -> str:
    """An x86 image with no function table, using CRC-32's polynomial in a routine."""
    image = SyntheticPE(is64=False, image_base=0x400000)
    image.put("text", 0x210, b"\x35" + struct.pack("<I", 0xEDB88320) + b"\xc3")
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())
    return str(target)


class _Calls:
    """Stands in for the node's server step call, answering each step from a table."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.asked: list[tuple[str, dict[str, str], float | None]] = []

    def __call__(self, step: Any, values: Any, left: float | None) -> ServerAnswer:
        self.asked.append((step.id, dict(values), left))
        return ServerAnswer(
            tool=step.called,
            args={"path": values["sample_path"]},
            server=step.server,
            output=json.dumps(self.answers[step.id]),
            started_at=time.time(),
        )


def _pack(path: str, steps: Any = None, server_step: Any = None, **over: Any) -> Any:
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    inputs = PackInputs(
        sample_path=path,
        sha256="a" * 64,
        file_type="pe",
        strings_head=10,
        capa=CapaSettings(rules_dir="r", signatures_dir="s", timeout_s=7),
        steps=effective_steps(steps) if steps is not None else None,
        **over,
    )
    return run_pack(recorder, inputs, server_step=server_step)


def _line(result: Any, entry: LedgerEntry) -> str:
    text = pack_block(pack_entries(result.entries), 0)
    return next(line for line in text.splitlines() if line.startswith(f"[{entry.id}] "))


def _only(result: Any, tool: str) -> LedgerEntry:
    (entry,) = [e for e in result.entries if e.tool == tool]
    return entry


class TestTheShippedList:
    def test_it_is_today_s_pack_in_today_s_order(self) -> None:
        assert [step.id for step in default_steps()] == (
            SHIPPED_IDS[:_AFTER_THE_READERS]
            + SHIPPED_SERVER_STEPS
            + SHIPPED_IDS[_AFTER_THE_READERS:_AFTER_YARA]
            + ["yarax_scan"]
            + SHIPPED_IDS[_AFTER_YARA:]
        )
        assert effective_steps() == default_steps()

    def test_every_shipped_step_has_its_own_implementation(self) -> None:
        assert set(triage_pack._BUILTIN_STEPS) == set(SHIPPED_IDS)

    def test_every_declared_renderer_is_a_renderer_of_the_pack(self) -> None:
        assert {*triage_pack._RENDERERS, "function_table"} == set(PACK_RENDERERS)
        assert {step.renderer for step in default_steps()} - {""} <= set(PACK_RENDERERS)

    def test_a_run_with_no_list_handed_in_runs_the_shipped_list(self, tmp_path: Path) -> None:
        path = _sample(tmp_path)
        plain = [(e.id, e.tool, e.args) for e in _pack(path).entries]
        listed = [(e.id, e.tool, e.args) for e in _pack(path, steps=[]).entries]
        assert plain == listed


class TestTheOperatorsDeclarations:
    def test_stored_settings_with_no_steps_keep_the_legacy_numbers(self) -> None:
        held = Settings(_env_file=None)
        assert held.triage.steps == []
        assert held.triage.budget_seconds == 1200
        assert held.triage.memory_floor_mb == 10240

    def test_a_shipped_step_is_dropped_or_changed_in_its_place(self) -> None:
        steps = effective_steps(
            [{"id": "capa", "enabled": False}, {"id": "yara_scan", "budget_seconds": 30}]
        )
        ids = [step.id for step in steps]
        shipped = [step.id for step in default_steps()]
        assert "capa" not in ids and ids.index("yara_scan") == shipped.index("yara_scan")
        assert next(s for s in steps if s.id == "yara_scan").budget_seconds == 30

    def test_a_new_step_goes_where_its_after_says_else_last(self) -> None:
        steps = effective_steps(
            [
                {
                    "id": "inventory",
                    "server": "inventory",
                    "tool": "count_sections",
                    "after": "hashes",
                },
                {"id": "late", "server": "inventory", "tool": "count_sections"},
            ]
        )
        ids = [step.id for step in steps]
        assert ids[ids.index("hashes") + 1] == "inventory"
        assert ids[-1] == "late"

    def test_a_step_naming_another_tool_replaces_the_shipped_one_in_its_place(self) -> None:
        (swapped,) = [
            s
            for s in effective_steps([{"id": "capa", "server": "rules", "tool": "match"}])
            if s.id == "capa"
        ]
        assert swapped.server == "rules" and swapped.called == "match"
        # Of the shipped step only the id and the place are kept.
        assert swapped.renderer == "" and swapped.display_name == ""

    @pytest.mark.parametrize(
        ("steps", "said"),
        [
            (
                [{"id": "x", "server": "s", "tool": "t"}, {"id": "x", "server": "s", "tool": "u"}],
                "declared twice",
            ),
            (
                [{"id": "x", "server": "s", "tool": "t", "arguments": {"a": "{token}"}}],
                "cannot name",
            ),
            ([{"id": "x", "tool": "t"}], "names no server"),
            ([{"id": "strings", "arguments": {"limit": 5}}], "computes its own arguments"),
            ([{"id": "strings", "budget_seconds": 5}], "no wall clock of its own"),
            ([{"id": "x", "server": "s", "tool": "t", "after": "nowhere"}], "which no step is"),
            ([{"id": "x", "server": "s", "tool": "t", "beside": ["nowhere"]}], "which no step is"),
            (
                [{"id": "x", "server": "s", "tool": "t", "renderer": "pretty"}],
                "not one of the pack's renderers",
            ),
            ([{"id": "x", "server": "s", "tool": "t", "enable": False}], "Extra inputs"),
            ([{"id": "X", "server": "s", "tool": "t"}], "not a step name"),
            ([{"id": "x", "server": "s"}], "no tool to call"),
        ],
    )
    def test_a_list_that_cannot_run_is_refused_where_it_is_saved(
        self, steps: list[Any], said: str
    ) -> None:
        with pytest.raises(ValidationError, match=said):
            TriageConfig(steps=steps)


@pytest.mark.usefixtures("settings")
class TestAnInventedToolAsAStep:
    STEP = {
        "id": "inventory",
        "server": "inventory",
        "tool": "count_sections",
        "display_name": "Inventory",
    }

    def test_its_answer_is_recorded_under_its_server_at_its_place(self, tmp_path: Path) -> None:
        path = _sample(tmp_path)
        calls = _Calls({"inventory": INVENTORY_ANSWER})
        plain = _pack(path)
        result = _pack(path, steps=[self.STEP], server_step=calls)

        entry = result.entries[-1]
        assert (entry.tool, entry.server, entry.source) == (
            "count_sections",
            "inventory",
            "mcp:inventory",
        )
        assert entry.ok and entry.agent == PIPELINE
        assert entry.pack_step == {"v": 1, "id": "inventory", "label": "Inventory"}
        assert (entry.facts or {})["kind"] == "section_table"
        assert entry.facts["display_name"] == "Inventory"
        # Every id the shipped steps issued is the id it was.
        assert [(e.id, e.tool) for e in result.entries[:-1]] == [
            (e.id, e.tool) for e in plain.entries
        ]
        (asked,) = calls.asked
        assert asked[0] == "inventory"
        assert asked[1] == {"sample_path": path, "sha256": "a" * 64, "file_type": "pe"}

    def test_its_line_is_the_generic_line_under_its_label_and_cites_its_id(
        self, tmp_path: Path
    ) -> None:
        result = _pack(
            _sample(tmp_path),
            steps=[self.STEP],
            server_step=_Calls({"inventory": INVENTORY_ANSWER}),
        )
        entry = result.entries[-1]
        assert _line(result, entry) == (
            f"[{entry.id}] Inventory: 2 rows of kind section_table (.text @ 0x1000, .data)"
        )

    def test_with_no_server_calls_it_is_not_run_and_is_not_a_failure(self, tmp_path: Path) -> None:
        result = _pack(_sample(tmp_path), steps=[self.STEP])
        entry = result.entries[-1]
        assert entry.ok is False
        assert entry.error == (
            "not run: this run calls no tool server, so inventory's count_sections was not asked"
        )
        assert "count_sections" not in result.failed
        assert _line(result, entry).startswith(f"[{entry.id}] Inventory: not done (not run: ")

    def test_a_failed_call_is_a_failure_of_its_tool(self, tmp_path: Path) -> None:
        def failing(step: Any, values: Any, left: float | None) -> ServerAnswer:
            return ServerAnswer(
                tool=step.called, args={}, server=step.server, output="boom", ok=False, error="boom"
            )

        result = _pack(_sample(tmp_path), steps=[self.STEP], server_step=failing)
        assert result.failed == ["count_sections"]
        assert _line(result, result.entries[-1]).endswith("Inventory: failed (boom)")

    def test_it_can_start_beside_the_pack_and_keep_its_place(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(triage_pack, "available_memory_bytes", lambda: 64 * 1024**3)
        monkeypatch.setattr(triage_pack, "cgroup_headroom_bytes", lambda: None)
        monkeypatch.setattr(capa_yara, "_CAPA_PEAK_BYTES", 1024**3)
        step = {**self.STEP, "starts_after": "signing_info", "peak_mb": 512, "beside": ["capa"]}
        result = _pack(
            _sample(tmp_path), steps=[step], server_step=_Calls({"inventory": INVENTORY_ANSWER})
        )
        assert result.entries[-1].tool == "count_sections" and result.entries[-1].ok
        assert result.to_state()["inventory"] == "beside capa"

    def test_with_no_room_it_runs_in_turn_and_says_why(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(triage_pack, "available_memory_bytes", lambda: 64 * 1024**3)
        monkeypatch.setattr(triage_pack, "cgroup_headroom_bytes", lambda: None)
        step = {**self.STEP, "starts_after": "signing_info"}
        result = _pack(
            _sample(tmp_path), steps=[step], server_step=_Calls({"inventory": INVENTORY_ANSWER})
        )
        assert result.to_state()["inventory"] == "in turn: Inventory declares no memory peak"
        assert result.entries[-1].ok

    def test_its_tool_s_declared_peak_sizes_it_against_the_floor(
        self, settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core import declared_reading

        facts = {**INVENTORY["tool_facts"]["count_sections"], "memory_peak_mb": 2048}
        declared = {**INVENTORY, "tool_facts": {"count_sections": facts}}
        settings.mcp.servers["inventory"] = MCPServerConfig.model_validate(declared)
        declared_reading.forget()
        monkeypatch.setattr(triage_pack, "available_memory_bytes", lambda: 11 * 1024**3)
        monkeypatch.setattr(triage_pack, "cgroup_headroom_bytes", lambda: None)
        step = {**self.STEP, "starts_after": "signing_info"}
        result = _pack(
            _sample(tmp_path),
            steps=[step],
            server_step=_Calls({"inventory": INVENTORY_ANSWER}),
            memory_floor_bytes=10240 * 1024 * 1024,
        )
        declared_reading.forget()
        assert result.to_state()["inventory"] == (
            "in turn: 11264 MiB available, less Inventory's 2048 MiB bound, is under the "
            "10240 MiB floor"
        )


@pytest.mark.usefixtures("settings")
class TestASwappedRuleMatcher:
    STEP = {"id": "capa", "server": "rules", "tool": "match"}

    def _run(self, tmp_path: Path, asked: list[str]) -> Any:
        result = _pack(
            _sample(tmp_path), steps=[self.STEP], server_step=_Calls({"capa": RULEMATCH_ANSWER})
        )
        assert asked == [], "the shipped rule matcher did not run"
        return result

    def test_it_takes_the_shipped_matcher_s_place(self, tmp_path: Path, _tools: list[str]) -> None:
        plain = _pack(_sample(tmp_path))
        _tools.clear()
        result = self._run(tmp_path, _tools)
        capa = _only(plain, "capa")
        match = _only(result, "match")
        assert match.id == capa.id and match.server == "rules"
        assert result.facts.capa_hits == 2

    def test_the_readings_of_the_bytes_take_its_function_starts(
        self, tmp_path: Path, _tools: list[str]
    ) -> None:
        result = self._run(tmp_path, _tools)
        resolved = _only(result, "resolve_api_hashes")
        assert resolved.args["function_starts"] == "RuleMatch's 3 function starts"
        blobs = _only(result, "decode_string_blobs")
        assert "RuleMatch, 3 function starts" in str((blobs.structured or {}).get("function_table"))

    def test_the_function_index_takes_its_places_and_names_it(
        self, tmp_path: Path, _tools: list[str]
    ) -> None:
        result = self._run(tmp_path, _tools)
        match = _only(result, "match")
        index = _only(result, "function_index")
        data = index.structured or {}
        assert f"{match.id} match" in index.args["joined"]
        assert data["function_sources"]["RuleMatch function starts"] == 3
        rows = {row["offset"]: row for row in data["rows"]}
        assert rows[hex(ROUTINE)]["rules"] == [
            {"rule": "hash data with CRC32", "sources": [match.id]}
        ]
        assert data["rule_sources"] == {match.id: "RuleMatch"}
        assert '"capa"' not in json.dumps(data)
        text = pack_block(pack_entries(result.entries), 0)
        assert f"RuleMatch: hash data with CRC32 ({match.id})" in text
        assert "capa" not in json.dumps(data.get("absent") or {})

    def test_the_constant_scan_agrees_with_it_by_name(
        self, tmp_path: Path, _tools: list[str]
    ) -> None:
        result = self._run(tmp_path, _tools)
        constants = _only(result, crypto_constants.TOOL)
        line = _line(result, constants)
        assert "agrees with RuleMatch at" in line
        assert "capa" not in line.replace('"capa"', "")


class TestADroppedMatcher:
    def test_the_index_names_the_kind_it_lacks(self, tmp_path: Path) -> None:
        result = _pack(_sample(tmp_path), steps=[{"id": "capa", "enabled": False}])
        index = _only(result, "function_index")
        absent = (index.structured or {})["absent"]
        assert absent["capability_rules"] == triage_pack.INDEX_SOURCE_NOT_IN_PACK
        assert "capability_rules: no: the pack holds no entry of it" in _line(result, index)
        assert "function_starts" not in _only(result, "resolve_api_hashes").args


class TestTheLineOfAnEntry:
    def test_a_server_tool_named_as_a_shipped_step_gets_the_generic_line(self) -> None:
        entry = LedgerEntry(
            id="ev_0001", agent=PIPELINE, server="lookalike", tool="strings", output="three words"
        )
        assert triage_pack.renderer_of(entry) == ""
        assert triage_pack.render_pack([entry], 0) == "[ev_0001] strings: three words"

    def test_an_entry_of_a_shipped_step_is_read_by_that_step(self) -> None:
        entry = LedgerEntry(
            id="ev_0001", agent=PIPELINE, server=PIPELINE, tool="strings", output="{}"
        )
        assert triage_pack.renderer_of(entry) == "string_runs"


class TestTheServerStepCall:
    """The node's call: through the registry, to the path the server opens, never raising."""

    class _Tool:
        name = "count_sections"
        metadata: dict[str, Any] = {}

        def __init__(self) -> None:
            self.asked: list[dict[str, Any]] = []

        async def ainvoke(self, args: dict[str, Any]) -> str:
            self.asked.append(args)
            return json.dumps(INVENTORY_ANSWER)

    def _container(self, settings: Settings, tool: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
        container = ServiceContainer(settings, mock=True)

        class _Registry:
            def tools_for_ref(self, ref: Any, job_id: str, **_: Any) -> tuple[list[Any], list[str]]:
                return ([tool], []) if ref.server == "inventory" else ([], ["not attached"])

        monkeypatch.setattr(container, "get_server_registry", lambda: _Registry())
        return container

    def test_the_declared_path_argument_takes_the_sample(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tool = self._Tool()
        call = _server_step_call(self._container(settings, tool, monkeypatch))
        (step,) = [
            s for s in effective_steps([TestAnInventedToolAsAStep.STEP]) if s.id == "inventory"
        ]
        answer = call(step, {"sample_path": "/s.exe", "sha256": "a" * 64, "file_type": "pe"}, 30.0)
        assert answer.ok and json.loads(answer.output) == INVENTORY_ANSWER
        assert tool.asked == [{"target": "/s.exe"}]
        assert (answer.tool, answer.server, answer.args) == (
            "count_sections",
            "inventory",
            {"target": "/s.exe"},
        )

    def test_a_template_is_filled(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tool = self._Tool()
        call = _server_step_call(self._container(settings, tool, monkeypatch))
        declared = {
            **TestAnInventedToolAsAStep.STEP,
            "arguments": {"f": "{sample_path}", "h": "{sha256}", "n": 3},
        }
        (step,) = [s for s in effective_steps([declared]) if s.id == "inventory"]
        call(step, {"sample_path": "/s.exe", "sha256": "b" * 64, "file_type": "pe"}, None)
        assert tool.asked == [{"f": "/s.exe", "h": "b" * 64, "n": 3}]

    def test_a_withheld_or_unknown_server_is_not_asked(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tool = self._Tool()
        container = self._container(settings, tool, monkeypatch)
        monkeypatch.setattr(
            container, "active_profile", lambda: type("P", (), {"exclude_servers": ["inventory"]})()
        )
        call = _server_step_call(container)
        (step,) = [
            s for s in effective_steps([TestAnInventedToolAsAStep.STEP]) if s.id == "inventory"
        ]
        answer = call(step, {"sample_path": "/s.exe", "sha256": "", "file_type": "pe"}, None)
        assert not answer.ok and answer.error.startswith("not run: inventory withheld")
        assert tool.asked == []
        (other,) = [
            s
            for s in effective_steps([{"id": "x", "server": "nowhere", "tool": "t"}])
            if s.id == "x"
        ]
        monkeypatch.setattr(
            container, "active_profile", lambda: type("P", (), {"exclude_servers": []})()
        )
        missing = call(other, {"sample_path": "/s.exe", "sha256": "", "file_type": "pe"}, None)
        assert missing.error.startswith("not run: no enabled tool server is configured as nowhere")

    def test_a_tool_that_raises_is_a_failed_answer(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Raises(self._Tool):  # type: ignore[name-defined]
            async def ainvoke(self, args: dict[str, Any]) -> str:
                raise RuntimeError("server went away")

        call = _server_step_call(self._container(settings, _Raises(), monkeypatch))
        (step,) = [
            s for s in effective_steps([TestAnInventedToolAsAStep.STEP]) if s.id == "inventory"
        ]
        answer = call(step, {"sample_path": "/s.exe", "sha256": "", "file_type": "pe"}, None)
        assert not answer.ok and answer.error == "RuntimeError: server went away"

    def test_the_node_runs_the_operators_steps(
        self, settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.pipeline.nodes import make_triage_node
        from tests.unit.pipeline.test_stage_events import _state

        settings.triage.steps = TriageConfig(steps=[TestAnInventedToolAsAStep.STEP]).steps
        tool = self._Tool()
        container = self._container(settings, tool, monkeypatch)
        node = make_triage_node(container, stage=container.active_profile().stage("triage_pack"))
        update = asyncio.run(node(_state(sample_path=_sample(tmp_path))))
        last = update["evidence_ledger"][-1]
        assert (last["tool"], last["server"], last["ok"]) == ("count_sections", "inventory", True)
        assert last["pack_step"] == {"v": 1, "id": "inventory", "label": "Inventory"}
        assert len(tool.asked) == 1


@pytest.mark.usefixtures("settings")
class TestAStepNamedAsAKeyOfThePackState:
    """A step named as a key of the pack's state that starts beside the pack.

    Its schedule used to land on that key: ``entries`` broke the run summary,
    ``has_signature`` became a truthy text, ``hits`` and ``yara_hits`` were
    replaced. It runs as any other step, its schedule held apart, stated in
    the state and in the run summary.
    """

    SCHEDULE = "in turn: Inventory declares no memory peak"

    @staticmethod
    def _step(name: str, **over: Any) -> dict[str, Any]:
        return {
            "id": name,
            "server": "inventory",
            "tool": "count_sections",
            "display_name": "Inventory",
            **over,
        }

    def _run(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, step: dict[str, Any]) -> Any:
        monkeypatch.setattr(triage_pack, "available_memory_bytes", lambda: 64 * 1024**3)
        monkeypatch.setattr(triage_pack, "cgroup_headroom_bytes", lambda: None)
        return _pack(
            _sample(tmp_path), steps=[step], server_step=_Calls({step["id"]: INVENTORY_ANSWER})
        )

    @pytest.mark.parametrize("name", ["entries", "has_signature", "hits", "yara_hits"])
    def test_it_runs_and_its_schedule_never_replaces_a_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
    ) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder
        from maljan.pipeline.conditions import HELD_SCHEDULES
        from maljan.pipeline.triage_pack import PackResult

        result = self._run(tmp_path, monkeypatch, self._step(name, starts_after="signing_info"))
        entry = result.entries[-1]
        assert (entry.tool, entry.ok) == ("count_sections", True)

        state = result.to_state()
        unscheduled = PackResult(
            entries=result.entries,
            facts=result.facts,
            failed=result.failed,
            duration_ms=result.duration_ms,
            degraded=result.degraded,
        ).to_state()
        for key, value in unscheduled.items():
            assert state[key] == value, key
        assert isinstance(state["entries"], int) and isinstance(state["has_signature"], bool)
        assert isinstance(state["hits"], dict) and isinstance(state["yara_hits"], int)
        assert state[HELD_SCHEDULES] == {name: self.SCHEDULE}

        triage = RunSummaryBuilder(start_time=0.0).set_triage(state).build().to_dict()["triage"]
        assert (triage["entries"], triage["failed"]) == (len(result.entries), len(result.failed))
        assert triage[HELD_SCHEDULES] == {name: self.SCHEDULE}

    def test_without_starts_after_it_writes_no_schedule_at_all(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.pipeline.conditions import HELD_SCHEDULES

        result = self._run(tmp_path, monkeypatch, self._step("entries"))
        state = result.to_state()
        assert result.entries[-1].ok and state["entries"] == len(result.entries)
        assert HELD_SCHEDULES not in state
