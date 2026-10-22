"""A generic MCP server gets the pre-pass, the function hashes and the scan by declared data.

``MCPServerConfig.prepass_tools`` names the tool for each pass, and that tool's
own declaration (``tool_facts``) says where the call names the sample and where
the answer's parts sit. With nothing declared the provider answers as it
always did: no call graph, no hashes, no scan. A server that served MCP
``instructions`` and declares no workflow is introduced by them, quoted; one
that served none still gets the generated paragraph.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from maljan.core.config import MCPServerConfig, PrepassToolsConfig
from maljan.providers.base import StaticJobContext
from maljan.providers.static.declared_prepass import (
    call_graph_of,
    function_hashes_of,
    scan_findings,
)
from maljan.providers.static.generic_mcp import GenericMCPStaticProvider

MIRROR = "/data/samples/.work/abc.exe"


class _Tool:
    def __init__(self, name: str, answer: Any, calls: list[tuple[str, dict[str, Any]]]):
        self.name = name
        self.description = f"[TOOL] What {name} does."
        self._answer = answer
        self._calls = calls

    async def ainvoke(self, arguments: dict[str, Any]) -> Any:
        self._calls.append((self.name, dict(arguments)))
        answer = self._answer
        return answer(arguments) if callable(answer) else answer


class _Handle:
    """A stand-in ``ServerHandle``: its advertised tools answer from a table."""

    def __init__(self, cfg: MCPServerConfig, answers: dict[str, Any], *, is_open: bool = True):
        self.name = "custom"
        self.config = cfg
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._tools = {n: _Tool(n, a, self.calls) for n, a in answers.items()}
        self.is_open = is_open
        self.opened: list[str] = []
        self.closed = 0
        self.sample_notes: Any = None
        self.note_key = "custom-note"
        self.server_instructions = ""
        self.guard = object()

    def advertised_tool(self, name: str) -> Any:
        return self._tools.get(name)

    def tools(self) -> list[Any]:
        return list(self._tools.values())

    def open(self, key: str, **_kw: Any) -> None:
        self.opened.append(key)
        self.is_open = True

    def close(self) -> None:
        self.closed += 1
        self.is_open = False


def _provider(answers: dict[str, Any], *, is_open: bool = True, **block: Any):
    cfg = MCPServerConfig(enabled=True, command="my-mcp", **block)
    handle = _Handle(cfg, answers, is_open=is_open)
    provider = GenericMCPStaticProvider(cfg, label="Custom")
    provider._handle = handle  # type: ignore[assignment]
    return provider, handle


# -- nothing declared: exactly as before -------------------------------------


def test_a_server_that_declares_no_pass_tool_answers_none_for_every_pass() -> None:
    provider, handle = _provider({"get_call_graph": "a -> b"})
    assert provider.capabilities.provides_function_hashes is False
    assert provider.call_graph(MIRROR) is None
    assert provider.priority_functions(MIRROR) is None
    assert provider.function_hashes(StaticJobContext(mirror_sample_path=MIRROR)) == []
    assert provider.anti_analysis_scan(StaticJobContext(mirror_sample_path=MIRROR)) is None
    assert handle.calls == [] and handle.opened == []


def test_the_block_field_is_unset_by_default() -> None:
    assert MCPServerConfig().prepass_tools is None
    with pytest.raises(ValueError, match="prepass_tools.call_graph"):
        PrepassToolsConfig(call_graph=" padded ")


# -- the call graph ------------------------------------------------------------


def test_a_declared_call_graph_tool_answering_edge_lines_feeds_the_pre_pass() -> None:
    lines = "FUN_00401000 -> CreateRemoteThread\nFUN_00401000 -> FUN_00402000\nnot an edge\n"
    provider, handle = _provider(
        {"whole_graph": lines},
        prepass_tools={"call_graph": "whole_graph"},
        auto_name_prefixes=["FUN_"],
    )
    graph = provider.call_graph(MIRROR)
    assert graph is not None
    assert graph.callees["FUN_00401000"] == {"CreateRemoteThread", "FUN_00402000"}
    assert graph.addresses["FUN_00401000"] == "0x00401000"
    assert handle.calls == [("whole_graph", {})]
    ranked = provider.priority_functions(MIRROR)
    assert ranked is not None and [f.name for f in ranked] == ["FUN_00401000"]


def test_a_call_graph_answer_is_read_by_the_tool_s_declared_rows_and_arguments() -> None:
    answer = json.dumps(
        {"calls": [{"from": {"name": "main", "at": "0x1000"}, "to": "VirtualAlloc"}]}
    )
    provider, handle = _provider(
        {"graph": answer},
        prepass_tools={"call_graph": "graph"},
        tool_facts={
            "graph": {
                "kind": "call_graph",
                "rows": "/calls/*",
                "values": {"caller": "/from/name", "callee": "/to"},
                "places": {"address": "/from/at"},
                "arguments": {"path": "file"},
            }
        },
    )
    graph = provider.call_graph(MIRROR)
    assert graph is not None
    assert graph.callees == {"main": frozenset({"VirtualAlloc"})}
    assert graph.addresses == {"main": "0x1000"}
    assert handle.calls == [("graph", {"file": MIRROR})]


def test_a_program_argument_is_given_the_name_the_declared_open_gave() -> None:
    provider, handle = _provider(
        {
            "load": json.dumps({"program": "abc.exe-1"}),
            "graph": "main -> WinExec",
        },
        prepass_tools={"call_graph": "graph"},
        sample_open={"open_tool": "load", "path_argument": "file", "name_field": "program"},
        tool_facts={"graph": {"kind": "call_graph", "arguments": {"program": "program"}}},
    )
    graph = provider.call_graph(MIRROR)
    assert graph is not None and graph.callees == {"main": frozenset({"WinExec"})}
    assert handle.calls == [("load", {"file": MIRROR}), ("graph", {"program": "abc.exe-1"})]


def test_a_declared_argument_with_no_value_makes_no_call() -> None:
    provider, handle = _provider(
        {"graph": "a -> b"},
        prepass_tools={"call_graph": "graph"},
        tool_facts={"graph": {"kind": "call_graph", "arguments": {"program": "program"}}},
    )
    assert provider.call_graph(MIRROR) is None
    assert handle.calls == []


def test_a_refused_call_graph_is_no_hint() -> None:
    provider, _handle = _provider(
        {"graph": json.dumps({"error": "no program open"})},
        prepass_tools={"call_graph": "graph"},
    )
    assert provider.priority_functions(MIRROR) is None


# -- function hashes -------------------------------------------------------------


def test_declared_function_hashes_are_read_by_rows_and_said_as_a_capability() -> None:
    answer = json.dumps(
        {
            "functions": [
                {"name": "f1", "hash": "aa"},
                {"name": "f1", "hash": "aa"},
                {"address": "0x2000", "hash": "bb"},
                {"name": "f3"},
            ]
        }
    )
    provider, handle = _provider(
        {"hashes": answer},
        prepass_tools={"function_hashes": "hashes"},
        tool_facts={"hashes": {"kind": "function_hashes", "rows": "/functions/*"}},
    )
    assert provider.capabilities.provides_function_hashes is True
    pairs = provider.function_hashes(StaticJobContext(mirror_sample_path=MIRROR))
    assert list(pairs) == [("f1", "aa"), ("0x2000", "bb")]
    assert getattr(pairs, "unavailable", "") == ""


def test_a_refused_hash_read_says_why_rather_than_reading_as_no_function() -> None:
    provider, _handle = _provider(
        {"hashes": json.dumps({"error": "not analysed"})},
        prepass_tools={"function_hashes": "hashes"},
    )
    pairs = provider.function_hashes(StaticJobContext(mirror_sample_path=MIRROR))
    assert list(pairs) == []
    assert "not analysed" in pairs.unavailable


# -- attaching for a pass ----------------------------------------------------------


def test_a_pass_before_any_attach_attaches_the_server_and_lets_it_go_after() -> None:
    provider, handle = _provider(
        {"hashes": json.dumps([{"name": "f", "hash": "cc"}])},
        is_open=False,
        prepass_tools={"function_hashes": "hashes"},
    )
    pairs = provider.function_hashes(StaticJobContext(mirror_sample_path=MIRROR, job_key="j1"))
    assert list(pairs) == [("f", "cc")]
    assert handle.opened == ["j1"] and handle.closed == 1 and not handle.is_open


def test_an_attached_server_is_left_attached_after_a_pass() -> None:
    provider, handle = _provider({"graph": "a -> b"}, prepass_tools={"call_graph": "graph"})
    provider.call_graph(MIRROR)
    assert handle.opened == [] and handle.closed == 0 and handle.is_open


# -- the anti-analysis scan ----------------------------------------------------------


def test_a_declared_scan_states_its_exact_part_in_the_pack_s_shape() -> None:
    answer = json.dumps(
        {
            "matches": [
                {"kind": "suspicious_instruction", "rule": "RDTSC", "insn": "RDTSC", "at": "0x10"},
                {"kind": "suspicious_instruction", "rule": "RDTSC", "insn": "RDTSC", "at": "0x10"},
                {"kind": "api_call", "rule": "IsDebuggerPresent", "at": "0x20"},
            ]
        }
    )
    provider, handle = _provider(
        {"scan": answer},
        is_open=False,
        prepass_tools={"anti_analysis": "scan"},
        tool_facts={
            "scan": {
                "kind": "anti_analysis_scan",
                "rows": "/matches/*",
                "values": {"category": "/kind", "technique": "/rule", "instruction": "/insn"},
                "places": {"offset": "/at"},
                "routed_formats": ["pe"],
                "arguments": {"path": "file"},
            }
        },
    )
    scan = provider.anti_analysis_scan(StaticJobContext(mirror_sample_path=MIRROR))
    assert scan is not None and scan.unavailable == ""
    assert scan.formats == frozenset({"pe"})
    assert handle.calls == [], "the scan is made by the pack, not when it is handed over"
    data = scan.anti_analysis()
    assert data["server"] == provider.id and data["tool"] == "scan"
    assert data["stated"] == [
        {"category": "suspicious_instruction", "what": "RDTSC", "offset": "0x10"}
    ]
    assert data["not_stated"] == 1 and data["beside_capa"] == []
    assert handle.calls == [("scan", {"file": MIRROR})]
    assert handle.closed == 1
    scan.close()


def test_a_declared_scan_with_no_copy_of_the_sample_says_why() -> None:
    provider, handle = _provider({"scan": "[]"}, prepass_tools={"anti_analysis": "scan"})
    scan = provider.anti_analysis_scan(StaticJobContext())
    assert scan is not None and scan.unavailable
    assert handle.calls == []


def test_a_failed_declared_scan_raises_a_pass_failure() -> None:
    from maljan.analysis.anti_analysis import PassFailed

    provider, _handle = _provider(
        {"scan": json.dumps({"error": "busy"})}, prepass_tools={"anti_analysis": "scan"}
    )
    scan = provider.anti_analysis_scan(StaticJobContext(mirror_sample_path=MIRROR))
    assert scan is not None
    with pytest.raises(PassFailed, match="busy"):
        scan.anti_analysis()


# -- the readers on their own ------------------------------------------------------


def test_the_readers_take_the_row_s_own_keys_where_nothing_is_declared() -> None:
    assert call_graph_of([["a", "b"], {"caller": "a", "callee": "c"}], None).callees == {
        "a": frozenset({"b", "c"})
    }
    assert function_hashes_of([{"function": "f", "hash": "h"}], None) == [("f", "h")]
    assert scan_findings({"not": "a list"}, None) == []


# -- T-130: the served instructions ---------------------------------------------------


def test_a_server_s_served_instructions_stand_in_for_the_generated_paragraph() -> None:
    provider, handle = _provider({"scan_it": "{}"})
    handle.server_instructions = 'Open first.\nThen call "scan_it".'
    workflow = provider.workflow_fragment()
    assert "TOOL USAGE WORKFLOW" not in workflow
    assert "declares no workflow of its own" in workflow
    assert '"Open first. Then call \\"scan_it\\"."' in workflow
    assert '"scan_it": "What scan_it does."' in workflow


def test_a_server_that_served_no_instructions_keeps_the_generated_paragraph() -> None:
    provider, _handle = _provider({"scan_it": "{}"})
    workflow = provider.workflow_fragment()
    assert workflow.startswith("=== TOOL USAGE WORKFLOW ===\nAvailable tools: `scan_it`.")


def test_a_declared_workflow_still_comes_before_the_served_instructions() -> None:
    provider, handle = _provider({"scan_it": "{}"}, prompt_fragment="Do it my way.")
    handle.server_instructions = "Do it the server's way."
    assert provider.workflow_fragment() == "Do it my way."


# -- the review's fix round -------------------------------------------------------

_OPEN = {"open_tool": "load", "path_argument": "file", "name_field": "program"}
_BY_PROGRAM = {"kind": "call_graph", "arguments": {"program": "program"}}


def test_three_empty_names_are_held_as_none_declared() -> None:
    assert MCPServerConfig(prepass_tools={}).prepass_tools is None
    assert MCPServerConfig(prepass_tools={"call_graph": ""}).prepass_tools is None
    held = MCPServerConfig(prepass_tools={"anti_analysis": "scan"}).prepass_tools
    assert held is not None and held.anti_analysis == "scan"


def test_a_pass_that_attached_the_server_leaves_no_open_in_the_job_s_note() -> None:
    from maljan.providers.sample_open import SampleNotes, SampleOpener

    provider, handle = _provider(
        {"load": json.dumps({"program": "abc.exe-1"}), "graph": "main -> WinExec"},
        is_open=False,
        prepass_tools={"call_graph": "graph"},
        sample_open=_OPEN,
        tool_facts={"graph": _BY_PROGRAM},
    )
    notes = SampleNotes()
    handle.sample_notes = notes
    assert provider.call_graph(MIRROR) is not None
    assert handle.closed == 1
    opener = SampleOpener(handle.note_key, provider._cfg.sample_open, notes)
    assert opener.name_of(MIRROR) is None
    # The analyst's later attach is a new process: its open loads the sample again.
    handle.open("job")
    handle.calls.clear()
    opener.open(MIRROR, lambda tool, args: json.dumps({"program": "abc.exe-2"}), held=MIRROR)
    assert opener.name_of(MIRROR) == "abc.exe-2"


def test_a_pass_on_an_attached_server_notes_its_open_in_the_job_s_note() -> None:
    from maljan.providers.sample_open import SampleNotes, SampleOpener

    provider, handle = _provider(
        {"load": json.dumps({"program": "abc.exe-1"}), "graph": "main -> WinExec"},
        prepass_tools={"call_graph": "graph"},
        sample_open=_OPEN,
        tool_facts={"graph": _BY_PROGRAM},
    )
    notes = SampleNotes()
    handle.sample_notes = notes
    provider.call_graph(MIRROR)
    opener = SampleOpener(handle.note_key, provider._cfg.sample_open, notes)
    assert opener.name_of(MIRROR) == "abc.exe-1"


_REFUSED = json.dumps({"error": "file is not a program it can load"})


def test_a_refused_open_is_said_where_a_pass_needs_the_program() -> None:
    from maljan.analysis.anti_analysis import PassFailed

    provider, handle = _provider(
        {"load": _REFUSED, "graph": "a -> b", "hashes": "[]", "scan": "[]"},
        prepass_tools={"call_graph": "graph", "function_hashes": "hashes", "anti_analysis": "scan"},
        sample_open=_OPEN,
        tool_facts={
            "graph": _BY_PROGRAM,
            "hashes": {"kind": "function_hashes", "arguments": {"program": "program"}},
            "scan": {"kind": "anti_analysis_scan", "arguments": {"program": "program"}},
        },
    )
    assert provider.priority_functions(MIRROR) is None
    pairs = provider.function_hashes(StaticJobContext(mirror_sample_path=MIRROR))
    assert list(pairs) == []
    assert "refused to open" in pairs.unavailable
    assert "file is not a program it can load" in pairs.unavailable
    scan = provider.anti_analysis_scan(StaticJobContext(mirror_sample_path=MIRROR))
    assert scan is not None
    with pytest.raises(PassFailed, match="file is not a program it can load"):
        scan.anti_analysis()
    assert all(name == "load" for name, _args in handle.calls)


def test_a_tool_named_by_its_path_alone_opens_nothing_first() -> None:
    provider, handle = _provider(
        {"load": json.dumps({"program": "abc.exe-1"}), "graph": "a -> b"},
        prepass_tools={"call_graph": "graph"},
        sample_open=_OPEN,
        tool_facts={"graph": {"kind": "call_graph", "arguments": {"path": "file"}}},
    )
    assert provider.call_graph(MIRROR) is not None
    assert handle.calls == [("graph", {"file": MIRROR})]


def test_a_tool_that_names_no_argument_has_the_sample_opened_first() -> None:
    provider, handle = _provider(
        {"load": json.dumps({"program": "abc.exe-1"}), "graph": "a -> b"},
        prepass_tools={"call_graph": "graph"},
        sample_open=_OPEN,
    )
    assert provider.call_graph(MIRROR) is not None
    assert handle.calls == [("load", {"file": MIRROR}), ("graph", {})]
