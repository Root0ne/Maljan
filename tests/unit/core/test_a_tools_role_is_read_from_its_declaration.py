"""What a tool is for is read from what it declares; its name is read only when it declares nothing.

Role (decompiler, code listing, cross-references, strings), the tag its
description is shown with, the argument it takes an address in, the prefixes
its server's decompiler names functions with, the capture tools a network
turn offers, and the sandbox sections a report names unavailable: each is
read from the declaration, with ``core.undeclared_tools`` the one place the
name heuristics remain, for an undeclared tool.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.core import undeclared_tools as roles
from maljan.core.config import Settings
from maljan.core.tool_declarations import ToolFacts


class _Args(BaseModel):
    address: str = ""


def _tool(name: str, server: str = "") -> Any:
    async def _run(**_: object) -> str:
        return ""

    tool = StructuredTool.from_function(
        func=None, coroutine=_run, name=name, description=name, args_schema=_Args
    )
    if server:
        tool = tool.model_copy(update={"metadata": {"maljan_server": server}})
    return tool


def _facts(kind: str, **more: Any) -> ToolFacts:
    return ToolFacts.model_validate({"kind": kind, **more})


class TestRoles:
    def test_a_declared_decompiler_of_any_name_decompiles(self) -> None:
        assert roles.decompiles(_facts("decompile"), "pseudo_c")
        assert not roles.decompiles(_facts("program_edit"), "set_decompiler_comment")

    def test_an_undeclared_tool_is_read_by_its_name(self) -> None:
        assert roles.decompiles(None, "my_decompile_fn")
        assert roles.lists_code(None, "disassemble_range")
        assert roles.lists_a_function(None, "disassemble_function")
        assert roles.reads_xrefs(None, "find_xrefs")
        assert roles.is_strings_source(None, "dump_strings")

    def test_a_declared_strings_tool_of_any_name_is_a_strings_source(self) -> None:
        for kind in ("strings", "emulated_strings", "decoded_strings", "listing_strings"):
            assert roles.is_strings_source(_facts(kind), "dump_text")
        assert not roles.is_strings_source(_facts("analysis"), "find_undocumented_by_string")

    def test_a_listing_of_a_whole_function(self) -> None:
        assert roles.lists_a_function(_facts("function_disassembly"), "pdf_at")
        assert roles.lists_code(_facts("byte_disassembly"), "bytes_as_code")
        assert not roles.lists_a_function(_facts("byte_disassembly"), "bytes_as_code")

    def test_the_prompt_reads_an_offered_tool_by_its_declared_kind(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import prompt_fragments, tool_pinning

        declared = {"pseudo_c": _facts("decompile"), "who_calls": _facts("xrefs")}
        monkeypatch.setattr(
            tool_pinning,
            "declared_facts_of",
            lambda tool: declared.get(str(getattr(tool, "name", ""))),
        )
        tools = [_tool("pseudo_c", "rev"), _tool("who_calls", "rev")]
        assert prompt_fragments.has_decompiler(tools)
        assert prompt_fragments.has_xrefs(tools)
        assert not prompt_fragments.has_decompiler([_tool("plain", "rev")])


class TestTheDescriptionTag:
    def test_a_declared_category_wins_over_the_name(self) -> None:
        from maljan.agents.mcp_client import MCPLangChainToolkit

        toolkit = MCPLangChainToolkit(categories={"get_thing": "analyze"})
        assert toolkit._tag_description("get_thing", "x") == "[ANALYZE] x"
        assert toolkit._tag_description("get_other", "x") == "[LIST] x"
        assert toolkit._tag_description("zap", "x") == "[TOOL] x"


class TestAddressArguments:
    def test_the_declared_argument_is_read_first(self) -> None:
        facts = _facts("decompile", arguments={"address": "offset_va"})
        assert roles.address_arguments(facts)[0] == "offset_va"
        assert "address" in roles.address_arguments(facts)

    def test_an_undeclared_tool_reads_the_shared_list(self) -> None:
        assert roles.address_arguments(None) == roles.ADDRESS_ARGUMENTS
        # A page's first row is not an address.
        assert "start" not in roles.ADDRESS_ARGUMENTS

    def test_a_decompile_given_its_address_under_a_declared_name_is_placed(self) -> None:
        from maljan.pipeline.validation import decompiled_functions

        entry = SimpleNamespace(
            id="ev_0001",
            tool="pseudo_c",
            ok=True,
            args={"offset_va": "0x401000"},
            output="int f(void) { return 0; }",
            repeated_of=None,
            source="mcp:rev",
            facts={"v": 1, "kind": "decompile", "arguments": {"address": "offset_va"}},
        )
        (function,) = decompiled_functions([entry])
        assert function.address == 0x401000

    def test_the_stored_facts_carry_the_declared_arguments(self) -> None:
        from maljan.core.declared_reading import stored_record

        record = stored_record(_facts("decompile", arguments={"address": "offset_va"}))
        assert record["arguments"] == {"address": "offset_va"}


class TestAutoNames:
    def test_the_defaults_read_every_built_in_prefix(self) -> None:
        pattern = roles.auto_name_pattern()
        for name in ("FUN_00401000", "fcn.00401000", "sub_401000", "LAB_00401000"):
            assert pattern.fullmatch(name), name

    def test_a_declared_prefix_joins_them(self) -> None:
        words = roles.auto_name_words(["PROC_"])
        assert words[-1] == "proc" and words[: len(roles.DEFAULT_AUTO_NAME_WORDS)] == (
            roles.DEFAULT_AUTO_NAME_WORDS
        )
        assert roles.auto_name_pattern(words).fullmatch("PROC_00401000").group(1) == "00401000"
        assert not roles.auto_name_pattern().fullmatch("PROC_00401000")

    def test_the_run_reads_every_prefix_its_servers_declare(self) -> None:
        settings = Settings.model_validate(
            {"mcp": {"servers": {"rev": {"command": "x", "auto_name_prefixes": ["PROC_"]}}}}
        )
        assert roles.declared_auto_name_pattern(settings).fullmatch("proc_401000")

    def test_reading_is_linear_in_the_text(self) -> None:
        import time

        pattern = roles.auto_name_pattern(roles.auto_name_words(["PROC_", "ROUTINE."]))

        def best(n: int) -> float:
            text = "FUN_ " * n + "proc_" * n
            times = []
            for _ in range(3):
                start = time.perf_counter()
                list(pattern.finditer(text))
                times.append(time.perf_counter() - start)
            return min(times)

        assert best(20000) <= best(2000) * 10 * 2.5 + 0.05


class TestCaptureTools:
    def test_a_capture_tool_is_offered_by_its_declared_kind_under_its_own_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import network_analyst, tool_pinning

        declared = {"pkt_overview": _facts("packet_overview"), "dns_names": _facts("dns")}
        monkeypatch.setattr(
            tool_pinning,
            "declared_facts_of",
            lambda tool: declared.get(str(getattr(tool, "name", ""))),
        )
        tools = [_tool("dns_names", "cap"), _tool("pkt_overview", "cap"), _tool("x", "cap")]
        assert network_analyst._pcap_tools_in(tools) == [
            ("pkt_overview", "get packet overview"),
            ("dns_names", "extract all DNS queries"),
        ]

    def test_the_built_in_capture_server_is_offered_as_before(self) -> None:
        from maljan.agents import network_analyst

        tools = [
            _tool(name, "network") for name in ("extract_http", "read_pcap_summary", "extract_dns")
        ]
        assert [name for name, _ in network_analyst._pcap_tools_in(tools)] == [
            "read_pcap_summary",
            "extract_dns",
            "extract_http",
        ]


class TestUnavailableSections:
    def test_new_reports_name_the_platforms_section_ids(self) -> None:
        from maljan.providers.sandbox.triage import TriageSandboxProvider
        from maljan.schemas.sandbox_report import SECTION_IDS

        assert set(TriageSandboxProvider.UNAVAILABLE) == set(SECTION_IDS)

    def test_a_stored_report_s_own_words_are_read_through_the_legacy_map(self) -> None:
        from maljan.analysis.sandbox_sections import Sections
        from maljan.schemas.sandbox_report import section_id

        assert section_id("calls") == "api_calls" and section_id("generic_events") == "events"
        stored = Sections(
            {"behavior": {}, "unavailable": ["apistats", "calls", "registry", "generic_events"]}
        )
        for name in ("api_calls", "events", "apistats", "registry"):
            assert stored.sections[name].no, name
            assert f"`{name}`" in stored.sections[name].no
