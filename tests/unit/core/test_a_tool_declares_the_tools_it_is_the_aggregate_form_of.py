"""A tool declares the tools of its server it is the aggregate (combined) form of.

``ToolFacts.aggregate_of`` is data any server block may carry: each name is a
tool of the same server, refused on save where it is not one and read without
it, with a warning, where a stored block names one. The model is shown the
fact after the tool's description, written once the names a request offers
are settled, so it can choose one call over many; a tool that declares none
is shown and called exactly as before. Ghidra's batch and whole-program tools
are read as the aggregate forms they are from what Ghidra lists
(``core.program_reading``), and the static workflows leave the number of
functions to decompile to the model.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any

import pytest
from langchain_core.tools import StructuredTool
from pydantic import ValidationError

from maljan.core.builtin_declarations import GHIDRA_WORKFLOW, R2_WORKFLOW
from maljan.core.config import MCPServerConfig, Settings
from maljan.core.tool_declarations import (
    KIND_FREE_FIELDS,
    ToolDeclarations,
    ToolFacts,
    aggregate_reference_errors,
    changed_declaration_errors,
    declaration_digest,
    strict_declarations,
)
from maljan.core.undeclared_tools import aggregate_note, aggregates_of, with_aggregate_notes


def _tool(name: str, description: str = "") -> StructuredTool:
    return StructuredTool.from_function(
        func=lambda: "ok", name=name, description=description or f"[TOOL] {name}."
    )


@pytest.fixture(scope="module")
def ghidra() -> dict[str, ToolFacts]:
    # As the platform reads them: from what Ghidra lists, under its block.
    held = ToolDeclarations.from_settings(Settings()).source("provider:ghidra")
    assert held is not None
    return dict(held.tools)


class TestTheField:
    def test_it_is_read_without_a_kind(self) -> None:
        assert "aggregate_of" in KIND_FREE_FIELDS
        with strict_declarations():
            facts = ToolFacts.model_validate({"aggregate_of": ["decompile"]})
        assert facts.aggregate_of == ("decompile",)
        assert facts.kind == ""

    def test_a_name_named_twice_or_not_a_tool_name_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="more than once"):
            ToolFacts.model_validate({"aggregate_of": ["one", "one"]})
        with pytest.raises(ValidationError):
            ToolFacts.model_validate({"aggregate_of": [""]})

    def test_a_declaration_without_it_holds_none(self) -> None:
        assert ToolFacts.model_validate({"kind": "decompile"}).aggregate_of == ()


class TestTheReferences:
    def test_a_name_no_tool_of_the_server_has_is_refused_on_save(self) -> None:
        sent = {"many": {"aggregate_of": ["one", "ghost"]}, "one": {"category": "list"}}
        errors = changed_declaration_errors(sent)
        assert list(errors) == ["many.aggregate_of"]
        message = errors["many.aggregate_of"]
        assert "'ghost'" in message and "not a tool of this server" in message
        # The way out keeps every other tool at full strength: no allow-list.
        assert message.endswith("declare each in tool_facts (e.g. its category)")
        assert "list it in tools" not in message

    def test_a_tool_the_allow_list_names_is_a_tool_of_the_server(self) -> None:
        sent = {"many": {"aggregate_of": ["one"]}}
        assert changed_declaration_errors(sent, tools=["one", "many"]) == {}
        assert "many.aggregate_of" in changed_declaration_errors(sent, tools=["other"])

    def test_a_tool_is_not_the_aggregate_form_of_itself(self) -> None:
        errors = aggregate_reference_errors({"many": {"aggregate_of": ["many"]}})
        assert errors == {"many.aggregate_of": "a tool is not the aggregate form of itself"}

    def test_two_tools_are_not_each_the_aggregate_form_of_the_other(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        pair = {"a": {"aggregate_of": ["b"]}, "b": {"aggregate_of": ["a"]}}
        errors = changed_declaration_errors(pair)
        assert set(errors) == {"a.aggregate_of", "b.aggregate_of"}
        assert "declares itself the aggregate form of 'a'" in errors["a.aggregate_of"]
        caplog.set_level(logging.WARNING)
        cfg = MCPServerConfig.model_validate({"tool_facts": pair})
        assert cfg.tool_facts["a"].aggregate_of == ()
        assert cfg.tool_facts["b"].aggregate_of == ()

    def test_an_unchanged_stored_declaration_never_blocks_a_save(self) -> None:
        stored = {"many": {"aggregate_of": ["ghost"]}}
        sent = {**stored, "other": {"category": "list"}}
        assert changed_declaration_errors(sent, [stored]) == {}

    def test_a_stored_block_is_read_without_the_unknown_name(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.WARNING)
        cfg = MCPServerConfig.model_validate(
            {"tool_facts": {"many": {"aggregate_of": ["one", "ghost"]}, "one": {"category": "x"}}}
        )
        assert cfg.tool_facts["many"].aggregate_of == ("one",)
        assert cfg.model_fields_set == {"tool_facts"}
        assert any("ghost" in record.getMessage() for record in caplog.records)


class TestTheSavePathsReadTheAllowListInForce:
    def test_the_server_map_refuses_it_naming_the_field(self) -> None:
        from app.services.server_map import ServerMapError, validate_server_map

        entry = {
            "transport": "stdio",
            "command": "x",
            "tool_facts": {"many": {"aggregate_of": ["ghost"]}},
        }
        with pytest.raises(ServerMapError) as raised:
            validate_server_map({"custom": entry})
        assert "custom.tool_facts.many.aggregate_of" in raised.value.errors
        listed = {**entry, "tools": ["many", "ghost"]}
        assert "custom" in validate_server_map({"custom": listed})

    def test_the_server_map_reads_the_stored_allow_list_when_none_is_sent(self) -> None:
        from app.services.server_map import validate_server_map

        stored = {"custom": {"transport": "stdio", "command": "x", "tools": ["many", "one"]}}
        sent = {
            "custom": {
                "transport": "stdio",
                "command": "x",
                "tool_facts": {"many": {"aggregate_of": ["one"]}},
            }
        }
        assert "custom" in validate_server_map(sent, stored=stored)

    def test_a_provider_leaf_reads_the_block_s_allow_list(self) -> None:
        from app.services.settings_service import changed_declaration_refusals

        leaf = "core.static.ghidra.tool_facts"
        change = {leaf: {"many_more": {"aggregate_of": ["not_ghidra_s"]}}}
        assert f"{leaf}.many_more.aggregate_of" in changed_declaration_refusals(change, {})
        listed = {**change, "core.static.ghidra.tools": ["not_ghidra_s", "many_more"]}
        assert changed_declaration_refusals(listed, {}) == {}
        stored = {"core.static.ghidra.tools": ["not_ghidra_s", "many_more"]}
        assert changed_declaration_refusals(change, stored) == {}


class TestGhidraDeclaresItsAggregates:
    def test_each_names_a_ghidra_tool(self, ghidra: dict[str, ToolFacts]) -> None:
        held = aggregates_of(ghidra)
        assert held["batch_decompile"] == ("decompile_function",)
        assert held["get_bulk_function_hashes"] == ("get_function_hash",)
        assert held["get_full_call_graph"] == ("get_function_call_graph",)
        for tool, names in held.items():
            assert tool not in names
            assert set(names) <= set(ghidra), tool

    def test_a_batch_that_is_not_one_tools_declares_none(
        self, ghidra: dict[str, ToolFacts]
    ) -> None:
        # Its definition does not say references to or from each address.
        assert ghidra["get_bulk_xrefs"].aggregate_of == ()
        r2 = ToolDeclarations.from_settings(Settings()).source("provider:r2")
        assert r2 is not None and aggregates_of(dict(r2.tools)) == {}


class TestTheModelIsShownIt:
    def test_the_note_follows_the_description(self) -> None:
        tools = [_tool("many", "[BATCH] Many at once."), _tool("one")]
        noted = with_aggregate_notes(tools, {"many": ("one",)}, {"many": "many", "one": "one"})
        assert noted[0].description == (
            "[BATCH] Many at once. Aggregate form of `one`: one call answers what many calls "
            "of it would."
        )
        assert noted[1] is tools[1]
        assert aggregate_note(("a", "b")).endswith("many calls of those would.")

    def test_a_tool_not_offered_is_left_out_of_the_note(self) -> None:
        tools = [_tool("many")]
        aggregates = {"many": ("one", "two")}
        noted = with_aggregate_notes(tools, aggregates, {"many": "many", "two": "two"})
        assert noted[0].description.endswith(
            "Aggregate form of `two`: one call answers what many calls of it would."
        )
        assert with_aggregate_notes(tools, aggregates, {"many": "many"})[0] is tools[0]

    def test_a_tool_with_no_description_gets_the_note_alone(self) -> None:
        tool = SimpleNamespace(name="many", description="")
        tool.model_copy = lambda update: SimpleNamespace(name="many", **update)  # type: ignore[attr-defined]
        noted = with_aggregate_notes([tool], {"many": ("one",)}, {"one": "one"})
        assert noted[0].description == aggregate_note(("one",))

    def test_the_registry_names_a_renamed_aggregated_tool_as_offered(self) -> None:
        from maljan.providers.servers import ServerRegistry

        registry = ServerRegistry(Settings(_env_file=None))
        tools: list[Any] = []
        claimed: dict[str, str] = {}
        registry.merge_tools("first", [_tool("one")], tools, claimed)
        registry.merge_tools(
            "x", [_tool("many"), _tool("one")], tools, claimed, aggregates={"many": ("one",)}
        )
        assert [t.name for t in tools] == ["one", "many", "x__one"]
        assert tools[1].description.endswith(aggregate_note(("x__one",)))
        assert tools[0].description == "[TOOL] one."

    def test_the_registry_leaves_a_tool_the_reference_did_not_pick_out(self) -> None:
        from maljan.providers.servers import ServerRegistry

        registry = ServerRegistry(Settings(_env_file=None))
        tools: list[Any] = []
        registry.merge_tools("x", [_tool("many")], tools, {}, aggregates={"many": ("one",)})
        assert tools[0].description == "[TOOL] many."

    def test_ghidra_s_attach_notes_its_offered_aggregates(
        self, ghidra: dict[str, ToolFacts]
    ) -> None:
        from maljan.providers.static.ghidra.provider import GhidraStaticProvider

        provider = object.__new__(GhidraStaticProvider)
        provider._cfg = SimpleNamespace(tool_facts=ghidra)
        tools = [_tool("batch_decompile"), _tool("decompile_function"), _tool("get_bulk_xrefs")]
        noted = provider._with_aggregate_notes(tools)
        assert noted[0].description.endswith(aggregate_note(("decompile_function",)))
        assert noted[1] is tools[1] and noted[2] is tools[2]

    def test_a_generic_server_s_quoted_words_never_carry_the_note(self) -> None:
        from maljan.providers.static.generic_mcp import GenericMCPStaticProvider

        tools = [_tool("many", "[BATCH] Its own words."), _tool("one")]
        handle = SimpleNamespace(
            name="custom",
            tools=lambda: list(tools),
            server_instructions="I read binaries.",
            config=SimpleNamespace(
                tool_facts={"many": ToolFacts(aggregate_of=("one",)), "one": ToolFacts()}
            ),
        )
        provider = object.__new__(GenericMCPStaticProvider)
        provider._handle = handle
        provider._cfg = SimpleNamespace(prompt_fragment="")
        assert provider.get_tools()[0].description.endswith(aggregate_note(("one",)))
        text = provider.workflow_fragment()
        assert "Its own words." in text
        assert "Aggregate form" not in text


class TestTheWorkflowsSetNoNumber:
    def test_no_count_of_functions_is_prescribed(self) -> None:
        for text in (GHIDRA_WORKFLOW, R2_WORKFLOW):
            assert "3–5" not in text and "3-5" not in text
        assert "`batch_decompile`" in GHIDRA_WORKFLOW
        assert "Large binaries may have 1000+ functions." in GHIDRA_WORKFLOW

    def test_a_generic_server_s_generated_workflow_sets_none(self) -> None:
        from maljan.providers.static.generic_mcp import GenericMCPStaticProvider

        handle = SimpleNamespace(
            name="custom", tools=lambda: [_tool("t")], server_instructions="", config=None
        )
        provider = object.__new__(GenericMCPStaticProvider)
        provider._handle = handle
        provider._cfg = SimpleNamespace(prompt_fragment="")
        text = provider.workflow_fragment()
        assert "the functions that matter for the question" in text
        assert "few most suspicious" not in text


class TestTheDigests:
    def test_a_block_whose_tools_declare_none_keeps_its_digest(self) -> None:
        plain = MCPServerConfig.model_validate({"tool_facts": {"a": {"category": "x"}}})
        spelled = MCPServerConfig.model_validate(
            {"tool_facts": {"a": {"category": "x", "aggregate_of": []}}}
        )
        declaring = MCPServerConfig.model_validate(
            {"tool_facts": {"a": {"category": "x", "aggregate_of": ["b"]}, "b": {"category": "x"}}}
        )
        assert declaration_digest(plain) == declaration_digest(spelled)
        assert declaration_digest(plain) != declaration_digest(declaring)

    def test_an_unchanged_built_in_keeps_dev_s_digest(self) -> None:
        # The knowledge server declares no aggregate; its digest as dev records it.
        # (The analysis server's moved when two of its tools declared what their
        # answers show and do not show.)
        # Its trust in its server's own declaration (T-418) moved its digest,
        # and so did its tool table's removal: the server declares its tools
        # itself (T-418 PR1b), so its block is its trust, roles and launch alone.
        settings = Settings(_env_file=None)
        assert settings.mcp.servers["knowledge"].trusts_served_declaration is True
        object.__setattr__(settings.mcp.servers["knowledge"], "trusts_served_declaration", False)
        digests = ToolDeclarations.from_settings(settings).digests()
        assert digests["mcp:knowledge"] == "b261c17f07e13ef9"
