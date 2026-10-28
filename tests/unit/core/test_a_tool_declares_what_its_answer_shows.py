"""A tool declares what its answer shows and what it does not show, and its notes are settled once.

``ToolFacts.shows`` / ``does_not_show`` are kind-free operator text any server
block may carry: one line each, refused on save with a line break and read
with it as a space where a stored block holds one. They are shown in the
console and the docs; the model is shown them after the tool's description
only while ``mcp.answer_scope_notes`` is on, which it is not by default, so
prompts stay as they were. The notes after a description (``aggregate_of``'s
and these) are settled once over an agent's whole tool list
(``servers.settle_tool_notes``), so a server's tool merged before the tool it
aggregates still names it (T-313), and a note naming a tool no longer offered
is taken off.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
from langchain_core.tools import StructuredTool
from pydantic import ValidationError

from maljan.agents.tool_pinning import DECLARED_NAME_METADATA_KEY, SERVER_METADATA_KEY
from maljan.core.config import MCPServerConfig, Settings
from maljan.core.tool_declarations import (
    DIGEST_OMITS_AT_DEFAULT,
    KIND_FREE_FIELDS,
    ToolDeclarations,
    ToolFacts,
    declaration_digest,
    strict_declarations,
)
from maljan.core.undeclared_tools import (
    OWN_DESCRIPTION_METADATA_KEY,
    aggregate_note,
    answer_scope_note,
    answer_scopes_of,
    with_aggregate_notes,
    with_declared_notes,
)
from maljan.providers.servers import ServerHandle, ServerRegistry, settle_tool_notes


def _tool(name: str, description: str = "", **metadata: Any) -> StructuredTool:
    return StructuredTool.from_function(
        func=lambda: "ok",
        name=name,
        description=description or f"[TOOL] {name}.",
        metadata=metadata or None,
    )


def _served(name: str, server: str = "x", declared: str = "") -> StructuredTool:
    meta: dict[str, Any] = {SERVER_METADATA_KEY: server}
    if declared:
        meta[DECLARED_NAME_METADATA_KEY] = declared
    return _tool(name, **meta)


def _settings(tool_facts: dict[str, Any], *, on: bool = False) -> Settings:
    entry = {"transport": "stdio", "command": "x", "tool_facts": tool_facts}
    return Settings(_env_file=None, mcp={"servers": {"x": entry}, "answer_scope_notes": on})


_SCOPED = {
    "many": {"aggregate_of": ["one"], "shows": "every function at once"},
    "one": {"category": "list", "shows": "one function", "does_not_show": "its callers"},
}


class TestTheFields:
    def test_they_are_read_without_a_kind(self) -> None:
        assert {"shows", "does_not_show"} <= set(KIND_FREE_FIELDS)
        with strict_declarations():
            facts = ToolFacts.model_validate({"shows": "a", "does_not_show": "b"})
        assert (facts.shows, facts.does_not_show, facts.kind) == ("a", "b", "")
        assert ToolFacts.model_validate({"kind": "strings"}).shows == ""

    def test_a_line_break_is_refused_on_save(self) -> None:
        with strict_declarations(), pytest.raises(ValidationError, match="one line of text"):
            ToolFacts.model_validate({"does_not_show": "a\nb"})

    @pytest.mark.parametrize("brk", ["\x85", "\u2028", "\u2029"])
    def test_a_unicode_line_break_is_refused_on_save_and_read_as_a_space(self, brk: str) -> None:
        with strict_declarations(), pytest.raises(ValidationError, match="one line of text"):
            ToolFacts.model_validate({"shows": f"a{brk}b"})
        held = ToolFacts.model_validate({"does_not_show": f"a{brk}b"})
        assert held.does_not_show == "a b"

    def test_a_stored_line_break_is_read_as_a_space(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.WARNING)
        facts = ToolFacts.model_validate({"shows": "a\n\tb"})
        assert facts.shows == "a b"
        assert any("line breaks" in record.getMessage() for record in caplog.records)

    def test_no_length_is_imposed(self) -> None:
        with strict_declarations():
            assert len(ToolFacts.model_validate({"shows": "w " * 2000}).shows) == 4000


class TestTheDigests:
    def test_a_block_that_declares_neither_keeps_its_digest(self) -> None:
        assert {"shows", "does_not_show"} <= set(DIGEST_OMITS_AT_DEFAULT)
        plain = MCPServerConfig.model_validate({"tool_facts": {"a": {"category": "x"}}})
        spelled = MCPServerConfig.model_validate(
            {"tool_facts": {"a": {"category": "x", "shows": "", "does_not_show": ""}}}
        )
        declaring = MCPServerConfig.model_validate(
            {"tool_facts": {"a": {"category": "x", "shows": "y"}}}
        )
        assert declaration_digest(plain) == declaration_digest(spelled)
        assert declaration_digest(plain) != declaration_digest(declaring)

    def test_the_built_ins_that_declare_neither_keep_dev_s_digests(self) -> None:
        # Each of the two servers' trust in its own declaration (T-418) moves
        # its digest; without it each block is as recorded below. Both moved
        # again when their tool tables went: each server declares its tools
        # itself (T-418 PR1b), these fields with them. Ghidra's moved when its
        # block declared its data-label prefix (``data_label_prefixes``, T-426),
        # and when its tools came to be read from its listing under its
        # block's statement (T-418 PR4).
        settings = Settings(_env_file=None)
        for key in ("knowledge", "network"):
            object.__setattr__(settings.mcp.servers[key], "trusts_served_declaration", False)
        digests = ToolDeclarations.from_settings(settings).digests()
        assert digests["mcp:knowledge"] == "b261c17f07e13ef9"
        assert digests["mcp:network"] == "7211e6023885a063"
        assert digests["provider:ghidra"] == "01e22fee1043d4c4"
        assert digests["sandbox"] == "c2bf77971e47dfa4"


class TestTheBuiltInsDeclare:
    def test_the_answers_whose_limits_are_material(self) -> None:
        from maljan.core.declared_reading import builtin_tools

        # As each server declares its tools (its own, kept from its listing).
        held = {
            key: answer_scopes_of(builtin_tools(key))
            for key in ("analysis", "threatintel", "virustotal", "knowledge", "network")
        }
        assert set(held["analysis"]) == {"strings", "capa"}
        assert "encrypted" in held["analysis"]["strings"][1]
        assert "whether the matched code runs" in held["analysis"]["capa"][1]
        assert held["analysis"]["capa"][0].endswith("the file, its code and its structure")
        assert "shorter than min_len" in held["analysis"]["strings"][1]
        assert "(read next_offset)" in held["analysis"]["strings"][1]
        assert set(held["threatintel"]) == {
            "check_hash",
            "check_ip_reputation",
            "check_domain_reputation",
        }
        assert "whether the sample contacts" in held["threatintel"]["check_ip_reputation"][1]
        assert "no evidence that the file is clean" in held["virustotal"]["get_file_report"][1]
        assert held["knowledge"] == {} and held["network"] == {}
        for scopes in held.values():
            for shows, hidden in scopes.values():
                assert shows and hidden and "\n" not in shows + hidden

    def test_the_switch_is_off_by_default(self) -> None:
        assert Settings(_env_file=None).mcp.answer_scope_notes is False


class TestTheNote:
    def test_it_reads_as_two_sentences(self) -> None:
        assert answer_scope_note("a", "b.") == "This answer shows: a. It does not show: b."
        assert answer_scope_note("", "b") == "It does not show: b."
        assert answer_scope_note(" ", "") == ""

    def test_it_follows_the_aggregate_note(self) -> None:
        tools = [_tool("many", "[BATCH] All."), _tool("one")]
        noted = with_declared_notes(
            tools,
            {"many": ("one",)},
            {"many": "many", "one": "one"},
            scopes={"many": ("all of them", "")},
        )
        assert noted[0].description == (
            f"[BATCH] All. {aggregate_note(('one',))} This answer shows: all of them."
        )
        assert noted[0].metadata[OWN_DESCRIPTION_METADATA_KEY] == "[BATCH] All."
        assert noted[1] is tools[1]

    def test_settling_again_replaces_the_notes_and_never_repeats_them(self) -> None:
        tools = [_tool("many"), _tool("one")]
        offered = {"many": "many", "one": "one"}
        once = with_aggregate_notes(tools, {"many": ("one",)}, offered)
        twice = with_aggregate_notes(once, {"many": ("one",)}, offered)
        assert twice[0].description == once[0].description
        assert twice[0] is once[0]
        # Narrowed: the note naming a tool no longer offered is taken off.
        narrowed = with_aggregate_notes(once[:1], {"many": ("one",)}, {"many": "many"})
        assert narrowed[0].description == "[TOOL] many."
        assert OWN_DESCRIPTION_METADATA_KEY not in (narrowed[0].metadata or {})


class TestTheSwitch:
    def test_off_no_scope_note_reaches_a_description(self) -> None:
        tools = [_served("one")]
        settled = settle_tool_notes(tools, _settings(_SCOPED))
        assert settled[0] is tools[0]
        assert settled[0].description == "[TOOL] one."

    def test_on_each_declared_tool_carries_it(self) -> None:
        settled = settle_tool_notes([_served("one"), _served("many")], _settings(_SCOPED, on=True))
        assert settled[0].description == (
            "[TOOL] one. This answer shows: one function. It does not show: its callers."
        )
        assert settled[1].description == (
            f"[TOOL] many. {aggregate_note(('one',))} This answer shows: every function at once."
        )

    def test_an_undeclared_tool_is_shown_as_before_either_way(self) -> None:
        tools = [_served("other"), _tool("in_process")]
        settled = settle_tool_notes(tools, _settings(_SCOPED, on=True))
        assert settled[0] is tools[0] and settled[1] is tools[1]


class TestTheNotesAreSettledOverTheWholeList:
    """T-313: the aggregate note does not depend on the order a server's tools arrived in."""

    def test_a_tool_merged_before_the_one_it_aggregates_names_it(self) -> None:
        settings = _settings(_SCOPED)
        registry = ServerRegistry(settings)
        tools: list[Any] = []
        seen: dict[str, str] = {}
        aggregates = {"many": ("one",)}
        registry.merge_tools("x", [_tool("many")], tools, seen, aggregates=aggregates)
        registry.merge_tools("x", [_tool("one")], tools, seen, aggregates=aggregates)
        # Merged in two halves, ``many`` was written before ``one`` was offered.
        assert tools[0].description == "[TOOL] many."
        settled = settle_tool_notes(tools, settings)
        assert settled[0].description.endswith(aggregate_note(("one",)))
        assert settled[1] is tools[1]

    def test_a_renamed_aggregated_tool_is_named_as_offered(self) -> None:
        settled = settle_tool_notes(
            [_served("many"), _served("x__one", declared="one")], _settings(_SCOPED)
        )
        assert settled[0].description.endswith(aggregate_note(("x__one",)))

    def test_a_note_naming_a_tool_no_longer_offered_is_taken_off(self) -> None:
        settings = _settings(_SCOPED)
        full = settle_tool_notes([_served("many"), _served("one")], settings)
        assert "Aggregate form" in full[0].description
        narrowed = settle_tool_notes(full[:1], settings)
        assert narrowed[0].description == "[TOOL] many."

    def test_a_delivery_tool_is_never_named(self) -> None:
        settings = _settings({"put_sample": {"aggregate_of": ["put_sample_chunk"]}})
        settled = settle_tool_notes([_served("put_sample"), _served("put_sample_chunk")], settings)
        assert settled[0].description == "[TOOL] put_sample."
        # Read by the name it is declared under, not the one it is offered under.
        renamed = settle_tool_notes(
            [_served("put_sample"), _served("x__put_sample_chunk", declared="put_sample_chunk")],
            settings,
        )
        assert renamed[0].description == "[TOOL] put_sample."

    def test_a_provider_s_note_is_recomputed_over_what_the_agent_is_offered(self) -> None:
        settings = Settings(_env_file=None)
        stamp = {"maljan_declared_source": "provider:ghidra"}
        tools = [_tool("batch_decompile", **stamp), _tool("decompile_function", **stamp)]
        offered = {"batch_decompile": "batch_decompile", "decompile_function": "decompile_function"}
        attached = with_aggregate_notes(
            tools, {"batch_decompile": ("decompile_function",)}, offered
        )
        settled = settle_tool_notes(attached, settings)
        assert settled[0] is attached[0]
        assert settle_tool_notes(attached[:1], settings)[0].description == "[TOOL] batch_decompile."

    def test_agent_tools_settles_the_merged_halves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = _settings(_SCOPED)
        registry = ServerRegistry(settings)

        def halves(self: ServerRegistry, role: str, job_id: str, **kw: Any) -> Any:
            tools: list[Any] = []
            if kw.get("builtin") is False:
                self.merge_tools("x", [_tool("one")], tools, kw["seen"])
            return tools, []

        def referenced(self: ServerRegistry, ref: Any, job_id: str, **kw: Any) -> Any:
            tools: list[Any] = []
            self.merge_tools("x", [_tool("many")], tools, kw["seen"], aggregates={"many": ("one",)})
            return tools, []

        monkeypatch.setattr(ServerRegistry, "tools_for", halves)
        monkeypatch.setattr(ServerRegistry, "tools_for_ref", referenced)
        tools, _ = registry.agent_tools("static", "job", [object()])
        assert [t.name for t in tools] == ["many", "one"]
        assert tools[0].description.endswith(aggregate_note(("one",)))


# --- The call sites: the job's own settings, not the process's -----------------

_KIT_FACTS = {
    "many": {"aggregate_of": ["one"], "shows": "every function at once"},
    "one": {"category": "list"},
}
# The provider's declaration lives in a block that is never attached itself.
_PROVIDER_FACTS = {"decompile": {"category": "read", "does_not_show": "what is never called"}}


def _kit_tool(name: str, owner: str) -> StructuredTool:
    return StructuredTool.from_function(func=lambda: owner, name=name, description=f"[{owner}].")


@pytest.fixture
def _kit_served(monkeypatch: pytest.MonkeyPatch) -> None:
    offers = {"kit": ["many", "one"]}

    async def _aopen(self: ServerHandle, job_id: str, **context: Any) -> None:
        return None

    monkeypatch.setattr(ServerHandle, "open", lambda self, job_id, **context: None)
    monkeypatch.setattr(ServerHandle, "aopen", _aopen)
    monkeypatch.setattr(
        ServerHandle,
        "tools",
        lambda self: [_kit_tool(n, self.name) for n in offers.get(self.name, [])],
    )
    monkeypatch.setattr(ServerHandle, "withheld_reasons", lambda self: [])


class _Provider:
    """A static provider whose tools are declared by the ``pv`` block."""

    id = "acme"
    server_name = ""
    declaration_source = "mcp:pv"

    class capabilities:  # noqa: N801 — a stand-in for the frozen dataclass
        provides_tools = True
        degrade_on_failure = False

    def open(self, job: Any) -> None:
        return None

    def get_tools(self) -> list[Any]:
        return [_kit_tool("decompile", "provider")]


def _job_settings(kit_agents: list[str], **extra: Any) -> Settings:
    servers = {
        "kit": {
            "enabled": True,
            "transport": "stdio",
            "command": "kit",
            "agents": kit_agents,
            "tool_facts": _KIT_FACTS,
        },
        "pv": {
            "enabled": False,
            "transport": "stdio",
            "command": "pv",
            "tool_facts": _PROVIDER_FACTS,
        },
    }
    return Settings(_env_file=None, mcp={"servers": servers, "answer_scope_notes": True}, **extra)


def _expect_notes(tools: list[Any]) -> None:
    by_name = {t.name: t.description for t in tools}
    assert by_name["decompile"] == "[provider]. It does not show: what is never called."
    assert by_name["many"] == (
        f"[kit]. {aggregate_note(('one',))} This answer shows: every function at once."
    )


@pytest.mark.usefixtures("_kit_served")
class TestTheCallSitesReadTheJobsSettings:
    def test_a_resolved_agent_s_provider_and_referenced_tools_carry_their_notes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents import composition
        from maljan.agents.composition import resolve_agent
        from maljan.core.config import get_settings
        from maljan.core.container import ServiceContainer

        assert get_settings().mcp.answer_scope_notes is False
        cfg = _job_settings(
            ["x"],
            agents={
                "definitions": {
                    "x": {
                        "role": "generic",
                        "prompt": "p",
                        "tools": [
                            {"kind": "provider"},
                            {"kind": "mcp", "server": "kit", "name": "many"},
                        ],
                    }
                },
                "profiles": {"one": {"analysts": ["x"]}},
                "profile": "one",
            },
        )
        container = ServiceContainer(config=cfg, mock=True)
        monkeypatch.setattr(container, "get_static_provider", lambda *a, **k: _Provider())
        # The prompt is not what this reads, and the stand-in provider writes none.
        monkeypatch.setattr(composition, "_agent_prompt", lambda *a, **k: "")
        _expect_notes(list(resolve_agent("x", container).tools))

    def test_the_static_analyst_s_provider_and_server_tools_carry_their_notes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from unittest.mock import MagicMock

        from maljan.core.config import get_settings
        from maljan.core.container import ServiceContainer

        assert get_settings().mcp.answer_scope_notes is False
        container = ServiceContainer(config=_job_settings(["static"]), mock=True)
        agent = container.agent_registry.create("static", MagicMock())
        agent._container = container
        monkeypatch.setattr(type(agent), "_provider", lambda self: _Provider())
        agent._initialize_mcp_client()
        _expect_notes(list(agent.tools))
