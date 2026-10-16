"""A tool declares the routed formats it serves, and its absence costs only those formats.

``pipeline.nodes`` kept a table of the platform's own format-specific parsers,
by tool name (``pe_info`` is for ``pe`` …), read only for a built-in server
that ships the tool: a parser the sample's format never calls on is no
degradation of the run. The formats are now each tool's declaration
(``ToolFacts.routed_formats``), held to the one list of the formats the router
gives a sample (``extractors.sample_identity.routed_formats``): a name it never
gives (``macos``, ``exe``) would drop the tool's reason for every sample.
The analysis server's shipped declarations carry the table's routed names, an
operator's server may declare them for its own tools, and an operator's edit of
a built-in tool's formats is in force; a built-in map stored whole before the
field existed reads as shipped. Every built-in tool and every format the router
gives reads as the table read it.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from maljan.core import builtin_declarations, declared_reading
from maljan.core.config import Settings
from maljan.core.settings_overrides import build_settings
from maljan.core.tool_declarations import (
    CHANGES_FORM,
    CHANGES_MARK,
    ToolDeclarations,
    ToolFacts,
    strict_declarations,
)
from maljan.extractors.sample_identity import UNKNOWN_FORMAT, routed_formats
from maljan.pipeline.nodes import _needed_for, reason_applies_to_format

# ``pipeline.nodes._FORMAT_TOOLS`` as origin/dev held it.
DEV_FORMAT_TOOLS: dict[str, frozenset[str]] = {
    "pe_info": frozenset({"pe"}),
    "elf_info": frozenset({"elf"}),
    "macho_info": frozenset({"mach-o", "macho"}),
    "apk_info": frozenset({"apk", "dex"}),
    "document_info": frozenset({"ole2", "ooxml", "pdf", "doc", "docx", "xls", "xlsx", "rtf"}),
}
# Every format the router gives a sample, an unknown one, none, and spellings
# the reading lowercases and trims into a routed one.
FORMATS = sorted({*routed_formats(), "", "unknown", "PE", " Mach-O ", "  pe  ", "OLE2"})


def _dev_needed_for(tool: str, file_type: str, server: str) -> bool:
    """``pipeline.nodes._needed_for`` as origin/dev wrote it."""
    if not declared_reading.ships_tool(f"mcp:{server}", tool):
        return True
    formats = DEV_FORMAT_TOOLS.get(tool)
    routed = str(file_type or "").strip().lower()
    if formats is None or not routed or routed == "unknown":
        return True
    return routed in formats


@pytest.fixture
def in_force(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """Put a settings object's declarations in force for the reader."""

    def use(settings: Settings) -> None:
        held = ToolDeclarations.from_settings(settings)
        monkeypatch.setattr(declared_reading, "declarations", lambda settings=None: held)

    use(Settings())
    yield use


def _server(entry: dict[str, Any], key: str = "analysis") -> Settings:
    return build_settings({"mcp.servers": {key: {"command": "python", **entry}}})


def test_every_built_in_tool_and_routed_format_reads_as_the_table_did(in_force: Any) -> None:
    built_in = builtin_declarations.builtin_server_names()
    tools = set(DEV_FORMAT_TOOLS) | {"no_such_tool"}
    for key in built_in:
        tools |= set(builtin_declarations.server_declaration(key).get("tool_facts") or {})

    def differ(servers: tuple[str, ...]) -> list[tuple[str, str, str]]:
        return [
            (server, tool, routed)
            for server in servers
            for tool in sorted(tools)
            for routed in FORMATS
            if _needed_for(tool, routed, server) != _dev_needed_for(tool, routed, server)
        ]

    # The shipped settings: every built-in server's live declarations.
    assert ToolDeclarations.from_settings(Settings()).source("mcp:analysis") is not None
    assert differ(built_in) == []
    # An operator's server whose tools share the parsers' names and declare nothing.
    in_force(_server({"tool_facts": {tool: {"kind": "format_info"} for tool in tools}}, "kit"))
    assert differ(("kit",)) == []
    assert len(built_in) * len(tools) * len(FORMATS) > 3000


def test_the_table_s_other_names_are_ones_the_router_never_gives() -> None:
    """``macho``, ``doc``, ``docx``, ``xls``, ``xlsx`` and ``rtf`` were never a sample's format."""
    named = {name for formats in DEV_FORMAT_TOOLS.values() for name in formats}
    never_routed = named - set(routed_formats())
    assert never_routed == {"macho", "doc", "docx", "xls", "xlsx", "rtf"}


def test_the_shipped_declarations_carry_the_table_s_routed_names_and_nothing_else() -> None:
    routed = set(routed_formats())
    declared = ToolDeclarations.from_settings(Settings())
    found: dict[str, dict[str, frozenset[str]]] = {}
    for source in declared.sources():
        for tool, facts in source.tools.items():
            if facts.routed_formats:
                found.setdefault(str(source.source), {})[tool] = frozenset(facts.routed_formats)
    assert found == {
        "mcp:analysis": {tool: formats & routed for tool, formats in DEV_FORMAT_TOOLS.items()}
    }


def test_an_operator_server_declares_formats_for_its_own_tools(in_force: Any) -> None:
    facts = {"read_macho": {"routed_formats": ["mach-o"]}, "pe_info": {"kind": "format_info"}}
    in_force(_server({"tool_facts": facts}, key="kit"))

    assert _needed_for("read_macho", "pe", "kit") is False
    assert _needed_for("read_macho", "mach-o", "kit") is True
    assert _needed_for("read_macho", "unknown", "kit") is True
    assert _needed_for("read_macho", "", "kit") is True
    # Named like a built-in parser, it declares no formats: it keeps its reason.
    assert _needed_for("pe_info", "elf", "kit") is True
    reason = "server.kit.read_macho_unavailable(the Mach-O library is missing)"
    assert reason_applies_to_format(reason, "pe") is False
    assert reason_applies_to_format(reason, "mach-o") is True


def test_a_built_in_map_stored_whole_before_the_field_reads_as_shipped(in_force: Any) -> None:
    shipped = builtin_declarations.server_declaration("analysis")["tool_facts"]
    whole = {
        tool: {key: value for key, value in facts.items() if key != "routed_formats"}
        for tool, facts in shipped.items()
    }
    in_force(_server({"tool_facts": whole}))

    assert _needed_for("macho_info", "pe", "analysis") is False
    assert _needed_for("macho_info", "mach-o", "analysis") is True
    in_force(_server({"tool_facts": {}}))
    assert _needed_for("document_info", "elf", "analysis") is False


def test_an_edit_of_a_built_in_tool_s_formats_is_in_force(in_force: Any) -> None:
    edited = {CHANGES_MARK: CHANGES_FORM, "pe_info": {"routed_formats": ["pe", "lnk"]}}
    in_force(_server({"tool_facts": edited}))
    assert _needed_for("pe_info", "lnk", "analysis") is True
    assert _needed_for("pe_info", "elf", "analysis") is False
    assert _needed_for("macho_info", "pe", "analysis") is False

    cleared = {CHANGES_MARK: CHANGES_FORM, "pe_info": {"routed_formats": []}}
    in_force(_server({"tool_facts": cleared}))
    assert _needed_for("pe_info", "elf", "analysis") is True


@pytest.mark.parametrize(
    "name",
    ["Mach-O", "", " pe", "pe\n", "pe info", "-pe", "x" * 65, "macos", "exe", "pe32", "doc"],
)
def test_a_format_the_router_never_gives_is_refused(name: str) -> None:
    with strict_declarations(), pytest.raises(ValueError, match="routed format"):
        ToolFacts.model_validate({"kind": "format_info", "routed_formats": [name]})


def test_every_known_format_the_router_gives_is_accepted() -> None:
    known = tuple(name for name in routed_formats() if name != UNKNOWN_FORMAT)
    with strict_declarations():
        facts = ToolFacts.model_validate({"routed_formats": list(known)})
    assert facts.routed_formats == known


def test_a_tool_s_routed_formats_are_the_known_formats_it_serves() -> None:
    """``unknown`` labels a sample of no known format: the router gives it, no tool serves it."""
    assert UNKNOWN_FORMAT in routed_formats()
    with strict_declarations(), pytest.raises(ValueError, match="known formats it serves"):
        ToolFacts.model_validate({"kind": "format_info", "routed_formats": [UNKNOWN_FORMAT]})


def test_a_stored_change_the_model_refuses_leaves_the_tool_as_shipped(in_force: Any) -> None:
    refused = {CHANGES_MARK: CHANGES_FORM, "pe_info": {"routed_formats": ["macos"]}}
    in_force(_server({"tool_facts": refused}))
    assert _needed_for("pe_info", "elf", "analysis") is False
    assert _needed_for("pe_info", "pe", "analysis") is True


def test_every_format_given_a_platform_is_a_routed_format() -> None:
    """A format the platform table binds is one the router gives.

    The source guard over the detector's own returns, which holds the list to
    every label the detector gives, is
    ``tests/unit/extractors/test_every_routed_format_is_listed.py``.
    """
    from maljan.extractors import sample_identity

    formats = set(routed_formats())
    assert UNKNOWN_FORMAT in formats
    assert set(sample_identity.PLATFORM_BY_FILE_TYPE) <= formats
