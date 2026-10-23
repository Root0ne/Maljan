"""An entry's facts are the declaration of the name its server gave the tool, found exactly.

A registry renames a tool two servers both offer to ``<server key>__<tool>``.
That rename is recorded on the tool (``maljan_declared_name``) and the facts
stored with its entries are the declaration of the original name, so a tool a
server natively spells ``<its key>__x`` is no longer read as its tool ``x``.
An entry written before the name was recorded is still read by taking its own
server's prefix off.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import StructuredTool

from maljan.agents.tool_pinning import (
    DECLARED_NAME_METADATA_KEY,
    declared_facts_of,
    declared_name_of,
)
from maljan.core.config import Settings
from maljan.core.declared_reading import facts_record
from maljan.core.tool_declarations import ToolDeclarations
from maljan.providers.servers import ServerRegistry
from maljan.schemas.evidence import build_entry


def _declared() -> ToolDeclarations:
    settings = Settings.model_validate(
        {"mcp": {"servers": {"mine": {"command": "x", "tool_facts": {"x": {"kind": "strings"}}}}}}
    )
    return ToolDeclarations.from_settings(settings)


def _tool(name: str) -> StructuredTool:
    return StructuredTool.from_function(func=lambda: "ok", name=name, description=name)


def _merged(*servers: tuple[str, str]) -> list[Any]:
    registry = ServerRegistry(Settings(_env_file=None))
    tools: list[Any] = []
    claimed: dict[str, str] = {}
    for server, name in servers:
        registry.merge_tools(server, [_tool(name)], tools, claimed)
    return tools


def test_a_renamed_tool_records_the_name_its_server_gave_it() -> None:
    tools = _merged(("other", "x"), ("mine", "x"))
    assert [t.name for t in tools] == ["x", "mine__x"]
    assert [declared_name_of(t) for t in tools] == ["x", "x"]
    assert DECLARED_NAME_METADATA_KEY not in (tools[0].metadata or {})
    assert tools[1].metadata[DECLARED_NAME_METADATA_KEY] == "x"


def test_a_natively_spelled_prefix_is_no_rename() -> None:
    (tool,) = _merged(("mine", "mine__x"))
    assert tool.name == "mine__x"
    assert declared_name_of(tool) == "mine__x"


def test_the_facts_of_a_renamed_tool_are_its_original_declaration() -> None:
    held = _declared()
    record = facts_record("mcp:mine", "mine__x", declared=held, declared_name="x")
    assert record is not None and record["kind"] == "strings"


def test_a_native_tool_spelled_like_a_renamed_one_is_not_the_other_tool() -> None:
    held = _declared()
    record = facts_record("mcp:mine", "mine__x", declared=held, declared_name="mine__x")
    assert record is not None and record.get("kind") in ("", None)
    entry = build_entry(
        entry_id="ev_0001", seq=1, agent="a", tool="mine__x", args={}, server="mine",
        output="{}", source="mcp:mine", declared_name="mine__x",
    )  # fmt: skip
    assert entry.facts is not None
    assert entry.facts.get("kind") in ("", None)


def test_an_entry_written_before_the_name_was_recorded_is_read_by_its_prefix() -> None:
    held = _declared()
    record = facts_record("mcp:mine", "mine__x", declared=held)
    assert record is not None and record["kind"] == "strings"


def test_the_tool_as_offered_finds_its_declaration_exactly() -> None:
    renamed, native = _merged(("other", "x"), ("mine", "x"))[1], _merged(("mine", "mine__x"))[0]
    assert declared_name_of(renamed) == "x"
    assert declared_name_of(native) == "mine__x"
    assert declared_facts_of(native) is None
