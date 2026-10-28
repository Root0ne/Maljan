"""A tool map stored whole keeps every field no release that stored one knew, as shipped.

A map stored whole predates the per-tool form, so a field added after it
(``read_only``, ``function_starts``, ``routed_formats``, ...) is one it leaves
out because it never had it, never one it clears. Read as changes, a shipped
tool the map holds as that release shipped it changes nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from maljan.core import builtin_declarations as shipped
from maljan.core.settings_overrides import shipped_tool_facts
from maljan.core.tool_declarations import (
    FIELDS_AFTER_WHOLE_MAPS,
    WHOLE_MAP_FIELDS,
    ToolFacts,
    whole_as_changes,
)

RECORD = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261012000000_shipped_tool_declarations.json"
)


def _blocks() -> list[tuple[str, dict[str, Any]]]:
    """Each shipped block's tool declarations as the settings hold them, every field dumped."""
    paths = [f"mcp.servers.{key}" for key in shipped.builtin_server_names()]
    paths += list(shipped.provider_block_paths().values())
    return [(path, tools) for path in paths if (tools := shipped_tool_facts(path))]


def _as_a_whole_map(tools: dict[str, Any]) -> dict[str, Any]:
    return {
        tool: {key: value for key, value in facts.items() if key in WHOLE_MAP_FIELDS}
        for tool, facts in tools.items()
    }


def test_the_fields_whole_maps_knew_are_the_frozen_record_s() -> None:
    assert set(json.loads(RECORD.read_text("utf-8"))["defaults"]) == WHOLE_MAP_FIELDS


def test_every_field_after_them_follows_the_shipped_declaration() -> None:
    assert set(FIELDS_AFTER_WHOLE_MAPS) == set(ToolFacts.model_fields) - WHOLE_MAP_FIELDS
    assert {"read_only", "routed_formats", "function_starts"} <= set(FIELDS_AFTER_WHOLE_MAPS)


@pytest.mark.parametrize(("where", "tools"), _blocks(), ids=[w for w, _ in _blocks()])
def test_a_tool_held_as_shipped_changes_nothing(where: str, tools: dict[str, Any]) -> None:
    assert whole_as_changes(_as_a_whole_map(tools), tools) == {}, where


def test_an_operator_s_value_of_a_later_field_wins() -> None:
    # A block that still ships a table of its tools.
    tools = shipped_tool_facts("static.ghidra")
    tool = next(name for name, facts in tools.items() if facts.get("read_only"))
    whole = _as_a_whole_map(tools)
    whole[tool] = {**whole[tool], "read_only": False}
    assert whole_as_changes(whole, tools) == {tool: {"read_only": False}}
