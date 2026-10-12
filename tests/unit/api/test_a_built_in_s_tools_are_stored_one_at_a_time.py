"""A built-in block's tool declarations are stored and read one tool at a time.

A save stores, per tool, only what the operator changed over the shipped
declaration of that tool: nothing for a tool left as shipped, the changed
fields for one edited, ``null`` for a shipped tool removed, the whole
declaration of a tool the block does not ship. On load the shipped map is
merged with those changes field by field, so a correction a later release
ships for any tool the operator did not change reaches the run.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import pytest

from app.services import settings_service as svc
from app.services.server_map import validate_server_map
from maljan.core import builtin_declarations
from maljan.core import settings_overrides as so
from maljan.core.tool_declarations import merge_tool_facts, tool_facts_changes

LEAF = "core.static.ghidra.tool_facts"


def _stored_map() -> dict[str, Any]:
    """The tool-server map as a save stores it with nothing changed."""
    return validate_server_map({})


def _accept(stored: dict[str, Any], server: str, tool: str, facts: dict[str, Any]) -> dict:
    """What the console sends when one proposal is accepted on ``server``.

    The editor holds the stored entry, whose ``tool_facts`` are its changes,
    and adds the accepted tool to them.
    """
    entry = dict(stored[server])
    entry["tool_facts"] = {**(entry.get("tool_facts") or {}), tool: facts}
    return {**stored, server: entry}


@pytest.fixture
def shipped_release() -> Iterator[Any]:
    """Change what the analysis server ships, as a later release would."""
    blocks = builtin_declarations._SERVER_BLOCKS["analysis"]["tool_facts"]
    saved = {name: dict(entry) for name, entry in blocks.items()}
    so._shipped_dump.cache_clear()

    def correct(tool: str, **fields: Any) -> None:
        blocks[tool] = {**blocks[tool], **fields}
        so._shipped_dump.cache_clear()

    yield correct
    blocks.clear()
    blocks.update(saved)
    so._shipped_dump.cache_clear()


def _in_force(stored: dict[str, Any], server: str = "analysis") -> dict[str, Any]:
    return so.build_settings({"mcp.servers": stored}).mcp.servers[server].tool_facts


def test_accepting_one_proposal_stores_that_tool_alone() -> None:
    stored = _stored_map()
    out = validate_server_map(
        _accept(stored, "analysis", "pack_scan", {"display_name": "Pack scanner"}), stored=stored
    )
    facts = out["analysis"]["tool_facts"]
    assert list(facts) == ["pack_scan"]
    assert facts["pack_scan"]["display_name"] == "Pack scanner"
    held = _in_force(out)
    assert set(held) == set(so.shipped_tool_facts("mcp.servers.analysis")) | {"pack_scan"}


def test_a_later_correction_to_another_tool_reaches_the_run(shipped_release: Any) -> None:
    stored = _stored_map()
    out = validate_server_map(
        _accept(stored, "analysis", "pack_scan", {"display_name": "Pack scanner"}), stored=stored
    )
    untouched = next(iter(so.shipped_tool_facts("mcp.servers.analysis")))
    shipped_release(untouched, timeout_seconds=4321.0)
    held = _in_force(out)
    assert held[untouched].timeout_seconds == 4321.0
    assert held["pack_scan"].display_name == "Pack scanner"


def test_an_edited_tool_keeps_its_field_and_takes_the_rest_from_the_release(
    shipped_release: Any,
) -> None:
    stored = _stored_map()
    tool = next(iter(so.shipped_tool_facts("mcp.servers.analysis")))
    out = validate_server_map(
        _accept(stored, "analysis", tool, {"long_running": True}), stored=stored
    )
    assert out["analysis"]["tool_facts"] == {tool: {"long_running": True}}
    shipped_release(tool, timeout_seconds=99.0)
    held = _in_force(out)[tool]
    assert held.long_running is True
    assert held.timeout_seconds == 99.0


def test_a_removed_tool_stays_removed(shipped_release: Any) -> None:
    stored = _stored_map()
    first, second, *_ = list(so.shipped_tool_facts("mcp.servers.analysis"))
    out = validate_server_map(_accept(stored, "analysis", first, None), stored=stored)
    assert out["analysis"]["tool_facts"] == {first: None}
    shipped_release(first, timeout_seconds=7.0)
    held = _in_force(out)
    assert first not in held and second in held
    # Saving again (the editor sends the stored entry back) keeps the removal.
    again = validate_server_map(out, stored=out)
    assert again["analysis"]["tool_facts"] == {first: None}


def test_a_new_shipped_tool_appears_beside_the_stored_changes(shipped_release: Any) -> None:
    stored = _stored_map()
    out = validate_server_map(
        _accept(stored, "analysis", "pack_scan", {"display_name": "Pack scanner"}), stored=stored
    )
    blocks = builtin_declarations._SERVER_BLOCKS["analysis"]["tool_facts"]
    blocks["shipped_later"] = {"kind": "strings"}
    so._shipped_dump.cache_clear()
    assert _in_force(out)["shipped_later"].kind == "strings"


def test_a_provider_leaf_is_stored_one_tool_at_a_time() -> None:
    shipped = so.shipped_tool_facts("static.ghidra")
    tool = next(iter(shipped))
    whole = {name: dict(entry) for name, entry in shipped.items()}
    whole[tool]["long_running"] = True
    stored = svc.stored_declaration_leaves({LEAF: whole})[LEAF]
    assert stored == {tool: {"long_running": True}}
    # A removal of a tool the block does not ship removes nothing.
    changes = {tool: {"long_running": True}, "my_script": {"kind": "strings"}, "not_shipped": None}
    stored = svc.stored_declaration_leaves({LEAF: changes})[LEAF]
    assert set(stored) == {tool, "my_script"}
    held = so.build_settings({"static.ghidra.tool_facts": stored}).static.ghidra.tool_facts
    assert held[tool].long_running is True and held["my_script"].kind == "strings"
    assert set(held) == set(shipped) | {"my_script"}


def test_an_export_and_import_round_trip_keeps_the_changes() -> None:
    stored = _stored_map()
    first = next(iter(so.shipped_tool_facts("mcp.servers.analysis")))
    servers = validate_server_map(
        _accept(
            _accept(stored, "analysis", "pack_scan", {"display_name": "P"}), "analysis", first, None
        ),
        stored=stored,
    )
    leaf = svc.stored_declaration_leaves(
        {LEAF: {next(iter(so.shipped_tool_facts("static.ghidra"))): {"long_running": True}}}
    )[LEAF]
    exported = {"core.mcp.servers": servers, LEAF: leaf}
    imported, warnings = svc.lenient_imported_declarations(exported)
    assert warnings == {}
    assert imported == exported
    assert validate_server_map(imported["core.mcp.servers"], stored=servers) == servers
    assert svc.stored_declaration_leaves({LEAF: imported[LEAF]})[LEAF] == leaf


def test_merging_and_storing_grow_linearly() -> None:
    def timed(size: int) -> float:
        shipped = {f"t{i}": {"kind": "strings", "rows": f"/r{i}/*"} for i in range(size)}
        stored = {f"t{i}": ({"rows": "/x/*"} if i % 3 else None) for i in range(0, size, 2)}
        stored.update({f"n{i}": {"kind": "strings"} for i in range(size // 4)})
        best = float("inf")
        for _ in range(2):
            start = time.perf_counter()
            in_force = merge_tool_facts(shipped, stored)
            tool_facts_changes(in_force, shipped)
            best = min(best, time.perf_counter() - start)
        return best

    small, large = timed(2_000), timed(20_000)
    assert large <= small * 15 + 0.05
