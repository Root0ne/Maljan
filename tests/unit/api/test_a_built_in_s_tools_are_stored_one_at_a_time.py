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
from maljan.core.tool_declarations import (
    holds_changes,
    merge_tool_facts,
    stored_in_force,
    tool_facts_changes,
    with_mark,
    without_mark,
)

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
    assert holds_changes(facts)
    assert list(without_mark(facts)) == ["pack_scan"]
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
    assert out["analysis"]["tool_facts"] == with_mark({tool: {"long_running": True}})
    shipped_release(tool, timeout_seconds=99.0)
    held = _in_force(out)[tool]
    assert held.long_running is True
    assert held.timeout_seconds == 99.0


def test_a_removed_tool_stays_removed(shipped_release: Any) -> None:
    stored = _stored_map()
    first, second, *_ = list(so.shipped_tool_facts("mcp.servers.analysis"))
    out = validate_server_map(_accept(stored, "analysis", first, None), stored=stored)
    assert out["analysis"]["tool_facts"] == with_mark({first: None})
    shipped_release(first, timeout_seconds=7.0)
    held = _in_force(out)
    assert first not in held and second in held
    # Saving again (the editor sends the stored entry back) keeps the removal.
    again = validate_server_map(out, stored=out)
    assert again["analysis"]["tool_facts"] == with_mark({first: None})


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
    assert stored == with_mark({tool: {"long_running": True}})
    # A removal of a tool the block does not ship removes nothing.
    changes = {tool: {"long_running": True}, "my_script": {"kind": "strings"}, "not_shipped": None}
    stored = svc.stored_declaration_leaves({LEAF: changes})[LEAF]
    assert set(without_mark(stored)) == {tool, "my_script"}
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
            stored_in_force(shipped, with_mark(stored))
            best = min(best, time.perf_counter() - start)
        return best

    small, large = timed(2_000), timed(20_000)
    assert large <= small * 15 + 0.05


def test_a_change_a_later_release_makes_invalid_never_stops_the_settings(
    shipped_release: Any, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    from maljan.core import tool_declarations

    blocks = builtin_declarations._SERVER_BLOCKS["analysis"]["tool_facts"]
    blocks["shipped_later"] = {"kind": "strings", "rows": "/r/*"}
    so._shipped_dump.cache_clear()
    stored = _stored_map()
    out = validate_server_map(
        _accept(stored, "analysis", "shipped_later", {"places": {"offset": "/o"}}), stored=stored
    )
    assert _in_force(out)["shipped_later"].places == {"offset": "/o"}
    # A later release stops reading rows for the tool: the stored places
    # would need them, so the change is left out and the release's
    # declaration is in force; the rest of the settings is built.
    shipped_release("shipped_later", rows="")
    tool_declarations._WARNED.clear()
    with caplog.at_level(logging.WARNING, logger="maljan"):
        held = _in_force(out)
        _in_force(out)
    assert held["shipped_later"].places == {} and held["shipped_later"].kind == "strings"
    said = [r.getMessage() for r in caplog.records if "does not validate" in r.getMessage()]
    assert len(said) == 1 and "shipped_later" in said[0] and "mcp.servers.analysis" in said[0]
    assert so.refused_tool_changes({"mcp.servers": out}) == {
        "mcp.servers.analysis": ["shipped_later"]
    }
    # An unrelated save keeps the operator's change as stored, for them to
    # reset or edit.
    again = validate_server_map(out, stored=out)
    assert again["analysis"]["tool_facts"] == out["analysis"]["tool_facts"]


def test_a_provider_leaf_change_a_later_release_makes_invalid_is_left_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shipped = {"scan": {**_unset(), "kind": "strings", "rows": "/r/*"}}
    monkeypatch.setattr(so, "shipped_tool_facts", lambda block: shipped)
    stored = with_mark({"scan": {"places": {"offset": "/o"}}})
    built = so.build_settings({"static.ghidra.tool_facts": stored})
    assert built.static.ghidra.tool_facts["scan"].places == {"offset": "/o"}
    shipped["scan"] = {**shipped["scan"], "rows": ""}
    built = so.build_settings({"static.ghidra.tool_facts": stored})
    assert built.static.ghidra.tool_facts["scan"].places == {}
    assert so.refused_tool_changes({"static.ghidra.tool_facts": stored}) == {
        "static.ghidra": ["scan"]
    }


def _unset() -> dict[str, Any]:
    from maljan.core.tool_declarations import ToolFacts

    return ToolFacts.model_construct().model_dump(mode="json")


def test_a_map_sent_without_the_mark_is_read_as_changes() -> None:
    """Through the API a whole map no longer removes the shipped tools it
    leaves out; ``null`` removes one."""
    stored = _stored_map()
    shipped = so.shipped_tool_facts("mcp.servers.analysis")
    first, second, *_ = list(shipped)
    sent = {**stored, "analysis": {**stored["analysis"], "tool_facts": {first: shipped[first]}}}
    out = validate_server_map(sent, stored=stored)
    assert "tool_facts" not in out["analysis"]
    assert set(_in_force(out)) == set(shipped)
    sent["analysis"]["tool_facts"] = {second: None}
    assert second not in _in_force(validate_server_map(sent, stored=stored))


def test_a_whole_map_sent_back_as_stored_keeps_reading_whole() -> None:
    """A row an earlier release stored whole, sent back unchanged with an
    unrelated edit (the credential bootstrap, a raw client), reads as stored."""
    shipped = so.shipped_tool_facts("mcp.servers.analysis")
    first, *_ = list(shipped)
    whole = {tool: facts for tool, facts in shipped.items() if tool != first}
    stored = _stored_map()
    stored["analysis"] = {**stored["analysis"], "tool_facts": whole}
    sent = {**stored, "analysis": {**stored["analysis"], "label": "edited"}}
    out = validate_server_map(sent, stored=stored)
    assert out["analysis"]["tool_facts"] == with_mark({first: None})
    assert first not in _in_force(out)


@pytest.mark.asyncio
async def test_the_api_serves_every_stored_map_as_marked_changes() -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, MagicMock

    from app.models import RuntimeSetting

    shipped = so.shipped_tool_facts("static.ghidra")
    first, second, *_ = list(shipped)
    whole_leaf = {tool: facts for tool, facts in shipped.items() if tool != first}
    servers = _stored_map()
    analysis = so.shipped_tool_facts("mcp.servers.analysis")
    gone = next(iter(analysis))
    servers["analysis"] = {
        **servers["analysis"],
        "tool_facts": {tool: facts for tool, facts in analysis.items() if tool != gone},
    }
    rows = [
        RuntimeSetting(key=LEAF, value=whole_leaf, is_secret=False),
        RuntimeSetting(key="core.mcp.servers", value=servers, is_secret=False),
    ]
    db = MagicMock()
    db.execute = AsyncMock(
        return_value=SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))
    )
    values = await svc.SettingsService(db).values()
    assert values[LEAF].value == with_mark({first: None})
    assert values["core.mcp.servers"].value["analysis"]["tool_facts"] == with_mark({gone: None})


def test_what_the_console_stages_for_a_removed_tool_s_proposal_saves(shipped_release: Any) -> None:
    """The proposals panel stages a removed shipped tool's accepted proposal
    with every shipped field it does not name at its default: that saves, and
    what is in force is the proposal alone."""
    blocks = builtin_declarations._SERVER_BLOCKS["analysis"]["tool_facts"]
    blocks["shipped_later"] = {"kind": "strings", "rows": "/m/*", "display_name": "Scan"}
    so._shipped_dump.cache_clear()
    stored = validate_server_map(_accept(_stored_map(), "analysis", "shipped_later", None))
    staged = {"kind": "unclassified", "rows": "", "display_name": "P"}
    out = validate_server_map(_accept(stored, "analysis", "shipped_later", staged), stored=stored)
    held = _in_force(out)["shipped_later"]
    assert (held.kind, held.rows, held.display_name) == ("", "", "P")


def test_what_a_block_ships_is_a_copy_a_caller_cannot_change() -> None:
    held = so.shipped_tool_facts("mcp.servers.analysis")
    tool = next(iter(held))
    held[tool]["display_name"] = "changed by a caller"
    assert so.shipped_tool_facts("mcp.servers.analysis")[tool]["display_name"] != (
        "changed by a caller"
    )
