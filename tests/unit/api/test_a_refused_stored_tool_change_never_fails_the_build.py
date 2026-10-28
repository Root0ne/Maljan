"""A stored tool change this release refuses never fails the settings build or blocks an edit.

A stored change of one tool's declaration can stop validating after a later
release: a field it sets needs one the release no longer ships, or the
release no longer ships the tool at all, so the stored partial change is
read as the tool's whole declaration. Either way the change is left out with
one sanitised warning (the tool is in force as shipped, or not at all where
nothing ships for it), named in the schema's ``tool_facts_conflicts`` so the
console marks it, and kept as stored by every save that sends it back as
stored, also one that edits another tool of the same block.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

import pytest

from app.services import settings_service as svc
from app.services.server_map import validate_server_map
from maljan.core import builtin_declarations, tool_declarations
from maljan.core import settings_overrides as so
from maljan.core.tool_declarations import stored_changes, with_mark, without_mark

SERVER = "virustotal"
BLOCK = f"mcp.servers.{SERVER}"


@pytest.fixture(autouse=True)
def _fresh_warnings() -> None:
    tool_declarations._WARNED.clear()


@pytest.fixture
def release() -> Iterator[dict[str, Any]]:
    """What the VirusTotal block ships, changed in place as a later release would."""
    blocks = builtin_declarations._SERVER_BLOCKS[SERVER]["tool_facts"]
    saved = {name: dict(entry) for name, entry in blocks.items()}
    so._shipped_dump.cache_clear()
    yield blocks
    blocks.clear()
    blocks.update(saved)
    so._shipped_dump.cache_clear()


def _ship(blocks: dict[str, Any], tool: str, facts: dict[str, Any] | None) -> None:
    if facts is None:
        blocks.pop(tool, None)
    else:
        blocks[tool] = facts
    so._shipped_dump.cache_clear()


def _save_one(stored: dict[str, Any], tool: str, change: Any) -> dict[str, Any]:
    """The server map after the console saves ``change`` of ``tool`` over ``stored``."""
    entry = dict(stored[SERVER])
    entry["tool_facts"] = with_mark({**without_mark(entry.get("tool_facts") or {}), tool: change})
    return validate_server_map({**stored, SERVER: entry}, stored=stored)


def _served(stored: dict[str, Any]) -> dict[str, Any]:
    """The entry's tool declarations as ``GET /settings`` serves them to the console."""
    return svc.served_tool_facts(stored[SERVER]["tool_facts"], so.shipped_tool_facts(BLOCK))


def _refused_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if "does not validate" in r.getMessage()]


def test_a_partial_change_of_a_tool_the_release_stops_shipping_never_fails_the_build(
    release: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    _ship(
        release,
        "scan",
        {
            "kind": "command_match",
            "asserts_techniques": True,
            "techniques": [{"path": "/t", "format": "attck"}],
            "display_name": "Scan",
        },
    )
    change = {"kind": "strings", "source": "x"}
    stored = _save_one(validate_server_map({}), "scan", change)
    assert without_mark(stored[SERVER]["tool_facts"]) == {"scan": change}
    # A later release no longer ships the tool: the partial change alone is
    # now the tool's whole declaration, and it does not validate.
    _ship(release, "scan", None)
    with caplog.at_level(logging.WARNING, logger="maljan"):
        built = so.build_settings({"mcp.servers": stored})
    assert "scan" not in built.mcp.servers[SERVER].tool_facts
    assert set(built.mcp.servers[SERVER].tool_facts) == set(so.shipped_tool_facts(BLOCK))
    assert so.refused_tool_changes({"mcp.servers": stored}) == {BLOCK: ["scan"]}
    assert len(_refused_warnings(caplog)) == 1
    # The worker builds a job's settings the same way, so it never falls back
    # to the defaults for every job.
    from app.worker.analysis_worker import build_job_settings

    job = build_job_settings({"mcp.servers": stored}, None)
    assert "scan" not in job.mcp.servers[SERVER].tool_facts


@pytest.mark.parametrize(
    "stored",
    [
        {"": "changes", "gone_tool": {"kind": "strings", "source": "x"}},
        {"": "changes", "gone_tool": {"kind": "strings", "places": {"offset": "/o"}}},
        {"": "changes", "gone_tool": "not a declaration"},
        {"": "changes", " padded ": {"display_name": "x"}},
        {"gone_tool": {"kind": "strings", "places": {"offset": "/o"}}},
    ],
)
def test_no_stored_change_of_an_invented_block_fails_the_build(stored: dict[str, Any]) -> None:
    """A server an operator added ships nothing; the same holds for a provider leaf."""
    servers = {
        "invented": {
            "transport": "http",
            "url": "http://127.0.0.1:9/mcp",
            "tool_facts": stored,
        }
    }
    built = so.build_settings({"mcp.servers": servers, "static.ghidra.tool_facts": stored})
    assert built.mcp.servers["invented"].tool_facts == {}
    shipped = so.shipped_tool_facts("static.ghidra")
    assert set(built.static.ghidra.tool_facts) == (set(shipped) if "" in stored else set())
    refused = so.refused_tool_changes({"mcp.servers": servers, "static.ghidra.tool_facts": stored})
    named = [tool for tool in stored if tool != ""]
    assert refused == {"mcp.servers.invented": named, "static.ghidra": named}


def test_the_warning_is_sanitised(caplog: pytest.LogCaptureFixture) -> None:
    forged = "gone\nWARNING forged line\x1b[31m"
    with caplog.at_level(logging.WARNING, logger="maljan"):
        so.build_settings(
            {
                "static.ghidra.tool_facts": {
                    "": "changes",
                    forged: {"kind": "strings", "source": "x"},
                }
            }
        )
    (said,) = _refused_warnings(caplog)
    assert "\n" not in said and "\x1b" not in said
    assert "gone\\nWARNING forged line\\x1b[31m" in said


def test_an_unrelated_edit_of_the_block_saves_and_keeps_the_conflicting_change(
    release: dict[str, Any],
) -> None:
    _ship(release, "scan", {"kind": "strings", "rows": "/r/*", "display_name": "Scan"})
    stored = _save_one(validate_server_map({}), "scan", {"places": {"offset": "/o"}})
    held = stored[SERVER]["tool_facts"]
    # A later release makes the stored change conflict.
    _ship(release, "scan", {"kind": "strings", "rows": "", "display_name": "Scan"})
    assert so.refused_tool_changes({"mcp.servers": stored}) == {BLOCK: ["scan"]}
    other = next(tool for tool in so.shipped_tool_facts(BLOCK) if tool != "scan")
    # The console stages the served changes plus an edit of another tool.
    staged = with_mark({**without_mark(_served(stored)), other: {"display_name": "Z"}})
    saved = validate_server_map(
        {**stored, SERVER: {**stored[SERVER], "tool_facts": staged}}, stored=stored
    )
    facts = saved[SERVER]["tool_facts"]
    assert facts["scan"] == held["scan"]
    assert facts[other] == {"display_name": "Z"}
    assert so.refused_tool_changes({"mcp.servers": saved}) == {BLOCK: ["scan"]}
    built = so.build_settings({"mcp.servers": saved}).mcp.servers[SERVER].tool_facts
    assert built[other].display_name == "Z"
    # Resetting it (the console drops the tool from the changes) removes it.
    reset = with_mark({tool: c for tool, c in without_mark(facts).items() if tool != "scan"})
    cleared = validate_server_map(
        {**saved, SERVER: {**saved[SERVER], "tool_facts": reset}}, stored=saved
    )
    assert "scan" not in without_mark(cleared[SERVER].get("tool_facts") or {})
    assert so.refused_tool_changes({"mcp.servers": cleared}) == {}


def test_an_edit_of_a_conflicting_change_is_still_held_to_the_strict_rules(
    release: dict[str, Any],
) -> None:
    from app.services.server_map import ServerMapError

    _ship(release, "scan", {"kind": "strings", "rows": "/r/*", "display_name": "Scan"})
    stored = _save_one(validate_server_map({}), "scan", {"places": {"offset": "/o"}})
    _ship(release, "scan", {"kind": "strings", "rows": "", "display_name": "Scan"})
    with pytest.raises(ServerMapError) as refused:
        _save_one(stored, "scan", {"places": {"offset": "/other"}})
    assert any(key.startswith(f"{SERVER}.tool_facts.scan") for key in refused.value.errors)


def test_a_provider_leaf_keeps_a_conflicting_change_through_an_unrelated_edit() -> None:
    leaf = "core.static.ghidra.tool_facts"
    shipped = so.shipped_tool_facts("static.ghidra")
    first, second, *_ = list(shipped)
    # A stored change of a tool this release no longer ships, which conflicts.
    held = with_mark({"gone_tool": {"kind": "strings", "places": {"offset": "/o"}}})
    current = {leaf: held}
    assert so.refused_tool_changes({"static.ghidra.tool_facts": held}) == {
        "static.ghidra": ["gone_tool"]
    }
    served = svc.served_tool_facts(held, shipped)
    staged = with_mark({**without_mark(served), first: {"display_name": "Mine"}})
    changes = svc.incoming_declaration_leaves({leaf: staged}, current)
    assert svc.changed_declaration_refusals(changes, current) == {}
    stored = svc.stored_declaration_leaves(changes, current)[leaf]
    assert stored["gone_tool"] == held["gone_tool"]
    assert stored[first] == {"display_name": "Mine"}
    assert second not in stored
    assert stored_changes(stored, shipped)["gone_tool"] == held["gone_tool"]
