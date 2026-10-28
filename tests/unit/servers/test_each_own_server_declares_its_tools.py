"""Each of the platform's own tool servers declares its tools itself, and the client reads it.

Every sidecar under ``services/`` lists each tool with MCP annotations and,
under the tool's ``_meta``, its declaration (``maljan.tools.declared_facts``,
``cli_sidecar.reading_tool``). The client reads that for any server alike
(``core.served_declarations``), under what a block puts in force.

The parity gate: for every tool of these servers, the facts the client reads
from the server's own listing equal, field by field, the facts captured from
the platform's shipped tables before any of them is taken out
(``tests/fixtures/own_server_tool_facts.json``). The capture is frozen: it is
never regenerated, so it keeps holding the servers to what the platform read
before. The tables are gone: what the platform reads of these servers is what
each serves, and nothing else ships it.

Each server is imported in-process and listed as a client's handshake lists
it; no image is built and no program runs.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from maljan.core.builtin_declarations import server_declaration
from maljan.core.config import Settings
from maljan.core.served_declarations import (
    FACTS_META_KEY,
    _set_fields,
    forget_served,
    layered,
    register_served,
    served,
    served_facts_of,
    served_tool_facts,
)
from maljan.core.tool_declarations import SourceRef, ToolDeclarations, ToolFacts, launch_identity
from maljan.tools.declared_facts import NO_EFFECT, tool_declaration

ROOT = Path(__file__).resolve().parents[3]
SERVICES = ROOT / "services"
CAPTURED = ROOT / "tests" / "fixtures" / "own_server_tool_facts.json"
SERVERS = (
    "analysis",
    "knowledge",
    "network",
    "threatintel",
    "die",
    "ilspy",
    "goresym",
    "yarax",
    "oletools",
    "webcrack",
    "unblob",
    "jadx",
)


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@cache
def _sidecar() -> Any:
    return _load("cli_sidecar", SERVICES / "cli-sidecar" / "cli_sidecar.py")


@cache
def _listing(key: str) -> tuple[Any, ...]:
    """The server's tools as a client's handshake lists them."""
    _sidecar()
    module = _load(f"{key}_mcp_declares_itself", SERVICES / f"{key}-mcp" / "server.py")
    return tuple(asyncio.run(module.mcp.list_tools()))


@cache
def _captured() -> dict[str, dict[str, dict[str, Any]]]:
    return json.loads(CAPTURED.read_text())  # type: ignore[no-any-return]


def _fields(facts: ToolFacts) -> dict[str, Any]:
    return facts.model_dump(mode="json", exclude_defaults=True)


def _diffs(key: str) -> list[str]:
    """Every field on which what the server declares differs from the capture."""
    read = served_tool_facts(_listing(key), where=f"{key}.")
    captured = _captured()[key]
    out = [
        f"{key}.{tool}: not declared by the server" for tool in sorted(set(captured) - set(read))
    ]
    out += [f"{key}.{tool}: declared, not captured" for tool in sorted(set(read) - set(captured))]
    for tool in sorted(set(read) & set(captured)):
        # Every field the server gives, at its default too, against the capture.
        mine = _set_fields(read[tool])
        theirs = _set_fields(ToolFacts.model_validate(captured[tool]))
        for name in sorted(set(mine) | set(theirs)):
            if mine.get(name) != theirs.get(name):
                out.append(f"{key}.{tool}.{name}: {mine.get(name)!r} != {theirs.get(name)!r}")
    return out


@pytest.mark.parametrize("key", SERVERS)
def test_what_the_server_declares_is_what_the_platform_read_field_by_field(key: str) -> None:
    assert _diffs(key) == []


def test_the_parity_gate_covers_every_tool_of_every_own_server() -> None:
    tools = sum(len(_captured()[key]) for key in SERVERS)
    assert set(_captured()) == set(SERVERS)
    assert tools == 81
    assert sum(len(_diffs(key)) for key in SERVERS) == 0


@pytest.mark.parametrize("key", SERVERS)
def test_no_own_server_ships_a_table_of_its_tools(key: str) -> None:
    # What the platform reads of it is what it serves, and nothing else.
    assert "tool_facts" not in server_declaration(key)
    assert Settings(_env_file=None).mcp.servers[key].tool_facts == {}


@pytest.mark.parametrize("key", SERVERS)
def test_each_tool_s_hints_say_what_its_declaration_says(key: str) -> None:
    for definition in _listing(key):
        facts = served_facts_of(definition)
        assert facts is not None, definition.name
        hints = definition.annotations
        assert hints is not None and (hints.title or "").strip(), definition.name
        assert hints.readOnlyHint is facts.read_only, definition.name
        assert hints.idempotentHint is facts.read_only, definition.name
        network = facts.effects.network if facts.effects is not None else None
        assert hints.openWorldHint is (network is True), definition.name
        if facts.read_only:
            assert hints.destructiveHint is False, definition.name


def test_a_sidecar_that_imports_nothing_of_the_platform_declares_as_the_platform_s_helper() -> None:
    sidecar = _sidecar()
    assert sidecar.FACTS_META_KEY == FACTS_META_KEY
    assert sidecar.NO_EFFECT == NO_EFFECT
    facts = {"kind": "identification", "arguments": {"path": "path"}}
    theirs = sidecar.reading_tool("Scan", facts)
    ours = tool_declaration("Scan", {**facts, "effects": NO_EFFECT}, read_only=True)
    assert theirs["meta"] == ours["meta"]
    assert theirs["annotations"] == ours["annotations"]


# ---------------------------------------------------------------------------
# The client reads any server's declaration alike
# ---------------------------------------------------------------------------


def _definition(name: str, facts: Any) -> dict[str, Any]:
    return {"name": name, "inputSchema": {"type": "object"}, "_meta": {FACTS_META_KEY: facts}}


def test_a_third_party_server_s_declaration_is_read_as_a_built_in_s() -> None:
    read = served_tool_facts(
        [
            _definition("scan_it", {"kind": "strings", "rows": "/s/*", "values": {"t": "/t"}}),
            {"name": "says_nothing", "inputSchema": {"type": "object"}},
        ]
    )
    assert set(read) == {"scan_it"}
    assert read["scan_it"].kind == "strings" and read["scan_it"].rows == "/s/*"


def test_an_unknown_field_is_left_out_and_a_refused_declaration_declares_nothing() -> None:
    kept = served_facts_of(_definition("t", {"kind": "strings", "not_a_field": 1}))
    assert kept is not None and kept.kind == "strings"
    assert served_facts_of(_definition("t", {"kind": "Not A Word"})) is None
    assert served_facts_of(_definition("t", ["strings"])) is None
    assert served_facts_of({"name": "t", "_meta": {"other/key": {"kind": "strings"}}}) is None


def test_an_aggregate_of_a_tool_the_server_did_not_list_is_left_out() -> None:
    read = served_tool_facts(
        [
            _definition("one", {"kind": "decompile"}),
            _definition("all", {"kind": "decompile_batch", "aggregate_of": ["one", "nowhere"]}),
        ]
    )
    assert list(read["all"].aggregate_of) == ["one"]


@pytest.fixture
def clean_served() -> Any:
    forget_served()
    yield
    forget_served()


def _settings(tool_facts: dict[str, Any], *, trusts: bool = True) -> Settings:
    return Settings.model_validate(
        {
            "mcp": {
                "servers": {
                    "mine": {
                        "command": "x",
                        "tool_facts": tool_facts,
                        "trusts_served_declaration": trusts,
                    }
                }
            }
        }
    )


def test_the_operator_s_declaration_wins_field_by_field_over_the_server_s(
    clean_served: None,
) -> None:
    register_served(
        "mcp:mine",
        served_tool_facts(
            [
                _definition(
                    "scan_it",
                    {
                        "kind": "strings",
                        "rows": "/s/*",
                        "display_name": "Server",
                        "effects": NO_EFFECT,
                    },
                ),
                _definition("only_served", {"kind": "identity"}),
            ]
        ),
        launch_identity(_settings({}).mcp.servers["mine"]),
    )
    settings = _settings(
        {
            "scan_it": {"display_name": "Operator", "effects": {"network": True}},
            "own": {"kind": "x"},
        }
    )
    d = ToolDeclarations.from_settings(settings)
    scan = d.declaration_for(("mcp:mine", "scan_it"))
    assert scan is not None
    # The operator's fields are in force; the server's fill what the operator left out.
    assert scan.display_name == "Operator" and scan.kind == "strings" and scan.rows == "/s/*"
    assert scan.effects is not None and scan.effects.network is True
    assert scan.effects.executes == "no" and scan.effects.third_party == "no"
    only = d.declaration_for(("mcp:mine", "only_served"))
    assert only is not None and only.kind == "identity"
    own = d.declaration_for(("mcp:mine", "own"))
    assert own is not None and own.kind == "x"
    # What no one declares is not declared.
    assert d.declaration_for(("mcp:mine", "nobody")) is None
    # Another server's key reads nothing of it.
    assert d.declaration_for(("mcp:other", "scan_it")) is None


def test_a_field_an_operator_gave_at_its_default_is_in_force_over_the_server_s() -> None:
    above = ToolFacts.model_validate({"kind": "decompile", "routed_formats": []})
    below = ToolFacts.model_validate({"kind": "decompile", "routed_formats": ["pe"]})
    assert list(layered({"t": above}, {"t": below})[0]["t"].routed_formats) == []


def test_a_shipped_tool_an_operator_removed_stays_removed_whatever_its_server_says() -> None:
    read = served_tool_facts(_listing("die"))
    assert "die_scan" in layered({}, read)[0]
    assert "die_scan" not in layered({}, read, removed={"die_scan"})[0]


def test_a_listing_is_kept_until_the_next_one_and_rebuilds_the_held_declarations(
    clean_served: None,
) -> None:
    from maljan.core.tool_declarations import declaration_version

    before = declaration_version()
    register_served("mcp:mine", {"t": ToolFacts(kind="strings")}, "L")
    assert declaration_version() == before + 1
    register_served("mcp:mine", {"t": ToolFacts(kind="strings")}, "L")
    assert declaration_version() == before + 1
    assert set(served("mcp:mine")) == {"t"}
    register_served("mcp:mine", {}, "L")
    assert served("mcp:mine") == {}
    assert declaration_version() == before + 2


def test_what_a_built_in_server_declares_is_what_the_platform_reads(
    clean_served: None,
) -> None:
    # Before any listing, its block declares nothing: it is read as undeclared.
    before = ToolDeclarations.from_settings(Settings())
    for key in SERVERS:
        held = before.source(f"mcp:{key}")
        assert held is not None and dict(held.tools) == {}
    for key in SERVERS:
        register_served(
            str(SourceRef("mcp", key)),
            served_tool_facts(_listing(key)),
            launch_identity(Settings().mcp.servers[key]),
        )
    after = ToolDeclarations.from_settings(Settings())
    for key in SERVERS:
        theirs = after.source(f"mcp:{key}")
        assert theirs is not None
        assert {t: _fields(f) for t, f in theirs.tools.items()} == _captured()[key]
