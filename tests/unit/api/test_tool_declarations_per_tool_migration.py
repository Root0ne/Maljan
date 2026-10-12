"""A built-in block's tool declarations stored whole are rewritten once as per-tool changes.

Dev stored a built-in server's ``tool_facts`` whole on any save that touched
them (the server's entry in ``core.mcp.servers``, or a provider block's
``core.<block>.tool_facts`` leaf). The revision rewrites each such map as what
the operator changed, against the declarations of the release that wrote it,
so a tool the operator never touched follows the declaration shipped now, and
every map still reads as it did except for that.
"""

from __future__ import annotations

import importlib.util
import json
import logging
from pathlib import Path
from typing import Any

VERSIONS = Path(__file__).resolve().parents[3] / "apps/api/alembic/versions"
MIGRATION = VERSIONS / "20261012000000_tool_declarations_stored_per_tool.py"
RECORD = VERSIONS / "20261012000000_shipped_tool_declarations.json"
SERVERS = "core.mcp.servers"
GHIDRA = "core.static.ghidra.tool_facts"


def _module():
    spec = importlib.util.spec_from_file_location("tool_declarations_per_tool", MIGRATION)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _connect():
    """A throwaway in-memory SQLite database, never the developer database."""
    import sqlalchemy as sa

    engine = sa.create_engine("sqlite://")
    conn = engine.connect()
    conn.execute(
        sa.text(
            "CREATE TABLE runtime_settings ("
            "key TEXT PRIMARY KEY, value TEXT, is_secret BOOLEAN NOT NULL DEFAULT 0)"
        )
    )
    return conn


def _insert(conn, key: str, value: Any, *, secret: bool = False) -> None:
    import sqlalchemy as sa

    conn.execute(
        sa.text("INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, :s)"),
        {"k": key, "v": value if secret else json.dumps(value), "s": 1 if secret else 0},
    )


def _rows(conn) -> dict[str, Any]:
    import sqlalchemy as sa

    result = conn.execute(sa.text("SELECT key, value, is_secret FROM runtime_settings"))
    return {k: (v if s else json.loads(v)) for k, v, s in result.fetchall()}


def _run(mod, conn, direction: str = "upgrade") -> None:
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        getattr(mod, direction)()


def _shipped_dump() -> dict[str, Any]:
    from maljan.core.settings_overrides import build_settings

    return build_settings({}).model_dump(mode="json")


def _dev_row(*, analysis_facts: dict[str, Any]) -> dict[str, Any]:
    """``core.mcp.servers`` as dev's save wrote it: declarations equal to shipped stripped,
    a changed ``tool_facts`` written whole as full dumps."""
    from app.services.server_map import validate_server_map

    row = validate_server_map({})
    row["analysis"] = {**row["analysis"], "tool_facts": analysis_facts}
    return row


def _marked(changes: dict[str, Any]) -> dict[str, Any]:
    """A map stored as changes, with the mark a save of this release writes."""
    return {"": "changes", **changes}


def _one_change(server: str) -> dict[str, Any]:
    tool = next(iter(_shipped_dump()["mcp"]["servers"][server]["tool_facts"]))
    return {tool: {"display_name": "Mine"}}


def _full(entry: dict[str, Any]) -> dict[str, Any]:
    from maljan.core.tool_declarations import ToolFacts

    return ToolFacts.model_validate(entry).model_dump(mode="json")


def _in_force(rows: dict[str, Any]) -> dict[str, Any]:
    from maljan.core.settings_overrides import build_settings

    core = {k.removeprefix("core."): v for k, v in rows.items()}
    return build_settings(core).model_dump(mode="json")


def test_a_dev_row_with_one_accepted_proposal_keeps_only_that_tool() -> None:
    shipped = _shipped_dump()["mcp"]["servers"]["analysis"]["tool_facts"]
    proposed = _full({"display_name": "Pack scanner", "timeout_seconds": 600})
    whole = {**shipped, "pack_scan": proposed}
    conn = _connect()
    _insert(conn, SERVERS, _dev_row(analysis_facts=whole))
    _run(_module(), conn)
    after_rows = _rows(conn)
    assert after_rows[SERVERS]["analysis"]["tool_facts"] == _marked({"pack_scan": proposed})
    assert _in_force(after_rows)["mcp"]["servers"]["analysis"]["tool_facts"] == whole


def test_a_tool_an_older_release_stored_as_shipped_takes_todays_declaration() -> None:
    record = json.loads(RECORD.read_text("utf-8"))
    block = record["blocks"]["mcp.servers.network"]
    first = {t: block["versions"][t][i] for t, i in block["states"][0].items()}
    last = {t: block["versions"][t][i] for t, i in block["states"][-1].items()}
    moved = [t for t in first if first[t] != last[t]]
    assert moved, "the record holds a network tool whose shipped declaration changed"
    whole = {t: _full(e) for t, e in first.items()}
    from app.services.server_map import validate_server_map

    row = validate_server_map({})
    row["network"] = {**row["network"], "tool_facts": whole}
    conn = _connect()
    _insert(conn, SERVERS, row)
    _run(_module(), conn)
    stored = _rows(conn)[SERVERS]["network"]
    assert "tool_facts" not in stored
    now = _in_force(_rows(conn))["mcp"]["servers"]["network"]["tool_facts"]
    assert now == _shipped_dump()["mcp"]["servers"]["network"]["tool_facts"]


def test_an_operator_change_keeps_its_fields_and_a_removal_stays() -> None:
    shipped = _shipped_dump()["mcp"]["servers"]["analysis"]["tool_facts"]
    first, second, *_ = list(shipped)
    whole = dict(shipped)
    whole.pop(first)
    whole[second] = {**whole[second], "timeout_seconds": 1234.0}
    conn = _connect()
    _insert(conn, SERVERS, _dev_row(analysis_facts=whole))
    _run(_module(), conn)
    stored = _rows(conn)[SERVERS]["analysis"]["tool_facts"]
    assert stored == _marked({first: None, second: {"timeout_seconds": 1234.0}})
    # What dev read from the whole map is what is in force now.
    assert _in_force(_rows(conn))["mcp"]["servers"]["analysis"]["tool_facts"] == whole


def test_a_provider_leaf_typed_whole_is_rewritten_the_same_way() -> None:
    shipped = _shipped_dump()["static"]["ghidra"]["tool_facts"]
    tool = next(iter(shipped))
    typed = {name: dict(entry) for name, entry in shipped.items()}
    typed[tool] = {**typed[tool], "long_running": True}
    typed["my_script"] = {"kind": "strings"}
    conn = _connect()
    _insert(conn, GHIDRA, typed)
    _run(_module(), conn)
    assert _rows(conn)[GHIDRA] == _marked(
        {tool: {"long_running": True}, "my_script": {"kind": "strings"}}
    )
    held = _in_force(_rows(conn))["static"]["ghidra"]["tool_facts"]
    assert held[tool]["long_running"] is True
    assert held["my_script"]["kind"] == "strings"


def test_a_map_whose_release_cannot_be_known_is_kept_whole_as_the_operators() -> None:
    record = json.loads(RECORD.read_text("utf-8"))
    block = record["blocks"]["mcp.servers.network"]
    last = {t: block["versions"][t][i] for t, i in block["states"][-1].items()}
    first = {t: block["versions"][t][i] for t, i in block["states"][0].items()}
    moved = next(t for t in first if first[t] != last[t])
    # Equal to no release's declaration of the moved tool, and differing from
    # each in other fields, so the two releases read it differently.
    whole = {t: _full(e) for t, e in last.items()}
    whole[moved] = _full({**first[moved], **last[moved], "display_name": "Mine"})
    mod = _module()
    changes, known = mod.per_tool_changes(whole, block, record["defaults"])
    assert known is False
    assert changes == whole


def test_a_secret_row_and_marked_maps_are_left_alone(caplog) -> None:
    from app.services.server_map import validate_server_map

    row = validate_server_map({})
    row["mine"] = {
        "transport": "http",
        "url": "http://127.0.0.1:9/mcp",
        "enabled": True,
        "tool_facts": _marked({"scan": {"kind": "strings"}}),
    }
    shipped = _shipped_dump()["mcp"]["servers"]["analysis"]["tool_facts"]
    first, second, *_ = list(shipped)
    row["analysis"] = {**row["analysis"], "tool_facts": _marked({first: None})}
    # A marked map with no removal in it (one tool's change alone) is the
    # operator's change of that tool, never a whole map missing the others.
    row["network"] = {**row["network"], "tool_facts": _marked({}) | _one_change("network")}
    conn = _connect()
    _insert(conn, SERVERS, row)
    _insert(conn, "core.mcp.servers.mine.auth_token", "ciphertext", secret=True)
    before = _rows(conn)
    with caplog.at_level(logging.INFO):
        _run(_module(), conn)
    assert _rows(conn) == before
    assert not [r for r in caplog.records if "rewritten" in r.getMessage()]


def test_a_custom_server_s_whole_map_is_marked_and_an_unknown_leaf_stays_whole(caplog) -> None:
    """A server an operator added ships nothing, so its whole map is its changes:
    it is marked and reads the same. A provider leaf no recorded release shipped
    declarations for is left unmarked, read whole until a save writes it."""
    from app.services.server_map import validate_server_map

    row = validate_server_map({})
    custom = {"scan": {"kind": "strings"}, "probe": {"display_name": "Probe"}}
    row["mine"] = {
        "transport": "http",
        "url": "http://127.0.0.1:9/mcp",
        "enabled": True,
        "tool_facts": dict(custom),
    }
    row["empty"] = {"transport": "http", "url": "http://127.0.0.1:9/mcp", "tool_facts": {}}
    unknown_leaf = "core.invented.block.tool_facts"
    conn = _connect()
    _insert(conn, SERVERS, row)
    _insert(conn, unknown_leaf, {"my_script": {"kind": "strings"}})
    in_force_before = _in_force({SERVERS: row})["mcp"]["servers"]["mine"]["tool_facts"]
    mod = _module()
    with caplog.at_level(logging.INFO):
        _run(mod, conn)
    after = _rows(conn)
    assert after[SERVERS]["mine"]["tool_facts"] == _marked(custom)
    assert after[SERVERS]["empty"]["tool_facts"] == {}
    assert after[unknown_leaf] == {"my_script": {"kind": "strings"}}
    assert _in_force(after)["mcp"]["servers"]["mine"]["tool_facts"] == in_force_before
    assert [r.getMessage() for r in caplog.records if r.name == mod.logger.name] == [mod.REWRITTEN]
    _run(mod, conn, "downgrade")
    assert _rows(conn)[SERVERS]["mine"]["tool_facts"] == custom


def test_one_fixed_info_line_is_logged_and_a_downgrade_reads_the_same(caplog) -> None:
    shipped = _shipped_dump()["mcp"]["servers"]["analysis"]["tool_facts"]
    whole = {**shipped, "pack_scan": _full({"display_name": "Pack scanner"})}
    whole.pop(next(iter(shipped)))
    conn = _connect()
    _insert(conn, SERVERS, _dev_row(analysis_facts=whole))
    mod = _module()
    with caplog.at_level(logging.INFO):
        _run(mod, conn)
    lines = [r for r in caplog.records if r.name == mod.logger.name]
    assert [r.getMessage() for r in lines] == [mod.REWRITTEN]
    assert lines[0].levelno == logging.INFO
    _run(mod, conn, "downgrade")
    restored = _rows(conn)[SERVERS]["analysis"]["tool_facts"]
    assert set(restored) == set(whole)
    from maljan.core.tool_declarations import ToolFacts

    for tool, entry in whole.items():
        assert ToolFacts.model_validate(restored[tool]) == ToolFacts.model_validate(entry)


def test_the_revision_s_mark_is_the_application_s() -> None:
    from maljan.core.tool_declarations import CHANGES_FORM, CHANGES_MARK

    mod = _module()
    assert (mod.CHANGES_MARK, mod.CHANGES_FORM) == (CHANGES_MARK, CHANGES_FORM)


def test_a_save_before_the_migration_keeps_every_tool_after_it() -> None:
    """The new code saves first (a hand-run deploy, a worker restart before
    ``make migrate``): its one-tool change of a built-in, and of a provider
    leaf, are marked, so the migration leaves them alone and no other shipped
    tool is dropped."""
    from app.services import settings_service as svc
    from app.services.server_map import validate_server_map

    shipped = _shipped_dump()["mcp"]["servers"]["analysis"]["tool_facts"]
    tool = sorted(shipped)[0]
    dev = _dev_row(analysis_facts=dict(shipped))
    changes = _marked({tool: {"display_name": "Mine"}})
    sent = {**dev, "analysis": {**dev["analysis"], "tool_facts": changes}}
    saved = validate_server_map(sent, stored=dev)
    ghidra = _shipped_dump()["static"]["ghidra"]["tool_facts"]
    leaf_tool = sorted(ghidra)[0]
    leaf = svc.stored_declaration_leaves({GHIDRA: _marked({leaf_tool: {"timeout_seconds": 5}})})[
        GHIDRA
    ]
    conn = _connect()
    _insert(conn, SERVERS, saved)
    _insert(conn, GHIDRA, leaf)
    before = _rows(conn)
    _run(_module(), conn)
    assert _rows(conn) == before
    held = _in_force(_rows(conn))
    analysis = held["mcp"]["servers"]["analysis"]["tool_facts"]
    assert set(analysis) == set(shipped)
    assert analysis[tool]["display_name"] == "Mine"
    assert analysis[tool]["kind"] == shipped[tool]["kind"]
    assert set(held["static"]["ghidra"]["tool_facts"]) == set(ghidra)


def test_an_unmigrated_whole_map_is_read_as_dev_read_it() -> None:
    shipped = _shipped_dump()["mcp"]["servers"]["analysis"]["tool_facts"]
    first, second, *_ = list(shipped)
    whole = dict(shipped)
    whole.pop(first)
    whole[second] = _full({"display_name": "Only this"})
    held = _in_force({SERVERS: _dev_row(analysis_facts=whole)})
    analysis = held["mcp"]["servers"]["analysis"]["tool_facts"]
    # The removed tool stays removed, and a field the whole entry leaves at its
    # default is not filled from what ships.
    assert analysis == whole
    ghidra = _shipped_dump()["static"]["ghidra"]["tool_facts"]
    tool = next(iter(ghidra))
    leaf = _in_force({GHIDRA: {tool: {"kind": "strings"}}})["static"]["ghidra"]["tool_facts"]
    assert set(leaf) == {tool}


def test_running_the_revision_again_changes_nothing(caplog) -> None:
    shipped = _shipped_dump()["mcp"]["servers"]["analysis"]["tool_facts"]
    whole = {**shipped, "pack_scan": _full({"display_name": "Pack scanner"})}
    conn = _connect()
    _insert(conn, SERVERS, _dev_row(analysis_facts=whole))
    _insert(conn, GHIDRA, {"my_script": {"kind": "strings"}})
    mod = _module()
    _run(mod, conn)
    once = _rows(conn)
    caplog.clear()
    with caplog.at_level(logging.INFO):
        _run(mod, conn)
    assert _rows(conn) == once
    assert not [r for r in caplog.records if r.name == mod.logger.name]


def test_a_downgrade_reads_as_dev_and_leaves_an_unmarked_map_alone() -> None:
    from app.services.server_map import validate_server_map

    shipped = _shipped_dump()["mcp"]["servers"]["analysis"]["tool_facts"]
    first, second, *_ = list(shipped)
    row = validate_server_map({})
    row["analysis"] = {
        **row["analysis"],
        "tool_facts": _marked({first: None, second: {"timeout_seconds": 77.0}}),
    }
    row["mine"] = {
        "transport": "http",
        "url": "http://127.0.0.1:9/mcp",
        "enabled": True,
        "tool_facts": _marked({"scan": {"kind": "strings"}}),
    }
    whole_leaf = {"my_script": {"kind": "strings"}}
    conn = _connect()
    _insert(conn, SERVERS, row)
    _insert(conn, GHIDRA, whole_leaf)
    in_force_before = _in_force(_rows(conn))
    _run(_module(), conn, "downgrade")
    after = _rows(conn)
    assert after[GHIDRA] == whole_leaf
    assert after[SERVERS]["mine"]["tool_facts"] == {"scan": {"kind": "strings"}}
    restored = after[SERVERS]["analysis"]["tool_facts"]
    assert "" not in restored and first not in restored
    assert restored[second]["timeout_seconds"] == 77.0
    # What dev reads from the downgraded rows (whole maps) is what was in force.
    assert _in_force(after) == in_force_before
