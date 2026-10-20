"""An agent tool left naming a role key moves to the agent that key's rename moved, once.

Revision 20261009000000 moved an operator's own ``mediator`` or ``summarizer``
definition to ``<key>_custom`` and every reference it knew of, but not a
lead's agent tool, which still names the role key: a reference to nothing the
settings could hold. This revision points it at the renamed definition, only
when exactly one definition is that rename, writes nothing else and finds
nothing to do the second time.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
MIGRATION = ROOT / "apps/api/alembic/versions/20261025000000_agent_tools_follow_a_renamed_agent.py"
ROLE_ENTRIES = (
    ROOT / "apps/api/alembic/versions/20261009000000_role_entries_for_mediator_and_summarizer.py"
)


def _module(path: Path = MIGRATION):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _connect():
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


def _insert(conn, key, value, secret=False):
    import sqlalchemy as sa

    conn.execute(
        sa.text("INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, :s)"),
        {"k": key, "v": json.dumps(value), "s": secret},
    )


def _rows(conn):
    import sqlalchemy as sa

    result = conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall()
    return {k: json.loads(v) for k, v in result}


def _run(mod, conn, direction="upgrade"):
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        getattr(mod, direction)()


def _lead(*called: str) -> dict:
    return {
        "role": "lead",
        "prompt": "lead",
        "tools": [{"kind": "agent", "agent": name} for name in called]
        + [{"kind": "mcp", "server": "knowledge"}],
    }


def _migrated_store(conn, **definitions):
    """A store 20261009000000 already ran over: the agent renamed, the lead's tool not."""
    _insert(
        conn,
        "core.agents.definitions",
        definitions
        or {
            "mediator_custom": {"role": "generic", "prompt": "mine"},
            "my_lead": _lead("mediator", "static"),
        },
    )
    _insert(conn, "core.llm.agents", {"mediator_custom": {"provider": "openai", "model": "m"}})


def test_a_stale_agent_tool_names_the_renamed_agent() -> None:
    conn = _connect()
    _migrated_store(conn)
    _run(_module(), conn)
    tools = _rows(conn)["core.agents.definitions"]["my_lead"]["tools"]
    assert tools == [
        {"kind": "agent", "agent": "mediator_custom"},
        {"kind": "agent", "agent": "static"},
        {"kind": "mcp", "server": "knowledge"},
    ]


def test_running_it_twice_changes_nothing_the_second_time() -> None:
    conn = _connect()
    _migrated_store(conn)
    mod = _module()
    _run(mod, conn)
    once = _rows(conn)
    _run(mod, conn)
    assert _rows(conn) == once


def test_other_rows_and_untouched_definitions_are_not_written() -> None:
    conn = _connect()
    _migrated_store(conn)
    _insert(conn, "core.agents.profile", "default")
    _insert(conn, "core.mcp.servers.vt.auth_token", "ciphertext", secret=True)
    before = _rows(conn)
    _run(_module(), conn)
    after = _rows(conn)
    assert {k: v for k, v in after.items() if k != "core.agents.definitions"} == {
        k: v for k, v in before.items() if k != "core.agents.definitions"
    }
    assert (
        after["core.agents.definitions"]["mediator_custom"]
        == before["core.agents.definitions"]["mediator_custom"]
    )


def test_a_store_with_nothing_stale_is_not_written(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _connect()
    _migrated_store(conn, helper={"role": "generic", "prompt": "p"}, my_lead=_lead("helper"))
    mod = _module()
    writes: list = []
    monkeypatch.setattr(mod, "_store", lambda *a: writes.append(a))
    _run(mod, conn)
    assert writes == []


def test_a_reference_to_a_seeded_key_is_left_as_it_is() -> None:
    conn = _connect()
    _migrated_store(
        conn,
        reverser_custom={"role": "generic", "prompt": "mine"},
        my_lead=_lead("reverser"),
    )
    _run(_module(), conn)
    assert _rows(conn)["core.agents.definitions"]["my_lead"]["tools"][0]["agent"] == "reverser"


def test_with_two_candidates_the_reference_is_left_for_the_settings_to_refuse() -> None:
    conn = _connect()
    _migrated_store(
        conn,
        mediator_custom={"role": "generic", "prompt": "an older one"},
        mediator_custom_2={"role": "generic", "prompt": "the renamed one"},
        my_lead=_lead("mediator"),
    )
    _run(_module(), conn)
    assert _rows(conn)["core.agents.definitions"]["my_lead"]["tools"][0]["agent"] == "mediator"


def test_the_numbered_rename_is_followed_when_it_is_the_only_one() -> None:
    conn = _connect()
    _migrated_store(
        conn,
        summarizer_custom_2={"role": "generic", "prompt": "mine"},
        my_lead=_lead("summarizer"),
    )
    _run(_module(), conn)
    tools = _rows(conn)["core.agents.definitions"]["my_lead"]["tools"]
    assert tools[0]["agent"] == "summarizer_custom_2"


def test_after_the_role_entry_revision_the_store_loads() -> None:
    """The two revisions in order leave a document the settings model accepts."""
    from maljan.core.settings_overrides import build_settings

    conn = _connect()
    _insert(
        conn,
        "core.agents.definitions",
        {"mediator": {"role": "generic", "prompt": "mine"}, "my_lead": _lead("mediator")},
    )
    _run(_module(ROLE_ENTRIES), conn)
    _run(_module(), conn)
    rows = _rows(conn)
    built = build_settings({"agents.definitions": rows["core.agents.definitions"]})
    called = [ref.agent for ref in built.agents.definitions["my_lead"].tools if ref.kind == "agent"]
    assert called == ["mediator_custom"]


def test_the_revision_follows_the_token_generation() -> None:
    mod = _module()
    assert mod.down_revision == "20261024000000"
    assert mod.revision == "20261025000000"
