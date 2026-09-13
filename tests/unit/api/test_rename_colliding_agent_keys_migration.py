"""The stored document is repaired once, rather than renamed on every read.

The settings model performs the same rename when it loads, so a database that
never runs this still comes up. What the migration adds is that the new name is
written down: the console then shows it, and an operator who renames it again
to something they prefer keeps that name.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20260917000000_rename_colliding_agent_keys.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("rename_colliding_agent_keys", MIGRATION)
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


def _insert(conn, key, value, *, secret=False):
    import sqlalchemy as sa

    conn.execute(
        sa.text("INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, :s)"),
        {"k": key, "v": json.dumps(value), "s": 1 if secret else 0},
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


def _seeded_document(conn):
    _insert(
        conn,
        "core.agents.definitions",
        {
            "reverser": {"role": "generic", "prompt": "mine"},
            "strings": {"role": "generic", "prompt": "untouched"},
        },
    )
    _insert(
        conn,
        "core.agents.profiles",
        {
            "mobile": {"label": "Mine", "analysts": ["reverser"]},
            "team": {
                "label": "Team",
                "stages": [{"key": "analysis", "kind": "analysis", "agents": ["reverser"]}],
            },
        },
    )
    _insert(conn, "core.agents.profile", "mobile")
    _insert(conn, "core.llm.agents", {"reverser": {"provider": "openai", "model": "gpt-x"}})
    _insert(
        conn,
        "core.mcp.servers",
        {"mine": {"enabled": True, "transport": "stdio", "command": "x", "agents": ["reverser"]}},
    )
    _insert(conn, "core.react_agent_timeout_overrides", {"reverser": 900, "static": 1200})


class TestUpgrade:
    def test_a_colliding_definition_and_team_are_renamed(self):
        conn = _connect()
        _seeded_document(conn)
        _run(_module(), conn)
        rows = _rows(conn)
        assert set(rows["core.agents.definitions"]) == {"reverser_custom", "strings"}
        assert set(rows["core.agents.profiles"]) == {"mobile_custom", "team"}

    def test_the_operator_s_entry_is_carried_over_untouched(self):
        conn = _connect()
        _seeded_document(conn)
        _run(_module(), conn)
        rows = _rows(conn)
        assert rows["core.agents.definitions"]["reverser_custom"] == {
            "role": "generic",
            "prompt": "mine",
        }
        assert rows["core.agents.definitions"]["strings"]["prompt"] == "untouched"

    def test_every_reference_moves_with_it(self):
        conn = _connect()
        _seeded_document(conn)
        _run(_module(), conn)
        rows = _rows(conn)
        assert rows["core.agents.profiles"]["mobile_custom"]["analysts"] == ["reverser_custom"]
        assert rows["core.agents.profiles"]["team"]["stages"][0]["agents"] == ["reverser_custom"]
        assert rows["core.agents.profile"] == "mobile_custom"
        assert set(rows["core.llm.agents"]) == {"reverser_custom"}
        assert rows["core.mcp.servers"]["mine"]["agents"] == ["reverser_custom"]
        assert rows["core.react_agent_timeout_overrides"] == {
            "reverser_custom": 900,
            "static": 1200,
        }

    def test_a_document_with_no_collision_is_left_alone(self):
        conn = _connect()
        _insert(conn, "core.agents.definitions", {"strings": {"role": "generic", "prompt": "p"}})
        before = _rows(conn)
        _run(_module(), conn)
        assert _rows(conn) == before

    def test_an_empty_store_is_left_alone(self):
        conn = _connect()
        _run(_module(), conn)
        assert _rows(conn) == {}

    def test_running_it_twice_changes_nothing_the_second_time(self):
        conn = _connect()
        _seeded_document(conn)
        mod = _module()
        _run(mod, conn)
        once = _rows(conn)
        _run(mod, conn)
        assert _rows(conn) == once

    def test_a_secret_row_is_never_read_or_rewritten(self):
        """No agent map was ever stored as a secret, and a credential must not
        pass through a JSON rewrite. A secret row under one of these keys is
        therefore skipped entirely rather than parsed."""
        conn = _connect()
        _insert(conn, "core.agents.definitions", "encrypted-blob", secret=True)
        _run(_module(), conn)
        assert _rows(conn)["core.agents.definitions"] == "encrypted-blob"

    def test_a_second_collision_gets_a_counter(self):
        conn = _connect()
        _insert(
            conn,
            "core.agents.definitions",
            {
                "reverser": {"role": "generic", "prompt": "mine"},
                "reverser_custom": {"role": "generic", "prompt": "also mine"},
            },
        )
        _run(_module(), conn)
        definitions = _rows(conn)["core.agents.definitions"]
        assert definitions["reverser_custom"]["prompt"] == "also mine"
        assert definitions["reverser_custom_2"]["prompt"] == "mine"


class TestDowngrade:
    def test_it_puts_the_key_back_when_nothing_took_the_old_name(self):
        conn = _connect()
        _seeded_document(conn)
        mod = _module()
        _run(mod, conn)
        _run(mod, conn, "downgrade")
        rows = _rows(conn)
        assert set(rows["core.agents.definitions"]) == {"reverser", "strings"}
        assert set(rows["core.agents.profiles"]) == {"mobile", "team"}
        assert rows["core.agents.profile"] == "mobile"
        assert set(rows["core.llm.agents"]) == {"reverser"}

    def test_it_round_trips_the_whole_document(self):
        conn = _connect()
        _seeded_document(conn)
        before = _rows(conn)
        mod = _module()
        _run(mod, conn)
        _run(mod, conn, "downgrade")
        assert _rows(conn) == before

    def test_it_leaves_the_rename_alone_when_the_old_name_is_taken(self):
        """Undoing a rename into an occupied key would lose one of the two."""
        conn = _connect()
        _insert(
            conn,
            "core.agents.definitions",
            {
                "reverser": {"role": "generic", "prompt": "the seed"},
                "reverser_custom": {"role": "generic", "prompt": "mine"},
            },
        )
        _run(_module(), conn, "downgrade")
        definitions = _rows(conn)["core.agents.definitions"]
        assert definitions["reverser"]["prompt"] == "the seed"
        assert definitions["reverser_custom"]["prompt"] == "mine"

    def test_an_empty_store_is_left_alone(self):
        conn = _connect()
        _run(_module(), conn, "downgrade")
        assert _rows(conn) == {}


def test_the_revision_follows_the_stage_migration():
    mod = _module()
    assert mod.revision == "20260917000000"
    assert mod.down_revision == "20260916000000"


def test_the_seeded_names_it_knows_are_the_ones_this_release_added():
    mod = _module()
    assert set(mod.SEEDED_DEFINITIONS) == {"triage", "android_static", "reverser"}
    assert set(mod.SEEDED_PROFILES) == {"mobile", "deep_static"}
