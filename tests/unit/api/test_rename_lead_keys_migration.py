"""An operator's own `lead` or `team_lead` is moved off the seeded name, once.

The same repair the earlier rename revision makes, for the two names this
release seeds; the rewriting is that revision's, so what is checked here is
that the new names go through it and that a document without them is left
alone.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20260921000000_rename_lead_keys.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("rename_lead_keys", MIGRATION)
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


def _insert(conn, key, value):
    import sqlalchemy as sa

    conn.execute(
        sa.text("INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, 0)"),
        {"k": key, "v": json.dumps(value)},
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
            "lead": {"role": "generic", "prompt": "mine"},
            "reverser": {"role": "generic", "prompt": "the earlier revision's business"},
        },
    )
    _insert(
        conn,
        "core.agents.profiles",
        {
            "team_lead": {
                "label": "Mine",
                "stages": [{"key": "analysis", "kind": "analysis", "agents": ["lead"]}],
            }
        },
    )
    _insert(conn, "core.agents.profile", "team_lead")
    _insert(conn, "core.llm.agents", {"lead": {"provider": "openai", "model": "gpt-x"}})


class TestUpgrade:
    def test_the_two_new_names_are_renamed_and_every_reference_moves(self):
        conn = _connect()
        _seeded_document(conn)
        _run(_module(), conn)
        rows = _rows(conn)
        assert set(rows["core.agents.definitions"]) == {"lead_custom", "reverser"}
        assert rows["core.agents.definitions"]["lead_custom"] == {
            "role": "generic",
            "prompt": "mine",
        }
        assert set(rows["core.agents.profiles"]) == {"team_lead_custom"}
        assert rows["core.agents.profiles"]["team_lead_custom"]["stages"][0]["agents"] == [
            "lead_custom"
        ]
        assert rows["core.agents.profile"] == "team_lead_custom"
        assert set(rows["core.llm.agents"]) == {"lead_custom"}

    def test_the_earlier_revision_s_names_are_not_its_business(self):
        conn = _connect()
        _insert(conn, "core.agents.definitions", {"reverser": {"role": "generic", "prompt": "p"}})
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


class TestDowngrade:
    def test_a_renamed_key_goes_back_when_the_old_name_is_free(self):
        conn = _connect()
        _seeded_document(conn)
        mod = _module()
        _run(mod, conn)
        _run(mod, conn, "downgrade")
        rows = _rows(conn)
        assert set(rows["core.agents.definitions"]) == {"lead", "reverser"}
        assert set(rows["core.agents.profiles"]) == {"team_lead"}
        assert rows["core.agents.profile"] == "team_lead"

    def test_a_renamed_key_stays_when_the_seed_has_since_been_written(self):
        conn = _connect()
        _insert(
            conn,
            "core.agents.definitions",
            {
                "lead_custom": {"role": "generic", "prompt": "mine"},
                "lead": {"role": "lead", "prompt": "the seed"},
            },
        )
        _run(_module(), conn, "downgrade")
        assert set(_rows(conn)["core.agents.definitions"]) == {"lead_custom", "lead"}
