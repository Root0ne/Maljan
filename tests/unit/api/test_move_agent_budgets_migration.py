"""A budget an operator set through the UI lands on the agent's own card.

The two override maps are read for one more release, so a database that never
runs this still honours what is in them. What the migration adds is that the
value moves to where the console now shows it: an operator who opens the agent
card sees the budget they set rather than a blank box they would fill in a
second time.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20260927000000_move_agent_budgets_into_definitions.py"
)

DEFINITIONS = "core.agents.definitions"
STEPS = "core.react_agent_max_steps_overrides"
TIMEOUT = "core.react_agent_timeout_overrides"


def _module():
    spec = importlib.util.spec_from_file_location("move_agent_budgets", MIGRATION)
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


def _seeded(conn):
    _insert(
        conn,
        DEFINITIONS,
        {
            "scout": {"role": "generic", "prompt": "look around"},
            "clerk": {"role": "generic", "prompt": "write it up", "max_steps": 5},
        },
    )
    _insert(conn, STEPS, {"scout": 24, "clerk": 30, "static": 40})
    _insert(conn, TIMEOUT, {"scout": 900})


class TestUpgrade:
    def test_a_budget_moves_onto_the_definition_it_belongs_to(self):
        conn = _connect()
        _seeded(conn)

        _run(_module(), conn)

        definitions = _rows(conn)[DEFINITIONS]
        assert definitions["scout"]["max_steps"] == 24
        assert definitions["scout"]["timeout_seconds"] == 900

    def test_what_moved_is_taken_out_of_the_map_so_the_two_cannot_drift(self):
        conn = _connect()
        _seeded(conn)

        _run(_module(), conn)

        assert "scout" not in _rows(conn)[STEPS]
        assert _rows(conn)[TIMEOUT] == {}

    def test_a_budget_for_an_agent_the_stored_map_does_not_name_is_left_alone(self):
        """A built-in the operator never edited keeps its map entry."""
        conn = _connect()
        _seeded(conn)

        _run(_module(), conn)

        assert _rows(conn)[STEPS]["static"] == 40

    def test_a_definition_that_already_says_so_is_not_overwritten(self):
        conn = _connect()
        _seeded(conn)

        _run(_module(), conn)

        assert _rows(conn)[DEFINITIONS]["clerk"]["max_steps"] == 5
        assert _rows(conn)[STEPS]["clerk"] == 30

    def test_a_store_with_nothing_to_move_is_not_written_to(self):
        conn = _connect()
        _insert(conn, DEFINITIONS, {"scout": {"role": "generic", "prompt": "p"}})

        _run(_module(), conn)

        assert _rows(conn) == {DEFINITIONS: {"scout": {"role": "generic", "prompt": "p"}}}

    def test_running_it_twice_changes_nothing_the_first_run_did_not(self):
        conn = _connect()
        _seeded(conn)
        mod = _module()

        _run(mod, conn)
        once = _rows(conn)
        _run(mod, conn)

        assert _rows(conn) == once


class TestDowngrade:
    def test_a_moved_budget_goes_back_into_its_map(self):
        conn = _connect()
        _seeded(conn)
        mod = _module()

        _run(mod, conn)
        _run(mod, conn, "downgrade")

        rows = _rows(conn)
        assert rows[STEPS] == {"scout": 24, "clerk": 5, "static": 40}
        assert rows[TIMEOUT] == {"scout": 900}
        assert "max_steps" not in rows[DEFINITIONS]["scout"]
        assert "timeout_seconds" not in rows[DEFINITIONS]["scout"]
