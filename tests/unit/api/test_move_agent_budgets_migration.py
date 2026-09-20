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


class TestAValueTheNewFieldWouldRefuse:
    """It stays where it is. Moved, it would make every settings read raise.

    The maps are plain integer maps with no per-value bound, so a zero or a
    negative is storable in one today; the definition's field is bounded. A
    value left behind is still read by the deprecated-map fallback, so nothing
    is lost by leaving it.
    """

    @staticmethod
    def _after(value):
        conn = _connect()
        _insert(conn, DEFINITIONS, {"scout": {"role": "generic", "prompt": "p"}})
        _insert(conn, STEPS, {"scout": value})

        _run(_module(), conn)

        return _rows(conn)

    def test_a_zero_a_negative_and_a_non_number_all_stay_in_the_map(self) -> None:
        for value in (0, -5, "lots", 1.5, True, None, [], {"a": 1}):
            rows = self._after(value)
            assert rows[STEPS] == {"scout": value}, value
            assert "max_steps" not in rows[DEFINITIONS]["scout"], value

    def test_a_value_the_field_takes_still_moves(self) -> None:
        rows = self._after(24)

        assert rows[STEPS] == {}
        assert rows[DEFINITIONS]["scout"]["max_steps"] == 24

    def test_what_is_left_behind_is_still_the_budget_that_is_used(self) -> None:
        """The deprecated-map fallback reads it, held to the same bound."""
        from maljan.agents.base_agent import a_budget

        assert a_budget(0) is None
        assert a_budget(True) is None
        assert a_budget(24) == 24

    def test_a_good_value_beside_a_bad_one_in_the_same_map_still_moves(self) -> None:
        conn = _connect()
        _insert(
            conn,
            DEFINITIONS,
            {
                "scout": {"role": "generic", "prompt": "p"},
                "clerk": {"role": "generic", "prompt": "p"},
            },
        )
        _insert(conn, STEPS, {"scout": 0, "clerk": 24})

        _run(_module(), conn)

        rows = _rows(conn)
        assert rows[STEPS] == {"scout": 0}
        assert rows[DEFINITIONS]["clerk"]["max_steps"] == 24
        assert "max_steps" not in rows[DEFINITIONS]["scout"]

    def test_the_stored_settings_still_build_after_the_move(self) -> None:
        """The property the whole check exists for, asserted against the model."""
        from maljan.core.settings_overrides import build_settings

        conn = _connect()
        _insert(conn, DEFINITIONS, {"scout": {"role": "generic", "prompt": "p"}})
        _insert(conn, STEPS, {"scout": 0})

        _run(_module(), conn)

        settings = build_settings({"agents.definitions": _rows(conn)[DEFINITIONS]})
        assert settings.agents.definitions["scout"].max_steps is None


class TestASecretRowIsLeftAlone:
    """A credential must not pass through a JSON rewrite, as ``20260917000000`` says.

    Neither of these keys has ever been stored as a secret, so this is the
    pattern being followed rather than a case anybody reaches; what it buys is
    that reaching it skips the row instead of aborting the upgrade.
    """

    def test_a_secret_definition_map_is_skipped_rather_than_read(self) -> None:
        conn = _connect()
        _insert(conn, DEFINITIONS, "Z0FBQUFBQm9wYXFl", secret=True)
        _insert(conn, STEPS, {"scout": 24})

        _run(_module(), conn)

        assert _rows(conn)[STEPS] == {"scout": 24}

    def test_a_secret_override_map_is_skipped_rather_than_read(self) -> None:
        conn = _connect()
        _insert(conn, DEFINITIONS, {"scout": {"role": "generic", "prompt": "p"}})
        _insert(conn, STEPS, "Z0FBQUFBQm9wYXFl", secret=True)

        _run(_module(), conn)

        assert "max_steps" not in _rows(conn)[DEFINITIONS]["scout"]


class TestDowngrade:
    def test_a_moved_budget_goes_back_into_its_map(self):
        conn = _connect()
        _seeded(conn)
        mod = _module()

        _run(mod, conn)
        _run(mod, conn, "downgrade")

        rows = _rows(conn)
        # ``clerk``'s 30 is gone: the definition's 5 was the value in effect
        # and is the one written back. A downgrade is a recovery path.
        assert rows[STEPS] == {"scout": 24, "clerk": 5, "static": 40}
        assert rows[TIMEOUT] == {"scout": 900}
        assert "max_steps" not in rows[DEFINITIONS]["scout"]
        assert "timeout_seconds" not in rows[DEFINITIONS]["scout"]
