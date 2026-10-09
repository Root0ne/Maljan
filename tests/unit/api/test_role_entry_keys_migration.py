"""The mediator and the summariser take their ``llm.agents`` keys, once, in the store.

Two repairs in one revision. The two summariser settings that never reached a
model (``preprocessing.summarizer_provider`` and ``summarizer_model``) leave
the store; ``llm.agents.summarizer`` is what sets that model now. And an
operator's own agent definition named ``mediator`` or ``summarizer`` moves to
``<key>_custom`` with every reference, its ``llm.agents`` entry included, so
the entry that configured that agent does not start configuring the role.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261009000000_role_entries_for_mediator_and_summarizer.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("role_entries", MIGRATION)
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


def _own_agents(conn):
    _insert(
        conn,
        "core.agents.definitions",
        {
            "mediator": {"role": "generic", "prompt": "mine"},
            "summarizer": {"role": "generic", "prompt": "also mine"},
            "helper": {"role": "generic", "prompt": "p"},
        },
    )
    _insert(
        conn,
        "core.agents.profiles",
        {
            "mine": {
                "label": "Mine",
                "stages": [
                    {"key": "analysis", "kind": "analysis", "agents": ["mediator", "helper"]}
                ],
            }
        },
    )
    _insert(
        conn,
        "core.llm.agents",
        {
            "mediator": {"provider": "openai", "model": "gpt-x"},
            "helper": {"provider": "openai", "model": "gpt-y"},
        },
    )


class TestTheRetiredSettings:
    def test_the_two_rows_go_and_their_neighbours_stay(self):
        conn = _connect()
        _insert(conn, "core.preprocessing.summarizer_provider", "openai")
        _insert(conn, "core.preprocessing.summarizer_model", "gpt-x")
        _insert(conn, "core.preprocessing.summarizer_max_words", 90)
        _insert(conn, "core.preprocessing.use_function_summarizer", True)

        _run(_module(), conn)

        assert _rows(conn) == {
            "core.preprocessing.summarizer_max_words": 90,
            "core.preprocessing.use_function_summarizer": True,
        }

    def test_no_entry_is_made_from_them(self):
        conn = _connect()
        _insert(conn, "core.preprocessing.summarizer_provider", "openai")
        _insert(conn, "core.preprocessing.summarizer_model", "gpt-x")

        _run(_module(), conn)

        assert "core.llm.agents" not in _rows(conn)


class TestAnOwnAgentUnderARoleKey:
    def test_it_moves_with_every_reference(self):
        conn = _connect()
        _own_agents(conn)

        _run(_module(), conn)
        rows = _rows(conn)

        assert set(rows["core.agents.definitions"]) == {
            "mediator_custom",
            "summarizer_custom",
            "helper",
        }
        assert rows["core.agents.definitions"]["mediator_custom"]["prompt"] == "mine"
        stage = rows["core.agents.profiles"]["mine"]["stages"][0]
        assert stage["agents"] == ["mediator_custom", "helper"]
        assert set(rows["core.llm.agents"]) == {"mediator_custom", "helper"}

    def test_an_entry_a_deleted_agent_left_behind_moves_too(self):
        """No role read ``llm.agents.mediator`` before this revision.

        So one stored then belonged to an agent, never to the role.
        """
        conn = _connect()
        _insert(
            conn,
            "core.llm.agents",
            {
                "mediator": {"provider": "openai", "model": "gpt-x"},
                "summarizer": {"provider": "openai", "model": "gpt-s"},
                "helper": {"provider": "openai", "model": "gpt-y"},
            },
        )

        _run(_module(), conn)

        assert _rows(conn)["core.llm.agents"] == {
            "mediator_custom": {"provider": "openai", "model": "gpt-x"},
            "summarizer_custom": {"provider": "openai", "model": "gpt-s"},
            "helper": {"provider": "openai", "model": "gpt-y"},
        }

    def test_a_downgrade_puts_a_left_behind_entry_back(self):
        conn = _connect()
        _insert(conn, "core.llm.agents", {"mediator": {"provider": "openai", "model": "gpt-x"}})
        mod = _module()
        _run(mod, conn)
        _run(mod, conn, "downgrade")
        assert set(_rows(conn)["core.llm.agents"]) == {"mediator"}

    def test_running_it_twice_changes_nothing_the_second_time(self):
        conn = _connect()
        _own_agents(conn)
        mod = _module()
        _run(mod, conn)
        once = _rows(conn)
        _run(mod, conn)
        assert _rows(conn) == once

    def test_a_downgrade_puts_the_names_back_when_they_are_free(self):
        conn = _connect()
        _own_agents(conn)
        mod = _module()
        _run(mod, conn)
        _run(mod, conn, "downgrade")
        rows = _rows(conn)
        assert set(rows["core.agents.definitions"]) == {"mediator", "summarizer", "helper"}
        assert set(rows["core.llm.agents"]) == {"mediator", "helper"}


def test_the_revision_follows_the_function_ranges():
    mod = _module()
    assert mod.down_revision == "20261008000000"
    assert mod.revision == "20261009000000"
