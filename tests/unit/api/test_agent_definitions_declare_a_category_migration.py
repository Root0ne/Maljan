"""Stored agent definitions are given the category their role and tools fit, once (T-559).

Revision 20261103000000 writes the category into each stored definition that
is not a built-in and names none, by the rule the settings model reads it by;
it keeps a stored category, leaves a built-in to its seed, names in the log
what it set to ``other`` because nothing told it and what it could not fit,
and writes nothing the second time.
"""

from __future__ import annotations

import importlib.util
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from malspark.core.agent_category import fitting_category
from malspark.core.config import Settings, _builtin_definitions

ROOT = Path(__file__).resolve().parents[3]
MIGRATION = (
    ROOT / "apps/api/alembic/versions/20261103000000_agent_definitions_declare_a_category.py"
)
KEY = "core.agents.definitions"


def _module():
    spec = importlib.util.spec_from_file_location(MIGRATION.stem, MIGRATION)
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


def _insert(conn, key: str, value: Any, secret: bool = False) -> None:
    import sqlalchemy as sa

    conn.execute(
        sa.text("INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, :s)"),
        {"k": key, "v": json.dumps(value), "s": secret},
    )


def _rows(conn) -> dict[str, Any]:
    import sqlalchemy as sa

    result = conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall()
    return {k: json.loads(v) for k, v in result}


def _run(mod, conn, direction: str = "upgrade") -> None:
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        getattr(mod, direction)()


STORED = {
    "my_reverser": {"role": "generic", "prompt": "r", "tools": [{"kind": "provider"}]},
    "my_sandbox": {"role": "generic", "prompt": "s", "tools": [{"kind": "sandbox"}]},
    "my_static": {"role": "static", "static_provider": "r2"},
    "my_checker": {
        "role": "generic",
        "prompt": "c",
        "tools": [{"kind": "mcp", "server": "knowledge"}],
    },
    "chosen": {"role": "generic", "prompt": "c", "category": "intel"},
    "triage": {"role": "generic", "enabled": False},
}


def test_the_chain_follows_the_budgets_revision() -> None:
    mod = _module()
    assert (mod.revision, mod.down_revision) == ("20261103000000", "20261102000000")


def test_each_stored_definition_is_given_the_category_it_fits(caplog) -> None:
    conn = _connect()
    _insert(conn, KEY, STORED)
    with caplog.at_level(logging.WARNING):
        _run(_module(), conn)
    stored = _rows(conn)[KEY]
    assert {name: entry.get("category") for name, entry in stored.items()} == {
        "my_reverser": "code_reader",
        "my_sandbox": "dynamic",
        "my_static": "code_reader",
        "my_checker": "other",
        "chosen": "intel",
        # A built-in reads its seed's; nothing is written for it.
        "triage": None,
    }
    # Every other field is as it was stored.
    assert {k: v for k, v in stored["my_reverser"].items() if k != "category"} == STORED[
        "my_reverser"
    ]
    assert "my_checker" in caplog.text and "tell no category" in caplog.text


def test_the_store_loads_and_reads_what_was_written() -> None:
    conn = _connect()
    _insert(conn, KEY, STORED)
    _run(_module(), conn)
    stored = _rows(conn)[KEY]
    cfg = Settings(_env_file=None, agents={"definitions": stored})
    assert cfg.agents.definitions["my_reverser"].category == "code_reader"
    assert cfg.agents.definitions["triage"].category == "static"
    # Read without the migration, the settings model fits the same values.
    unmigrated = Settings(_env_file=None, agents={"definitions": STORED})
    for name in STORED:
        assert unmigrated.agents.definitions[name].category == cfg.agents.definitions[name].category


def test_running_it_twice_writes_nothing_more() -> None:
    conn = _connect()
    _insert(conn, KEY, STORED)
    mod = _module()
    _run(mod, conn)
    once = _rows(conn)
    _run(mod, conn)
    assert _rows(conn) == once


def test_what_cannot_be_fitted_is_left_and_named(caplog) -> None:
    conn = _connect()
    odd = {
        "broken": "not an object",
        "unknown": {"role": "wizard"},
        "bad": {"role": "generic", "prompt": "p", "category": "reverser"},
    }
    _insert(conn, KEY, odd)
    with caplog.at_level(logging.WARNING):
        _run(_module(), conn)
    assert _rows(conn)[KEY] == odd
    for name in ("bad", "broken", "unknown"):
        assert name in caplog.text


def test_a_secret_row_and_other_rows_are_not_touched() -> None:
    conn = _connect()
    _insert(conn, KEY, STORED, secret=True)
    _insert(conn, "core.agents.profile", "default")
    _run(_module(), conn)
    assert _rows(conn) == {KEY: STORED, "core.agents.profile": "default"}


def test_the_downgrade_writes_nothing() -> None:
    conn = _connect()
    _insert(conn, KEY, STORED)
    mod = _module()
    _run(mod, conn)
    once = _rows(conn)
    _run(mod, conn, "downgrade")
    assert _rows(conn) == once


@pytest.mark.parametrize(
    "entry",
    [
        {"role": "static"},
        {"role": "dynamic"},
        {"role": "network"},
        {"role": "judge"},
        {"role": "report"},
        {"role": "generic"},
        {"role": "lead", "tools": [{"kind": "agent", "agent": "static"}]},
        {"role": "generic", "tools": [{"kind": "provider", "provider": "r2"}]},
        {"role": "generic", "tools": [{"kind": "sandbox"}, {"kind": "provider"}]},
        {"role": "generic", "data_sources": ["sandbox.network"]},
        {"role": "generic", "data_sources": ["sandbox.full"]},
        {"role": "generic", "data_sources": ["sample.path"]},
        {"role": "generic", "tools": [{"kind": "capability", "capability": "reputation"}]},
        {"role": "generic", "tools": [{"kind": "capability", "capability": "other"}]},
        {"role": "generic", "tools": [{"kind": "mcp", "server": "x"}]},
    ],
)
def test_the_revision_s_rule_is_the_settings_model_s(entry: dict[str, Any]) -> None:
    assert _module().fitting_category(entry) == fitting_category(entry)


def test_the_built_in_keys_it_leaves_are_seeded_ones() -> None:
    assert set(_module().BUILTIN_KEYS) <= set(_builtin_definitions())
