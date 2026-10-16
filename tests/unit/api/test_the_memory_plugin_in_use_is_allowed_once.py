"""The memory plugin a deployment has in use is added to the plugin allow-list once.

Installed memory backends used to load on their own; a plugin now loads only
when the allow-list names it. Revision ``20261016000000`` adds the one plugin
the stored ``memory.backend`` names, when it is installed, and nothing else.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261016000000_memory_plugin_in_use_allowed.py"
)


def _module() -> Any:
    spec = importlib.util.spec_from_file_location(MIGRATION.stem, MIGRATION)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _connect(rows: dict[str, Any]) -> Any:
    """A throwaway in-memory SQLite database holding ``rows``, never the developer database."""
    import sqlalchemy as sa

    conn = sa.create_engine("sqlite://").connect()
    conn.execute(
        sa.text(
            "CREATE TABLE runtime_settings ("
            "key TEXT PRIMARY KEY, value TEXT, is_secret BOOLEAN NOT NULL DEFAULT 0)"
        )
    )
    for key, value in rows.items():
        conn.execute(
            sa.text("INSERT INTO runtime_settings (key, value) VALUES (:k, :v)"),
            {"k": key, "v": json.dumps(value)},
        )
    return conn


def _rows(conn: Any) -> dict[str, Any]:
    import sqlalchemy as sa

    result = conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall()
    return {key: json.loads(value) for key, value in result}


ALLOWED = "core.plugins.allowed"
BACKEND = "core.memory.backend"


def test_the_backend_in_use_is_allowed_when_its_plugin_is_installed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    conn = _connect({BACKEND: "vectorhub"})
    with caplog.at_level("WARNING"):
        added = _module().allow_the_memory_plugin_in_use(conn, ["vectorhub", "other"])
    assert added == "memory:vectorhub"
    assert _rows(conn)[ALLOWED] == ["memory:vectorhub"]
    assert "added to the plugin allow-list" in caplog.text


def test_an_existing_list_keeps_its_entries_and_gains_the_one() -> None:
    conn = _connect({BACKEND: " VectorHub ", ALLOWED: ["llm:acme"]})
    assert _module().allow_the_memory_plugin_in_use(conn, ["vectorhub"]) == "memory:vectorhub"
    assert _rows(conn)[ALLOWED] == ["llm:acme", "memory:vectorhub"]


def test_a_list_that_names_it_already_is_left_alone() -> None:
    conn = _connect({BACKEND: "vectorhub", ALLOWED: ["memory:vectorhub"]})
    assert _module().allow_the_memory_plugin_in_use(conn, ["vectorhub"]) is None
    assert _rows(conn)[ALLOWED] == ["memory:vectorhub"]


@pytest.mark.parametrize(
    ("rows", "installed"),
    [
        ({}, ["vectorhub"]),
        ({BACKEND: "qdrant"}, ["qdrant"]),
        ({BACKEND: "memory"}, ["memory"]),
        ({BACKEND: "vectorhub"}, []),
        ({BACKEND: "vectorhub"}, ["vectorhub-plugin"]),
        ({BACKEND: "vectorhub", ALLOWED: "not a list"}, ["vectorhub"]),
    ],
)
def test_nothing_else_is_ever_added(rows: dict[str, Any], installed: list[str]) -> None:
    conn = _connect(rows)
    assert _module().allow_the_memory_plugin_in_use(conn, installed) is None
    assert _rows(conn) == rows


@pytest.mark.parametrize(
    ("installed", "named"),
    [
        (["vectorhub-plugin"], "vectorhub-plugin"),
        (["VectorHub"], "VectorHub"),
        ([], "none"),
    ],
)
def test_a_backend_no_entry_point_carries_by_name_is_stated_with_what_to_do(
    installed: list[str],
    named: str,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    conn = _connect({BACKEND: "vectorhub"})
    with caplog.at_level("WARNING"):
        assert _module().allow_the_memory_plugin_in_use(conn, installed) is None
    printed = capsys.readouterr().out
    for said in (printed, caplog.text):
        assert "The memory backend in use, 'vectorhub', is not shipped" in said
        assert f"(installed memory entry points: {named})" in said
        assert "must be the backend id it registers in lowercase" in said
        assert "allow memory:vectorhub" in said
    assert ALLOWED not in _rows(conn)


def test_the_revision_names_what_the_application_names() -> None:
    from maljan.core.plugins import ALLOW_LIST_KEY, PLUGIN_GROUPS
    from maljan.memory.store_factory import BUILT_IN_BACKENDS

    mod = _module()
    assert mod.MEMORY_GROUP == PLUGIN_GROUPS["memory"]
    assert mod.SHIPPED_BACKENDS == BUILT_IN_BACKENDS
    assert mod.ALLOW_LIST_KEY == ALLOW_LIST_KEY
    assert mod.BACKEND_KEY == "core.memory.backend"
    assert mod.down_revision == "20261014000000"


def test_the_written_list_is_one_the_settings_accept() -> None:
    from maljan.core.config import Settings

    conn = _connect({BACKEND: "vectorhub"})
    _module().allow_the_memory_plugin_in_use(conn, ["vectorhub"])
    stored = _rows(conn)[ALLOWED]
    assert Settings(_env_file=None, plugins={"allowed": stored}).plugins.allowed == stored
