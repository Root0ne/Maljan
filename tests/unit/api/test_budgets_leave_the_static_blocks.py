"""A deployment's call floor and its rule check budget move out of the static blocks, in the store.

The migration is run against a throwaway in-memory SQLite copy of the table,
never a real database.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa

MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261102000000_budgets_leave_the_static_blocks.py"
)
CAPA = "core.static.capa.timeout_seconds"
YARA = "core.static.yara.timeout_seconds"
BUDGET = "core.mcp.breaker.default_call_timeout_seconds"
CHECK = "core.reporting.detection_rule_check_seconds"


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("budgets_leave_the_static_blocks", MIGRATION)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _connect() -> Any:
    conn = sa.create_engine("sqlite://").connect()
    conn.execute(
        sa.text(
            "CREATE TABLE runtime_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, "
            "is_secret BOOLEAN NOT NULL DEFAULT 0, updated_by TEXT, updated_at TEXT)"
        )
    )
    return conn


def _insert(conn: Any, key: str, value: Any, is_secret: bool = False) -> None:
    conn.execute(
        sa.text("INSERT INTO runtime_settings VALUES (:k, :v, :s, 'admin-1', '2026-01-02')"),
        {"k": key, "v": json.dumps(value), "s": is_secret},
    )


def _table(conn: Any) -> dict[str, Any]:
    rows = conn.execute(sa.text("SELECT key, value FROM runtime_settings"))
    return {k: json.loads(v) for k, v in rows.fetchall()}


def _run(conn: Any, direction: str) -> None:
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    with Operations.context(MigrationContext.configure(conn)):
        getattr(_module(), direction)()


def test_the_revision_follows_the_head_it_was_written_on() -> None:
    mod = _module()
    assert (mod.revision, mod.down_revision) == ("20261102000000", "20261101000000")
    assert (mod.CALL_BUDGET_KEY, mod.OLD_CHECK_KEY, mod.NEW_CHECK_KEY) == (BUDGET, YARA, CHECK)


def test_the_restated_defaults_are_the_settings_models() -> None:
    from maljan.core.config import MCPBreakerConfig, ReportingConfig, StaticCapaConfig

    mod = _module()
    assert mod.FLOOR_SOURCES[CAPA] == StaticCapaConfig().timeout_seconds
    assert mod.FLOOR_SOURCES[YARA] == ReportingConfig().detection_rule_check_seconds
    assert mod.CALL_BUDGET_DEFAULT == MCPBreakerConfig().default_call_timeout_seconds
    assert mod.floor({}) == mod.CALL_BUDGET_DEFAULT


def test_the_moved_key_is_the_one_the_settings_rename_names_and_the_new_ones_are_held() -> None:
    from maljan.core.settings_annotations import RENAMED_SETTINGS
    from maljan.core.settings_catalog import core_catalog

    keys = {e.key for e in core_catalog()}
    assert RENAMED_SETTINGS[YARA] == CHECK
    assert {BUDGET, CHECK} <= keys and YARA not in keys


@pytest.mark.parametrize(
    ("stored", "written"),
    [
        ({CAPA: 900}, 900),
        ({YARA: 1200}, 1200),
        ({CAPA: 900, YARA: 1200}, 1200),
        ({CAPA: 120}, 120),
        ({CAPA: 120.5}, 120.5),
    ],
)
def test_upgrade_writes_the_floor_every_server_had(stored: dict[str, Any], written: Any) -> None:
    conn = _connect()
    for key, value in stored.items():
        _insert(conn, key, value)
    _run(conn, "upgrade")
    table = _table(conn)
    assert table[BUDGET] == written
    assert table.get(CAPA) == stored.get(CAPA)
    assert table.get(CHECK) == stored.get(YARA)
    assert YARA not in table


def test_the_settings_read_the_same_budget_the_old_floor_gave() -> None:
    """Every built-in server's budget is the same before and after, by the model's own reading."""
    from maljan.core.config import Settings
    from maljan.providers.server_guard import server_call_budget

    conn = _connect()
    _insert(conn, CAPA, 900)
    _insert(conn, YARA, 1200)
    _run(conn, "upgrade")
    table = _table(conn)
    settings = Settings.model_validate(
        {
            "static": {"capa": {"timeout_seconds": table[CAPA]}},
            "mcp": {"breaker": {"default_call_timeout_seconds": table[BUDGET]}},
            "reporting": {"detection_rule_check_seconds": table[CHECK]},
        }
    )
    for name, block in settings.mcp.servers.items():
        assert server_call_budget(settings, block) == 1200.0, name
    assert settings.reporting.detection_rule_check_seconds == 1200


def test_nothing_is_written_where_the_floor_is_the_default() -> None:
    conn = _connect()
    _insert(conn, CAPA, 300)
    _insert(conn, "core.static.provider", "r2")
    _run(conn, "upgrade")
    assert _table(conn) == {CAPA: 300, "core.static.provider": "r2"}


def test_a_held_budget_and_a_held_check_are_kept() -> None:
    conn = _connect()
    _insert(conn, CAPA, 900)
    _insert(conn, YARA, 30)
    _insert(conn, BUDGET, 45)
    _insert(conn, CHECK, 15)
    _run(conn, "upgrade")
    assert _table(conn) == {CAPA: 900, BUDGET: 45, CHECK: 15}


def test_a_secret_or_a_value_that_is_no_number_is_read_as_not_stored() -> None:
    conn = _connect()
    _insert(conn, CAPA, "nine hundred")
    _insert(conn, YARA, 1200, is_secret=True)
    _run(conn, "upgrade")
    assert _table(conn) == {CAPA: "nine hundred", YARA: 1200}


def test_running_it_again_writes_nothing_more() -> None:
    conn = _connect()
    _insert(conn, CAPA, 900)
    _insert(conn, YARA, 20)
    _run(conn, "upgrade")
    before = _table(conn)
    _run(conn, "upgrade")
    assert _table(conn) == before == {CAPA: 900, BUDGET: 900, CHECK: 20}


def test_downgrade_puts_the_check_back_and_drops_the_budget() -> None:
    conn = _connect()
    _insert(conn, CAPA, 900)
    _insert(conn, YARA, 20)
    _run(conn, "upgrade")
    _run(conn, "downgrade")
    assert _table(conn) == {CAPA: 900, YARA: 20}
