"""Stored UI overrides survive the provider rename.

The alembic revision renames ``runtime_settings.key`` in place. It is derived
from the same alias table the config uses, is idempotent (running it twice is a
no-op), and never overwrites a row that already carries the new key.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

_REV = _API / "alembic" / "versions" / "20260903000000_rename_provider_setting_keys.py"


def _load():
    spec = importlib.util.spec_from_file_location("rename_provider_setting_keys", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_rename_table_covers_every_moved_key():
    from maljan.core.config import SETTINGS_ALIASES

    mod = _load()
    for old, new in SETTINGS_ALIASES:
        if old in ("mcp.ghidra", "mcp.cape"):
            # Sub-tree aliases: the stored keys are leaves under them.
            assert any(k.startswith(f"core.{old}.") for k in mod.KEY_RENAMES), old
        elif old.startswith("static.generic."):
            # Folded into core.mcp.servers by 20260905000000, not a rename.
            assert f"core.{old}" not in mod.KEY_RENAMES
        else:
            assert mod.KEY_RENAMES[f"core.{old}"] == f"core.{new}"


def test_every_renamed_key_is_a_real_catalog_key():
    from app.services.settings_catalog_api import catalog_index

    mod = _load()
    index = catalog_index()
    for old, new in mod.KEY_RENAMES.items():
        assert new in index, f"{old} renames to unknown {new}"


def test_renames_are_one_to_one():
    mod = _load()
    assert len(set(mod.KEY_RENAMES.values())) == len(mod.KEY_RENAMES)


def test_upgrade_is_idempotent_and_keeps_the_new_row_on_collision(caplog):
    """Exercised against a throwaway in-memory SQLite database, never the
    developer database. Binding a plain connection through ``MigrationContext``
    and resolving the module's ``op`` calls through ``Operations.context`` is
    the standard way to run a revision's data migration outside a real
    ``alembic upgrade``.

    Covers the three properties the brief cannot check by inspection alone:
    a second ``upgrade()`` pass changes nothing (idempotent), a row already
    sitting at both the legacy and the current key keeps the current row's
    value and only logs the collision, and ``downgrade()`` reverses a plain
    rename. Values are opaque strings throughout, standing in for an
    already-encrypted secret payload the migration must move without ever
    reading it as anything but a key lookup.
    """
    import logging

    import sqlalchemy as sa
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _load()
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        conn.execute(sa.text("CREATE TABLE runtime_settings (key TEXT PRIMARY KEY, value TEXT)"))
        conn.execute(
            sa.text("INSERT INTO runtime_settings (key, value) VALUES (:k, :v)"),
            {"k": "core.sandbox.backend", "v": '"cape2"'},
        )
        # Both the legacy and the current key are already set for the same
        # setting (an operator saved the new one before this revision ran).
        conn.execute(
            sa.text("INSERT INTO runtime_settings (key, value) VALUES (:k, :v)"),
            {"k": "core.sandbox.cape2_api_token", "v": '"enc:v1:OLD"'},
        )
        conn.execute(
            sa.text("INSERT INTO runtime_settings (key, value) VALUES (:k, :v)"),
            {"k": "core.sandbox.cape2.api_token", "v": '"enc:v1:NEW"'},
        )
        conn.commit()

        ctx = MigrationContext.configure(conn)
        with caplog.at_level(logging.WARNING):
            with Operations.context(ctx):
                mod.upgrade()
            first_pass = dict(
                conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall()
            )
            with Operations.context(ctx):
                mod.upgrade()  # second pass: must change nothing
            second_pass = dict(
                conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall()
            )

        assert first_pass == second_pass
        assert first_pass["core.sandbox.provider"] == '"cape2"'
        assert "core.sandbox.backend" not in first_pass
        # Collision: the row already at the new key survives with its own
        # value untouched; the stale row at the old key is gone.
        assert first_pass["core.sandbox.cape2.api_token"] == '"enc:v1:NEW"'
        assert "core.sandbox.cape2_api_token" not in first_pass
        assert "core.sandbox.cape2_api_token" in caplog.text
        assert "core.sandbox.cape2.api_token" in caplog.text

        with Operations.context(ctx):
            mod.downgrade()
        reverted = dict(conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall())
        assert reverted["core.sandbox.backend"] == '"cape2"'
        assert reverted["core.sandbox.cape2_api_token"] == '"enc:v1:NEW"'
