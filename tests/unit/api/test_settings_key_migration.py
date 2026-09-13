"""Stored UI overrides survive the provider rename.

The alembic revision renames ``runtime_settings.key`` in place. It carries its
own frozen copy of the renames it was written against, is idempotent (running it
twice is a no-op), and never overwrites a row that already carries the new key.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
_REV = _API / "alembic" / "versions" / "20260903000000_rename_provider_setting_keys.py"


def _load():
    spec = importlib.util.spec_from_file_location("rename_provider_setting_keys", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_rename_table_covers_every_moved_key():
    mod = _load()
    for old, new in mod._RENAMES:
        if old in ("mcp.ghidra", "mcp.cape"):
            # Sub-tree renames: the stored keys are leaves under them.
            assert any(k.startswith(f"core.{old}.") for k in mod.KEY_RENAMES), old
        elif old.startswith("static.generic."):
            # Folded into core.mcp.servers by 20260905000000, not a rename.
            assert f"core.{old}" not in mod.KEY_RENAMES
        else:
            assert mod.KEY_RENAMES[f"core.{old}"] == f"core.{new}"


# Leaves a later revision retired again (``20260913000000_drop_tool_selection_settings``
# removes the tool-selection modes). The rename table is frozen history, so its
# targets for these two are no longer catalog keys and are skipped here.
_RETIRED_LEAVES = ("tool_selection", "use_all_tools")


def test_every_renamed_key_is_a_real_catalog_key():
    from app.services.settings_catalog_api import catalog_index

    mod = _load()
    index = catalog_index()
    for old, new in mod.KEY_RENAMES.items():
        if new.rsplit(".", 1)[-1] in _RETIRED_LEAVES:
            continue
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


# ---------------------------------------------------------------------------
# 20260915000000 — the judgement-layer settings go, the rule directory moves
# ---------------------------------------------------------------------------

_JUDGEMENT_REV = _API / "alembic" / "versions" / "20260915000000_drop_judgement_layer_settings.py"


def _load_judgement_rev():
    spec = importlib.util.spec_from_file_location("drop_judgement_layer_settings", _JUDGEMENT_REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_no_dropped_judgement_key_is_still_a_catalog_key():
    """A key the revision deletes must be one the catalog no longer knows.

    The inverse of ``test_every_renamed_key_is_a_real_catalog_key``: a drop
    that removes a setting still in the catalog would delete an operator's
    live configuration.
    """
    from app.services.settings_catalog_api import catalog_index

    mod = _load_judgement_rev()
    index = catalog_index()
    for key in (*mod.DROPPED_KEYS, *mod.MOVED_KEYS):
        assert key not in index, f"{key} is still a catalog key"


def test_the_move_target_is_the_analysis_server_entry():
    from app.services.settings_catalog_api import catalog_index

    mod = _load_judgement_rev()
    assert mod.MAP_KEY in catalog_index()


def _judgement_engine(rows: dict[str, str]):
    import sqlalchemy as sa

    engine = sa.create_engine("sqlite://")
    conn = engine.connect()
    conn.execute(
        sa.text(
            "CREATE TABLE runtime_settings "
            "(key TEXT PRIMARY KEY, value TEXT, is_secret BOOLEAN DEFAULT 0)"
        )
    )
    for key, value in rows.items():
        conn.execute(
            sa.text("INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, 0)"),
            {"k": key, "v": value},
        )
    conn.commit()
    return conn


def test_the_judgement_keys_are_dropped_and_the_rule_dir_moves():
    import json

    import sqlalchemy as sa
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _load_judgement_rev()
    conn = _judgement_engine(
        {
            "core.preprocessing.use_attck_autocorrect": "true",
            "core.preprocessing.use_tool_artifacts": "false",
            "core.analysis.sigma_rules_dir": '"/srv/rules/sigma"',
            "core.llm.provider": '"ollama"',
        }
    )
    with conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
        first = dict(conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall())
        with Operations.context(ctx):
            mod.upgrade()  # second pass: nothing left to do
        assert (
            dict(conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall())
            == first
        )

        assert "core.preprocessing.use_attck_autocorrect" not in first
        assert "core.preprocessing.use_tool_artifacts" not in first
        assert "core.analysis.sigma_rules_dir" not in first
        # An unrelated override is untouched.
        assert first["core.llm.provider"] == '"ollama"'

        servers = json.loads(first[mod.MAP_KEY])
        assert servers["analysis"]["env"][mod.SIGMA_ENV_NAME] == "/srv/rules/sigma"

        with Operations.context(ctx):
            mod.downgrade()
        reverted = dict(conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall())
        assert json.loads(reverted["core.analysis.sigma_rules_dir"]) == "/srv/rules/sigma"


def test_a_secret_row_is_never_folded_into_the_server_document():
    """``is_secret`` values are encrypted and the registry has no key for them."""
    import sqlalchemy as sa
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _load_judgement_rev()
    conn = _judgement_engine({})
    with conn:
        conn.execute(
            sa.text("INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, 1)"),
            {"k": "core.analysis.sigma_rules_dir", "v": '"enc:v1:SECRET"'},
        )
        conn.commit()
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
        rows = dict(conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall())
        assert mod.MAP_KEY not in rows


def test_a_database_with_nothing_stored_is_left_alone():
    import sqlalchemy as sa
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _load_judgement_rev()
    conn = _judgement_engine({})
    with conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
        assert conn.execute(sa.text("SELECT COUNT(*) FROM runtime_settings")).scalar() == 0


# ---------------------------------------------------------------------------
# 20260916000000 — a stored profile becomes a stage list
# ---------------------------------------------------------------------------

_STAGES_REV = _API / "alembic" / "versions" / "20260916000000_migrate_profiles_to_stages.py"


def _load_stages_rev():
    spec = importlib.util.spec_from_file_location("migrate_profiles_to_stages", _STAGES_REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_revision_follows_the_one_before_it():
    mod = _load_stages_rev()
    judgement = _load_judgement_rev()
    assert mod.down_revision == judgement.revision


def test_the_migration_s_stage_form_is_the_one_the_settings_model_produces():
    """Two copies of the conversion, and they have to agree on the day it runs.

    The revision keeps its own copy on purpose — a migration must keep
    producing the document that was correct when it was written — so this is
    the check that the copy was correct in the first place.
    """
    from maljan.core.config import stages_from_analysts

    mod = _load_stages_rev()
    assert mod.stage_form(["static", "dynamic"], parallel=False, max_rounds=5, consensus=0.85) == [
        stage.model_dump()
        for stage in stages_from_analysts(
            ["static", "dynamic"], parallel=False, max_rounds=5, consensus_threshold=0.85
        )
    ]


def test_a_stored_profile_gains_stages_from_the_two_global_keys_and_can_go_back():
    import json

    import sqlalchemy as sa
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _load_stages_rev()
    conn = _judgement_engine(
        {
            mod.PROFILES_KEY: json.dumps(
                {
                    "lean": {"label": "Lean", "analysts": ["static", "network"]},
                    "written": {
                        "label": "Written",
                        "stages": [{"key": "only", "kind": "analysis", "agents": ["static"]}],
                    },
                }
            ),
            mod.PARALLEL_KEY: "true",
            mod.MAX_ROUNDS_KEY: "9",
            "core.llm.provider": '"ollama"',
        }
    )
    with conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
        first = dict(conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall())
        with Operations.context(ctx):
            mod.upgrade()  # second pass: every profile already has stages
        assert (
            dict(conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall())
            == first
        )

        profiles = json.loads(first[mod.PROFILES_KEY])
        lean = profiles["lean"]
        assert [s["key"] for s in lean["stages"]] == ["analysis", "debate", "verdict", "report"]
        assert lean["stages"][0]["agents"] == ["static", "network"]
        assert lean["stages"][0]["mode"] == "parallel"
        assert lean["stages"][1]["debate"]["max_rounds"] == 9
        # The analyst list is kept: it is what the downgrade restores from.
        assert lean["analysts"] == ["static", "network"]
        # A profile that already had stages is left exactly as it was.
        assert profiles["written"]["stages"] == [
            {"key": "only", "kind": "analysis", "agents": ["static"]}
        ]
        assert first["core.llm.provider"] == '"ollama"'

        with Operations.context(ctx):
            mod.downgrade()
        reverted = json.loads(
            dict(conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall())[
                mod.PROFILES_KEY
            ]
        )
        assert "stages" not in reverted["lean"]
        assert reverted["lean"]["analysts"] == ["static", "network"]
        # A team written as stages has its members recovered rather than lost.
        assert reverted["written"]["analysts"] == ["static"]


def test_the_converted_document_loads_as_the_settings_it_describes():
    """The point of the migration: the stored document still validates."""
    import json

    import sqlalchemy as sa
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    from maljan.core.config import Settings

    mod = _load_stages_rev()
    conn = _judgement_engine(
        {mod.PROFILES_KEY: json.dumps({"lean": {"label": "Lean", "analysts": ["static"]}})}
    )
    with conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
        stored = json.loads(
            dict(conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall())[
                mod.PROFILES_KEY
            ]
        )
    settings = Settings(_env_file=None, agents={"profiles": stored, "profile": "lean"})
    assert settings.agents.profiles["lean"].analysis_agents == ["static"]


def test_a_secret_profiles_row_is_never_rewritten():
    """No profile was ever stored as a secret, and none is decrypted here."""
    import sqlalchemy as sa
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _load_stages_rev()
    conn = _judgement_engine({})
    with conn:
        conn.execute(
            sa.text("INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, 1)"),
            {"k": mod.PROFILES_KEY, "v": '"enc:v1:SECRET"'},
        )
        conn.commit()
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()
        rows = dict(conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall())
        assert rows[mod.PROFILES_KEY] == '"enc:v1:SECRET"'
