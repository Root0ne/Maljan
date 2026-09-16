"""One Qdrant server, one set of settings, and the stored values carried over.

``api.qdrant_*`` and ``core.memory.qdrant_*`` addressed the same server. The
enrichment worker read the first, the analysis path read the second, and an
operator who filled in one got a 401 out of every enrich run. The ``api.*``
half is gone from the catalog, so what a deployment stored under it has to
reach the half that is left before the rows are deleted.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20260918000000_unify_qdrant_settings.py"
)


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("unify_qdrant", MIGRATION)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _connect() -> Any:
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


def _insert(conn: Any, key: str, value: Any, is_secret: bool = False) -> None:
    import sqlalchemy as sa

    conn.execute(
        sa.text("INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, :s)"),
        {"k": key, "v": json.dumps(value), "s": is_secret},
    )


def _rows(conn: Any) -> dict[str, Any]:
    import sqlalchemy as sa

    result = conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall()
    return {key: json.loads(value) for key, value in result}


def _secret_flags(conn: Any) -> dict[str, bool]:
    import sqlalchemy as sa

    result = conn.execute(sa.text("SELECT key, is_secret FROM runtime_settings")).fetchall()
    return {key: bool(flag) for key, flag in result}


def _run(mod: Any, conn: Any, direction: str = "upgrade") -> None:
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        getattr(mod, direction)()


def test_the_revision_names_the_three_keys_and_their_counterparts() -> None:
    mod = _module()

    assert mod.MOVES == {
        "api.qdrant_url": "core.memory.qdrant_url",
        "api.qdrant_collection": "core.memory.qdrant_collection",
        "api.qdrant_api_key": "core.memory.qdrant_api_key",
    }


def test_the_api_values_move_across_and_the_rows_go() -> None:
    mod = _module()
    conn = _connect()
    _insert(conn, "api.qdrant_url", "http://qdrant:6333")
    _insert(conn, "api.qdrant_collection", "maljan_ltm")
    _insert(conn, "api.qdrant_api_key", "gAAAAAencrypted", is_secret=True)
    conn.commit()

    _run(mod, conn)
    first = _rows(conn)
    _run(mod, conn)

    assert first == _rows(conn), "running it twice changes nothing"
    assert first["core.memory.qdrant_url"] == "http://qdrant:6333"
    assert first["core.memory.qdrant_collection"] == "maljan_ltm"
    assert first["core.memory.qdrant_api_key"] == "gAAAAAencrypted"
    assert not any(key.startswith("api.qdrant") for key in first)


def test_the_credential_keeps_its_secret_flag_and_its_ciphertext() -> None:
    """The revision has no key to decrypt with, and needs none."""
    mod = _module()
    conn = _connect()
    _insert(conn, "api.qdrant_api_key", "gAAAAAencrypted", is_secret=True)
    conn.commit()

    _run(mod, conn)

    assert _rows(conn)["core.memory.qdrant_api_key"] == "gAAAAAencrypted"
    assert _secret_flags(conn)["core.memory.qdrant_api_key"] is True


def test_a_configured_analysis_path_wins() -> None:
    """The half that a run already uses is the half that keeps working."""
    mod = _module()
    conn = _connect()
    _insert(conn, "core.memory.qdrant_url", "http://real:6333")
    _insert(conn, "api.qdrant_url", "http://127.0.0.1:6333")
    conn.commit()

    _run(mod, conn)

    assert _rows(conn)["core.memory.qdrant_url"] == "http://real:6333"
    assert "api.qdrant_url" not in _rows(conn)


def test_an_empty_api_value_carries_nothing_over() -> None:
    mod = _module()
    conn = _connect()
    _insert(conn, "api.qdrant_api_key", "", is_secret=True)
    conn.commit()

    _run(mod, conn)

    assert _rows(conn) == {}


def test_an_empty_core_value_is_replaced_rather_than_kept() -> None:
    mod = _module()
    conn = _connect()
    _insert(conn, "core.memory.qdrant_url", "")
    _insert(conn, "api.qdrant_url", "http://qdrant:6333")
    conn.commit()

    _run(mod, conn)

    assert _rows(conn)["core.memory.qdrant_url"] == "http://qdrant:6333"


def test_an_empty_store_is_left_alone() -> None:
    mod = _module()
    conn = _connect()

    _run(mod, conn)

    assert _rows(conn) == {}


def test_the_downgrade_puts_the_api_rows_back() -> None:
    mod = _module()
    conn = _connect()
    _insert(conn, "core.memory.qdrant_url", "http://qdrant:6333")
    _insert(conn, "core.memory.qdrant_api_key", "gAAAAAencrypted", is_secret=True)
    conn.commit()

    _run(mod, conn, "downgrade")
    rows = _rows(conn)

    assert rows["api.qdrant_url"] == "http://qdrant:6333"
    assert rows["api.qdrant_api_key"] == "gAAAAAencrypted"
    assert _secret_flags(conn)["api.qdrant_api_key"] is True
    assert rows["core.memory.qdrant_url"] == "http://qdrant:6333", "the source is left in place"


def test_it_imports_no_application_code() -> None:
    """A migration that imports the app breaks the moment the app moves on."""
    source = MIGRATION.read_text(encoding="utf-8")

    assert "import maljan" not in source
    assert "from maljan" not in source
    assert "from app" not in source
