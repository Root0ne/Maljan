"""A retired environment variable is read once into the setting that replaced it.

``GHIDRA_CONTAINER_SAMPLES_PATH`` is read no more; Ghidra's mount is its block's
``sample_mount``. The revision writes a set value to that setting where the
store holds nothing for it, and only a value that is a mount and differs from
the shipped one.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

from maljan.core.settings_annotations import RETIRED_ENVIRONMENT

MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261011000000_retired_environment_read_into_the_store.py"
)
KEY = "core.static.ghidra.sample_mount"


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("retired_environment", MIGRATION)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _connect() -> Any:
    """A throwaway in-memory SQLite database, never the developer database."""
    import sqlalchemy as sa

    conn = sa.create_engine("sqlite://").connect()
    conn.execute(
        sa.text(
            "CREATE TABLE runtime_settings ("
            "key TEXT PRIMARY KEY, value TEXT, is_secret BOOLEAN NOT NULL DEFAULT 0)"
        )
    )
    return conn


def _rows(conn: Any) -> dict[str, Any]:
    import sqlalchemy as sa

    result = conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall()
    return {key: json.loads(value) for key, value in result}


def test_the_revision_reads_what_the_application_map_names() -> None:
    mod = _module()
    assert {v: key for v, (key, _shipped) in mod.READS.items()} == RETIRED_ENVIRONMENT


def test_the_shipped_value_in_the_revision_is_the_block_s() -> None:
    from maljan.core.settings_overrides import build_settings

    (_key, shipped) = _module().READS["GHIDRA_CONTAINER_SAMPLES_PATH"]
    assert build_settings({}).static.ghidra.sample_mount == shipped


def test_a_set_value_is_written_where_the_store_holds_none() -> None:
    conn = _connect()
    written = _module().read_environment(
        conn, {"GHIDRA_CONTAINER_SAMPLES_PATH": "/srv/maljan/samples/"}
    )
    assert written == [KEY]
    assert _rows(conn) == {KEY: "/srv/maljan/samples"}


def test_a_value_an_operator_saved_is_kept() -> None:
    import sqlalchemy as sa

    conn = _connect()
    conn.execute(
        sa.text("INSERT INTO runtime_settings (key, value) VALUES (:k, :v)"),
        {"k": KEY, "v": json.dumps("/saved")},
    )
    assert _module().read_environment(conn, {"GHIDRA_CONTAINER_SAMPLES_PATH": "/env"}) == []
    assert _rows(conn) == {KEY: "/saved"}


def test_the_shipped_value_an_unset_one_and_no_mount_write_nothing() -> None:
    mod = _module()
    for environ in (
        {},
        {"GHIDRA_CONTAINER_SAMPLES_PATH": ""},
        {"GHIDRA_CONTAINER_SAMPLES_PATH": "/data/samples"},
        {"GHIDRA_CONTAINER_SAMPLES_PATH": "data/samples"},
        {"GHIDRA_CONTAINER_SAMPLES_PATH": "/data/../etc"},
    ):
        conn = _connect()
        assert mod.read_environment(conn, environ) == [], environ
        assert _rows(conn) == {}


def test_the_written_value_is_one_the_setting_accepts() -> None:
    from maljan.core.settings_overrides import build_settings

    conn = _connect()
    _module().read_environment(conn, {"GHIDRA_CONTAINER_SAMPLES_PATH": "/srv//in"})
    (value,) = _rows(conn).values()
    assert build_settings({"static.ghidra.sample_mount": value}).static.ghidra.sample_mount == (
        "/srv/in"
    )


def test_the_key_is_one_the_catalogue_serves() -> None:
    from app.services.settings_catalog_api import catalog_index

    keys = set(catalog_index())
    assert set(RETIRED_ENVIRONMENT.values()) <= keys
