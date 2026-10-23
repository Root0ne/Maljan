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


ATTCK_MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261014000000_attck_refresh_interval_read_into_the_store.py"
)
ATTCK_KEY = "core.validation.attck_refresh_days"


def _module(path: Path = MIGRATION) -> Any:
    spec = importlib.util.spec_from_file_location(path.stem, path)
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


def test_the_revisions_read_what_the_application_map_names() -> None:
    reads: dict[str, str] = {}
    for path in (MIGRATION, ATTCK_MIGRATION):
        reads.update({v: key for v, (key, _shipped) in _module(path).READS.items()})
    assert reads == RETIRED_ENVIRONMENT


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


def test_the_attck_interval_s_shipped_value_is_the_setting_s() -> None:
    from maljan.core.settings_overrides import build_settings
    from maljan.memory.attck_loader import DEFAULT_MAX_AGE_DAYS

    (_key, shipped) = _module(ATTCK_MIGRATION).READS["MALJAN_ATTCK_MAX_AGE_DAYS"]
    assert build_settings({}).validation.attck_refresh_days == shipped == DEFAULT_MAX_AGE_DAYS


def test_a_set_attck_interval_is_written_where_the_store_holds_none() -> None:
    conn = _connect()
    written = _module(ATTCK_MIGRATION).read_environment(conn, {"MALJAN_ATTCK_MAX_AGE_DAYS": "30"})
    assert written == [ATTCK_KEY]
    assert _rows(conn) == {ATTCK_KEY: 30}


def test_a_zero_attck_interval_is_written_too() -> None:
    conn = _connect()
    _module(ATTCK_MIGRATION).read_environment(conn, {"MALJAN_ATTCK_MAX_AGE_DAYS": "0"})
    assert _rows(conn) == {ATTCK_KEY: 0}


def test_a_saved_attck_interval_is_kept() -> None:
    import sqlalchemy as sa

    conn = _connect()
    conn.execute(
        sa.text("INSERT INTO runtime_settings (key, value) VALUES (:k, :v)"),
        {"k": ATTCK_KEY, "v": json.dumps(3)},
    )
    assert (
        _module(ATTCK_MIGRATION).read_environment(conn, {"MALJAN_ATTCK_MAX_AGE_DAYS": "30"}) == []
    )
    assert _rows(conn) == {ATTCK_KEY: 3}


def test_the_shipped_interval_an_unset_one_and_no_number_write_nothing() -> None:
    mod = _module(ATTCK_MIGRATION)
    for environ in (
        {},
        {"MALJAN_ATTCK_MAX_AGE_DAYS": ""},
        {"MALJAN_ATTCK_MAX_AGE_DAYS": "7"},
        {"MALJAN_ATTCK_MAX_AGE_DAYS": "weekly"},
        {"MALJAN_ATTCK_MAX_AGE_DAYS": "1.5"},
        {"MALJAN_ATTCK_MAX_AGE_DAYS": "\u00b2"},
    ):
        conn = _connect()
        assert mod.read_environment(conn, environ) == [], environ
        assert _rows(conn) == {}


def test_a_negative_attck_interval_is_never_checking_as_the_old_loader_read_it() -> None:
    for raw in ("-1", " -30 "):
        conn = _connect()
        written = _module(ATTCK_MIGRATION).read_environment(
            conn, {"MALJAN_ATTCK_MAX_AGE_DAYS": raw}
        )
        assert written == [ATTCK_KEY]
        assert _rows(conn) == {ATTCK_KEY: 0}


def test_an_attck_interval_past_the_setting_s_bound_is_never_checking() -> None:
    from maljan.core.config import ATTCK_REFRESH_DAYS_MAX
    from maljan.core.settings_overrides import build_settings

    mod = _module(ATTCK_MIGRATION)
    assert mod.REFRESH_DAYS_MAX == ATTCK_REFRESH_DAYS_MAX
    for raw, expected in (
        ("99999999", 0),
        (str(ATTCK_REFRESH_DAYS_MAX + 1), 0),
        (str(ATTCK_REFRESH_DAYS_MAX), ATTCK_REFRESH_DAYS_MAX),
    ):
        conn = _connect()
        mod.read_environment(conn, {"MALJAN_ATTCK_MAX_AGE_DAYS": raw})
        (value,) = _rows(conn).values()
        assert value == expected
        assert build_settings({"validation.attck_refresh_days": value})
