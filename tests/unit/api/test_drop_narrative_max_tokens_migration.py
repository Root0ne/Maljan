"""The retired narrative setting leaves the stored overrides, and a stored value is ignored."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

_REV = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20260930000000_drop_narrative_max_tokens.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("drop_narrative_max_tokens", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _engine(rows: dict[str, str]):
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


def _keys(conn) -> set[str]:
    return {row[0] for row in conn.execute(sa.text("SELECT key FROM runtime_settings"))}


def _run(conn, module) -> None:
    context = MigrationContext.configure(conn)
    with Operations.context(context):
        module.upgrade()
    conn.commit()


class TestTheDrop:
    def test_the_row_goes_and_its_neighbours_stay(self) -> None:
        conn = _engine(
            {
                "core.reporting.narrative_max_tokens": "1500",
                "core.reporting.composer_section_max_tokens": "0",
                "core.llm.judge_max_tokens": "8192",
            }
        )
        _run(conn, _load())
        assert _keys(conn) == {
            "core.reporting.composer_section_max_tokens",
            "core.llm.judge_max_tokens",
        }

    def test_running_twice_changes_nothing(self) -> None:
        module = _load()
        conn = _engine({"core.llm.judge_max_tokens": "8192"})
        _run(conn, module)
        _run(conn, module)
        assert _keys(conn) == {"core.llm.judge_max_tokens"}

    def test_the_revision_follows_the_judge_bundle(self) -> None:
        module = _load()
        assert module.down_revision == "20260929000000"
        assert module.revision == "20260930000000"


class TestAStoredValueOfTheRemovedKey:
    def test_building_the_settings_ignores_it(self) -> None:
        from maljan.core.settings_overrides import build_settings

        settings = build_settings(
            {"reporting.narrative_max_tokens": 1500, "reporting.composer_enabled": False}
        )

        assert settings.reporting.composer_enabled is False
        assert not hasattr(settings.reporting, "narrative_max_tokens")

    def test_the_catalog_no_longer_offers_it(self) -> None:
        from maljan.core.config import ReportingConfig
        from maljan.core.settings_annotations import ANNOTATIONS

        assert "narrative_max_tokens" not in ReportingConfig.model_fields
        assert "reporting.narrative_max_tokens" not in ANNOTATIONS
