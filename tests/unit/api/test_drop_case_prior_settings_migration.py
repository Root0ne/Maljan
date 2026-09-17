"""The five case-prior rows leave the stored overrides, and nothing else does."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

_REV = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20260920000000_drop_case_prior_settings.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("drop_case_prior_settings", _REV)
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
    def test_the_five_rows_go_and_their_neighbours_stay(self) -> None:
        module = _load()
        conn = _engine(
            {
                "core.preprocessing.use_attck_case_rag": "true",
                "core.preprocessing.attck_case_corpus_path": '"data/x.json"',
                "core.preprocessing.attck_case_rag_top_k": "5",
                "core.preprocessing.attck_case_rag_min_score": "0.35",
                "core.preprocessing.attck_case_rag_max_techniques": "8",
                "core.preprocessing.use_family_feature_rag": "false",
                "core.triage.enabled": "true",
            }
        )
        _run(conn, module)
        assert _keys(conn) == {"core.preprocessing.use_family_feature_rag", "core.triage.enabled"}

    def test_running_twice_changes_nothing(self) -> None:
        module = _load()
        conn = _engine({"core.triage.enabled": "true"})
        _run(conn, module)
        _run(conn, module)
        assert _keys(conn) == {"core.triage.enabled"}

    def test_the_revision_follows_the_triage_seed(self) -> None:
        module = _load()
        assert module.down_revision == "20260919000000"
        assert module.revision == "20260920000000"
