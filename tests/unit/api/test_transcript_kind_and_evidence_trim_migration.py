"""The seven columns a stored conversation and a stored ledger were missing.

Chains onto ``20260925000000`` — the alembic head at the time the transcript
was given the rest of its payload. Exercised against a throwaway in-memory
SQLite database, the same technique as ``test_job_events_migration.py``: bind a
plain connection through ``MigrationContext`` and resolve the module's ``op``
calls through ``Operations.context``.

What the round trip has to hold is that an existing row survives the upgrade
reading as a row whose values were never recorded, rather than as one
asserting a default that did not happen. That is why every added column but
``truncated`` is nullable with no default, and why the assertions below read
the value back out of a row inserted before the upgrade ran.
"""

from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path

import sqlalchemy as sa

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
_REV = _API / "alembic" / "versions" / "20260926000000_transcript_kind_and_evidence_trim.py"

_TRANSCRIPT_COLUMNS = ("kind", "stage", "display_name")
_LEDGER_COLUMNS = ("truncated", "repeated_of", "symbol", "started_at")


def _load():
    spec = importlib.util.spec_from_file_location("transcript_kind", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tables(conn) -> None:
    conn.execute(sa.text("CREATE TABLE agent_messages (id TEXT PRIMARY KEY, seq INTEGER)"))
    conn.execute(sa.text("CREATE TABLE evidence_entries (id TEXT PRIMARY KEY, entry_id TEXT)"))
    conn.execute(
        sa.text(
            "CREATE TABLE analysis_reports (id TEXT PRIMARY KEY, overall_confidence FLOAT NOT NULL)"
        )
    )
    conn.commit()


def _old_rows(conn) -> None:
    """One row per table, written as they were before this revision."""
    conn.execute(
        sa.text("INSERT INTO agent_messages (id, seq) VALUES (:i, 3)"), {"i": str(uuid.uuid4())}
    )
    conn.execute(
        sa.text("INSERT INTO evidence_entries (id, entry_id) VALUES (:i, 'ev_0001')"),
        {"i": str(uuid.uuid4())},
    )
    conn.execute(
        sa.text("INSERT INTO analysis_reports (id, overall_confidence) VALUES (:i, 0.91)"),
        {"i": str(uuid.uuid4())},
    )
    conn.commit()


def _upgraded(conn):
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    module = _load()
    _tables(conn)
    _old_rows(conn)
    with Operations.context(MigrationContext.configure(conn)):
        module.upgrade()
    return module


def _columns(conn, table: str) -> dict:
    return {c["name"]: c for c in sa.inspect(conn).get_columns(table)}


def test_this_revision_chains_onto_the_real_alembic_head() -> None:
    versions = _API / "alembic" / "versions"
    module = _load()
    assert module.down_revision == "20260925000000"
    for path in versions.glob("*.py"):
        if path == _REV:
            continue
        if 'down_revision = "20260925000000"' in path.read_text(encoding="utf-8"):
            raise AssertionError(f"{path.name} also chains onto 20260925000000 — no longer head")


def test_the_revision_imports_no_application_code() -> None:
    text = _REV.read_text(encoding="utf-8")
    assert "maljan" not in text
    assert "from app" not in text


def test_the_transcript_gains_the_three_payload_fields_it_was_dropping() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _upgraded(conn)
        columns = _columns(conn, "agent_messages")
        for name in _TRANSCRIPT_COLUMNS:
            assert name in columns, name
            assert columns[name]["nullable"] is True, name


def test_a_row_recorded_before_the_upgrade_asserts_none_of_the_three() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _upgraded(conn)
        row = conn.execute(sa.text("SELECT kind, stage, display_name FROM agent_messages")).one()
        assert row.kind is None
        assert row.stage is None
        assert row.display_name is None


def test_the_ledger_gains_the_four_entry_fields_it_was_dropping() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _upgraded(conn)
        columns = _columns(conn, "evidence_entries")
        for name in _LEDGER_COLUMNS:
            assert name in columns, name
        for name in ("repeated_of", "symbol", "started_at"):
            assert columns[name]["nullable"] is True, name
        # The trim flag is a fact about every call, including the ones made
        # before the column existed: none of them was trimmed by a budget this
        # revision had not yet given the ledger a way to record.
        assert columns["truncated"]["nullable"] is False


def test_an_entry_recorded_before_the_upgrade_reads_as_untrimmed_and_unlinked() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _upgraded(conn)
        row = conn.execute(
            sa.text("SELECT truncated, repeated_of, symbol, started_at FROM evidence_entries")
        ).one()
        assert not row.truncated
        assert row.repeated_of is None
        assert row.symbol is None
        assert row.started_at is None


def test_a_report_may_say_that_no_confidence_was_assessed() -> None:
    """The column could not hold "nothing assessed one", so it held a number."""
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _upgraded(conn)
        assert _columns(conn, "analysis_reports")["overall_confidence"]["nullable"] is True
        conn.execute(
            sa.text("INSERT INTO analysis_reports (id, overall_confidence) VALUES (:i, NULL)"),
            {"i": str(uuid.uuid4())},
        )
        conn.commit()
        stored = (
            conn.execute(
                sa.text(
                    "SELECT overall_confidence FROM analysis_reports ORDER BY overall_confidence"
                )
            )
            .scalars()
            .all()
        )
        assert stored == [None, 0.91]


def test_the_downgrade_says_what_it_costs_a_report_with_no_confidence() -> None:
    """A zero, because the older schema cannot express the difference."""
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        module = _upgraded(conn)
        conn.execute(
            sa.text("INSERT INTO analysis_reports (id, overall_confidence) VALUES (:i, NULL)"),
            {"i": str(uuid.uuid4())},
        )
        conn.commit()
        with Operations.context(MigrationContext.configure(conn)):
            module.downgrade()
        stored = (
            conn.execute(
                sa.text(
                    "SELECT overall_confidence FROM analysis_reports ORDER BY overall_confidence"
                )
            )
            .scalars()
            .all()
        )
        assert stored == [0.0, 0.91]


def test_upgrade_downgrade_upgrade_is_a_clean_round_trip() -> None:
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        module = _upgraded(conn)
        ctx = MigrationContext.configure(conn)

        with Operations.context(ctx):
            module.downgrade()
        assert not set(_columns(conn, "agent_messages")) & set(_TRANSCRIPT_COLUMNS)
        assert not set(_columns(conn, "evidence_entries")) & set(_LEDGER_COLUMNS)

        with Operations.context(ctx):
            module.upgrade()
        assert set(_TRANSCRIPT_COLUMNS) <= set(_columns(conn, "agent_messages"))
        assert set(_LEDGER_COLUMNS) <= set(_columns(conn, "evidence_entries"))

        with Operations.context(ctx):
            module.downgrade()
        assert not set(_columns(conn, "agent_messages")) & set(_TRANSCRIPT_COLUMNS)
