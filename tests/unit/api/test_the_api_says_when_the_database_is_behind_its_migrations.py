"""The API says once, in fixed text, when the database is not at this release's head revision.

A store a revision has not rewritten yet is read as the release that wrote it
read it, so nothing is refused; the line tells the operator to run the
migrations before starting this release.
"""

from __future__ import annotations

import logging

import pytest
import sqlalchemy as sa

from app.services import migration_state


def _stamped(revision: str | None) -> sa.engine.Connection:
    """A throwaway in-memory SQLite database stamped with ``revision``."""
    conn = sa.create_engine("sqlite://").connect()
    if revision is not None:
        conn.execute(sa.text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        conn.execute(sa.text("INSERT INTO alembic_version VALUES (:v)"), {"v": revision})
    return conn


def _said(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.name == migration_state.logger.name]


def test_a_database_at_head_says_nothing(caplog: pytest.LogCaptureFixture) -> None:
    (head,) = migration_state.head_revisions()
    with caplog.at_level(logging.WARNING):
        assert migration_state.warn_when_behind_head(_stamped(head)) is False
    assert _said(caplog) == []


@pytest.mark.parametrize("revision", ["20261011000000", None])
def test_a_database_behind_head_is_named_in_one_fixed_line(
    revision: str | None, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        assert migration_state.warn_when_behind_head(_stamped(revision)) is True
    said = _said(caplog)
    assert [r.getMessage() for r in said] == [migration_state.BEHIND_HEAD]
    assert said[0].levelno == logging.WARNING
    assert "make migrate" in migration_state.BEHIND_HEAD


def test_there_is_one_head() -> None:
    assert len(migration_state.head_revisions()) == 1


def test_a_database_ahead_of_head_is_named_as_ahead(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        assert migration_state.warn_when_behind_head(_stamped("29991231000000")) is True
    assert [r.getMessage() for r in _said(caplog)] == [migration_state.AHEAD_OF_HEAD]
    assert "ahead" in migration_state.AHEAD_OF_HEAD
    assert "behind" in migration_state.BEHIND_HEAD


def test_a_failed_check_logs_one_fixed_line_without_what_the_driver_said(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(_connection: object) -> set[str]:
        raise RuntimeError("driver text: host=db port=5432")

    monkeypatch.setattr(migration_state, "current_revisions", broken)
    with caplog.at_level(logging.DEBUG):
        migration_state.check_revision_at_start(object())
    said = _said(caplog)
    assert [r.getMessage() for r in said] == [migration_state.CHECK_FAILED % "RuntimeError"]
    assert all(r.exc_info is None for r in said)
    assert "driver text" not in caplog.text
