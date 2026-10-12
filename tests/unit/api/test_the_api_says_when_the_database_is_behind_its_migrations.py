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
