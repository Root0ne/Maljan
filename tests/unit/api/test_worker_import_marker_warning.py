"""The worker says so when it starts before the configuration import has run.

The worker never imports -- by design it only reads the store -- so on an
upgrading deployment a job taken in the seconds before the API's lifespan
finishes its one-time import runs on catalog defaults: the wrong LLM provider,
the wrong sandbox (final review I4). Compose makes the worker wait for a
healthy API; this warning covers every other way the two are started, and it
never blocks.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.worker.analysis_worker import _warn_if_configuration_import_has_not_run


def _session_factory(marker, monkeypatch, *, raises: Exception | None = None):
    session = MagicMock()
    if raises is not None:
        session.execute = AsyncMock(side_effect=raises)
    else:
        session.execute = AsyncMock(return_value=SimpleNamespace(scalar_one_or_none=lambda: marker))

    @asynccontextmanager
    async def factory():
        yield session

    monkeypatch.setattr("app.database.async_session_factory", factory)


@pytest.mark.asyncio
async def test_a_missing_marker_warns_and_names_the_risk(monkeypatch, caplog):
    _session_factory(None, monkeypatch)
    with caplog.at_level(logging.WARNING):
        await _warn_if_configuration_import_has_not_run()
    assert "Configuration import has not run yet" in caplog.text
    assert "catalog" in caplog.text


@pytest.mark.asyncio
async def test_an_existing_marker_says_nothing(monkeypatch, caplog):
    _session_factory(SimpleNamespace(key="legacy_env_import"), monkeypatch)
    with caplog.at_level(logging.WARNING):
        await _warn_if_configuration_import_has_not_run()
    assert caplog.text == ""


@pytest.mark.asyncio
async def test_an_unreadable_marker_never_stops_the_worker(monkeypatch, caplog):
    _session_factory(None, monkeypatch, raises=RuntimeError("no database"))
    with caplog.at_level(logging.WARNING):
        await _warn_if_configuration_import_has_not_run()
    assert "configuration import marker" in caplog.text
