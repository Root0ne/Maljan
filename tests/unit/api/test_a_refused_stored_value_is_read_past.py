"""A stored value the settings model refuses is read past, said, and shown.

One row a migration wrote past a bound added later used to fail every build of
the settings, so every route and job that reads them. Now that key is left
out with its default in force, a warning names it, and the console is served
it beside the setting; a save is still refused.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from maljan.core.config import ATTCK_REFRESH_DAYS_MAX
from maljan.core.settings_overrides import build_settings, stored_settings

BAD = {"validation.attck_refresh_days": ATTCK_REFRESH_DAYS_MAX + 1, "negotiation.max_iterations": 3}


def test_the_refused_key_falls_back_and_the_others_stay() -> None:
    built, refused = stored_settings(BAD)
    assert built.validation.attck_refresh_days == 7
    assert built.negotiation.max_iterations == 3
    assert list(refused) == ["validation.attck_refresh_days"]
    assert "less than or equal" in refused["validation.attck_refresh_days"]


def test_a_save_is_still_refused() -> None:
    with pytest.raises(ValidationError):
        build_settings(BAD)


def test_it_is_said_once(caplog: pytest.LogCaptureFixture) -> None:
    from maljan.core import settings_overrides

    settings_overrides._WARNED_VALUES.clear()
    with caplog.at_level("WARNING"):
        stored_settings(BAD)
        stored_settings(BAD)
    said = [r for r in caplog.records if "validation.attck_refresh_days" in r.getMessage()]
    assert len(said) == 1
    assert "its default is used" in said[0].getMessage()


def test_a_value_that_is_not_stored_is_still_refused() -> None:
    with pytest.raises(ValidationError):
        stored_settings(BAD, stored_keys={"negotiation.max_iterations"})


def test_the_core_settings_read_survives_it() -> None:
    from app.services import settings_service

    cache = settings_service._CoreSettingsCache()
    with patch.object(settings_service, "load_core_overrides", AsyncMock(return_value=dict(BAD))):
        built = asyncio.run(cache.get(MagicMock()))
    assert built.validation.attck_refresh_days == 7
    assert list(cache.refused) == ["validation.attck_refresh_days"]


def test_a_job_built_over_it_runs_with_the_default() -> None:
    from app.worker.analysis_worker import build_job_settings

    with patch("app.worker.analysis_worker.stored_settings", wraps=stored_settings) as read:
        built = build_job_settings(dict(BAD), None)
    assert built.validation.attck_refresh_days == 7
    assert read.call_args.kwargs["stored_keys"] == BAD


def test_the_console_is_served_it_beside_the_setting() -> None:
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id="u")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    stored: dict[str, Any] = {f"core.{key}": value for key, value in BAD.items()}
    with (
        patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value=stored)),
        patch(
            "app.services.settings_service.SettingsService.load_overrides",
            AsyncMock(return_value=stored),
        ),
    ):
        r = TestClient(app).get("/api/v1/settings/schema")
    assert r.status_code == 200
    refused = r.json()["stored_values_refused"]
    assert list(refused) == ["core.validation.attck_refresh_days"]
