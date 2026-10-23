"""A refused stored setting value fails what runs; only the settings page reads past it.

A job, an API read and the ATT&CK cron built over a refused stored value fail
loudly, naming the key, the reason and the remedy: a refused spend cap, server
map or timeout never quietly becomes a less safe default. The settings page
alone reads past it, so the admin can open it and repair the value, and it
names the refused keys in a banner and beside each row.
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
from maljan.core.settings_overrides import (
    StoredValueRefused,
    settings_from_store,
    stored_settings,
)

BAD = {
    "validation.attck_refresh_days": ATTCK_REFRESH_DAYS_MAX + 1,
    "negotiation.max_iterations": 3,
}


def test_a_read_that_runs_something_refuses_it_by_name_with_the_remedy(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level("ERROR"), pytest.raises(StoredValueRefused) as refused:
        settings_from_store(BAD)
    assert list(refused.value.refused) == ["core.validation.attck_refresh_days"]
    message = str(refused.value)
    assert "core.validation.attck_refresh_days" in message
    assert "less than or equal" in message
    assert "Fix it or reset it in the console" in message
    assert "core.validation.attck_refresh_days" in caplog.text


def test_a_refused_spend_cap_fails_the_job_with_the_key_named() -> None:
    from app.worker.analysis_worker import build_job_settings

    with pytest.raises(StoredValueRefused) as refused:
        build_job_settings({"llm.max_spend_usd_per_job": -5.0}, None)
    assert list(refused.value.refused) == ["core.llm.max_spend_usd_per_job"]


def test_a_refused_server_map_fails_the_job_with_the_key_named() -> None:
    from app.worker.analysis_worker import build_job_settings

    servers = {"custom": {"enabled": True, "transport": "stdio", "command": "x", "env_allow": 5}}
    with pytest.raises(StoredValueRefused) as refused:
        build_job_settings({"mcp.servers": servers}, None)
    assert list(refused.value.refused) == ["core.mcp.servers"]


def test_a_value_the_job_brought_is_refused_as_the_model_refuses_it() -> None:
    with pytest.raises(ValidationError):
        settings_from_store(BAD, stored_keys={"negotiation.max_iterations"})


def test_the_core_settings_read_fails_loudly() -> None:
    from app.services import settings_service

    cache = settings_service._CoreSettingsCache()
    with (
        patch.object(settings_service, "load_core_overrides", AsyncMock(return_value=dict(BAD))),
        pytest.raises(StoredValueRefused),
    ):
        asyncio.run(cache.get(MagicMock()))


def test_the_runtime_read_never_defaults_in_its_place() -> None:
    from app.runtime_config import RuntimeConfig

    class Session:
        async def __aenter__(self) -> Any:
            return MagicMock()

        async def __aexit__(self, *args: Any) -> None:
            return None

    config = RuntimeConfig(lambda: Session())
    with (
        patch(
            "app.services.settings_service.load_core_overrides",
            AsyncMock(return_value=dict(BAD)),
        ),
        patch("app.services.settings_service.core_settings_cache._cached", None),
        pytest.raises(StoredValueRefused),
    ):
        asyncio.run(config.core())


def test_a_route_that_reads_it_answers_409_with_the_key() -> None:
    from app.main import stored_value_refused_response

    app = FastAPI()
    app.add_exception_handler(StoredValueRefused, stored_value_refused_response)

    @app.get("/reads-settings")
    async def reads() -> None:
        settings_from_store(BAD)

    r = TestClient(app).get("/reads-settings")
    assert r.status_code == 409
    assert r.json()["refused"] == {
        "core.validation.attck_refresh_days": r.json()["refused"][
            "core.validation.attck_refresh_days"
        ]
    }
    assert "reset it in the console" in r.json()["detail"]


def test_the_attck_cron_skips_the_hour_loudly(caplog: pytest.LogCaptureFixture) -> None:
    from contextlib import asynccontextmanager

    from app.worker import attck_worker

    @asynccontextmanager
    async def factory() -> Any:
        yield MagicMock()

    async def get(db: Any) -> Any:
        raise StoredValueRefused({"validation.attck_refresh_days": "too large"})

    with (
        patch("app.services.settings_service.core_settings_cache.get", get),
        caplog.at_level("ERROR"),
    ):
        answer = asyncio.run(attck_worker.attck_scheduled_update({"db_session": factory}))
    assert answer["outcome"] == "skipped"
    assert "core.validation.attck_refresh_days" in caplog.text


def test_the_settings_page_reads_past_it_and_names_it() -> None:
    built, refused = stored_settings(BAD)
    assert built.validation.attck_refresh_days == 7
    assert list(refused) == ["validation.attck_refresh_days"]


def test_the_console_still_loads_and_is_served_the_refused_keys() -> None:
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


def test_the_refusal_carries_no_refused_value_in_its_traceback() -> None:
    import traceback

    from maljan.core.settings_overrides import settings_from_store

    secret = "sk-PROBE-" + "x" * 40
    stored = {"llm.max_spend_usd_per_job": secret}
    with pytest.raises(StoredValueRefused) as refused:
        settings_from_store(stored)
    assert refused.value.__cause__ is None and refused.value.__suppress_context__
    rendered = "".join(traceback.format_exception(refused.value))
    assert secret not in rendered
    assert "core.llm.max_spend_usd_per_job" in rendered


def test_the_unauthenticated_deep_health_says_only_that_one_is_refused() -> None:
    from app import main

    async def refused() -> Any:
        raise StoredValueRefused({"llm.openai.api_key": "a reason naming a value"})

    with patch("app.runtime_config.runtime_config.core", refused):
        answer = asyncio.run(main._probe_memory())
    assert answer == {
        "ok": False,
        "error": "a stored setting is refused; see the settings page",
        "backend": None,
    }
    assert "api_key" not in str(answer) and "reason" not in str(answer)
