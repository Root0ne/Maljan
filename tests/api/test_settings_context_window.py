"""The settings page can ask what window the configured models serve.

Free, read-only and never a failure: the route reads a model server's metadata
endpoint, and an endpoint that says nothing falls to the vendored table and
then to a stated fallback. The console prints the answer beside the
tool-output cap, because zero — the cap's default — means the window decides
and the window is the one thing that page cannot otherwise show.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.settings import router
from app.database import get_db
from app.deps import require_admin
from maljan.llm import context_window as cw


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(
        id="00000000-0000-0000-0000-000000000001"
    )
    # ``AsyncMock``: the route hands the transaction back before it probes, so
    # the session it is given has to have an awaitable ``commit``.
    app.dependency_overrides[get_db] = lambda: AsyncMock()
    return TestClient(app)


@pytest.fixture(autouse=True)
def _no_remembered_windows():
    cw.forget_learned_windows()
    yield
    cw.forget_learned_windows()


def _with_overrides(overrides: dict[str, Any]) -> Any:
    return patch(
        "app.api.v1.settings.SettingsService.load_overrides",
        AsyncMock(return_value=overrides),
    )


def test_a_declared_window_is_still_checked_against_the_server(client) -> None:
    """A settings value does not short-circuit the endpoint that knows better."""
    with (
        _with_overrides({"core.llm.openai.context_size": 32768}),
        patch.object(cw, "aprobe_window", AsyncMock(return_value=None)) as asked,
    ):
        r = client.get("/api/v1/settings/context-window")

    assert asked.await_count == 1
    assert r.status_code == 200
    body = r.json()
    assert body["tokens"] == 32768
    assert body["source"] == cw.DECLARED
    assert body["derived"] is True
    assert body["cap"] == 9216
    assert body["chars_per_token"] == cw.CHARS_PER_TOKEN


def test_a_server_serving_less_than_the_setting_claims_wins(client) -> None:
    """A stale context_size must not be allowed to overflow the real window."""
    smaller = cw.WindowFact(16384, cw.PROBED, "llama.cpp /props reported 16,384 tokens")
    with (
        _with_overrides({"core.llm.openai.context_size": 131072}),
        patch.object(cw, "aprobe_window", AsyncMock(return_value=smaller)),
    ):
        body = client.get("/api/v1/settings/context-window").json()

    assert body["tokens"] == 16384
    assert body["source"] == cw.PROBED


def test_an_unknown_window_derives_nothing_and_names_the_remedy(client) -> None:
    with (
        _with_overrides({"core.llm.openai.expert_model": "a-private-build"}),
        patch.object(cw, "aprobe_window", AsyncMock(return_value=None)),
    ):
        body = client.get("/api/v1/settings/context-window").json()

    assert body["source"] == cw.FALLBACK
    assert body["cap"] == cw.UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS
    assert "context_size" in body["remedy"]


def test_a_server_that_reports_its_window_is_reported_as_probed(client) -> None:
    fact = cw.WindowFact(40960, cw.PROBED, "llama.cpp /props reported 40,960 tokens")
    with (
        _with_overrides({}),
        patch.object(cw, "aprobe_window", AsyncMock(return_value=fact)),
    ):
        r = client.get("/api/v1/settings/context-window")

    body = r.json()
    assert body["tokens"] == 40960
    assert body["source"] == cw.PROBED
    assert "40,960" in body["detail"]


def test_an_endpoint_that_says_nothing_is_an_answer_and_not_an_error(client) -> None:
    with (
        _with_overrides({"core.llm.openai.expert_model": "a-private-build"}),
        patch.object(cw, "aprobe_window", AsyncMock(return_value=None)),
    ):
        r = client.get("/api/v1/settings/context-window")

    assert r.status_code == 200
    body = r.json()
    assert body["source"] == cw.FALLBACK
    assert body["tokens"] == cw.FALLBACK_WINDOW_TOKENS
    assert body["detail"].strip()


def test_an_operator_cap_says_the_window_decides_nothing(client) -> None:
    """And asks nothing: the window cannot change a cap the operator set."""
    with (
        _with_overrides({"core.preprocessing.max_tool_output_chars": 6000}),
        patch.object(cw, "aprobe_window", AsyncMock(side_effect=AssertionError("asked"))),
    ):
        r = client.get("/api/v1/settings/context-window")

    body = r.json()
    assert body["derived"] is False
    assert body["setting"] == 6000
    assert body["cap"] == 6000


def test_the_route_needs_an_admin() -> None:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: AsyncMock()
    with TestClient(app) as bare:
        assert bare.get("/api/v1/settings/context-window").status_code in (401, 403)
