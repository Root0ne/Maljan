"""A job whose team needs a provider that does not degrade is refused until it is there.

Ghidra fails a run loudly when the agent that needs it starts, minutes and a
paid model call after the sample was accepted. Submitting the job asks first:
the schema endpoint with the configured token, and nothing that analyses.
These run against a real HTTP server on the loopback, standing in for the
Ghidra container, so the check is the request a job would make.
"""

from __future__ import annotations

import asyncio
import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.provider_readiness import refusal_sentence, unready_static_providers
from maljan.core.config import Settings


class _Schema(BaseHTTPRequestHandler):
    """``/mcp/schema`` answering what ``status`` says, and every path recorded."""

    status = 200
    seen: list[tuple[str, str]] = []

    def do_GET(self) -> None:  # noqa: N802 - the stdlib's name
        type(self).seen.append((self.path, self.headers.get("Authorization", "")))
        code = type(self).status if self.path == "/mcp/schema" else 404
        body = b'{"tools": []}'
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        return None


@pytest.fixture
def ghidra() -> Iterator[tuple[str, type[_Schema]]]:
    handler = type("Handler", (_Schema,), {"status": 200, "seen": []})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _closed_port() -> str:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    return f"http://127.0.0.1:{port}"


def _team_settings(url: str, *, enabled: bool = True, global_provider: str = "r2") -> Settings:
    return Settings(
        _env_file=None,
        static={
            "provider": global_provider,
            "ghidra": {
                "enabled": enabled,
                "transport": "http",
                "url": url,
                "auth_token": "tok",
            },
        },
        agents={
            "definitions": {
                "reverser_ghidra": {
                    "role": "generic",
                    "prompt": "p",
                    "static_provider": "ghidra",
                    "tools": [{"kind": "provider"}],
                },
                "static_r2": {"role": "static", "static_provider": "r2"},
            },
            "profiles": {
                "team": {
                    "stages": [
                        {"key": "static", "kind": "analysis", "agents": ["static_r2"]},
                        {
                            "key": "reversing",
                            "kind": "analysis",
                            "agents": ["reverser_ghidra"],
                            "depends_on": ["static"],
                        },
                        {"key": "debate", "kind": "debate", "depends_on": ["reversing"]},
                        {
                            "key": "verdict",
                            "kind": "verdict",
                            "agents": ["judge"],
                            "depends_on": ["debate"],
                        },
                    ]
                }
            },
        },
    )


def _check(settings: Settings, profile: str = "team", **kw: Any) -> list[str]:
    return asyncio.run(unready_static_providers(settings, profile, **kw))


class TestTheCheck:
    def test_a_ghidra_that_answers_lets_the_job_through(self, ghidra) -> None:
        url, handler = ghidra
        assert _check(_team_settings(url)) == []
        assert handler.seen == [("/mcp/schema", "Bearer tok")], "the schema, with the token"

    def test_nothing_is_loaded_or_analysed(self, ghidra) -> None:
        url, handler = ghidra
        _check(_team_settings(url))
        assert [path for path, _ in handler.seen] == ["/mcp/schema"]

    def test_a_ghidra_that_is_down_is_named_with_the_agent_and_the_address(self) -> None:
        url = _closed_port()
        refusals = _check(_team_settings(url))
        assert len(refusals) == 1
        sentence = refusals[0]
        assert "agent 'reverser_ghidra'" in sentence
        assert "static provider 'ghidra'" in sentence
        assert f"at {url}" in sentence

    def test_a_token_the_server_refuses_is_not_ready(self, ghidra) -> None:
        url, handler = ghidra
        handler.status = 401
        refusals = _check(_team_settings(url))
        assert refusals and "HTTP 401" in refusals[0]

    def test_the_address_carries_no_credential(self) -> None:
        secret = "hunter2"
        url = _closed_port().replace("http://", "http://user:" + secret + "@")
        refusals = _check(_team_settings(url))
        assert refusals and secret not in " ".join(refusals)

    def test_a_ghidra_switched_off_is_refused_for_an_agent_given_it_by_name(self) -> None:
        refusals = _check(_team_settings(_closed_port(), enabled=False))
        assert refusals == [
            "agent 'reverser_ghidra' needs static provider 'ghidra', which is switched off"
        ]

    def test_the_shipped_default_is_not_refused(self) -> None:
        """Ghidra, switched off, as the global provider nobody set up: the run
        goes on without it, as it always has."""
        assert _check(Settings(_env_file=None), "default") == []

    def test_a_provider_that_degrades_is_not_asked(self, ghidra) -> None:
        url, handler = ghidra
        settings = _team_settings(url)
        settings.agents.definitions["reverser_ghidra"].static_provider = "r2"
        assert _check(settings) == []
        assert handler.seen == []

    def test_the_job_s_own_provider_is_the_one_asked(self) -> None:
        settings = Settings(
            _env_file=None,
            static={
                "provider": "r2",
                "ghidra": {"enabled": True, "transport": "http", "url": _closed_port()},
            },
        )
        assert _check(settings, "default") == []
        refusals = _check(settings, "default", global_provider="ghidra")
        assert [r.split(" needs")[0] for r in refusals] == ["agent 'static'"]

    def test_an_agent_a_lead_asks_is_checked_too(self) -> None:
        settings = _team_settings(_closed_port())
        settings.agents.definitions["boss"] = settings.agents.definitions[
            "reverser_ghidra"
        ].model_copy(
            update={
                "role": "lead",
                "static_provider": None,
                "tools": [
                    type(settings.agents.definitions["reverser_ghidra"].tools[0])(
                        kind="agent", agent="reverser_ghidra"
                    )
                ],
            }
        )
        profile = settings.agents.profiles["team"]
        profile.stages[1].agents = ["boss"]
        refusals = _check(settings)
        assert [r.split(" needs")[0] for r in refusals] == ["agent 'reverser_ghidra'"]

    def test_an_unknown_team_is_left_to_the_caller(self) -> None:
        assert _check(Settings(_env_file=None), "nope") == []


class TestSubmitting:
    @pytest.fixture
    def client(self) -> Any:
        import uuid

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.api.v1.jobs import router
        from app.database import get_db
        from app.deps import get_current_user

        app = FastAPI()
        app.include_router(router, prefix="/api/v1")
        app.dependency_overrides[get_current_user] = lambda: MagicMock(id=uuid.uuid4())
        app.dependency_overrides[get_db] = lambda: MagicMock()
        return TestClient(app)

    def test_an_unready_provider_is_a_422_naming_it(self, client: Any) -> None:
        import uuid

        sentence = (
            "agent 'reverser_ghidra' needs static provider 'ghidra' at "
            "http://ghidra-mcp:8089, which is not ready: ConnectError"
        )
        with (
            patch("app.api.v1.jobs._unprobed_models_for", AsyncMock(return_value=[])),
            patch("app.api.v1.jobs._unready_providers_for", AsyncMock(return_value=[sentence])),
            patch("app.api.v1.jobs.AnalysisService.create_job", AsyncMock()) as create,
        ):
            response = client.post("/api/v1/jobs", json={"sample_id": str(uuid.uuid4())})

        assert response.status_code == 422
        assert sentence in response.text
        assert refusal_sentence([sentence]).split(".")[0] in response.text
        create.assert_not_called()

    def test_the_team_and_provider_the_job_names_are_the_ones_checked(self) -> None:
        from app.api.v1 import jobs

        seen: dict[str, Any] = {}

        async def fake(settings: Any, profile: str, *, global_provider: str | None = None):
            seen.update(profile=profile, provider=global_provider)
            return []

        with (
            patch(
                "app.services.settings_service.effective_core_settings",
                AsyncMock(return_value=Settings(_env_file=None)),
            ),
            patch("app.services.provider_readiness.unready_static_providers", fake),
        ):
            asyncio.run(
                jobs._unready_providers_for(
                    MagicMock(), {"profile": "deep_static", "static_provider": "ghidra"}
                )
            )
            assert seen == {"profile": "deep_static", "provider": "ghidra"}
            asyncio.run(jobs._unready_providers_for(MagicMock(), {}))
            assert seen == {"profile": "default", "provider": None}
