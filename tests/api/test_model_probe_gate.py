"""A job is refused before it starts when it names a model no probe reached.

A model name is the one part of a definition nothing validates until the run
gets to that agent, and by then a sample has been uploaded and a queue slot
spent. The settings probe already answers the question; these pin that the
answer is written down against the endpoint and the model it was taken
against, and that submitting a job reads it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.jobs import router
from app.database import get_db
from app.deps import get_current_user
from app.services.model_probes import NEVER_PROBED, unprobed_models
from maljan.core.config import Settings
from maljan.core.model_assignments import assignment_for, endpoint_for


def _settings(**llm: Any) -> Settings:
    return Settings(_env_file=None, llm=llm or {})


class _Row:
    def __init__(self, endpoint: str, model: str, ok: bool, detail: str = "") -> None:
        self.endpoint, self.model, self.ok, self.detail = endpoint, model, ok, detail


class _Db:
    """An async session that answers one ``select`` with the rows it was given."""

    def __init__(self, rows: list[_Row]) -> None:
        self._rows = rows

    async def execute(self, _statement: Any) -> Any:
        result = MagicMock()
        result.scalars.return_value.all.return_value = self._rows
        return result


class TestWhereACallWouldGo:
    def test_an_agent_with_no_override_inherits_the_global_expert_model(self) -> None:
        settings = _settings(provider="ollama", ollama={"expert_model": "qwen3.5:9b"})

        assignment = assignment_for(settings, "static")

        assert assignment.model == "qwen3.5:9b"
        assert assignment.endpoint == "http://localhost:11434"
        assert assignment.key == ("http://localhost:11434", "qwen3.5:9b")

    def test_an_override_takes_its_own_provider_endpoint_and_model(self) -> None:
        settings = _settings(
            provider="ollama",
            agents={
                "static": {
                    "provider": "openai",
                    "model": "qwen3-coder",
                    "base_url": "http://127.0.0.1:8080/v1",
                }
            },
        )

        assignment = assignment_for(settings, "static")

        assert assignment.provider == "openai"
        assert assignment.key == ("http://127.0.0.1:8080/v1", "qwen3-coder")

    def test_a_vendor_api_is_named_rather_than_addressed(self) -> None:
        assert endpoint_for(_settings(provider="anthropic"), "anthropic") == "the Anthropic API"

    def test_openai_with_no_base_url_is_openai(self) -> None:
        assert endpoint_for(_settings(), "openai") == "https://api.openai.com/v1"


class TestTheGate:
    @pytest.mark.asyncio
    async def test_a_model_nothing_has_probed_is_refused_naming_agent_and_model(self) -> None:
        settings = _settings(provider="ollama", ollama={"expert_model": "qwen3.5:9b"})

        refusals = await unprobed_models(_Db([]), settings, ["static", "network"])

        assert len(refusals) == 2
        assert "agent 'static' names model 'qwen3.5:9b'" in refusals[0]
        assert "http://localhost:11434" in refusals[0]
        assert NEVER_PROBED in refusals[0]

    @pytest.mark.asyncio
    async def test_a_failed_probe_is_refused_with_the_sentence_it_came_back_with(self) -> None:
        settings = _settings(provider="ollama", ollama={"expert_model": "qwen3.5:9b"})
        rows = [_Row("http://localhost:11434", "qwen3.5:9b", False, "connection refused")]

        refusals = await unprobed_models(_Db(rows), settings, ["static"])

        assert refusals == [
            "agent 'static' names model 'qwen3.5:9b' at http://localhost:11434: connection refused"
        ]

    @pytest.mark.asyncio
    async def test_a_passing_probe_lets_every_agent_that_shares_it_through(self) -> None:
        settings = _settings(provider="ollama", ollama={"expert_model": "qwen3.5:9b"})
        rows = [_Row("http://localhost:11434", "qwen3.5:9b", True, "9 models available")]

        assert await unprobed_models(_Db(rows), settings, ["static", "network", "judge"]) == []

    @pytest.mark.asyncio
    async def test_a_probe_of_another_endpoint_does_not_count(self) -> None:
        settings = _settings(
            provider="ollama",
            ollama={"expert_model": "qwen3.5:9b", "base_url": "http://box:11434"},
        )
        rows = [_Row("http://localhost:11434", "qwen3.5:9b", True, "ok")]

        refusals = await unprobed_models(_Db(rows), settings, ["static"])

        assert refusals and NEVER_PROBED in refusals[0]

    @pytest.mark.asyncio
    async def test_the_setting_turns_the_whole_gate_off(self) -> None:
        settings = _settings(provider="ollama", require_probe=False)

        assert await unprobed_models(_Db([]), settings, ["static", "network"]) == []


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: MagicMock(id=uuid.uuid4())
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return TestClient(app)


def _submit(client: TestClient, refusals: list[str]) -> Any:
    created = MagicMock(
        id=uuid.uuid4(),
        sample_id=uuid.uuid4(),
        sample_sha256=None,
        sample_filename=None,
        status="pending",
        config={},
        created_at=datetime.now(UTC),
        started_at=None,
        completed_at=None,
        duration_seconds=None,
        error_message=None,
    )
    with (
        patch("app.api.v1.jobs.AnalysisService.create_job", AsyncMock(return_value=created)),
        patch("app.api.v1.jobs._unprobed_models_for", AsyncMock(return_value=refusals)),
        patch("app.api.v1.jobs.SettingsService.load_overrides", AsyncMock(return_value={})),
    ):
        return client.post("/api/v1/jobs", json={"sample_id": str(uuid.uuid4())})


class TestSubmitting:
    def test_an_unprobed_model_is_a_422_the_operator_can_act_on(self, client) -> None:
        response = _submit(
            client, ["agent 'static' names model 'qwen3:4b' at http://box:11434: not present"]
        )

        assert response.status_code == 422
        assert "agent 'static' names model 'qwen3:4b'" in response.text
        assert "not present" in response.text
        assert "core.llm.require_probe" in response.text, "it says how to turn the gate off"

    def test_a_team_whose_models_were_all_reached_is_accepted(self, client) -> None:
        assert _submit(client, []).status_code == 201
