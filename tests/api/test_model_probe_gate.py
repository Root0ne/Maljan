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


class _Store:
    """A session that keeps what ``record_probe`` writes and answers what reads it.

    The point of writing through the real recorder rather than building rows by
    hand is that the recorder has a rule of its own — a pair with an empty half
    is dropped — and a probe whose rows it silently drops is exactly the gap
    these tests are here to close.
    """

    def __init__(self) -> None:
        self.rows: list[Any] = []

    async def execute(self, _statement: Any) -> Any:
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        result.scalars.return_value.all.return_value = list(self.rows)
        return result

    def add(self, row: Any) -> None:
        self.rows.append(row)

    async def commit(self) -> None:
        return None


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


class TestWhoTheGateChecks:
    def test_it_follows_the_agents_a_lead_can_ask(self) -> None:
        """The lead team names one agent in its stage; the rest are reached by name."""
        from app.api.v1.jobs import _everyone_the_run_can_reach

        settings = Settings(
            _env_file=None,
            agents={
                "definitions": {
                    "boss": {
                        "role": "lead",
                        "prompt": "You lead.",
                        "tools": [
                            {"kind": "agent", "agent": "helper"},
                            {"kind": "agent", "agent": "second"},
                        ],
                    },
                    "helper": {
                        "role": "generic",
                        "prompt": "p",
                        "tools": [{"kind": "agent", "agent": "third"}],
                    },
                    "second": {"role": "generic", "prompt": "p"},
                    "third": {"role": "generic", "prompt": "p"},
                    "stranger": {"role": "generic", "prompt": "p"},
                }
            },
        )

        reached = _everyone_the_run_can_reach(settings, ["boss", "judge"])

        assert set(reached) == {"boss", "judge", "helper", "second", "third"}
        assert "stranger" not in reached

    def test_an_agent_nothing_names_is_not_checked(self) -> None:
        from app.api.v1.jobs import _everyone_the_run_can_reach

        assert _everyone_the_run_can_reach(_settings(), ["static"]) == ["static"]


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


class TestSavingAModel:
    @pytest.mark.asyncio
    async def test_a_save_naming_no_agent_model_is_answered_before_the_store_is_read(self) -> None:
        """Every PATCH passes the gate, and most of them have nothing for it to check.

        Reading the overrides back and rebuilding the whole settings model to
        conclude that is work on the path of every save.
        """
        from app.api.v1 import settings as settings_route
        from app.services.model_probes import AGENT_MODELS_KEY

        reader = AsyncMock(return_value={})
        with patch.object(settings_route.SettingsService, "load_overrides", reader):
            nothing = await settings_route._unprobed_models_in(
                _Db([]), {"core.llm.provider": "ollama"}
            )
            reader.assert_not_awaited()

            refusals = await settings_route._unprobed_models_in(
                _Db([]),
                {AGENT_MODELS_KEY: {"static": {"provider": "ollama", "model": "qwen3:4b"}}},
            )

        assert nothing == []
        assert refusals and "qwen3:4b" in refusals[0], "a save that names one is checked"
        reader.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_a_per_agent_model_no_probe_reached_is_refused_on_save(self) -> None:
        from app.services.model_probes import AGENT_MODELS_KEY, unprobed_models_being_saved

        settings = _settings(
            provider="ollama",
            agents={"static": {"provider": "ollama", "model": "qwen3:4b"}},
        )

        refusals = await unprobed_models_being_saved(
            _Db([]), settings, {AGENT_MODELS_KEY: {"static": {"model": "qwen3:4b"}}}
        )

        assert refusals and "agent 'static' names model 'qwen3:4b'" in refusals[0]

    @pytest.mark.asyncio
    async def test_a_save_that_names_no_model_asks_nothing(self) -> None:
        from app.services.model_probes import unprobed_models_being_saved

        settings = _settings(provider="ollama", ollama={"expert_model": "qwen3.5:9b"})

        assert (
            await unprobed_models_being_saved(_Db([]), settings, {"core.llm.provider": "ollama"})
            == []
        )

    @pytest.mark.asyncio
    async def test_the_setting_turns_this_half_off_too(self) -> None:
        from app.services.model_probes import AGENT_MODELS_KEY, unprobed_models_being_saved

        settings = _settings(
            provider="ollama",
            require_probe=False,
            agents={"static": {"provider": "ollama", "model": "qwen3:4b"}},
        )

        assert (
            await unprobed_models_being_saved(
                _Db([]), settings, {AGENT_MODELS_KEY: {"static": {"model": "qwen3:4b"}}}
            )
            == []
        )


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


class TestOneAddressUnderBothHalves:
    """What the probe files and what the gate looks up are one pair.

    The two used to be two computations of the same thing, and they agreed
    until they did not: a vendor API that has no URL, a base URL typed with a
    trailing slash. Either way the operator saw a green **Test** followed by a
    refused job, with nothing on either screen naming the disagreement.
    """

    CASES = {
        "openai": (
            {
                "provider": "openai",
                "base_url": "http://box:8080/v1/",
                "api_key": "k",
                "expert_model": "qwen",
            },
            {
                "provider": "openai",
                "openai": {"base_url": "http://box:8080/v1/", "expert_model": "qwen"},
            },
        ),
        "ollama": (
            {
                "provider": "ollama",
                "ollama_base_url": "http://ollama:11434/",
                "ollama_expert_model": "qwen3:8b",
                "ollama_judge_model": "qwen3:8b",
            },
            {
                "provider": "ollama",
                "ollama": {"base_url": "http://ollama:11434/", "expert_model": "qwen3:8b"},
            },
        ),
        "anthropic": (
            {
                "provider": "anthropic",
                "anthropic_api_key": "k",
                "anthropic_expert_model": "claude-x",
            },
            {"provider": "anthropic", "anthropic": {"expert_model": "claude-x"}},
        ),
        "gemini": (
            {
                "provider": "gemini",
                "gemini_api_key": "k",
                "gemini_expert_model": "gemini-2.5-pro",
            },
            {"provider": "gemini", "gemini": {"expert_model": "gemini-2.5-pro"}},
        ),
    }

    @staticmethod
    def _server(provider: str):
        """A stand-in for one provider: a catalogue on GET, one short answer on POST."""
        import httpx

        listing = {
            "openai": {"data": [{"id": "qwen"}]},
            "anthropic": {"data": [{"id": "claude-x"}]},
            "ollama": {"models": [{"name": "qwen3:8b"}]},
            "gemini": {"models": [{"name": "models/gemini-2.5-pro"}]},
        }[provider]
        answer = {
            "openai": {"choices": [{"message": {"content": "OK"}}]},
            "anthropic": {"content": [{"type": "text", "text": "OK"}]},
            "ollama": {"response": "OK"},
            "gemini": {"candidates": [{"content": {"parts": [{"text": "OK"}]}}]},
        }[provider]

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=answer if request.method == "POST" else listing)

        return handler

    async def _probed(self, monkeypatch, provider: str) -> list[dict[str, Any]]:
        import httpx

        from app.services import settings_probes as probes

        monkeypatch.setattr(
            probes,
            "_client",
            lambda *_a, **_k: httpx.AsyncClient(
                transport=httpx.MockTransport(self._server(provider)), timeout=10
            ),
        )
        result = await probes.probe_llm(dict(self.CASES[provider][0]))
        assert result.ok, result.detail
        return list((result.details or {})["completions"])

    @pytest.mark.parametrize("provider", ["openai", "ollama", "anthropic", "gemini"])
    @pytest.mark.asyncio
    async def test_the_pair_filed_is_the_pair_the_gate_resolves(
        self, provider: str, monkeypatch
    ) -> None:
        completions = await self._probed(monkeypatch, provider)
        settings = _settings(**self.CASES[provider][1])

        filed = {(pair["endpoint"], pair["model"]) for pair in completions}

        assert filed == {assignment_for(settings, "static").key}
        assert all(pair["endpoint"] for pair in completions), "an empty endpoint files no row"

    @pytest.mark.parametrize("provider", ["anthropic", "gemini"])
    @pytest.mark.asyncio
    async def test_a_test_then_a_submit_passes_the_gate(self, provider: str, monkeypatch) -> None:
        """The vendor APIs, end to end: press Test, then submit a job."""
        from app.services.model_probes import record_probe

        completions = await self._probed(monkeypatch, provider)
        store = _Store()
        for pair in completions:
            await record_probe(
                store,
                endpoint=pair["endpoint"],
                model=pair["model"],
                provider=pair["provider"],
                ok=pair["ok"],
                detail=pair["detail"],
            )

        assert store.rows, "the probe filed something"
        settings = _settings(**self.CASES[provider][1])
        assert await unprobed_models(store, settings, ["static", "network"]) == []
