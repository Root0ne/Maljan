"""A job may name a profile; an unknown one is a 422 at submit time."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.api.v1.jobs import router  # noqa: E402
from app.database import get_db  # noqa: E402
from app.deps import get_current_user  # noqa: E402
from app.schemas.job import JobCreateRequest, _KnownJobConfig  # noqa: E402
from app.worker.analysis_worker import build_job_settings  # noqa: E402
from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_the_field_is_a_free_string_not_a_literal():
    """Profiles are operator-invented names; a Literal could never hold them."""
    assert _KnownJobConfig.model_fields["profile"].annotation == (str | None)


def test_a_profile_folds_into_the_agents_setting():
    cfg = build_job_settings(
        {
            "agents.profiles": {"lean": {"analysts": ["network"]}},
        },
        {"profile": "lean"},
    )
    assert cfg.agents.profile == "lean"
    assert cfg.agents.profiles["lean"].analysts == ["network"]


def test_a_job_without_a_profile_changes_nothing():
    assert build_job_settings({}, {"llm_provider": "ollama"}).agents.profile == "default"
    assert build_job_settings({}, None).agents.profile == "default"


def test_an_explicit_null_profile_is_refused_like_every_other_known_key():
    with pytest.raises(ValueError, match="explicit null is not allowed for: profile"):
        JobCreateRequest(sample_id=uuid.uuid4(), config={"profile": None})


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: MagicMock(id=uuid.uuid4())
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return TestClient(app)


def _submit(client: TestClient, config: dict) -> object:
    # Every JobResponse field needs a concrete value: a bare MagicMock's
    # attribute auto-creation satisfies pydantic's uuid/str/dict field
    # validation with nothing (unlike its numeric/datetime fields, which
    # coerce a Mock's default magic-method return values without complaint).
    created = MagicMock(
        id=uuid.uuid4(),
        sample_id=uuid.uuid4(),
        sample_sha256=None,
        sample_filename=None,
        status="pending",
        config=config,
        created_at=datetime.now(UTC),
        started_at=None,
        completed_at=None,
        duration_seconds=None,
        error_message=None,
    )
    with patch("app.api.v1.jobs.AnalysisService.create_job", AsyncMock(return_value=created)):
        return client.post("/api/v1/jobs", json={"sample_id": str(uuid.uuid4()), "config": config})


def test_a_known_profile_is_accepted(client):
    with patch("app.api.v1.jobs.SettingsService.load_overrides", AsyncMock(return_value={})):
        response = _submit(client, {"profile": "default"})
    assert response.status_code == 201


def test_an_unknown_profile_is_a_422_naming_it(client):
    with patch("app.api.v1.jobs.SettingsService.load_overrides", AsyncMock(return_value={})):
        response = _submit(client, {"profile": "ghost"})
    assert response.status_code == 422
    assert "unknown profile 'ghost'" in response.text


def test_a_profile_an_operator_saved_is_accepted(client):
    stored = {"core.agents.profiles": {"lean": {"analysts": ["network"]}}}
    with patch("app.api.v1.jobs.SettingsService.load_overrides", AsyncMock(return_value=stored)):
        response = _submit(client, {"profile": "lean"})
    assert response.status_code == 201


def test_a_profile_naming_a_disabled_analyst_is_a_422_naming_both(client):
    """A profile may sit inactive with a disabled member; selecting it via a job

    makes it active, and the settings-level exemption for an inactive built-in
    no longer applies — the controller ruling refuses the job rather than
    letting the worker discover the conflict minutes later.
    """
    stored = {
        "core.agents.definitions": {"network": {"role": "network", "enabled": False}},
    }
    with patch("app.api.v1.jobs.SettingsService.load_overrides", AsyncMock(return_value=stored)):
        response = _submit(client, {"profile": "default"})
    assert response.status_code == 422
    assert "default" in response.text
    assert "network" in response.text
