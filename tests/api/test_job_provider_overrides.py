"""A job can name its providers, and a bad name is a 422 at submit time."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from app.schemas.job import JobCreateRequest, _KnownJobConfig  # noqa: E402


def _accepted(field: str, value: str) -> bool:
    try:
        _KnownJobConfig.model_validate({field: value})
    except ValidationError:
        return False
    return True


def test_the_job_accepts_exactly_the_registry_ids():
    """The job schema reads the registries; there is no copied list to fall behind."""
    from maljan.llm.provider_base import provider_names
    from maljan.providers.registry import sandbox_provider_ids, static_provider_ids

    for field, ids in (
        ("static_provider", static_provider_ids()),
        ("sandbox_provider", sandbox_provider_ids()),
        ("llm_provider", provider_names()),
    ):
        assert ids and all(_accepted(field, provider) for provider in ids), field
        assert not _accepted(field, "not-a-registered-provider"), field


def test_a_provider_registered_at_runtime_is_accepted_at_submit():
    from maljan.providers import registry

    @registry.register_sandbox_provider("acme-sandbox")
    class _Acme:  # noqa: B903 — a registration only needs the class
        pass

    try:
        assert _accepted("sandbox_provider", "acme-sandbox")
    finally:
        registry._SANDBOX_REGISTRY.pop("acme-sandbox", None)


def test_valid_providers_pass():
    cfg = {"static_provider": "r2", "sandbox_provider": "triage"}
    JobCreateRequest(sample_id=uuid.uuid4(), config=cfg)


def test_an_unknown_provider_is_refused_at_submit_time():
    with pytest.raises(ValidationError) as exc:
        JobCreateRequest(sample_id=uuid.uuid4(), config={"static_provider": "ida"})
    assert "static_provider" in str(exc.value)


def test_a_malformed_report_id_is_refused():
    with pytest.raises(ValidationError):
        JobCreateRequest(sample_id=uuid.uuid4(), config={"sandbox_report_id": "not-a-uuid"})


def test_an_explicit_null_is_still_refused():
    with pytest.raises(ValidationError) as exc:
        JobCreateRequest(sample_id=uuid.uuid4(), config={"sandbox_provider": None})
    assert "explicit null" in str(exc.value)


def test_omitting_the_keys_leaves_todays_payload_untouched():
    req = JobCreateRequest(sample_id=uuid.uuid4(), config={"max_iterations": 2})
    assert req.config == {"max_iterations": 2}


def test_the_choice_shows_up_in_the_settings_snapshot():
    # Task 3: build_job_settings is store-only, so the dev box's own .env
    # (which may point sandbox.provider at a live backend) never reaches it
    # -- the untouched leg is always the model default ("mock").
    from app.worker.analysis_worker import build_job_settings, settings_snapshot

    snap = settings_snapshot(build_job_settings({}, {"static_provider": "capa_yara"}))
    assert snap["static.provider"] == "capa_yara"
    assert snap["sandbox.provider"] == "mock"


def test_the_overridden_providers_show_up_in_the_snapshot():
    from app.worker.analysis_worker import build_job_settings, settings_snapshot

    job_settings = build_job_settings({}, {"static_provider": "r2", "sandbox_provider": "upload"})
    assert job_settings.static.provider == "r2"
    assert job_settings.sandbox.provider == "upload"
    snap = settings_snapshot(job_settings)
    assert snap["static.provider"] == "r2"
    assert snap["sandbox.provider"] == "upload"


def test_the_settings_choices_are_the_registry_ids():
    """The settings model and the registry agree; the job schema reads the registry."""
    from typing import get_args

    from maljan.core.config import SandboxConfig, StaticConfig
    from maljan.providers.registry import sandbox_provider_ids, static_provider_ids

    static_settings = set(get_args(StaticConfig.model_fields["provider"].annotation))
    sandbox_settings = set(get_args(SandboxConfig.model_fields["provider"].annotation))
    assert set(static_provider_ids()) == static_settings
    assert set(sandbox_provider_ids()) == sandbox_settings


def test_the_rest_sandbox_is_an_accepted_per_job_override():
    from typing import get_args

    from maljan.core.config import SandboxConfig

    assert "rest" in get_args(SandboxConfig.model_fields["provider"].annotation)
    assert _accepted("sandbox_provider", "rest")
    JobCreateRequest(sample_id=uuid.uuid4(), config={"sandbox_provider": "rest"})


def test_a_rest_job_override_reaches_the_settings():
    from app.worker.analysis_worker import build_job_settings

    cfg = build_job_settings({}, {"sandbox_provider": "rest"})
    assert cfg.sandbox.provider == "rest"


def test_a_mock_run_cannot_consume_an_uploaded_report():
    with pytest.raises(ValidationError) as exc:
        JobCreateRequest(
            sample_id=uuid.uuid4(),
            config={
                "mock_mode": True,
                "sandbox_report_id": "0b6c6e0e-0000-4000-8000-000000000000",
            },
        )
    assert "mock run cannot consume an uploaded report" in str(exc.value)
