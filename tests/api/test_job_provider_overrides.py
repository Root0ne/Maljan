"""A job can name its providers, and a bad name is a 422 at submit time."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Any, get_args

import pytest
from pydantic import ValidationError

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.schemas.job import JobCreateRequest, _KnownJobConfig  # noqa: E402


def _literal_choices(annotation: Any) -> tuple[Any, ...]:
    """Flatten a bare ``Literal[...]`` or an ``Optional[Literal[...]]`` alike.

    ``get_args`` on ``Literal[...] | None`` returns ``(Literal[...], NoneType)``
    rather than the string members, so the caller has to unwrap one more level
    when a field is optional.
    """
    args = get_args(annotation)
    for arg in args:
        inner = get_args(arg)
        if inner:
            return inner
    return args


def test_the_job_choices_equal_the_registry_ids():
    from maljan.providers.registry import sandbox_provider_ids, static_provider_ids

    static = _literal_choices(_KnownJobConfig.model_fields["static_provider"].annotation)
    sandbox = _literal_choices(_KnownJobConfig.model_fields["sandbox_provider"].annotation)
    assert set(static_provider_ids()) <= set(static)
    assert set(sandbox_provider_ids()) <= set(sandbox)


def test_the_job_choices_equal_the_settings_literals():
    """Registry parity for Settings itself is Task 5's job (tests/providers/test_registry.py);
    this only adds the job-schema leg so all three stay in step.
    """
    from maljan.core.config import SandboxConfig, StaticConfig

    static = _literal_choices(_KnownJobConfig.model_fields["static_provider"].annotation)
    sandbox = _literal_choices(_KnownJobConfig.model_fields["sandbox_provider"].annotation)
    assert set(static) == set(get_args(StaticConfig.model_fields["provider"].annotation))
    assert set(sandbox) == set(get_args(SandboxConfig.model_fields["provider"].annotation))


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


def test_the_choice_shows_up_in_the_settings_snapshot(monkeypatch):
    # The dev box's own .env may point sandbox.provider at a live backend;
    # pin the untouched leg to its documented default so the assertion is
    # about the override, not this box's local configuration.
    monkeypatch.setenv("SANDBOX__PROVIDER", "mock")
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
