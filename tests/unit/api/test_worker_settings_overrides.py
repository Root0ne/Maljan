import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.worker.analysis_worker import build_job_settings  # noqa: E402


def test_override_applies_and_job_config_still_wins():
    s = build_job_settings({"negotiation.max_iterations": 7, "llm.provider": "ollama"}, None)
    assert s.negotiation.max_iterations == 7 and s.llm.provider == "ollama"
    s2 = build_job_settings(
        {"negotiation.max_iterations": 7}, {"max_iterations": 2, "llm_provider": "openai"}
    )
    assert s2.negotiation.max_iterations == 2 and s2.llm.provider == "openai"


def test_snapshot_masks_secrets(monkeypatch):
    monkeypatch.setenv("LLM__OPENAI__API_KEY", "env-key")
    from app.worker.analysis_worker import settings_snapshot

    snap = settings_snapshot(build_job_settings({}, None))
    assert snap["llm.openai.api_key"] == "***"
    assert "env-key" not in str(snap)


def test_snapshot_records_overridden_keys():
    from app.worker.analysis_worker import settings_snapshot

    s = build_job_settings({"negotiation.max_iterations": 7}, None)
    snap = settings_snapshot(s, ["negotiation.max_iterations"])
    assert snap["overridden_keys"] == ["negotiation.max_iterations"]


def test_install_settings_replaces_the_process_singleton():
    from maljan.core import config as core_config

    s = build_job_settings({"negotiation.max_iterations": 7}, None)
    try:
        core_config.install_settings(s)
        assert core_config.get_settings() is s
        assert core_config.settings.negotiation.max_iterations == 7
    finally:
        core_config.reset_settings_cache()


def test_job_config_is_validated_by_the_model():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        build_job_settings({}, {"max_iterations": 0})
    with pytest.raises(ValidationError):
        build_job_settings({}, {"llm_provider": "bedrock"})


def test_job_create_request_rejects_bad_config_at_submit_time():
    import uuid

    import pytest
    from app.schemas.job import JobCreateRequest
    from pydantic import ValidationError

    ok = JobCreateRequest(sample_id=uuid.uuid4(), config={"max_iterations": 2, "extra": 1})
    assert ok.config == {"max_iterations": 2, "extra": 1}
    with pytest.raises(ValidationError):
        JobCreateRequest(sample_id=uuid.uuid4(), config={"max_iterations": 0})
    with pytest.raises(ValidationError):
        JobCreateRequest(sample_id=uuid.uuid4(), config={"llm_provider": "bedrock"})
    with pytest.raises(ValidationError):
        JobCreateRequest(sample_id=uuid.uuid4(), config={"max_iterations": None})
    # a null in a row written another way is "absent", not "zero"
    assert build_job_settings({}, {"max_iterations": None}).negotiation.max_iterations == 5


def test_the_job_config_can_choose_providers():
    s = build_job_settings({}, {"static_provider": "capa_yara", "sandbox_provider": "triage"})
    assert s.static.provider == "capa_yara"
    assert s.sandbox.provider == "triage"


def test_a_sandbox_report_id_forces_the_upload_provider():
    s = build_job_settings(
        {"sandbox.provider": "cape2"},
        {"sandbox_report_id": "0b6c6e0e-0000-4000-8000-000000000000"},
    )
    assert s.sandbox.provider == "upload"


def test_an_explicit_provider_still_loses_to_an_attached_report():
    s = build_job_settings({}, {"sandbox_provider": "cape2", "sandbox_report_id": "x"})
    assert s.sandbox.provider == "upload"
