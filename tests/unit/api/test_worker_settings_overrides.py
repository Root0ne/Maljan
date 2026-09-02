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
