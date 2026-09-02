import pytest
from pydantic import ValidationError

from maljan.core import settings_overrides as ov
from maljan.core.config import Settings


def test_nest_builds_nested_dict():
    input_dict = {
        "llm.openai.base_url": "http://x",
        "llm.provider": "openai",
        "chunking.overlap_tokens": 5,
    }
    expected = {
        "llm": {"openai": {"base_url": "http://x"}, "provider": "openai"},
        "chunking": {"overlap_tokens": 5},
    }
    assert ov.nest(input_dict) == expected


def test_flatten_is_inverse_of_nest_for_scalars():
    flat = {"a.b": 1, "a.c": "x", "d": [1, 2]}
    assert ov.flatten(ov.nest(flat)) == flat


def test_split_key():
    assert ov.split_key("core.llm.provider") == ("core", "llm.provider")
    assert ov.split_key("api.enrichment_enabled") == ("api", "enrichment_enabled")
    with pytest.raises(ValueError):
        ov.split_key("llm.provider")


def test_override_wins_and_env_sibling_survives(monkeypatch):
    monkeypatch.setenv("LLM__OPENAI__API_KEY", "env-key")
    monkeypatch.setenv("LLM__OPENAI__EXPERT_MODEL", "env-expert")
    s = ov.build_settings({"llm.openai.base_url": "http://ui:1/v1"})
    assert s.llm.openai.base_url == "http://ui:1/v1"
    assert s.llm.openai.api_key.get_secret_value() == "env-key"
    assert s.llm.openai.expert_model == "env-expert"


def test_build_settings_rejects_invalid_value():
    with pytest.raises(ValidationError):
        ov.build_settings({"negotiation.max_iterations": "not-a-number"})


def test_effective_source():
    assert ov.effective_source(overridden=True, env_value=1, default_value=1) == "ui"
    assert ov.effective_source(overridden=False, env_value=2, default_value=1) == "env"
    assert ov.effective_source(overridden=False, env_value=1, default_value=1) == "default"


def test_public_snapshot_masks_secrets(monkeypatch):
    monkeypatch.setenv("LLM__OPENAI__API_KEY", "env-key")
    snap = ov.public_snapshot(Settings(), secret_keys=["llm.openai.api_key"])
    assert snap["llm.openai.api_key"] == "***"
    assert "llm.provider" in snap


def test_flatten_leaves_reads_only_requested_keys():
    s = Settings()
    out = ov.flatten_leaves(s, ["llm.provider", "negotiation.max_iterations"])
    assert set(out) == {"llm.provider", "negotiation.max_iterations"}
    assert isinstance(out["negotiation.max_iterations"], int)
