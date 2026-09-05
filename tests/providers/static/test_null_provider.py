"""``static.provider=none`` is an analyst with no tools and no evidence."""

from __future__ import annotations

from unittest.mock import MagicMock

from maljan.core.config import Settings
from maljan.providers.registry import get_static_provider


def _cfg():
    cfg = Settings(_env_file=None)
    cfg.static.provider = "none"
    return cfg


def test_every_capability_is_off():
    caps = get_static_provider(_cfg()).capabilities
    # Blanket guard against a future capability field silently defaulting
    # true and going unnoticed — except ``degrade_on_failure``, which the
    # very next test requires to be True by design (the null provider must
    # never fail a run). ``vars()`` would otherwise catch that intentional
    # True and contradict it.
    if hasattr(caps, "__dict__"):
        other_fields = {k: v for k, v in vars(caps).items() if k != "degrade_on_failure"}
        assert not any(other_fields.values())
    assert caps.provides_tools is False
    assert caps.provides_evidence is False
    assert caps.provides_function_hashes is False
    assert caps.needs_sample_mirror is False
    assert caps.supports_tool_curation is False


def test_it_degrades_rather_than_raising():
    assert get_static_provider(_cfg()).capabilities.degrade_on_failure is True


def test_the_analyst_runs_toolless_and_says_so(caplog):
    from maljan.agents.static_analyst import StaticAnalyst

    analyst = StaticAnalyst(llm=MagicMock(), name="static")
    container = MagicMock()
    container.get_static_provider.return_value = get_static_provider(_cfg())
    container.get_server_registry.return_value = None
    analyst._container = container
    with caplog.at_level("INFO"):
        analyst._initialize_mcp_client()
    assert analyst.tools == []
    assert any("exposes no tools" in r.getMessage() for r in caplog.records)


def test_its_prompt_fragment_keeps_the_provider_neutral_instructions():
    fragment = get_static_provider(_cfg()).prompt_fragment()
    assert "cite a concrete artifact" in fragment
    assert "Ghidra" not in fragment
    assert "load_program" not in fragment
