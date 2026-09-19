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


def test_override_applies_and_the_environment_is_never_consulted(monkeypatch):
    """``build_settings`` is store-only (Task 3): an env sibling is ignored,
    not merged in -- the overridden field comes from the override, every
    other field comes from the model default."""
    monkeypatch.setenv("LLM__OPENAI__API_KEY", "env-key")
    monkeypatch.setenv("LLM__OPENAI__EXPERT_MODEL", "env-expert")
    s = ov.build_settings({"llm.openai.base_url": "http://ui:1/v1"})
    assert s.llm.openai.base_url == "http://ui:1/v1"
    assert s.llm.openai.api_key is None
    assert s.llm.openai.expert_model == "gpt-4o-mini"


def test_build_settings_rejects_invalid_value():
    with pytest.raises(ValidationError):
        ov.build_settings({"negotiation.max_iterations": "not-a-number"})


def test_effective_source():
    assert ov.effective_source(overridden=True) == "ui"
    assert ov.effective_source(overridden=False) == "default"


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


def test_public_snapshot_keeps_server_env_names_and_hides_their_values():
    """Defence in depth for an open-ended dict.

    ``mcp.servers.<key>.env`` is a plain mapping an admin fills in, and it is
    where a server's own credential naturally goes -- an API token a sidecar
    reads from its environment. The snapshot travels to the job owner through
    ``run_summary.settings_snapshot``, and unlike every other credential in
    the settings model these values are not typed as secrets, so nothing
    masked them. The variable names stay (an operator debugging a server needs
    to see what it was given); the values do not.
    """
    from maljan.core.config import MCPServerConfig

    settings = Settings()
    settings.mcp.servers["probe_srv"] = MCPServerConfig(
        enabled=True,
        transport="stdio",
        command="/bin/true",
        env={"UPSTREAM_API_TOKEN": "sk-not-a-real-token", "LOG_LEVEL": "debug"},
    )
    snap = ov.public_snapshot(settings, secret_keys=[])
    assert "mcp.servers.probe_srv.env.UPSTREAM_API_TOKEN" in snap
    assert snap["mcp.servers.probe_srv.env.UPSTREAM_API_TOKEN"] == "***"
    assert snap["mcp.servers.probe_srv.env.LOG_LEVEL"] == "***"
    assert "sk-not-a-real-token" not in str(snap)


class TestADeprecatedOverrideMapCannotHoldANonBudget:
    """``dict[str, int]`` accepted a zero, a negative and a boolean.

    A loop given one of those does not run at all, and the reader fell back to
    the deployment's own number — so the store held a value nothing would ever
    use and nobody was told. The bound the definition's own budget fields carry
    is on the maps now, and an entry that fails it is dropped rather than
    refused: a settings build that raises is a deployment that cannot serve.
    """

    def test_a_zero_is_dropped_and_nothing_raises(self):
        settings = Settings(react_agent_max_steps_overrides={"scout": 0, "static": 40})

        assert settings.react_agent_max_steps_overrides == {"static": 40}

    def test_a_negative_is_dropped(self):
        settings = Settings(react_agent_timeout_overrides={"scout": -5, "judge": 600})

        assert settings.react_agent_timeout_overrides == {"judge": 600}

    def test_a_boolean_arrives_as_the_number_pydantic_read_it_as(self):
        """Stated rather than assumed: the bound runs after the coercion.

        The field is ``dict[str, int]``, so pydantic has already made a
        ``True`` into a 1 by the time this bound sees it, and 1 is a budget a
        loop can run. ``a_budget`` still refuses a bare ``True`` where it reads
        a map pydantic did not build.
        """
        settings = Settings(react_agent_max_steps_overrides={"scout": True})

        assert settings.react_agent_max_steps_overrides == {"scout": 1}

    def test_a_good_map_is_untouched(self):
        settings = Settings(react_agent_timeout_overrides={"static": 1500, "judge": 600})

        assert settings.react_agent_timeout_overrides == {"static": 1500, "judge": 600}

    def test_the_operator_is_told_which_entry_went(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING, logger="maljan.core.config"):
            Settings(react_agent_max_steps_overrides={"scout": 0})

        assert "scout" in caplog.text
        assert "whole number of at least one" in caplog.text
