"""A misconfiguration is refused at the setting it is about, with the reason.

Two things this holds. An ``llm.agents`` entry (or one of its fallbacks) that
names an LLM provider nothing registered is refused on save and at build time,
never run on the role's global model in its place. And a refusal that needs
the whole document to see — an unknown static provider, a server bound to an
unknown agent, a tool reference to an unknown server — is located at the key
it is about, so the console's read can set that key aside and open, and the
error does not echo the document.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from maljan.core.config import Settings
from maljan.core.exceptions import LLMError
from maljan.core.model_assignments import assignment_chain_for
from maljan.core.settings_overrides import (
    StoredValueRefused,
    build_settings,
    settings_from_store,
    stored_settings,
)
from maljan.llm.registry import LLMProviderRegistry

UNKNOWN_PROVIDER = "nosuchprovider"


def _only_error(exc: ValidationError) -> dict:
    (error,) = exc.errors()
    return dict(error)


class TestAnAgentModelNamesARegisteredProvider:
    def test_an_entry_naming_no_registered_provider_is_refused_at_its_provider(self) -> None:
        with pytest.raises(ValidationError) as caught:
            build_settings({"llm.agents": {"static": {"provider": UNKNOWN_PROVIDER, "model": "m"}}})
        error = _only_error(caught.value)
        assert error["loc"] == ("llm", "agents", "static", "provider")
        assert UNKNOWN_PROVIDER in error["msg"] and "not registered" in error["msg"]

    def test_a_fallback_naming_no_registered_provider_is_refused_at_its_place(self) -> None:
        entry = {
            "provider": "openai",
            "model": "m",
            "fallbacks": [{"provider": UNKNOWN_PROVIDER, "model": "n"}],
        }
        with pytest.raises(ValidationError) as caught:
            build_settings({"llm.agents": {"static": entry}})
        assert _only_error(caught.value)["loc"] == (
            "llm",
            "agents",
            "static",
            "fallbacks",
            0,
            "provider",
        )

    def test_a_registered_provider_still_saves(self) -> None:
        built = build_settings(
            {"llm.agents": {"static": {"provider": "anthropic", "model": "claude-x"}}}
        )
        assert built.llm.agents["static"].provider == "anthropic"

    def test_a_stored_entry_stops_a_run_with_the_reason_and_the_console_still_opens(self) -> None:
        stored = {"llm.agents": {"static": {"provider": UNKNOWN_PROVIDER, "model": "m"}}}
        with pytest.raises(StoredValueRefused, match="core.llm.agents"):
            settings_from_store(stored)
        built, refused = stored_settings(stored)
        assert built.llm.agents == {}
        assert list(refused) == ["llm.agents"]

    def test_the_builder_refuses_rather_than_build_the_global_model(self) -> None:
        cfg = Settings(_env_file=None)
        # Past the save check, as an entry read from a store another process
        # wrote: the build itself refuses.
        cfg.llm.agents["static"] = _entry(UNKNOWN_PROVIDER)
        with pytest.raises(LLMError, match="names a provider that is not registered"):
            LLMProviderRegistry(cfg).build_model_for_agent("static")

    def test_the_probe_gate_reads_the_model_the_entry_names(self) -> None:
        cfg = Settings(_env_file=None)
        cfg.llm.agents["static"] = _entry(UNKNOWN_PROVIDER)
        (assignment,) = assignment_chain_for(cfg, "static")
        assert (assignment.provider, assignment.model) == (UNKNOWN_PROVIDER, "chosen-model")


def _entry(provider: str):
    from maljan.core.config import AgentLLMConfig

    return AgentLLMConfig.model_construct(
        provider=provider,
        model="chosen-model",
        temperature=None,
        base_url=None,
        effort=None,
        fallbacks=[],
    )


class TestADocumentRefusalNamesItsSetting:
    def test_an_unknown_static_provider_is_refused_at_its_field(self) -> None:
        with pytest.raises(ValidationError) as caught:
            build_settings(
                {
                    "agents.definitions": {
                        "mine": {"role": "generic", "prompt": "p", "static_provider": "nope"}
                    }
                }
            )
        error = _only_error(caught.value)
        assert error["loc"] == ("agents", "definitions", "mine", "static_provider")
        assert "unknown static provider 'nope'" in error["msg"]

    def test_a_server_bound_to_an_unknown_agent_is_refused_at_its_binding(self) -> None:
        server = {"enabled": True, "transport": "stdio", "command": "x", "agents": ["ghost"]}
        with pytest.raises(ValidationError) as caught:
            build_settings({"mcp.servers": {"mine": server}})
        error = _only_error(caught.value)
        assert error["loc"] == ("mcp", "servers", "mine", "agents")
        assert "unknown agent 'ghost'" in error["msg"]

    def test_a_tool_reference_to_an_unknown_server_is_refused_at_the_reference(self) -> None:
        definition = {
            "role": "generic",
            "prompt": "p",
            "tools": [{"kind": "mcp", "server": "nowhere"}],
        }
        with pytest.raises(ValidationError) as caught:
            build_settings({"agents.definitions": {"mine": definition}})
        error = _only_error(caught.value)
        assert error["loc"] == ("agents", "definitions", "mine", "tools", 0)
        assert "references unknown mcp server 'nowhere'" in error["msg"]

    def test_the_refusal_does_not_echo_the_document(self) -> None:
        with pytest.raises(ValidationError) as caught:
            build_settings(
                {
                    "agents.definitions": {
                        "mine": {"role": "generic", "prompt": "p", "static_provider": "nope"}
                    },
                    "langchain_project": "a-value-only-the-document-holds",
                }
            )
        assert "a-value-only-the-document-holds" not in str(caught.value)

    def test_the_console_opens_past_a_stored_document_refusal(self) -> None:
        server = {"enabled": True, "transport": "stdio", "command": "x", "agents": ["ghost"]}
        built, refused = stored_settings({"mcp.servers": {"mine": server}})
        assert "mine" not in built.mcp.servers
        assert list(refused) == ["mcp.servers"]
        assert "unknown agent 'ghost'" in refused["mcp.servers"]
