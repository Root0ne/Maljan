"""The registry ids are the settings vocabulary.

The one invariant worth a test of its own: a provider id exists in exactly two
places — the registry and the settings ``Literal`` — and they must be the same
set, or the UI offers a choice nothing can build.
"""

from __future__ import annotations

from typing import get_args

import pytest

from maljan.core.config import Settings, StaticConfig
from maljan.providers import registry


def test_static_ids_equal_the_settings_choices():
    field = StaticConfig.model_fields["provider"]
    assert sorted(registry.static_provider_ids()) == sorted(get_args(field.annotation))


def test_sandbox_ids_equal_the_settings_choices():
    from maljan.core.config import SandboxConfig

    field = SandboxConfig.model_fields["provider"]
    assert sorted(registry.sandbox_provider_ids()) == sorted(get_args(field.annotation))


def test_default_settings_build_the_ghidra_and_mock_providers():
    cfg = Settings(_env_file=None)
    static = registry.get_static_provider(cfg)
    sandbox = registry.get_sandbox_provider(cfg)
    assert static.id == "ghidra"
    assert sandbox.id == "mock"


def test_an_unknown_id_names_the_available_ones():
    from maljan.providers.errors import ProviderConfigurationError

    cfg = Settings(_env_file=None)
    object.__setattr__(cfg.static, "provider", "nope")
    with pytest.raises(ProviderConfigurationError) as exc:
        registry.get_static_provider(cfg)
    assert "ghidra" in str(exc.value)


def test_capability_defaults_are_conservative():
    from maljan.providers.base import SandboxCapabilities, StaticCapabilities

    s = StaticCapabilities()
    assert not any(
        (
            s.provides_tools,
            s.provides_evidence,
            s.provides_function_hashes,
            s.needs_sample_mirror,
            s.supports_tool_curation,
            s.degrade_on_failure,
        )
    )
    b = SandboxCapabilities()
    assert b.can_fetch_report is True and b.degrade_on_failure is True
    assert b.report_format == "generic"
