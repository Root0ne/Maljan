"""The registry ids are the settings vocabulary.

A provider id is what its registry holds: the settings catalogue offers exactly
the registered ids, a save refuses any other, and a stored id loads whatever
this process registered.
"""

from __future__ import annotations

import pytest

from maljan.core.config import Settings
from maljan.core.settings_catalog import core_catalog
from maljan.core.settings_overrides import build_settings
from maljan.providers import registry


def _choices(key: str) -> list[str]:
    entry = next(e for e in core_catalog() if e.key == key)
    assert entry.type == "enum"
    return list(entry.choices or [])


def test_static_ids_equal_the_settings_choices():
    assert sorted(registry.static_provider_ids()) == sorted(_choices("core.static.provider"))


def test_sandbox_ids_equal_the_settings_choices():
    assert sorted(registry.sandbox_provider_ids()) == sorted(_choices("core.sandbox.provider"))


def test_a_stored_id_registered_only_elsewhere_still_loads():
    cfg = build_settings({"static.provider": "elsewhere", "sandbox.provider": "elsewhere"})
    assert cfg.static.provider == "elsewhere" and cfg.sandbox.provider == "elsewhere"


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
            s.degrade_on_failure,
        )
    )
    b = SandboxCapabilities()
    assert b.can_fetch_report is True and b.degrade_on_failure is True
    assert b.report_format == "generic"
