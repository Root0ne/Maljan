from __future__ import annotations

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.loaders.sandbox_client import SandboxClient


def test_cape2_settings_select_the_cape2_provider():
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "cape2"
    container = ServiceContainer(config=cfg, mock=False)
    assert container.get_sandbox_provider().id == "cape2"
    assert isinstance(container.get_sandbox_client(), SandboxClient)


def test_mock_mode_overrides_the_configured_provider():
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "cape2"
    container = ServiceContainer(config=cfg, mock=True)
    assert container.get_sandbox_provider().id == "mock"


def test_providers_are_cached():
    container = ServiceContainer(config=Settings(_env_file=None), mock=True)
    assert container.get_sandbox_provider() is container.get_sandbox_provider()
    assert container.get_static_provider() is container.get_static_provider()


def test_the_default_profile_is_ghidra_plus_the_cape_equivalent():
    """The smoke test the spec's gate (6) names: today's .env, today's wiring."""
    container = ServiceContainer(config=Settings(_env_file=None), mock=False)
    assert container.get_static_provider().id == "ghidra"
    assert container.get_sandbox_provider().id == "mock"
