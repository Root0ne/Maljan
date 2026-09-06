"""Tests for Phase 6 sandbox container wiring and config.

Tests:
  SandboxConfig:
    - Default backend is "mock"
    - Default cape2_base_url, api_token, timeout, poll_interval
    - ENV var override: SANDBOX__BACKEND=cape2

  Settings.sandbox:
    - sandbox field present and returns SandboxConfig
    - sandbox field uses SandboxConfig defaults

  ServiceContainer.get_sandbox_client():
    - Selects the mock provider by default
    - Returns cached instance on second call
    - SandboxConfig backend="mock" -> the mock provider
    - Raises SandboxNotAvailableError for backend="cape2" without httpx
    - _samples_dir is forwarded to the mock provider's fixtures_dir
    - SandboxClient Protocol isinstance check

  End-to-end:
    - MaljanApp.container.get_sandbox_client() returns SandboxClient
    - load_from_sandbox via container uses the registered dynamic parser
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from maljan.loaders.sandbox_client import SandboxClient, SandboxNotAvailableError

# ---------------------------------------------------------------------------
# SandboxConfig
# ---------------------------------------------------------------------------


class TestSandboxConfig:
    def test_default_backend_is_mock(self) -> None:
        from maljan.core.config import SandboxConfig

        cfg = SandboxConfig()
        assert cfg.provider == "mock"

    def test_default_cape2_base_url(self) -> None:
        from maljan.core.config import SandboxConfig

        cfg = SandboxConfig()
        assert cfg.cape2.base_url == "http://localhost:8000"

    def test_default_api_token_empty(self) -> None:
        from maljan.core.config import SandboxConfig

        cfg = SandboxConfig()
        # ``cape2.api_token`` is now ``SecretStr`` so we have to unwrap it.
        assert cfg.cape2.api_token.get_secret_value() == ""

    def test_default_timeout_seconds(self) -> None:
        from maljan.core.config import SandboxConfig

        cfg = SandboxConfig()
        assert cfg.cape2.timeout_seconds == 300

    def test_default_poll_interval_seconds(self) -> None:
        from maljan.core.config import SandboxConfig

        cfg = SandboxConfig()
        assert cfg.cape2.poll_interval_seconds == 10

    def test_backend_override(self) -> None:
        from maljan.core.config import SandboxConfig

        cfg = SandboxConfig(backend="cape2")
        assert cfg.provider == "cape2"
        assert SandboxConfig(provider="cape2").provider == "cape2"


# ---------------------------------------------------------------------------
# Settings.sandbox
# ---------------------------------------------------------------------------


class TestSettingsSandbox:
    def test_sandbox_field_present(self) -> None:
        from maljan.core.config import Settings

        settings = Settings(_env_file=None)
        assert hasattr(settings, "sandbox")

    def test_sandbox_defaults_to_mock_backend(self) -> None:
        from maljan.core.config import Settings

        settings = Settings(_env_file=None)
        assert settings.sandbox.provider == "mock"

    def test_sandbox_config_type(self) -> None:
        from maljan.core.config import SandboxConfig, Settings

        settings = Settings(_env_file=None)
        assert isinstance(settings.sandbox, SandboxConfig)


# ---------------------------------------------------------------------------
# ServiceContainer.get_sandbox_client
# ---------------------------------------------------------------------------


class TestContainerGetSandboxClient:
    def test_returns_mock_sandbox_client_by_default(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(config=Settings(_env_file=None), mock=True)
        client = container.get_sandbox_client()
        assert isinstance(client, SandboxClient)
        assert container.get_sandbox_provider().id == "mock"

    def test_returns_cached_instance_on_second_call(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(config=Settings(_env_file=None), mock=True)
        c1 = container.get_sandbox_client()
        c2 = container.get_sandbox_client()
        assert c1 is c2

    def test_sandbox_client_protocol_isinstance(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(config=Settings(_env_file=None), mock=True)
        client = container.get_sandbox_client()
        assert isinstance(client, SandboxClient)

    def test_samples_dir_forwarded_to_mock_client(self, tmp_path: Path) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(
            config=Settings(_env_file=None), mock=True, samples_dir=str(tmp_path)
        )
        client = container.get_sandbox_client()
        assert isinstance(client, SandboxClient)
        # Verify the mock provider uses the correct fixtures directory
        assert container.get_sandbox_provider().fixtures_dir == str(tmp_path)

    def test_cape2_backend_raises_without_httpx(self) -> None:
        from maljan.core.config import SandboxConfig, Settings
        from maljan.core.container import ServiceContainer

        cfg = Settings(_env_file=None, sandbox=SandboxConfig(backend="cape2"))
        container = ServiceContainer(config=cfg, mock=False)

        with patch.dict("sys.modules", {"httpx": None}):
            # Reset cache to force rebuild
            container._sandbox_client_cache = None
            # The provider builds CAPEv2Client lazily inside submit/fetch now,
            # so the client itself only raises once a call reaches that import.
            with pytest.raises((SandboxNotAvailableError, ImportError)):
                container.get_sandbox_client().submit("sample.exe")

    def test_mock_config_selects_mock_client(self) -> None:
        from maljan.core.config import SandboxConfig, Settings
        from maljan.core.container import ServiceContainer

        cfg = Settings(sandbox=SandboxConfig(backend="mock"))
        container = ServiceContainer(config=cfg, mock=True)
        client = container.get_sandbox_client()
        assert isinstance(client, SandboxClient)
        assert container.get_sandbox_provider().id == "mock"


# ---------------------------------------------------------------------------
# End-to-end: MaljanApp
# ---------------------------------------------------------------------------


class TestMaljanAppSandboxClient:
    def test_app_container_has_sandbox_client(self) -> None:
        from maljan.app import MaljanApp

        app = MaljanApp(mock=True)
        client = app.container.get_sandbox_client()
        assert isinstance(client, SandboxClient)

    def test_sandbox_client_is_mock_by_default_in_app(self) -> None:
        from maljan.app import MaljanApp

        app = MaljanApp(mock=True)
        client = app.container.get_sandbox_client()
        assert isinstance(client, SandboxClient)
        assert app.container.get_sandbox_provider().id == "mock"

    def test_load_from_sandbox_via_container(self, tmp_path: Path) -> None:
        """End-to-end: container provides sandbox client, loader uses it."""
        import json

        from maljan.loaders.binary_chunker import TextChunk

        # Write a minimal fixture
        dynamic_dir = tmp_path / "dynamic"
        dynamic_dir.mkdir()
        report = {
            "target": {"sha256": "abc", "name": "test.exe", "md5": ""},
            "behavior": {
                "apistats": {"1": {"CreateFile": 1}},
                "generic": [{"category": "evasion", "description": "Timing check"}],
                "network": [],
                "processes": [],
            },
            "signatures": [],
        }

        sample = tmp_path / "test.exe"
        sample.write_bytes(b"malware payload bytes")

        import hashlib

        sha256 = hashlib.sha256(b"malware payload bytes").hexdigest()
        (dynamic_dir / f"{sha256}.json").write_text(json.dumps(report), encoding="utf-8")

        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(
            config=Settings(_env_file=None), mock=True, samples_dir=str(tmp_path)
        )
        sandbox_client = container.get_sandbox_client()

        chunks = container.loader.load_from_sandbox(
            sample_path=str(sample),
            data_type="dynamic",
            sandbox_client=sandbox_client,
        )
        assert isinstance(chunks, list)
        assert len(chunks) >= 1
        assert isinstance(chunks[0], TextChunk)
        assert len(chunks[0].content) > 0
