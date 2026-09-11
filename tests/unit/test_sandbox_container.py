"""Tests for Phase 6 sandbox container wiring and config.

Tests:
  SandboxConfig:
    - Default provider is "mock"
    - Default cape2_base_url, api_token, timeout, poll_interval
    - Explicit provider="cape2"

  Settings.sandbox:
    - sandbox field present and returns SandboxConfig
    - sandbox field uses SandboxConfig defaults

  ServiceContainer.get_sandbox_provider():
    - Selects the mock provider by default
    - Returns cached instance on second call
    - SandboxConfig provider="mock" -> the mock provider
    - Raises SandboxNotAvailableError for provider="cape2" without httpx
    - _samples_dir is forwarded to the mock provider's fixtures_dir

  End-to-end:
    - MaljanApp.container.get_sandbox_provider() is the mock provider
    - MaljanApp._submit_to_sandbox drives the provider ABC (submit / wait /
      fetch / fetch_pcap) and renders the CAPE-shaped report
    - load_from_sandbox with a MockSandboxClient uses the registered parser
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from maljan.loaders.sandbox_client import SandboxNotAvailableError

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

    def test_provider_override(self) -> None:
        from maljan.core.config import SandboxConfig

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
# ServiceContainer.get_sandbox_provider
# ---------------------------------------------------------------------------


class TestContainerGetSandboxProvider:
    def test_returns_mock_provider_by_default(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(config=Settings(_env_file=None), mock=True)
        assert container.get_sandbox_provider().id == "mock"

    def test_returns_cached_instance_on_second_call(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(config=Settings(_env_file=None), mock=True)
        assert container.get_sandbox_provider() is container.get_sandbox_provider()

    def test_provider_satisfies_the_sandbox_abc(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer
        from maljan.providers.base import SandboxProvider

        container = ServiceContainer(config=Settings(_env_file=None), mock=True)
        assert isinstance(container.get_sandbox_provider(), SandboxProvider)

    def test_samples_dir_forwarded_to_mock_provider(self, tmp_path: Path) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(
            config=Settings(_env_file=None), mock=True, samples_dir=str(tmp_path)
        )
        # Verify the mock provider uses the correct fixtures directory
        assert container.get_sandbox_provider().fixtures_dir == str(tmp_path)

    def test_cape2_provider_raises_without_httpx(self) -> None:
        from maljan.core.config import SandboxConfig, Settings
        from maljan.core.container import ServiceContainer

        cfg = Settings(_env_file=None, sandbox=SandboxConfig(provider="cape2"))
        container = ServiceContainer(config=cfg, mock=False)

        with patch.dict("sys.modules", {"httpx": None}):
            # Reset cache to force rebuild
            container._sandbox_provider_cache = None
            # The provider builds CAPEv2Client lazily inside submit/fetch, so
            # it only raises once a call reaches that import.
            with pytest.raises((SandboxNotAvailableError, ImportError)):
                container.get_sandbox_provider().submit("sample.exe")

    def test_mock_config_selects_mock_provider(self) -> None:
        from maljan.core.config import SandboxConfig, Settings
        from maljan.core.container import ServiceContainer

        cfg = Settings(sandbox=SandboxConfig(provider="mock"))
        container = ServiceContainer(config=cfg, mock=True)
        assert container.get_sandbox_provider().id == "mock"


# ---------------------------------------------------------------------------
# End-to-end: MaljanApp
# ---------------------------------------------------------------------------


def _run(provider: Any, sample: Path) -> dict[str, Any] | None:
    """Drive ``MaljanApp._submit_to_sandbox`` against one stub provider."""
    import asyncio

    from maljan.app import MaljanApp

    app = MaljanApp(mock=True)
    app.container.mock = False
    app.container._sandbox_provider_cache = provider
    return asyncio.run(app._submit_to_sandbox(str(sample)))


def _stub_run(task_id: str = "42") -> Any:
    from maljan.schemas.sandbox_report import SandboxReport, SandboxRun

    raw = {"target": {"sha256": "abc"}, "behavior": {}, "signatures": [], "network": {}}
    return SandboxRun(
        task_id=task_id,
        sample_sha256="abc",
        sample_name="s.exe",
        status="reported",
        report=SandboxReport(provider="mock", source_format="mock", raw=raw),
        raw=raw,
        error="",
    )


class _StubProvider:
    """The ABC surface ``_submit_to_sandbox`` uses, and nothing else."""

    id = "stub"

    def __init__(self, *, can_fetch_pcap: bool = False, status: str = "reported") -> None:
        from maljan.providers.base import SandboxCapabilities

        self._caps = SandboxCapabilities(
            can_submit=True,
            can_poll=True,
            can_fetch_pcap=can_fetch_pcap,
            report_format="mock",
        )
        self._status = status
        self.calls: list[tuple[str, Any]] = []

    @property
    def capabilities(self) -> Any:
        return self._caps

    def submit(self, sample_path: str) -> str:
        self.calls.append(("submit", sample_path))
        return "42"

    def wait_for_completion(
        self, task_id: str, timeout_seconds: int, poll_interval_seconds: int
    ) -> str:
        self.calls.append(("wait", (task_id, timeout_seconds, poll_interval_seconds)))
        return self._status

    def fetch(self, task_id: str) -> Any:
        self.calls.append(("fetch", task_id))
        return _stub_run(task_id)

    def fetch_pcap(self, task_id: str, dest_dir: str) -> str | None:
        self.calls.append(("fetch_pcap", (task_id, dest_dir)))
        return "/tmp/capture.pcap"


class TestMaljanAppSandboxProvider:
    def test_app_container_exposes_the_mock_provider(self) -> None:
        from maljan.app import MaljanApp
        from maljan.providers.base import SandboxProvider

        app = MaljanApp(mock=True)
        assert isinstance(app.container.get_sandbox_provider(), SandboxProvider)
        assert app.container.get_sandbox_provider().id == "mock"

    def test_submit_drives_the_provider_and_returns_the_cape_shaped_report(
        self, tmp_path: Path
    ) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"payload")
        provider = _StubProvider()

        report = _run(provider, sample)

        assert report is not None
        # ``to_cape_shaped_dict`` hands a mock/cape source its ``raw`` back.
        assert report == {
            "target": {"sha256": "abc"},
            "behavior": {},
            "signatures": [],
            "network": {},
        }
        names = [c[0] for c in provider.calls]
        assert names == ["submit", "wait", "fetch"]
        assert provider.calls[0][1] == str(sample)
        # The provider's own poll budget, not the client default.
        assert provider.calls[1][1] == ("42", 300, 10)

    def test_pcap_is_attached_only_when_the_provider_can_fetch_one(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"payload")

        without = _StubProvider(can_fetch_pcap=False)
        report = _run(without, sample)
        assert report is not None
        assert "fetch_pcap" not in [c[0] for c in without.calls]
        assert "pcap_local_path" not in report.get("network", {})

        with_pcap = _StubProvider(can_fetch_pcap=True)
        report = _run(with_pcap, sample)
        assert report is not None
        assert "fetch_pcap" in [c[0] for c in with_pcap.calls]
        assert report["network"]["pcap_local_path"] == "/tmp/capture.pcap"

    def test_a_non_reported_status_degrades_to_none(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.exe"
        sample.write_bytes(b"payload")
        provider = _StubProvider(status="failed")

        assert _run(provider, sample) is None
        assert "fetch" not in [c[0] for c in provider.calls]

    def test_load_from_sandbox_with_a_mock_client(self, tmp_path: Path) -> None:
        """``SandboxClient`` still serves ``load_from_sandbox`` directly."""
        import hashlib
        import json

        from maljan.loaders.binary_chunker import TextChunk
        from maljan.loaders.mock_sandbox_client import MockSandboxClient

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

        sha256 = hashlib.sha256(b"malware payload bytes").hexdigest()
        (dynamic_dir / f"{sha256}.json").write_text(json.dumps(report), encoding="utf-8")

        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(
            config=Settings(_env_file=None), mock=True, samples_dir=str(tmp_path)
        )

        chunks = container.loader.load_from_sandbox(
            sample_path=str(sample),
            data_type="dynamic",
            sandbox_client=MockSandboxClient(fixtures_dir=str(tmp_path)),
        )
        assert isinstance(chunks, list)
        assert len(chunks) >= 1
        assert isinstance(chunks[0], TextChunk)
        assert len(chunks[0].content) > 0
