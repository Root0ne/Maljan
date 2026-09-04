"""Fixture-backed mock sandbox behind the provider contract.

A thin seam over ``MockSandboxClient``: no network, no subprocess, just JSON
fixtures under ``fixtures_dir`` standing in for a real detonation.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from maljan.providers.base import ProviderProbe, SandboxCapabilities, SandboxProvider
from maljan.providers.registry import register_sandbox_provider
from maljan.schemas.sandbox_report import cape_report_to_sandbox_report

if TYPE_CHECKING:
    from maljan.core.config import Settings
    from maljan.schemas.sandbox_report import SandboxRun


@register_sandbox_provider("mock")
class MockSandboxProvider(SandboxProvider):
    """``MockSandboxClient`` behind the provider contract.

    ``fixtures_dir`` is the provider's only knob and is read lazily, on first
    use, rather than baked into an eagerly-built client — a caller (a test,
    the settings UI) can point it at a different directory any time before
    the first ``submit``/``fetch`` and have it take effect.
    """

    def __init__(self, fixtures_dir: str) -> None:
        self.fixtures_dir = fixtures_dir
        self._client: Any = None

    @classmethod
    def from_settings(cls, cfg: Settings) -> MockSandboxProvider:
        from maljan.core.paths import resolve_data

        return cls(str(resolve_data("data/samples")))

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            can_submit=True,
            can_poll=True,
            can_fetch_report=True,
            report_format="mock",
        )

    def _get_client(self) -> Any:
        if self._client is None:
            from maljan.loaders.mock_sandbox_client import MockSandboxClient

            self._client = MockSandboxClient(fixtures_dir=self.fixtures_dir)
        return self._client

    def submit(self, sample_path: str | Path) -> str:
        return str(self._get_client().submit(sample_path))

    def wait_for_completion(
        self,
        task_id: str,
        timeout_seconds: int | None = None,
        poll_interval_seconds: int | None = None,
    ) -> str:
        return str(
            self._get_client().wait_for_completion(
                task_id,
                timeout_seconds=timeout_seconds or 300,
                poll_interval_seconds=poll_interval_seconds or 10,
            )
        )

    def fetch(self, task_id: str) -> SandboxRun:
        from maljan.schemas.sandbox_report import SandboxRun

        result = self._get_client().fetch_report(task_id)
        report = cape_report_to_sandbox_report(
            result.report, provider="mock", source_format="mock", task_id=str(task_id)
        )
        return SandboxRun(
            task_id=str(task_id),
            sample_sha256=result.sample_sha256,
            sample_name=result.sample_name,
            status=result.status,
            report=report,
            raw=result.report,
            error=result.error,
        )

    async def probe(self) -> ProviderProbe:
        return ProviderProbe(ok=True, detail="mock sandbox: fixtures only, no connection to test")
