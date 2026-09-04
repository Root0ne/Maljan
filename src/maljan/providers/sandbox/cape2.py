"""CAPEv2 sandbox behind the provider contract.

A thin seam over ``CAPEv2Client``: the REST quirks it absorbs (three submit
response shapes, transient polls that are a busy sandbox rather than a
failure, the 24-byte empty-PCAP floor) are measured behaviour and are not
re-implemented here.
"""

from __future__ import annotations

from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from maljan.agents.base_agent import _run_coro_blocking
from maljan.core.settings_overrides import redact_url
from maljan.providers.base import ProviderProbe, SandboxCapabilities, SandboxProvider
from maljan.providers.registry import register_sandbox_provider
from maljan.schemas.sandbox_report import cape_report_to_sandbox_report

if TYPE_CHECKING:
    from maljan.core.config import SandboxCape2Config, Settings
    from maljan.schemas.sandbox_report import SandboxRun


@register_sandbox_provider("cape2")
class CAPE2SandboxProvider(SandboxProvider):
    """CAPEv2 behind the provider contract.

    A thin seam over ``CAPEv2Client``: the REST quirks it absorbs (three submit
    response shapes, transient polls that are a busy sandbox rather than a
    failure, the 24-byte empty-PCAP floor) are measured behaviour and are not
    re-implemented here.
    """

    CAPE_ESSENTIAL_TOOLS: ClassVar[tuple[str, ...]] = (
        "get_cuckoo_status",
        "search_task",
        "extended_search",
        "submit_file",
        "submit_static",
        "get_task_status",
        "get_task_report",
        "get_task_iocs",
        "get_task_config",
        "list_tasks",
        "view_task",
        "get_latest_tasks",
        "verify_auth",
    )
    CAPE_PROMPT_FRAGMENT: ClassVar[str] = ""  # filled by Task 11's verbatim move

    def __init__(self, cfg: SandboxCape2Config) -> None:
        self._cfg = cfg
        self._client: Any = None
        self._toolkit: Any = None

    @classmethod
    def from_settings(cls, cfg: Settings) -> CAPE2SandboxProvider:
        return cls(cfg.sandbox.cape2)

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            can_submit=True,
            can_poll=True,
            can_fetch_report=True,
            can_fetch_pcap=True,
            provides_tools=bool(self._cfg.mcp.enabled),
            report_format="cape2",
            degrade_on_failure=True,
        )

    def _get_client(self) -> Any:
        if self._client is None:
            from maljan.loaders.cape2_client import CAPEv2Client

            self._client = CAPEv2Client(base_url=self._cfg.base_url, api_token=self._cfg.api_token)
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
                timeout_seconds=timeout_seconds or self._cfg.timeout_seconds,
                poll_interval_seconds=poll_interval_seconds or self._cfg.poll_interval_seconds,
            )
        )

    def fetch(self, task_id: str) -> SandboxRun:
        from maljan.schemas.sandbox_report import SandboxRun

        result = self._get_client().fetch_report(task_id)
        report = cape_report_to_sandbox_report(
            result.report, provider="cape2", source_format="cape2", task_id=str(task_id)
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

    def fetch_pcap(self, task_id: str, dest_dir: str | Path) -> str | None:
        result = self._get_client().fetch_pcap(task_id, dest_dir)
        return str(result) if result is not None else None

    async def probe(self) -> ProviderProbe:
        """Ask CAPE about task 1: the cheapest call that exercises URL and token."""
        import time

        import httpx

        t0 = time.perf_counter()
        token = self._cfg.api_token.get_secret_value()
        headers = {"Authorization": f"Token {token}"} if token else {}
        url = f"{self._cfg.base_url.rstrip('/')}/apiv2/tasks/view/1/"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            return ProviderProbe(
                ok=False,
                detail=redact_url(f"{type(exc).__name__}: {exc}"),
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )
        return ProviderProbe(
            ok=response.status_code < 400,
            detail=f"HTTP {response.status_code}",
            latency_ms=int((time.perf_counter() - t0) * 1000),
        )

    def close(self) -> None:
        """Release the REST pool, if one was ever built. Never raises."""
        client, self._client = self._client, None
        if client is not None:
            with suppress(Exception):
                client.close()
        toolkit, self._toolkit = self._toolkit, None
        if toolkit is not None:
            with suppress(Exception):
                _run_coro_blocking(toolkit.cleanup(), hard_timeout=20.0, label="cape-mcp-close")
