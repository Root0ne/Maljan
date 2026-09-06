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

from langchain_core.tools import BaseTool

from maljan.agents.base_agent import _run_coro_blocking
from maljan.core.logger import logger
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
    # The tool-facing body of the dynamic system prompt: verbatim lines 25-36 of
    # the old ``_ISR_SYSTEM`` in ``dynamic_analyst.py``, moved rather than
    # retyped so a golden test can pin the assembled prompt byte for byte.
    # ``_DYN_HEAD`` in the analyst supplies the provider-independent opening
    # this fragment completes. A property of the sandbox, not of its MCP
    # server: it is what the analyst was measured against whether or not the
    # CAPE MCP server is actually enabled today (see ``dynamic_prompt_fragment``).
    CAPE_PROMPT_FRAGMENT: ClassVar[str] = (
        "=== TOOL USAGE WORKFLOW ===\n"
        "Follow this sequence when given a file path or hash:\n"
        "1. Call `get_cuckoo_status` to verify the sandbox is online.\n"
        "2. Call `search_task(hash_value=<sha256>)` to check if this sample was already analyzed.\n"
        "3. If no existing task: call `submit_file(file_path=<path>)` to submit for analysis.\n"
        "4. After submission, POLL with `get_task_status(task_id=<id>)` until status "
        "is 'reported'.\n"
        "5. Once reported: call `get_task_report(task_id=<id>, format='lean')` for a "
        "summarized report.\n"
        "6. Call `get_task_iocs(task_id=<id>)` for IOCs (domains, IPs, mutexes).\n"
        "7. Optionally call `get_task_config(task_id=<id>)` for extracted malware configs.\n\n"
        "IMPORTANT: Always use format='lean' for reports to avoid context overflow. "
        "The lean format filters 50MB reports down to key findings.\n"
        "If given a Task ID directly, skip to step 5."
    )

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

    def dynamic_prompt_fragment(self) -> str:
        """The tool-usage workflow text, whether or not the MCP server is up.

        A property of the sandbox report shape, not of the MCP toggle: the
        dynamic analyst was measured against this workflow description either
        way, and a disabled/unreachable MCP server degrades the *tools*
        (``dynamic_tools`` below), never the prompt.
        """
        return self.CAPE_PROMPT_FRAGMENT

    def dynamic_tools(self) -> list[BaseTool]:
        """The 13 essential CAPE MCP tools, or none while MCP is disabled.

        Moved from ``DynamicAnalyst._initialize_mcp_client`` unchanged apart
        from reading ``self._cfg.mcp`` (this provider's own config slice)
        instead of a module-level ``get_settings().mcp.cape``, and the
        allow-list itself, which is always ``CAPE_ESSENTIAL_TOOLS`` now — the
        dead ``mcp.cape.tools`` config-driven branch is not carried forward
        (``MCPServerConfig`` has no such field; it arrives in sub-project B).

        Idempotent: a toolkit already attached — by an earlier call, or by a
        caller that assigned ``_toolkit`` directly, as tests do — is reused
        rather than rebuilt. The static provider's ``open()`` learned this the
        hard way: a live subprocess or transport opened a second time leaks
        the first one instead of replacing it.
        """
        essential = set(self.CAPE_ESSENTIAL_TOOLS)
        if self._toolkit is not None:
            return [t for t in self._toolkit.get_tools() if t.name in essential]

        if not self._cfg.mcp.enabled:
            logger.info("CAPEv2 MCP is disabled in config.")
            return []

        from mcp import StdioServerParameters

        from maljan.agents.mcp_client import MCPLangChainToolkit

        transport = (getattr(self._cfg.mcp, "transport", "stdio") or "stdio").lower()

        if transport in ("http", "streamable-http", "sse"):
            # Remote CAPE MCP server (e.g. cape_mcp_wrapper.py running on a
            # separate Ubuntu VM with --transport streamable-http). There is no
            # local subprocess to launch; connect over HTTP.
            url = self._cfg.mcp.url
            if not url:
                logger.warning(
                    "CAPE MCP transport=%s but mcp.cape.url is empty; skipping MCP init.",
                    transport,
                )
                return []
            headers: dict[str, str] = {}
            raw_token = getattr(self._cfg.mcp, "auth_token", "")
            if hasattr(raw_token, "get_secret_value"):
                raw_token = raw_token.get_secret_value()
            if raw_token:
                headers["Authorization"] = f"Bearer {raw_token}"
            logger.info("Initializing CAPEv2 MCP over %s: %s", transport, url)
            toolkit = MCPLangChainToolkit(transport=transport, http_url=url, http_headers=headers)
        else:
            command = self._cfg.mcp.command
            args = self._cfg.mcp.args

            from maljan.agents.subprocess_env import child_env

            env = child_env(self._cfg.mcp.env)

            from maljan.core.paths import get_project_root, resolve_mcp_args

            project_root = str(get_project_root())
            args = resolve_mcp_args(args)
            server_params = StdioServerParameters(
                command=command, args=args, env=env, cwd=project_root
            )

            toolkit = MCPLangChainToolkit(server_params)

        # Init the MCP toolkit on the shared agent loop so its session/transport
        # is bound to the SAME loop the ReAct tool calls later run on. Running it
        # on a throwaway ``new_event_loop()`` (LangGraph runs sync nodes in a
        # worker thread with no running loop) bound the toolkit to a different
        # loop, so the first CAPE MCP tool call raised "<Event> is bound to a
        # different event loop" (see static_analyst._run_async for the full
        # rationale). Always called from the sync analyze path, never from within
        # the agent loop, so blocking on the result cannot deadlock.
        _run_coro_blocking(toolkit.initialize(), hard_timeout=120.0, label="cape-mcp-init")

        self._toolkit = toolkit
        all_tools = toolkit.get_tools()
        tools = [t for t in all_tools if t.name in essential]
        logger.info(
            "Initialized CAPEv2 MCP tools: %d/%d (essential only): %s",
            len(tools),
            len(all_tools),
            [t.name for t in tools],
        )
        return tools

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
