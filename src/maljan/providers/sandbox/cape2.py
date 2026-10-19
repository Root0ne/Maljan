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

from maljan.agents.base_agent import run_coro_blocking
from maljan.core import builtin_declarations
from maljan.core.logger import logger
from maljan.core.settings_overrides import redact_url
from maljan.core.undeclared_tools import categories_of
from maljan.providers.base import ProviderProbe, SandboxCapabilities, SandboxProvider
from maljan.providers.registry import register_sandbox_provider
from maljan.providers.sandbox.readers import required_reader

# The registered report reader (``providers.sandbox.readers``) this provider's
# reports are read by.
_READER = "cape2"

if TYPE_CHECKING:
    from maljan.core.config import SandboxCape2Config, Settings
    from maljan.schemas.sandbox_report import SandboxRun


def _probe_refusal(response: Any) -> str | None:
    """The reason CAPE's ``{"error": true}`` envelope states for the probe, or ``None``.

    The probe asks about task 1, which need not exist: CAPE saying the task
    was not found still proves the URL and the token, so that envelope is no
    refusal. Any other envelope (an API that is disabled, a token CAPE refused
    in words) is, with the reason CAPE stated. A body that is not JSON keeps
    the status code's answer.
    """
    from maljan.loaders.cape2_client import CAPEv2Client
    from maljan.loaders.sandbox_client import SandboxError

    try:
        data = response.json()
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    try:
        CAPEv2Client.raise_for_envelope(data, "probe")
    except SandboxError as exc:
        reason = " ".join(redact_url(str(exc)).splitlines())
        return None if "not found" in reason.lower() else reason
    return None


@register_sandbox_provider("cape2")
class CAPE2SandboxProvider(SandboxProvider):
    """CAPEv2 behind the provider contract.

    A thin seam over ``CAPEv2Client``: the REST quirks it absorbs (three submit
    response shapes, transient polls that are a busy sandbox rather than a
    failure, the 24-byte empty-PCAP floor) are measured behaviour and are not
    re-implemented here.
    """

    # What the console calls this provider and says about it, and its test's label.
    choice_label = "CAPE v2"
    guide_leaves = (
        "api_token",
        "base_url",
        "poll_interval_seconds",
        "timeout_seconds",
    )
    guide_advanced_leaves = ("mcp.",)
    choice_order = 1
    title = "CAPEv2"
    description = "A CAPEv2 instance detonates the sample and returns its report."
    probe_label = "Test CAPE connection"
    settings_intro = "The API token is stored on the server and never shown again."

    # The tool-facing body of the dynamic system prompt: the CAPE MCP block's
    # declared workflow (``sandbox.cape2.mcp.prompt_fragment``, shipped as
    # ``core.builtin_declarations.CAPE_WORKFLOW``), verbatim lines 25-36 of the
    # old ``_ISR_SYSTEM`` in ``dynamic_analyst.py``. ``_DYN_HEAD`` in the
    # analyst supplies the provider-independent opening this fragment
    # completes. It is sent only where the sandbox's own tools are attached
    # (``dynamic_analyst.sandbox_provider_parts``).
    CAPE_PROMPT_FRAGMENT: ClassVar[str] = builtin_declarations.CAPE_WORKFLOW

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
            report_format=_READER,
            degrade_on_failure=True,
        )

    def dynamic_prompt_fragment(self) -> str:
        """The workflow text the CAPE MCP block declares, whether or not the server is up.

        The analyst sends it only where the sandbox's own tools are in the
        request (``dynamic_analyst.sandbox_provider_parts``); a disabled or
        unreachable MCP server degrades the *tools* (``dynamic_tools`` below).
        """
        return str(getattr(self._cfg.mcp, "prompt_fragment", "") or "")

    def dynamic_tools(self) -> list[BaseTool]:
        """The CAPE MCP server's tools, narrowed only by ``mcp.tools``; none while disabled.

        ``mcp.tools`` follows the ``ServerHandle.tools()`` contract: ``None``
        exposes every tool the server advertises, a list keeps those names.

        Moved from ``DynamicAnalyst._initialize_mcp_client``, reading
        ``self._cfg.mcp`` (this provider's own config slice) instead of a
        module-level ``get_settings().mcp.cape``.

        Idempotent: a toolkit already attached — by an earlier call, or by a
        caller that assigned ``_toolkit`` directly, as tests do — is reused
        rather than rebuilt. The static provider's ``open()`` learned this the
        hard way: a live subprocess or transport opened a second time leaks
        the first one instead of replacing it.
        """
        if self._toolkit is not None:
            return self._allowed(self._toolkit.get_tools())

        if not self._cfg.mcp.enabled:
            logger.info("CAPEv2 MCP is disabled in config.")
            return []

        from mcp import StdioServerParameters

        from maljan.agents.mcp_client import MCPLangChainToolkit

        transport = (getattr(self._cfg.mcp, "transport", "stdio") or "stdio").lower()

        if transport in ("http", "streamable-http", "sse"):
            # Remote CAPE MCP server (one started on the sandbox host with
            # --transport streamable-http). There is no local subprocess to
            # launch; connect over HTTP.
            url = self._cfg.mcp.url
            if not url:
                logger.warning(
                    "CAPE MCP transport=%s but sandbox.cape2.mcp.url is empty; skipping MCP init.",
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
            toolkit = MCPLangChainToolkit(
                transport=transport,
                http_url=url,
                http_headers=headers,
                categories=categories_of(self._cfg.mcp.tool_facts),
            )
        else:
            command = self._cfg.mcp.command
            args = self._cfg.mcp.args

            from maljan.agents.subprocess_env import child_env

            env = child_env(self._cfg.mcp.env, server=self.id)

            from maljan.core.paths import get_project_root, resolve_mcp_args

            project_root = str(get_project_root())
            args = resolve_mcp_args(args)
            server_params = StdioServerParameters(
                command=command, args=args, env=env, cwd=project_root
            )

            toolkit = MCPLangChainToolkit(
                server_params, categories=categories_of(self._cfg.mcp.tool_facts)
            )

        # Init the MCP toolkit on the shared agent loop so its session/transport
        # is bound to the SAME loop the ReAct tool calls later run on. Running it
        # on a throwaway ``new_event_loop()`` (LangGraph runs sync nodes in a
        # worker thread with no running loop) bound the toolkit to a different
        # loop, so the first CAPE MCP tool call raised "<Event> is bound to a
        # different event loop" (see static_analyst._run_async for the full
        # rationale). Always called from the sync analyze path, never from within
        # the agent loop, so blocking on the result cannot deadlock.
        run_coro_blocking(toolkit.initialize(), hard_timeout=120.0, label="cape-mcp-init")

        self._toolkit = toolkit
        tools = self._allowed(toolkit.get_tools())
        logger.info(
            "Initialized CAPEv2 MCP tools: %d: %s",
            len(tools),
            [t.name for t in tools],
        )
        return tools

    def _allowed(self, tools: list[BaseTool]) -> list[BaseTool]:
        allowed = self._cfg.mcp.tools
        if allowed is None:
            return list(tools)
        keep = set(allowed)
        return [t for t in tools if t.name in keep]

    def _get_client(self) -> Any:
        if self._client is None:
            from maljan.loaders.cape2_client import CAPEv2Client

            self._client = CAPEv2Client(base_url=self._cfg.base_url, api_token=self._cfg.api_token)
        return self._client

    def submission_address(self) -> str | None:
        """The host the submission reaches: the client posts a relative path on the base URL."""
        from maljan.providers.base import requested_host

        return requested_host(self._cfg.base_url, "/apiv2/tasks/create/file/")

    def submit(self, sample_path: str | Path) -> str:
        """Submit, asking for the analysis package and guest this format needs.

        An APK handed to CAPE's default ``exe`` package detonates nothing, and
        a report of nothing is indistinguishable from a benign sample. The
        package comes from ``package_by_format`` (the sample's detected file
        type, then the ``"*"`` fallback) and the platform from the inferred
        one, only when CAPE has a name for it. Neither is guessed: an
        unconfigured format leaves both unset, which is CAPE deciding for
        itself exactly as it did before.
        """
        from maljan.providers.sandbox.formats import (
            cape_platform,
            detect_sample_format,
            option_for_format,
        )

        file_type, platform = detect_sample_format(sample_path)
        package = option_for_format(self._cfg.package_by_format, file_type)
        return str(
            self._get_client().submit(
                sample_path,
                package=package or None,
                platform=cape_platform(platform) or None,
                extra_fields=dict(self._cfg.submit_options),
            )
        )

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
        report = required_reader(_READER).read(
            result.report, provider=self.id, task_id=str(task_id)
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
        ok = response.status_code < 400
        detail = f"HTTP {response.status_code}"
        refusal = _probe_refusal(response) if ok else None
        if refusal is not None:
            ok, detail = False, f"{detail}: {refusal}"
        return ProviderProbe(
            ok=ok,
            detail=detail,
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
                run_coro_blocking(toolkit.cleanup(), hard_timeout=20.0, label="cape-mcp-close")
