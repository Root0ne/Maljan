"""Every MCP server Maljan attaches, and the one lifecycle they share.

Before sub-project B there were three copies of "start an MCP server and take
its tools": ``GhidraStaticProvider.open``, ``GenericMCPStaticProvider.open``,
and a hand-rolled pair inside the network analyst and the judge. They drifted
— only one of them honoured an output guardrail, only one closed its child on
a re-attach, and none of them could be exercised by a settings probe, so the
UI's "Test" button spoke a different dialect to the same server than the job
did. ``ServerHandle`` is that code, once; ``ServerRegistry`` is the set of
them a job holds, keyed by the operator's own slug.

The registry never decides policy. It attaches what settings say to attach,
filters to the allow-list the operator ticked, renames a colliding tool, and
reports which servers failed. Whether a failure degrades a run or fails it is
the analyst's question, answered by the provider's capability flags — and for
a registry server the answer is always "degrade", because a server an operator
added is never the evidence the run was measured on.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.providers.errors import ProviderConfigurationError

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

    from maljan.core.config import MCPServerConfig, Settings

# The reason string a failed server contributes to ``degradation_reasons``.
UNAVAILABLE_REASON = "mcp server '{name}' unavailable"


def _run_async(coro: Any, label: str) -> None:
    """Run an MCP-client coroutine on the shared agent loop.

    Same rationale as ``GenericMCPStaticProvider._run_async``: a toolkit's
    transport binds its async primitives to whichever loop first creates it,
    and the ReAct tool calls later run on the process-wide agent loop, so init
    has to run there too rather than on a throwaway loop. A module-level
    function rather than a method so a test can replace it in one place.
    """
    from maljan.agents.base_agent import _run_coro_blocking

    _run_coro_blocking(coro, hard_timeout=120.0, label=label)


class ServerHandle:
    """One configured MCP server, attached for at most one job at a time."""

    def __init__(self, name: str, config: MCPServerConfig) -> None:
        self.name = name
        self.config = config
        self._toolkit: Any = None
        self._all_tools: list[Any] = []
        self._job_id: str = ""

    @property
    def is_open(self) -> bool:
        return self._toolkit is not None

    @property
    def label(self) -> str:
        return self.config.label or self.name

    def _resolve_cwd(self) -> str | None:
        """The child's working directory, refused when it escapes the project.

        ``cwd`` is an operator setting that becomes a subprocess's working
        directory, so it gets the same treatment every other path-shaped
        setting gets: a relative value is rooted at the project directory and
        must stay inside it; an absolute value is allowed but must exist.
        Neither check is a sandbox — an operator who can edit settings can
        already run a command — it is there so a typo fails loudly at attach
        time instead of starting a server in an unexpected directory.
        """
        from maljan.core.paths import get_project_root

        if not self.config.cwd:
            return None
        root = Path(get_project_root()).resolve()
        candidate = Path(self.config.cwd)
        if candidate.is_absolute():
            resolved = candidate.resolve()
            if not resolved.is_dir():
                raise ProviderConfigurationError(
                    f"mcp server {self.name!r}: cwd {resolved} does not exist"
                )
            return str(resolved)
        resolved = (root / candidate).resolve()
        if not resolved.is_relative_to(root):
            raise ProviderConfigurationError(
                f"mcp server {self.name!r}: cwd {self.config.cwd!r} resolves outside the project"
            )
        if not resolved.is_dir():
            raise ProviderConfigurationError(
                f"mcp server {self.name!r}: cwd {resolved} does not exist"
            )
        return str(resolved)

    def open(
        self,
        job_id: str,
        *,
        output_guardrail: Callable[[str], str] | None = None,
        max_output_chars: int = 8000,
        truncation_ledger: Any | None = None,
    ) -> None:
        """Attach for ``job_id``. Same id is a no-op; a different id reattaches."""
        if self._toolkit is not None:
            if job_id == self._job_id:
                return
            logger.info(
                "mcp server '%s' re-opened for a different job; closing the stale toolkit first.",
                self.name,
            )
            self.close()
        self._job_id = job_id
        if not self.config.enabled:
            logger.info("mcp server '%s' is disabled.", self.name)
            return

        from maljan.agents.mcp_client import MCPLangChainToolkit

        if self.config.transport == "stdio":
            from mcp import StdioServerParameters

            from maljan.agents.subprocess_env import child_env
            from maljan.core.paths import resolve_mcp_args

            env = child_env(self.config.env, allow=tuple(self.config.env_allow))
            env.setdefault("PYTHONIOENCODING", "utf-8")
            params = StdioServerParameters(
                command=self.config.command,
                args=resolve_mcp_args(list(self.config.args)),
                env=env,
                cwd=self._resolve_cwd(),
            )
            toolkit = MCPLangChainToolkit(
                params,
                output_guardrail=output_guardrail,
                max_output_chars=max_output_chars,
                truncation_ledger=truncation_ledger,
            )
        else:
            token = self.config.auth_token.get_secret_value()
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            toolkit = MCPLangChainToolkit(
                transport=self.config.transport,
                http_url=self.config.url,
                http_headers=headers,
                output_guardrail=output_guardrail,
                max_output_chars=max_output_chars,
                truncation_ledger=truncation_ledger,
            )

        _run_async(toolkit.initialize(), label=f"{self.name}-mcp-init")
        self._toolkit = toolkit
        self._all_tools = list(toolkit.get_tools())
        logger.info(
            "mcp server '%s': %d/%d tools exposed.",
            self.name,
            len(self.tools()),
            len(self._all_tools),
        )

    def all_tool_names(self) -> list[str]:
        """Every tool the server advertises, allow-list ignored."""
        return [str(getattr(t, "name", "")) for t in self._all_tools]

    def tools(self) -> list[BaseTool]:
        """The tools the model may call: the allow-list applied to the manifest.

        ``None`` is "everything the server offers" and is what the two
        built-in sidecars carry, so their tool lists are byte-for-byte what
        the agents attached before this existed. ``[]`` is "nothing", which is
        what a newly registered custom server carries until the operator ticks
        tools off its probe result — a server is connected and inert until
        somebody says which of its tools may run.
        """
        allowed = self.config.tools
        if allowed is None:
            return list(self._all_tools)
        keep = set(allowed)
        return [t for t in self._all_tools if str(getattr(t, "name", "")) in keep]

    def close(self) -> None:
        """Release the client or subprocess. Never raises."""
        toolkit, self._toolkit = self._toolkit, None
        self._all_tools = []
        if toolkit is None:
            return
        closer = getattr(toolkit, "cleanup", None) or getattr(toolkit, "aclose", None)
        if closer is None:
            return
        try:
            from maljan.agents.base_agent import _run_coro_blocking

            _run_coro_blocking(closer(), hard_timeout=20.0, label=f"{self.name}-mcp-close")
        except Exception as exc:  # noqa: BLE001 — teardown never propagates
            logger.warning("mcp server '%s' teardown failed (non-fatal): %s", self.name, exc)


class ServerRegistry:
    """The tool servers one job may attach, built from ``cfg.mcp.servers``."""

    def __init__(self, cfg: Settings) -> None:
        self._handles = {
            name: ServerHandle(name, config) for name, config in cfg.mcp.servers.items()
        }
        # Every reason ``tools_for`` has produced this job, in order and
        # without duplicates. The judge node reads it into
        # ``degradation_reasons`` so the run summary says which server was
        # missing, rather than the report simply being thinner than the last.
        self.degradation_reasons: list[str] = []

    def get(self, name: str) -> ServerHandle:
        handle = self._handles.get(name)
        if handle is None:
            available = ", ".join(sorted(self._handles)) or "(none)"
            raise ProviderConfigurationError(
                f"Unknown mcp server: {name!r}. Available: {available}"
            )
        return handle

    def for_agent(self, role: str) -> list[ServerHandle]:
        """Enabled servers bound to ``role``, built-ins first then by key.

        Order is what makes the collision rule predictable: a built-in is
        attached before any custom server, so a custom server that happens to
        name a tool ``extract_dns`` is the one that gets renamed, and the
        pinned built-in tool names never move.
        """
        from maljan.core.config import BUILTIN_SERVER_KEYS

        bound = [
            handle
            for handle in self._handles.values()
            if handle.config.enabled and role in handle.config.agents
        ]
        return sorted(bound, key=lambda h: (h.name not in BUILTIN_SERVER_KEYS, h.name))

    def tools_for(self, role: str, job_id: str, **context: Any) -> tuple[list[BaseTool], list[str]]:
        """Open every server bound to ``role`` and concatenate their tools.

        Returns the tools and the degradation reasons: one per server that
        could not be opened. A failure here is never raised — the caller keeps
        the tools it did get, and the run summary says which server is missing
        rather than the report quietly being thinner than the last one.
        """
        tools: list[BaseTool] = []
        reasons: list[str] = []
        seen: set[str] = set()
        for handle in self.for_agent(role):
            try:
                handle.open(job_id, **context)
            except Exception as exc:  # noqa: BLE001 — a registry server always degrades
                logger.warning(
                    "mcp server '%s' could not be attached for the %s analyst: %s",
                    handle.name,
                    role,
                    exc,
                )
                reason = UNAVAILABLE_REASON.format(name=handle.name)
                reasons.append(reason)
                if reason not in self.degradation_reasons:
                    self.degradation_reasons.append(reason)
                continue
            renamed = 0
            for tool in handle.tools():
                name = str(getattr(tool, "name", ""))
                if name in seen:
                    tool = tool.model_copy(update={"name": f"{handle.name}__{name}"})
                    name = str(tool.name)
                    renamed += 1
                seen.add(name)
                tools.append(tool)
            if renamed:
                logger.info(
                    "mcp server '%s': %d tool name(s) already taken, prefixed with '%s__'.",
                    handle.name,
                    renamed,
                    handle.name,
                )
        return tools, reasons

    def close_all(self) -> None:
        for handle in self._handles.values():
            handle.close()
