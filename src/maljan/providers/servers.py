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

import asyncio
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

    def _build_toolkit(
        self,
        output_guardrail: Callable[[str], str] | None,
        max_output_chars: int,
        truncation_ledger: Any | None,
    ) -> Any:
        """Everything ``open`` does except awaiting ``initialize``.

        Factored out because the judge enters its toolkit with a plain
        ``await`` on the graph's own loop while the analysts hand theirs to
        the shared agent loop — the asymmetry ``JudgeAgent.aclose`` documents
        — and the only safe way to have both is one construction path and two
        ways of running the coroutine it returns.
        """
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
            return MCPLangChainToolkit(
                params,
                output_guardrail=output_guardrail,
                max_output_chars=max_output_chars,
                truncation_ledger=truncation_ledger,
            )
        token = self.config.auth_token.get_secret_value()
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return MCPLangChainToolkit(
            transport=self.config.transport,
            http_url=self.config.url,
            http_headers=headers,
            output_guardrail=output_guardrail,
            max_output_chars=max_output_chars,
            truncation_ledger=truncation_ledger,
        )

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

        toolkit = self._build_toolkit(output_guardrail, max_output_chars, truncation_ledger)

        try:
            _run_async(toolkit.initialize(), label=f"{self.name}-mcp-init")
        except Exception:
            # A transport or subprocess can be partly up (a socket connected,
            # a child process spawned) before ``initialize`` itself fails —
            # e.g. the handshake times out or the server rejects the token.
            # Nothing else ever gets a reference to this toolkit (``_toolkit``
            # is not assigned until initialize succeeds), so if this does not
            # close it, nothing does. The original exception is what the
            # caller (and the registry's degrade path) needs to see, so it is
            # re-raised unchanged after teardown.
            logger.warning(
                "mcp server '%s' failed to initialize; closing the partial attach.",
                self.name,
            )
            self._teardown(toolkit)
            raise
        self._toolkit = toolkit
        self._all_tools = list(toolkit.get_tools())
        allowed = self.config.tools
        if allowed:
            manifest = {str(getattr(t, "name", "")) for t in self._all_tools}
            missing = [name for name in allowed if name not in manifest]
            if missing:
                logger.warning(
                    "mcp server '%s': allow-listed tool(s) not offered by the server: %s",
                    self.name,
                    ", ".join(missing),
                )
        logger.info(
            "mcp server '%s': %d/%d tools exposed.",
            self.name,
            len(self.tools()),
            len(self._all_tools),
        )

    async def aopen(self, job_id: str, **context: Any) -> None:
        """Attach on the caller's own loop; the exit stack stays where it was wound.

        ``initialize`` is guarded the way the synchronous ``open`` guards
        ``_run_async(toolkit.initialize(), ...)``: a transport or subprocess
        can be partly up (a socket connected, a child process spawned) before
        ``initialize`` itself fails or is cancelled — e.g. ``handshake_tools``'s
        ``asyncio.wait_for`` timing out mid-handshake. ``_toolkit`` is never
        assigned until ``initialize`` succeeds, so if this does not close the
        partial attach, nothing does; the original exception (cancellation
        included) is what the caller needs to see, so it is re-raised
        unchanged after teardown.
        """
        if self._toolkit is not None:
            if job_id == self._job_id:
                return
            await self.aclose()
        self._job_id = job_id
        if not self.config.enabled:
            logger.info("mcp server '%s' is disabled.", self.name)
            return
        toolkit = self._build_toolkit(
            context.get("output_guardrail"),
            int(context.get("max_output_chars", 8000)),
            context.get("truncation_ledger"),
        )
        try:
            await toolkit.initialize()
        except (Exception, asyncio.CancelledError):
            logger.warning(
                "mcp server '%s' failed to initialize; closing the partial attach.",
                self.name,
            )
            await self._acleanup(toolkit)
            raise
        self._toolkit = toolkit
        self._all_tools = list(toolkit.get_tools())

    async def _acleanup(self, toolkit: Any) -> None:
        """Best-effort async close of ``toolkit``. Bounded, and never raises.

        Shared by ``aclose`` (a healthy, attached toolkit) and ``aopen``'s own
        exception handler (a toolkit that never made it into ``_toolkit``) —
        one teardown path so a partial attach and a normal close cannot drift.
        """
        closer = getattr(toolkit, "cleanup", None) or getattr(toolkit, "aclose", None)
        if closer is None:
            return
        try:
            # A stdio transport's exit stack waits on the child process, and a
            # child that does not exit waits forever — the 42-minute teardown
            # ``JudgeAgent.aclose`` was written for.
            await asyncio.wait_for(closer(), timeout=20.0)
        except TimeoutError:
            logger.warning(
                "mcp server '%s' cleanup did not finish in 20s; abandoning it. "
                "The subprocess may outlive this job.",
                self.name,
            )
        except Exception as exc:  # noqa: BLE001 — teardown never propagates
            logger.warning("mcp server '%s' teardown failed (non-fatal): %s", self.name, exc)

    async def aclose(self) -> None:
        """Close on the caller's own loop. Bounded, and never raises."""
        toolkit, self._toolkit = self._toolkit, None
        self._all_tools = []
        if toolkit is None:
            return
        await self._acleanup(toolkit)

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

    def _teardown(self, toolkit: Any) -> None:
        """Best-effort close of ``toolkit``, attached or abandoned mid-open. Never raises."""
        closer = getattr(toolkit, "cleanup", None) or getattr(toolkit, "aclose", None)
        if closer is None:
            return
        try:
            from maljan.agents.base_agent import _run_coro_blocking

            _run_coro_blocking(closer(), hard_timeout=20.0, label=f"{self.name}-mcp-close")
        except Exception as exc:  # noqa: BLE001 — teardown never propagates
            logger.warning("mcp server '%s' teardown failed (non-fatal): %s", self.name, exc)

    def close(self) -> None:
        """Release the client or subprocess. Never raises."""
        toolkit, self._toolkit = self._toolkit, None
        self._all_tools = []
        if toolkit is None:
            return
        self._teardown(toolkit)


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

    def for_agent(self, role: str, *, exclude: str = "") -> list[ServerHandle]:
        """Enabled servers bound to ``role``, built-ins first then by key.

        Order is what makes the collision rule predictable: a built-in is
        attached before any custom server, so a custom server that happens to
        name a tool ``extract_dns`` is the one that gets renamed, and the
        pinned built-in tool names never move.

        ``exclude`` drops one handle by name — the server a provider already
        opened itself, so the registry does not hand the same tools out twice.
        """
        from maljan.core.config import BUILTIN_SERVER_KEYS

        bound = [
            handle
            for handle in self._handles.values()
            if handle.config.enabled and role in handle.config.agents and handle.name != exclude
        ]
        return sorted(bound, key=lambda h: (h.name not in BUILTIN_SERVER_KEYS, h.name))

    def _merge(self, handle: ServerHandle, tools: list[BaseTool], seen: set[str]) -> int:
        """Append ``handle``'s tools to ``tools``, renaming any name collision.

        Returns how many tools were renamed, so the caller can log it once
        per handle instead of per tool.
        """
        renamed = 0
        for tool in handle.tools():
            name = str(getattr(tool, "name", ""))
            if name in seen:
                tool = tool.model_copy(update={"name": f"{handle.name}__{name}"})
                name = str(tool.name)
                renamed += 1
            seen.add(name)
            tools.append(tool)
        return renamed

    def tools_for(
        self, role: str, job_id: str, *, exclude: str = "", **context: Any
    ) -> tuple[list[BaseTool], list[str]]:
        """Open every server bound to ``role`` and concatenate their tools.

        Returns the tools and the degradation reasons: one per server that
        could not be opened. A failure here is never raised — the caller keeps
        the tools it did get, and the run summary says which server is missing
        rather than the report quietly being thinner than the last one.
        """
        tools: list[BaseTool] = []
        reasons: list[str] = []
        seen: set[str] = set()
        for handle in self.for_agent(role, exclude=exclude):
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
            renamed = self._merge(handle, tools, seen)
            if renamed:
                logger.info(
                    "mcp server '%s': %d tool name(s) already taken, prefixed with '%s__'.",
                    handle.name,
                    renamed,
                    handle.name,
                )
        return tools, reasons

    async def atools_for(
        self, role: str, job_id: str, *, exclude: str = "", **context: Any
    ) -> tuple[list[BaseTool], list[str]]:
        """``tools_for``, but ``await``ed on the caller's own loop.

        For a caller already inside an event loop (the judge's graph node),
        where handing the attach to the shared agent loop would bind the
        toolkit's transport to a loop other than the one that later awaits
        its tool calls.
        """
        tools: list[BaseTool] = []
        reasons: list[str] = []
        seen: set[str] = set()
        for handle in self.for_agent(role, exclude=exclude):
            try:
                await handle.aopen(job_id, **context)
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
            renamed = self._merge(handle, tools, seen)
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
