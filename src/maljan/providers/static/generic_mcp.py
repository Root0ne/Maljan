"""Generic MCP-server static analysis: any tool server the operator configures.

This is the whole point of the provider layer — how somebody plugs in a
reverse-engineering (or any other) MCP tool Maljan has never heard of, with
nothing more than ``static.generic.*`` settings. It is also the class Task
18's ``R2StaticProvider`` subclasses with radare2-specific defaults (command,
allow-list, prompt fragment): everything below is deliberately ignorant of
what its server's tools are called.

The tool allow-list is a constructor argument, not a setting:
``MCPServerConfig`` (and therefore ``static.generic``) has no ``tools`` field
yet — that arrives with the operator-configured MCP registry in sub-project
B. Until then, ``from_settings`` always passes ``allowed_tools=None``, so a
server attached purely from ``static.generic.*`` keeps every tool it
advertises in curated mode too; only a caller that constructs this class
directly (a subclass with its own default manifest, or a future settings
path) narrows it.

Unlike Ghidra, this provider degrades rather than raising
(``StaticCapabilities.degrade_on_failure=True``): an operator's own MCP
server going down should not fail an entire analysis when the deterministic
PE extraction is still there to fall back on. ``open()`` itself still lets a
failed attach propagate — exactly like ``GhidraStaticProvider.open`` — the
degrade decision belongs to the analyst's shared ``_try_initialize_mcp``,
which reads the capability flag; the provider's job is only to say what that
flag should be.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from langchain_core.tools import BaseTool

from maljan.core.logger import logger
from maljan.providers.base import (
    MirrorSpec,
    StaticCapabilities,
    StaticJobContext,
    StaticProvider,
)
from maljan.providers.registry import register_static_provider

if TYPE_CHECKING:
    from maljan.core.config import MCPServerConfig, Settings


@register_static_provider("generic_mcp")
class GenericMCPStaticProvider(StaticProvider):
    """Any MCP tool server, attached from ``MCPServerConfig`` alone.

    ``label`` names the server in logs and in the generated prompt fragment.
    ``allowed_tools`` is the curated/dynamic-mode allow-list — empty or
    ``None`` keeps every tool the server advertises. ``prompt_fragment_text``
    lets a caller supply real tool-specific guidance instead of the generated,
    tool-name-listing paragraph.
    """

    def __init__(
        self,
        cfg: MCPServerConfig,
        *,
        label: str = "MCP",
        allowed_tools: frozenset[str] | None = None,
        prompt_fragment_text: str = "",
    ) -> None:
        self._cfg = cfg
        self._label = label
        self._allowed_tools = allowed_tools or frozenset()
        self._prompt_fragment_text = prompt_fragment_text
        self._job = StaticJobContext()
        self._toolkit: Any = None
        self._all_tools: list[Any] = []
        self.tools: list[Any] = []

    @classmethod
    def from_settings(cls, cfg: Settings) -> GenericMCPStaticProvider:
        # `static.generic` is now a `StaticGenericConfig` reference (the name
        # of an entry in `mcp.servers`) rather than its own `MCPServerConfig`
        # copy; resolving the reference into the server it names is Task 4/5's
        # job. Left as-is (and mypy-silenced) so this task stays settings-only.
        return cls(cfg.static.generic)  # type: ignore[arg-type]

    @property
    def capabilities(self) -> StaticCapabilities:
        return StaticCapabilities(
            provides_tools=True,
            provides_evidence=False,
            provides_function_hashes=False,
            needs_sample_mirror=True,
            supports_tool_curation=True,
            degrade_on_failure=True,
        )

    def prompt_fragment(self) -> str:
        if self._prompt_fragment_text:
            return self._prompt_fragment_text
        names = [t.name for t in self.get_tools()]
        listed = ", ".join(f"`{n}`" for n in names[:20]) if names else "the tools you are given"
        return (
            f"Analyze the binary using the {self._label} tools available to you. "
            "For EVERY claim you make, you MUST cite a concrete artifact: a function name, "
            "string offset (.data+0xNN), API import, or hex pattern. "
            "Focus on MITRE ATT&CK: T1027 (Obfuscation), T1106 (Native API), "
            "T1055 (Process Injection), T1140 (Deobfuscation).\n\n"
            "=== TOOL USAGE WORKFLOW ===\n"
            f"Available tools: {listed}.\n"
            "Load or open the sample first, enumerate what the binary imports and "
            "contains, then examine the few most suspicious functions in depth. "
            "Prefer one summarising call over many narrow ones.\n"
        )

    def server_command(self) -> str:
        """The executable to launch for the stdio transport.

        A plain read of the configured command; a subclass whose config names
        the executable under a different field (``R2StaticProvider``'s
        ``binary_path``, since ``StaticR2Config`` reads better in the settings
        UI than a bare ``command``) overrides only this method rather than
        mutating ``self._cfg`` — the config object is the shared, user-editable
        ``Settings`` leaf that ``settings_snapshot()`` later persists into the
        job's run summary, so writing to it here would show the operator a
        value they never set.
        """
        return self._cfg.command

    def open(self, job: StaticJobContext) -> None:
        """Attach to the configured MCP server for ``job``. Idempotent, per the base contract.

        Same shape as ``GhidraStaticProvider.open``, for the same reason: a
        multi-chunk static run calls this once per chunk on one memoized
        provider instance, re-deriving a *fresh but equal* ``StaticJobContext``
        each time (same sample, same categories) rather than the literal same
        object. A repeat call whose job compares equal to the one already
        attached is a no-op; a call for a genuinely different job closes the
        previous toolkit before reattaching, so there is never a point where
        two toolkits — two clients or subprocesses — are live at once.
        """
        if self._toolkit is not None:
            if job == self._job:
                return
            logger.warning(
                "%s provider re-opened for a job different from the one already "
                "attached; closing the stale toolkit before re-attaching.",
                self._label,
            )
            self._close_toolkit()
        self._job = job
        if not self._cfg.enabled:
            logger.info("%s is disabled in config.", self._label)
            return

        from maljan.agents.mcp_client import MCPLangChainToolkit

        output_guardrail = job.output_guardrail
        max_chars = job.max_output_chars

        if self._cfg.transport == "stdio":
            from mcp import StdioServerParameters

            from maljan.agents.subprocess_env import child_env
            from maljan.core.paths import resolve_mcp_args

            env = child_env(self._cfg.env)
            env.setdefault("PYTHONIOENCODING", "utf-8")
            args = resolve_mcp_args(self._cfg.args)
            server_params = StdioServerParameters(command=self.server_command(), args=args, env=env)
            toolkit = MCPLangChainToolkit(
                server_params,
                output_guardrail=output_guardrail,
                max_output_chars=max_chars,
                truncation_ledger=job.truncation_ledger,
            )
        else:
            token = self._cfg.auth_token.get_secret_value()
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            toolkit = MCPLangChainToolkit(
                transport=self._cfg.transport,
                http_url=self._cfg.url,
                http_headers=headers,
                output_guardrail=output_guardrail,
                max_output_chars=max_chars,
                truncation_ledger=job.truncation_ledger,
            )

        self._run_async(toolkit.initialize())
        self._toolkit = toolkit
        all_tools = list(toolkit.get_tools())
        self._all_tools = all_tools
        self.tools = self.select_tools(all_tools)
        logger.info(
            "%s: %d/%d tools attached (mode=%s).",
            self._label,
            len(self.tools),
            len(all_tools),
            self._tool_mode(),
        )

    def _run_async(self, coro: Any) -> None:
        """Run the MCP-client init coroutine on the shared agent loop.

        Same rationale as ``GhidraStaticProvider._run_async``: the toolkit's
        transport binds its async primitives to whichever loop first creates
        it, and the ReAct tool calls later run on the process-wide agent loop,
        so init has to run there too rather than on a throwaway loop.
        """
        from maljan.agents.base_agent import _run_coro_blocking

        _run_coro_blocking(coro, hard_timeout=120.0, label=f"{self._label}-mcp-init")

    def get_tools(self) -> list[BaseTool]:
        return self._all_tools

    def select_tools(self, tools: list[Any], categories: set[str] | None = None) -> list[Any]:
        """``all`` keeps everything; ``curated`` and ``dynamic`` apply the allow-list.

        A generic server carries no capability-keyword map for ``dynamic`` to
        key off — that map is specific to Ghidra's own tool names — so
        ``dynamic`` falls back to the same allow-list narrowing as
        ``curated``. The allow-list is empty unless the caller supplied one
        (``static.generic`` has nowhere to configure it yet), so both modes
        keep everything by default.
        """
        if self._tool_mode() == "all":
            return list(tools)
        if not self._allowed_tools:
            return list(tools)
        return [t for t in tools if getattr(t, "name", "") in self._allowed_tools]

    def _tool_mode(self) -> str:
        """Resolve the effective tool-selection mode from config (back-compat)."""
        if getattr(self._cfg, "use_all_tools", False):
            return "all"
        return str(getattr(self._cfg, "tool_selection", "curated"))

    def mirror_spec(self) -> MirrorSpec:
        return MirrorSpec(work_subdir=".work", container_prefix="/data/samples")

    def _close_toolkit(self) -> None:
        """Release whatever client or subprocess is currently attached, if any.

        The one release path, shared by ``close()`` and by ``open()``'s
        mid-life re-attach — see ``GhidraStaticProvider._close_toolkit``, whose
        shape this copies. Teardown that can throw is teardown nobody calls,
        so every failure here is a warning, not a raise.
        """
        from maljan.agents.base_agent import _run_coro_blocking

        toolkit, self._toolkit = self._toolkit, None
        self._all_tools = []
        # M8 (final review): ``_all_tools`` was cleared but ``self.tools``
        # (the curated/selected subset ``get_tools()`` hands the analyst)
        # was not, so a closed provider kept advertising tool objects whose
        # transport was already gone.
        self.tools = []
        if toolkit is None:
            return
        closer = getattr(toolkit, "cleanup", None) or getattr(toolkit, "aclose", None)
        if closer is None:
            return
        try:
            _run_coro_blocking(closer(), hard_timeout=20.0, label=f"{self._label}-close")
        except Exception as exc:  # noqa: BLE001 - teardown never propagates
            logger.warning("%s provider teardown failed (non-fatal): %s", self._label, exc)

    def close(self) -> None:
        self._close_toolkit()
