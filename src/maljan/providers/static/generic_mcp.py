"""Generic MCP-server static analysis: any tool server the operator configures.

This is the whole point of the provider layer — how somebody plugs in a
reverse-engineering (or any other) MCP tool Maljan has never heard of, with
nothing more than ``static.generic.server`` naming an entry in
``mcp.servers``. It is also the class ``R2StaticProvider`` subclasses with
radare2-specific defaults (command, allow-list, prompt fragment): everything
below is deliberately ignorant of what its server's tools are called.

The tool allow-list is ``MCPServerConfig.tools`` now: ``None`` exposes every
tool the server advertises (what the built-ins do, and what a server attached
purely from ``static.generic.server`` keeps until the operator narrows it
from its probe result), and a list narrows to those names.
``ServerHandle.tools()`` applies that setting; the constructor's own
``allowed_tools`` is a second, class-level allow-list a subclass (like
``R2StaticProvider``) supplies as its own default, applied on top by
``select_tools`` — a belt the operator's own setting does not need to know
about.

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
from maljan.providers.servers import ServerHandle

if TYPE_CHECKING:
    from maljan.core.config import MCPServerConfig, Settings


@register_static_provider("generic_mcp")
class GenericMCPStaticProvider(StaticProvider):
    """Any MCP tool server, attached through a ``ServerHandle``.

    ``label`` names the server in logs and in the generated prompt fragment.
    ``allowed_tools`` is the curated/dynamic-mode allow-list a subclass
    supplies as its own default — empty or ``None`` applies no extra
    narrowing beyond the handle's own ``MCPServerConfig.tools`` setting.
    ``prompt_fragment_text`` lets a caller supply real tool-specific guidance
    instead of the generated, tool-name-listing paragraph.

    The constructor accepts either a ready ``ServerHandle`` (the normal path,
    built by ``from_settings`` from an ``mcp.servers`` entry) or a bare
    ``MCPServerConfig`` (the path ``R2StaticProvider`` and the header tests
    still use, since ``static.r2`` is its own config leaf rather than a
    registry entry) — the latter is wrapped in a handle this class builds and
    owns.
    """

    def __init__(
        self,
        cfg: MCPServerConfig | ServerHandle,
        *,
        label: str = "MCP",
        allowed_tools: frozenset[str] | None = None,
        prompt_fragment_text: str = "",
    ) -> None:
        if isinstance(cfg, ServerHandle):
            self._handle = cfg
            self._cfg = cfg.config
        else:
            self._cfg = cfg
            self._handle = self._build_handle(label or "generic", cfg)
        self._label = label
        self._allowed_tools = allowed_tools or frozenset()
        self._prompt_fragment_text = prompt_fragment_text
        self._job = StaticJobContext()
        self.tools: list[Any] = []

    def _build_handle(self, name: str, cfg: MCPServerConfig) -> ServerHandle:
        """Wrap a directly-supplied config in a handle, honouring ``server_command``.

        ``R2StaticProvider`` (and any future subclass that names its
        executable under its own field, like ``binary_path``) overrides
        ``server_command`` rather than writing to ``MCPServerConfig.command``
        itself — the config is the shared, user-editable ``Settings`` leaf
        that ``settings_snapshot()`` persists into the job's run summary, so
        writing to it here would show the operator a value they never set.
        The handle gets a private copy with ``command`` resolved instead.
        """
        command = self.server_command()
        if command == cfg.command:
            return ServerHandle(name, cfg)
        return ServerHandle(name, cfg.model_copy(update={"command": command}))

    @classmethod
    def from_settings(cls, cfg: Settings) -> GenericMCPStaticProvider:
        """The registry entry ``static.generic.server`` names, or an inert handle.

        An unset (or unknown) reference is not an error here: the provider is
        constructed eagerly by the container, and an operator who selected
        generic_mcp without picking a server should learn that from the probe,
        not from a container that refuses to build.
        """
        from maljan.core.config import MCPServerConfig

        name = cfg.static.generic.server
        entry = cfg.mcp.servers.get(name) if name else None
        if entry is None:
            if name:
                logger.warning(
                    "static.generic.server names %r, which is not in mcp.servers; "
                    "the generic_mcp provider has nothing to attach.",
                    name,
                )
            return cls(ServerHandle(name or "generic", MCPServerConfig()))
        return cls(ServerHandle(name, entry), label=entry.label or name)

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

    @property
    def server_name(self) -> str:
        """The registry key this provider owns; the static analyst excludes it."""
        return self._handle.name

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
        if self._handle.is_open:
            if job == self._job:
                return
            self._handle.close()
        self._job = job
        self._handle.open(
            job.sha256 or "static",
            output_guardrail=job.output_guardrail,
            max_output_chars=job.max_output_chars,
            truncation_ledger=job.truncation_ledger,
        )
        self.tools = self.select_tools(self._handle.tools())

    def get_tools(self) -> list[BaseTool]:
        return self._handle.tools()

    def select_tools(self, tools: list[Any], categories: set[str] | None = None) -> list[Any]:
        """``all`` keeps everything; ``curated`` and ``dynamic`` apply the allow-list.

        A generic server carries no capability-keyword map for ``dynamic`` to
        key off — that map is specific to Ghidra's own tool names — so
        ``dynamic`` falls back to the same allow-list narrowing as
        ``curated``. The allow-list is empty unless the caller supplied one
        (a subclass default; ``static.generic``'s own narrowing already
        happened in ``ServerHandle.tools()``), so both modes keep everything
        by default.
        """
        if self._tool_mode() == "all":
            return list(tools)
        if not self._allowed_tools:
            return list(tools)
        return [t for t in tools if getattr(t, "name", "") in self._allowed_tools]

    def _tool_mode(self) -> str:
        """Resolve the effective tool-selection mode from config (back-compat)."""
        cfg = self._handle.config
        if getattr(cfg, "use_all_tools", False):
            return "all"
        return str(getattr(cfg, "tool_selection", "curated"))

    def mirror_spec(self) -> MirrorSpec:
        return MirrorSpec(work_subdir=".work", container_prefix="/data/samples")

    def close(self) -> None:
        self.tools = []
        self._handle.close()
