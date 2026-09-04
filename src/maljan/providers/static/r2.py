"""radare2 static analysis over ``radareorg/radare2-mcp``, stdio.

Structurally this is ``GenericMCPStaticProvider`` with three r2-specific
defaults: the command comes from ``static.r2.binary_path``, the allow-list is
the pinned tool set below, and the prompt fragment describes an r2 workflow
rather than a Ghidra one. ``enumerate_r2_tools`` is the one place that speaks
raw MCP to a live r2mcp; both ``scripts/probe_r2_tools.py`` (which pins the
allow-list's source fixture) and ``probe_r2`` in the settings API's connection
test call it, so the two paths cannot drift apart.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, cast

from maljan.providers.base import MirrorSpec, StaticJobContext
from maljan.providers.registry import register_static_provider
from maljan.providers.static.generic_mcp import GenericMCPStaticProvider

if TYPE_CHECKING:
    from mcp.types import Tool

    from maljan.core.config import Settings, StaticR2Config


async def enumerate_r2_tools(command: str) -> list[Tool]:
    """List the tools an r2mcp at ``command`` offers, over a raw stdio MCP handshake.

    Used both to pin the golden fixture (``scripts/probe_r2_tools.py``) and to
    answer the settings-page connection test (``probe_r2``): the same coroutine
    either way, so the two cannot report different tool counts.
    """
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    from maljan.agents.subprocess_env import child_env

    params = StdioServerParameters(command=command, args=[], env=child_env())
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        response = await session.list_tools()
        return list(response.tools)


@register_static_provider("r2")
class R2StaticProvider(GenericMCPStaticProvider):
    """radare2 over ``radareorg/radare2-mcp``, stdio.

    Structurally this is the generic MCP adapter with three defaults: the
    command comes from ``static.r2.binary_path``, the allow-list is the pinned
    tool set below, and the prompt fragment describes an r2 workflow rather than
    a Ghidra one. The tool names were enumerated from a running r2mcp with
    ``scripts/probe_r2_tools.py`` and pinned in
    ``tests/fixtures/golden/r2_tools.json``; if a future r2mcp renames one, this
    constant changes and nothing else does.

    ``degrade_on_failure`` is True, unlike Ghidra's: r2 is an alternative here,
    not the profile this project's evaluation was measured on, so an operator
    whose r2mcp is missing gets a degraded run and a legible probe failure
    rather than a failed job.
    """

    # Read-only analysis core: open/analyse/enumerate/decompile/xref. Nothing
    # that writes, renames, or otherwise changes server state (rename_flag,
    # rename_function, set_comment, set_function_prototype, use_decompiler,
    # close_file, ...) is pinned here. A future r2mcp rename is a one-line
    # edit to this constant; nothing else in the provider changes.
    R2_ALLOWED_TOOLS: ClassVar[frozenset[str]] = frozenset(
        {
            "open_file",
            "analyze",
            "show_info",
            "list_entrypoints",
            "list_sections",
            "list_imports",
            "list_exports",
            "list_symbols",
            "list_libraries",
            "list_functions",
            "list_strings",
            "list_all_strings",
            "show_function_details",
            "get_function_prototype",
            "disassemble_function",
            "decompile_function",
            "xrefs_to",
            "list_memory_maps",
        }
    )

    R2_PROMPT_FRAGMENT: ClassVar[str] = (
        "Analyze binary files (e.g. PE, ELF) utilizing radare2 through your available tools. "
        "For EVERY claim you make, you MUST cite a concrete artifact: a function name, "
        "string offset (.data+0xNN), API import, or hex pattern. "
        "Focus on MITRE ATT&CK: T1027 (Obfuscation), T1106 (Native API), "
        "T1055 (Process Injection), T1140 (Deobfuscation).\n\n"
        "=== TOOL USAGE WORKFLOW ===\n"
        "1. Call `open_file` with the path you are given, then `analyze` to run the\n"
        "   analysis pass.\n"
        "2. Call `list_imports` and `list_strings` to see what the binary can reach.\n"
        "3. Call `list_functions` and pick the 3-5 that reference crypto, network or\n"
        "   process APIs; `decompile_function` those and `xrefs_to` their addresses.\n"
        "4. Summarise assembly patterns instead of dumping raw hex, and prefer one\n"
        "   summarising call over many narrow ones.\n"
    )

    @classmethod
    def from_settings(cls, cfg: Settings) -> R2StaticProvider:
        return cls(
            cfg.static.r2,
            label="radare2 MCP",
            allowed_tools=cls.R2_ALLOWED_TOOLS,
            prompt_fragment_text=cls.R2_PROMPT_FRAGMENT,
        )

    @property
    def _r2_cfg(self) -> StaticR2Config:
        """``self._cfg`` narrowed back to ``StaticR2Config``.

        The base class types its constructor parameter (and therefore the
        stored attribute) as the plain ``MCPServerConfig`` every generic
        server shares; ``from_settings`` always hands it the ``StaticR2Config``
        subclass, so this is a type-only narrowing, not a runtime check.
        """
        return cast("StaticR2Config", self._cfg)

    def server_command(self) -> str:
        cfg = self._r2_cfg
        return cfg.command or cfg.binary_path

    def open(self, job: StaticJobContext) -> None:
        """Same as the generic adapter's ``open``, with the command resolved from ``binary_path``.

        ``StaticR2Config`` carries the executable under its own
        ``binary_path`` field rather than the base ``MCPServerConfig.command``
        one (the r2-specific name reads better in the settings UI); syncing it
        here, once, keeps ``GenericMCPStaticProvider.open`` unmodified for
        Ghidra and ``generic_mcp``, both of which still use ``command``
        directly.
        """
        self._cfg.command = self.server_command()
        super().open(job)

    def mirror_spec(self) -> MirrorSpec:
        return MirrorSpec(work_subdir=Path(self._r2_cfg.mirror_dir).name, container_prefix="")
