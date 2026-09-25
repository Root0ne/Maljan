"""radare2 static analysis over ``radareorg/radare2-mcp``, stdio.

Structurally this is ``GenericMCPStaticProvider`` with two r2-specific
defaults: the command comes from ``static.r2.binary_path`` and the prompt
fragment describes an r2 workflow rather than a Ghidra one. Every tool r2mcp
offers reaches the model, minus whatever the operator unticks in
``static.r2.tools``. ``enumerate_r2_tools`` delegates to ``ServerHandle``, the
one stdio handshake a job itself uses, so ``probe_r2`` in the settings API's
connection test cannot report a different tool set than a job sees.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from maljan.core.logger import logger
from maljan.providers.base import MirrorSpec
from maljan.providers.registry import register_static_provider
from maljan.providers.static.generic_mcp import GenericMCPStaticProvider
from maljan.tools.errors import BAD_ARGUMENT, TOOL_FAILED, tool_error

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

    from maljan.core.config import Settings

# The replies r2mcp gives in place of an answer, as it writes them. r2mcp sends
# these as an ordinary text result rather than as an MCP error, so without this
# list the ledger filed "Invalid regex used in filter parameter, try a simpler
# expression" as a successful ``list_strings`` whose output was that sentence.
# Matched against the whole reply, never a line inside one: a listing of the
# sample's own strings can hold any sentence, and a string the sample carries is
# not the tool failing.
_R2_OPEN_FILE_FIRST = "call open_file with the path you are given, then call this tool again"
_R2_ERROR_REPLIES: tuple[tuple[re.Pattern[str], str, str | None], ...] = (
    (re.compile(r"Invalid regex used in filter parameter\b.*"), BAD_ARGUMENT, None),
    (re.compile(r"Invalid parameter '[^']*':.*"), BAD_ARGUMENT, None),
    (re.compile(r"Invalid params:.*"), BAD_ARGUMENT, None),
    (re.compile(r"Missing required parameter:.*"), BAD_ARGUMENT, None),
    (re.compile(r"Unknown tool: .*"), BAD_ARGUMENT, None),
    (re.compile(r"Unknown decompiler\b.*"), BAD_ARGUMENT, None),
    (
        re.compile(r"Cannot run (?:commands|script files) without calling the `open_file` tool.*"),
        TOOL_FAILED,
        _R2_OPEN_FILE_FIRST,
    ),
    (re.compile(r"No file is currently open\..*"), TOOL_FAILED, _R2_OPEN_FILE_FIRST),
    (
        re.compile(r"Failed to (?:open file|initialize r(?:adare)?2(?: core)?)\b.*"),
        TOOL_FAILED,
        None,
    ),
    (re.compile(r"Error: command returned NULL"), TOOL_FAILED, None),
)


def r2_error_reply(tool: str, reply: Any) -> dict[str, Any] | None:
    """The structured failure for one r2mcp reply that is an error, else ``None``.

    ``None`` for anything that is not one of r2mcp's own error sentences as the
    whole reply, so every answer keeps exactly what it said. The message is
    r2mcp's sentence, unchanged.
    """
    if not isinstance(reply, str):
        return None
    text = reply.strip()
    if not text or "\n" in text:
        return None
    for pattern, code, remediation in _R2_ERROR_REPLIES:
        if pattern.fullmatch(text):
            return tool_error(code, text, tool=tool, remediation=remediation)
    return None


def _reading_error_replies(tool: Any) -> Any:
    """``tool``, rebuilt so an r2mcp error reply comes back as the structured failure.

    The ledger's rule for a returned error (``schemas.evidence.build_entry``)
    reads the structured shape, so an error reply is then a failed entry with
    r2mcp's own message. A tool that cannot be rebuilt faithfully is returned
    as it is.
    """
    from langchain_core.tools import StructuredTool

    coroutine = getattr(tool, "coroutine", None)
    args_schema = getattr(tool, "args_schema", None)
    if coroutine is None or args_schema is None:
        return tool
    name = str(getattr(tool, "name", "") or "")

    async def _call(**kwargs: Any) -> Any:
        reply = await coroutine(**kwargs)
        failure = r2_error_reply(name, reply)
        return json.dumps(failure) if failure is not None else reply

    try:
        return StructuredTool.from_function(
            func=None,
            coroutine=_call,
            name=name,
            description=getattr(tool, "description", ""),
            args_schema=args_schema,
            infer_schema=False,
            metadata=dict(getattr(tool, "metadata", None) or {}),
        )
    except Exception as exc:  # noqa: BLE001 — reading a reply never costs a tool
        logger.warning("r2: tool '%s' kept as it is (%s).", name, exc)
        return tool


async def enumerate_r2_tools(command: str) -> list[str]:
    """Names of the tools an r2mcp at ``command`` offers, over one stdio handshake.

    Used by the settings API's connection test (``probe_r2``) and by anything else that needs to
    answer the settings-page connection test: the same ``ServerHandle`` either
    way, which is now the same one a job uses, so none of the three can report
    a different tool set than the others.
    """
    from maljan.core.config import MCPServerConfig
    from maljan.providers.servers import ServerHandle
    from maljan.tools import staging

    handle = ServerHandle("r2", MCPServerConfig(enabled=True, transport="stdio", command=command))
    try:
        await handle.aopen("probe-r2")
        return handle.all_tool_names()
    finally:
        await handle.aclose()
        # Not a job: whatever directory this call's identity named is this
        # call's to take away.
        staging.remove_job_staging("probe-r2")


@register_static_provider("r2")
class R2StaticProvider(GenericMCPStaticProvider):
    """radare2 over ``radareorg/radare2-mcp``, stdio.

    Structurally this is the generic MCP adapter with two defaults: the
    command comes from ``static.r2.binary_path`` and the prompt fragment
    describes an r2 workflow rather than a Ghidra one.

    ``degrade_on_failure`` is True, unlike Ghidra's: r2 is an alternative here,
    not the profile this project's evaluation was measured on, so an operator
    whose r2mcp is missing gets a degraded run and a legible probe failure
    rather than a failed job.
    """

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

    # ``StaticR2Config.mirror_dir``'s own default, kept here too: a provider
    # built any way other than ``from_settings`` (there is none today, but the
    # base class's constructor allows it) still gets a sane mirror spec — and,
    # since BUG 10, one radare2 will actually open. It rejects any path with a
    # ``/.`` segment, so this must never become a hidden directory again.
    _mirror_dir: str = "data/samples/r2-work"

    @classmethod
    def from_settings(cls, cfg: Settings) -> R2StaticProvider:
        from maljan.core.config import MCPServerConfig
        from maljan.providers.servers import ServerHandle

        r2 = cfg.static.r2
        handle = ServerHandle(
            "r2",
            MCPServerConfig.model_validate({**r2.model_dump(), "command": r2.binary_path}),
        )
        provider = cls(
            handle,
            label="radare2 MCP",
            prompt_fragment_text=cls.R2_PROMPT_FRAGMENT,
        )
        provider._mirror_dir = r2.mirror_dir
        return provider

    def open(self, job: Any) -> None:
        super().open(job)
        self.tools = self.get_tools()

    def get_tools(self) -> list[BaseTool]:
        return [_reading_error_replies(tool) for tool in super().get_tools()]

    def mirror_spec(self) -> MirrorSpec:
        return MirrorSpec(work_subdir=Path(self._mirror_dir).name, container_prefix="")
