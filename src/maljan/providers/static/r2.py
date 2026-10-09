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
import os
import re
import shutil
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from maljan.core.logger import logger
from maljan.providers.base import MirrorSpec
from maljan.providers.errors import ProviderError
from maljan.providers.registry import register_static_provider
from maljan.providers.static.generic_mcp import GenericMCPStaticProvider
from maljan.tools.errors import BAD_ARGUMENT, TOOL_FAILED, error_parts, tool_error

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
# The same advice when the path radare2 can open for this sample is known: it
# names it, so a model whose open failed is not left to guess it.
_R2_OPEN_FILE_FIRST_AT = "call open_file with {readable}, then call this tool again"
# What a failed open is told: the path it tried and the one radare2 can open.
_R2_OPEN_FAILED_AT = (
    "open_file could not open {tried}; the path radare2 can open for this sample is "
    "{readable}: call open_file with it"
)
_R2_OPEN_FAILED_ON_ITS_OWN = (
    "open_file could not open {tried}, the path radare2 was given for this sample; report "
    "it with the server log"
)
_R2_OPEN_TOOL = "open_file"
# The open-first refusal r2mcp raises as a protocol error rather than writing as
# a reply; it reaches the tool layer as the MCP client's failure marker.
_R2_OPEN_FIRST_ERROR = re.compile(
    r"(?:\w+: )?Use the open_file method before calling any other method\b.*"
)
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


# r2mcp hands back what radare2 logged while running a command inside a
# ``<log>…</log>`` envelope. A reply that is that envelope and nothing else, and
# whose lines are all radare2 log lines with at least one ``[ERROR]`` or
# ``[FATAL]``, is radare2 saying the command failed ("[ERROR] Cannot find
# function in 0x…") with no answer beside it. An envelope in front of an answer is not a failure.
_R2_LOG_ENVELOPE = re.compile(r"<log>(?P<body>.*)</log>", re.DOTALL)
# The levels radare2 logs a failure at; ``FATAL`` is the more severe of the two.
_R2_FAILURE_LEVELS = frozenset({"ERROR", "FATAL"})
_R2_LOG_LINE = re.compile(r"\[(?P<level>[A-Z]+)\]\s*\S.*")


# radare2's words for a function tool called at an address its analysis holds no
# function at, with the address as radare2 resolved it (always hex, so it is
# safe to hand back to radare2 in a command).
_R2_NO_FUNCTION = re.compile(
    r"\[ERROR\] Cannot find function (?:in|at) (?P<address>0x[0-9a-fA-F]+)"
)
# The tools that read one function radare2 has analysed, and the tool that runs
# a radare2 command (offered only by an r2mcp started with ``-r``).
_R2_FUNCTION_TOOLS = frozenset({"decompile_function", "disassemble_function"})
_R2_RUN_COMMAND = "run_command"
_R2_NO_FUNCTION_NO_AF = (
    "radare2 has no function at {address}: its analysis did not define one there, and this "
    "server offers no call that analyses one address (`af @ {address}` runs through "
    "`run_command`, which r2mcp offers only when started with -r). Call `analyze` with a level "
    "above the one this file was analysed at (1 adds the targets of calls, 2 runs aaa), then "
    "call this tool again, or call `disassemble` with this address to read its instructions "
    "without a function"
)
_R2_NO_FUNCTION_AFTER_AF = (
    "radare2 defined no function at {address} even after `af @ {address}` was run through "
    "`run_command`; call `disassemble` with this address to read its instructions without a "
    "function"
)


def af_ran_note(address: str) -> str:
    """The line an answer carries when the adapter analysed its function first."""
    return (
        f"[platform] radare2 had no function at {address}; the platform ran `af @ {address}` "
        "through run_command before this answer."
    )


def _unanalysed_address(tool: str, logged: str) -> str | None:
    """The address a function tool found no function at, from radare2's own error."""
    if tool not in _R2_FUNCTION_TOOLS:
        return None
    match = _R2_NO_FUNCTION.search(logged)
    return match.group("address") if match else None


def _r2_logged_error(text: str) -> str | None:
    """radare2's own error lines, when ``text`` is only a log envelope of them."""
    envelope = _R2_LOG_ENVELOPE.fullmatch(text)
    if envelope is None:
        return None
    lines = [line.strip() for line in envelope.group("body").splitlines() if line.strip()]
    matched = [_R2_LOG_LINE.fullmatch(line) for line in lines]
    if not lines or not all(matched):
        return None
    if not any(m is not None and m.group("level") in _R2_FAILURE_LEVELS for m in matched):
        return None
    return "\n".join(lines)


def r2_error_reply(
    tool: str,
    reply: Any,
    *,
    tried: str | None = None,
    readable: str | None = None,
    analysed: bool = False,
) -> dict[str, Any] | None:
    """The structured failure for one r2mcp reply that is an error, else ``None``.

    ``None`` for anything that is not one of r2mcp's own error sentences as the
    whole reply, a log envelope holding nothing but radare2's log lines with
    an ``[ERROR]`` or ``[FATAL]`` among them, or the MCP client's marker for
    r2mcp's open-first protocol error, so every answer keeps exactly what it
    said. The message is r2mcp's sentence, or radare2's log lines, unchanged.

    ``tried`` is the path an ``open_file`` call was given and ``readable`` the
    path radare2 can open for this sample (the provider's mirror): a failed
    open names both in its remediation, and an open-first refusal names the
    readable one.

    A function tool radare2 answers with "Cannot find function" is told which
    call analyses that address; ``analysed`` says the adapter already ran
    ``af`` there, and the remediation then names what is left.
    """
    marker = _open_first_marker(reply)
    if marker is not None:
        return tool_error(TOOL_FAILED, marker, tool=tool, remediation=_open_first(readable))
    if not isinstance(reply, str):
        return None
    text = reply.strip()
    logged = _r2_logged_error(text)
    if logged is not None:
        address = _unanalysed_address(tool, logged)
        if address is None:
            return tool_error(TOOL_FAILED, logged, tool=tool)
        told = _R2_NO_FUNCTION_AFTER_AF if analysed else _R2_NO_FUNCTION_NO_AF
        return tool_error(TOOL_FAILED, logged, tool=tool, remediation=told.format(address=address))
    if not text or "\n" in text:
        return None
    for pattern, code, remediation in _R2_ERROR_REPLIES:
        if pattern.fullmatch(text):
            if remediation == _R2_OPEN_FILE_FIRST:
                remediation = _open_first(readable)
            elif tool == _R2_OPEN_TOOL and text.startswith("Failed to open file") and tried:
                remediation = _open_failed(tried, readable)
            return tool_error(code, text, tool=tool, remediation=remediation)
    return None


def _failure_message(failure: dict[str, Any] | None) -> str:
    """The message of a structured failure, or ``""``."""
    error = (failure or {}).get("error")
    return str(error.get("message") or "") if isinstance(error, dict) else ""


def _open_first(readable: str | None) -> str:
    """The open-first advice, naming the path radare2 can open when it is known."""
    return _R2_OPEN_FILE_FIRST_AT.format(readable=readable) if readable else _R2_OPEN_FILE_FIRST


def _open_failed(tried: str, readable: str | None) -> str:
    """What a failed open is told: the path it tried, and the one radare2 can open."""
    if readable and readable != tried:
        return _R2_OPEN_FAILED_AT.format(tried=tried, readable=readable)
    return _R2_OPEN_FAILED_ON_ITS_OWN.format(tried=tried)


def _open_first_marker(reply: Any) -> str | None:
    """The message of the MCP client's failure marker for r2mcp's open-first error, or ``None``."""
    if not (isinstance(reply, dict) or (isinstance(reply, str) and reply.lstrip().startswith("{"))):
        return None
    parts = error_parts(reply)
    if parts is None:
        return None
    _code, message, _remediation = parts
    return message if _R2_OPEN_FIRST_ERROR.fullmatch(message.strip()) else None


def _reading_error_replies(
    tool: Any,
    readable: Callable[[], str | None] | None = None,
    run_command: Callable[..., Awaitable[Any]] | None = None,
) -> Any:
    """``tool``, rebuilt so an r2mcp error reply comes back as the structured failure.

    The ledger's rule for a returned error (``schemas.evidence.build_entry``)
    reads the structured shape, so an error reply is then a failed entry with
    r2mcp's own message. ``readable`` answers, at call time, the path radare2
    can open for this sample, which a failed open's remediation names beside
    the path it tried. A tool that cannot be rebuilt faithfully is returned as
    it is.

    ``run_command`` is the server's own ``run_command`` when it offers one. A
    function tool radare2 answers with "Cannot find function" at an address
    then has the function there analysed (``af @ <address>``, the address as
    radare2 printed it) and is called once more with the same arguments; its
    second reply is the answer. Without it the failure says which call
    analyses the address.
    """
    from langchain_core.tools import StructuredTool

    coroutine = getattr(tool, "coroutine", None)
    args_schema = getattr(tool, "args_schema", None)
    if coroutine is None or args_schema is None:
        return tool
    name = str(getattr(tool, "name", "") or "")

    async def _call(**kwargs: Any) -> Any:
        reply = await coroutine(**kwargs)
        tried = kwargs.get("file_path") if name == _R2_OPEN_TOOL else None
        failure = r2_error_reply(
            name,
            reply,
            tried=str(tried) if tried else None,
            readable=readable() if readable is not None else None,
        )
        address = _unanalysed_address(name, _failure_message(failure))
        if address is not None and run_command is not None:
            try:
                await run_command(command=f"af @ {address}")
            except Exception as exc:  # noqa: BLE001 — the first failure stands, as it was
                logger.warning("r2: af at %s did not run (%s).", address, exc)
            else:
                logger.info(
                    "r2: %s at %s found no function; ran af there and called again.", name, address
                )
                reply = await coroutine(**kwargs)
                failure = r2_error_reply(
                    name,
                    reply,
                    readable=readable() if readable is not None else None,
                    analysed=True,
                )
                if failure is None and isinstance(reply, str):
                    # The entry says what produced the answer: the adapter's
                    # own analysis, not a call the model made.
                    reply = f"{reply.rstrip()}\n\n{af_ran_note(address)}\n"
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


# What a run publishes about an r2mcp it could not find: the remedy, not the
# directories searched. The directories name the worker's user and its home,
# which the log keeps and a published degradation reason has no need of.
R2_NOT_FOUND_REMEDIATION = (
    "install r2mcp with `r2pm -ci r2mcp`, or set core.static.r2.binary_path to "
    "the absolute path of the r2mcp executable"
)


@dataclass(frozen=True)
class R2Binary:
    """Where the configured r2mcp was found, or every place it was looked for."""

    path: str | None
    looked: tuple[str, ...]

    def described(self) -> str:
        """The places looked, as one sentence for a log or a connection test."""
        return "; ".join(self.looked) or "nowhere"


class R2BinaryNotFound(ProviderError):
    """The configured r2mcp is not on PATH nor in radare2's own install places."""

    def __init__(self, configured: str, looked: str) -> None:
        super().__init__(f"r2mcp {configured!r} was not found; looked in: {looked}")
        self.remediation = R2_NOT_FOUND_REMEDIATION


def _r2pm_bin_dirs(env: Mapping[str, str]) -> list[str]:
    """Where ``r2pm`` puts the executables it installs, most specific first.

    radare2's package manager installs under its prefix, ``R2PM_PREFIX``,
    whose default is ``radare2/prefix`` under the user's data directory —
    ``$XDG_DATA_HOME``, else ``.local/share`` in the home directory — and puts
    executables in ``bin`` beneath it, unless ``R2PM_BINDIR`` says otherwise.
    Every one of these is read from the environment or the home directory:
    nothing about one host is written here.
    """
    dirs: list[str] = []
    if env.get("R2PM_BINDIR"):
        dirs.append(env["R2PM_BINDIR"])
    if env.get("R2PM_PREFIX"):
        dirs.append(os.path.join(env["R2PM_PREFIX"], "bin"))
    home = env.get("HOME") or os.path.expanduser("~")
    data_home = env.get("XDG_DATA_HOME") or os.path.join(home, ".local", "share")
    dirs.append(os.path.join(data_home, "radare2", "prefix", "bin"))
    return list(dict.fromkeys(dirs))


def _executable(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


def resolve_r2_binary(configured: str, env: Mapping[str, str] | None = None) -> R2Binary:
    """The r2mcp to launch for ``static.r2.binary_path``, and where it was looked for.

    A value with a directory in it is the operator's own path and is used as
    it is, when it is an executable file. A bare name is looked up on the
    worker's PATH, then in the directories ``r2pm`` installs into (see
    ``_r2pm_bin_dirs``), because ``r2pm -ci r2mcp`` puts it there and does not
    touch PATH. Nothing is guessed past those: when none holds it the answer
    is ``None`` with every place looked.
    """
    environ: Mapping[str, str] = os.environ if env is None else env
    name = str(configured or "r2mcp").strip() or "r2mcp"
    if name.startswith("~"):
        home = environ.get("HOME") or os.path.expanduser("~")
        name = home + name[1:]
    if os.sep in name or (os.altsep and os.altsep in name):
        return R2Binary(name if _executable(name) else None, (name,))
    path_value = environ.get("PATH", "")
    # PATH is counted, not listed: the whole of it is long, says nothing about
    # r2mcp, and the directories r2 installs into are named below one by one.
    entries = [d for d in path_value.split(os.pathsep) if d]
    looked: list[str] = [
        f"PATH ({len(entries)} {'directory' if len(entries) == 1 else 'directories'})"
    ]
    on_path = shutil.which(name, path=path_value) if path_value else None
    if on_path:
        return R2Binary(on_path, tuple(looked))
    for directory in _r2pm_bin_dirs(environ):
        candidate = os.path.join(directory, name)
        looked.append(candidate)
        if _executable(candidate):
            return R2Binary(candidate, tuple(looked))
    return R2Binary(None, tuple(looked))


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
        """Find r2mcp, then attach to it as the generic adapter does.

        ``static.r2.binary_path`` defaults to the bare name ``r2mcp``, which a
        worker whose PATH does not hold radare2's install directory could not
        start. It is resolved here, at the start of the provider, through PATH
        and the places ``r2pm`` installs into, and the handle launches what
        was found. Not found is a failure that says where it looked; r2
        degrades, so the analyst goes on without it and the run records why.
        """
        # Switched off, the handle attaches nothing; there is nothing to find.
        if not self._handle.is_open and self._handle.config.enabled:
            configured = str(self._handle.config.command or "r2mcp")
            binary = resolve_r2_binary(configured)
            if binary.path is None:
                raise R2BinaryNotFound(configured, binary.described())
            if binary.path != configured:
                logger.info("r2: launching r2mcp from %s.", binary.path)
                self._handle.config = self._handle.config.model_copy(
                    update={"command": binary.path}
                )
                self._cfg = self._handle.config
        super().open(job)
        self.tools = self.get_tools()

    def get_tools(self) -> list[BaseTool]:
        tools = super().get_tools()
        runner = next((t for t in tools if t.name == _R2_RUN_COMMAND), None)
        run_command = getattr(runner, "coroutine", None)
        return [
            _reading_error_replies(
                tool,
                self._held_path,
                run_command if tool.name in _R2_FUNCTION_TOOLS else None,
            )
            for tool in tools
        ]

    def pin_sample(self, path: str | None) -> None:
        """The mirror this provider's session opens, set by the analyst node; ``None`` clears it."""
        self._pinned_path = path or None

    def _held_path(self) -> str | None:
        """The path radare2 can open for this sample: the pin, else the job's mirror."""
        pinned = getattr(self, "_pinned_path", None) or getattr(
            getattr(self, "_job", None), "mirror_sample_path", None
        )
        return pinned if isinstance(pinned, str) and pinned else None

    def open_sample(self, path: str | None = None) -> bool:
        """Open the job's mirror in r2mcp's session before the loop, as Ghidra loads its program.

        r2mcp answers every tool but ``open_file`` with an open-first refusal
        until a file is open, and a model that tried another path first, or a
        listing tool first, spent its turns on refusals. The mirror is opened
        here with r2mcp's own ``open_file``; the model may still open it
        again. A failure is logged and changes nothing else: the model's own
        open is answered as before, with the path radare2 can open named.
        Returns whether the file opened.
        """
        target = path or self._held_path()
        tool = next((t for t in self.get_tools() if t.name == _R2_OPEN_TOOL), None)
        coroutine = getattr(tool, "coroutine", None)
        if not target or coroutine is None:
            return False
        from maljan.agents.base_agent import run_coro_blocking
        from maljan.core.config import get_settings
        from maljan.providers.server_guard import deployment_call_budget

        budget = deployment_call_budget(get_settings())
        try:
            reply = run_coro_blocking(
                coroutine(file_path=target),
                hard_timeout=budget if budget > 0 else None,
                label="r2-open",
            )
        except Exception as exc:  # noqa: BLE001 — the model's own open is still there
            logger.warning("r2: the job's sample was not opened at session start (%s).", exc)
            return False
        if error_parts(reply) is not None or r2_error_reply(_R2_OPEN_TOOL, reply) is not None:
            logger.warning(
                "r2: the job's sample was not opened at session start (a %d-character reply).",
                len(str(reply)),
            )
            logger.debug("r2: the reply to the session-start open: %s", reply)
            return False
        logger.info("r2: opened the job's sample at session start.")
        return True

    def mirror_spec(self) -> MirrorSpec:
        return MirrorSpec(work_subdir=Path(self._mirror_dir).name, container_prefix="")
