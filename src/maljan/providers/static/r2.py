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
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from maljan.core import builtin_declarations
from maljan.core.logger import logger
from maljan.core.tool_declarations import ErrorPattern
from maljan.providers.base import MirrorSpec, ProviderProbe
from maljan.providers.declared_errors import PROTOCOL_ERROR, declared_error
from maljan.providers.errors import ProviderError
from maljan.providers.registry import register_static_provider
from maljan.providers.static.generic_mcp import GenericMCPStaticProvider
from maljan.tools.errors import error_parts, tool_error

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

    from maljan.core.config import Settings

# radare2's error patterns are its declaration's (``core.builtin_declarations``),
# held by the general rule (``core.tool_declarations.ErrorPattern``) and run by
# RE2: the open-first refusal r2mcp raises as an MCP protocol error, its
# ``<log>`` envelope of radare2 log lines with an ``[ERROR]`` or ``[FATAL]``
# among them and nothing else, and the sentences it writes as an ordinary text
# result. Each is held against the whole reply, never a line inside one: a
# listing of the sample's own strings can hold any sentence.
_R2_PATTERNS: tuple[ErrorPattern, ...] = tuple(
    ErrorPattern.model_validate(p) for p in builtin_declarations.R2_ERROR_PATTERNS
)
_R2_OPEN_FIRST = next(p for p in _R2_PATTERNS if "protocol_error" in p.applies_to)
_R2_LOG_ENVELOPE = next(p for p in _R2_PATTERNS if p.multiline)
_R2_ERROR_REPLIES = tuple(
    p for p in _R2_PATTERNS if p is not _R2_OPEN_FIRST and p is not _R2_LOG_ENVELOPE
)
# What a model is told after an answer that says no file is open.
_R2_OPEN_FILE_FIRST = builtin_declarations.R2_OPEN_FILE_FIRST
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
    return _R2_LOG_ENVELOPE.message("", text)


def r2_error_reply(
    tool: str,
    reply: Any,
    *,
    tried: str | None = None,
    readable: str | None = None,
    analysed: bool = False,
    patterns: Sequence[ErrorPattern] = _R2_PATTERNS,
) -> dict[str, Any] | None:
    """The structured failure for one r2mcp reply that is an error, else ``None``.

    Read by the one function every server's answers are read by
    (``providers.declared_errors.declared_error``) against ``patterns``, the
    radare2 block's declared error patterns; this adapter adds only its own
    remediations around a failure.

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
    found = declared_error(patterns, tool, reply)
    if found is None:
        return None
    pattern, message, target = found
    remediation: str | None = pattern.remediation_for(readable) or None
    if target == PROTOCOL_ERROR:
        return tool_error(pattern.code, message, tool=tool, remediation=remediation)
    address = _unanalysed_address(tool, message) if pattern.multiline else None
    if address is not None:
        told = _R2_NO_FUNCTION_AFTER_AF if analysed else _R2_NO_FUNCTION_NO_AF
        remediation = told.format(address=address)
    elif (
        tool == _R2_OPEN_TOOL
        and isinstance(reply, str)
        and reply.strip().startswith("Failed to open file")
        and tried
    ):
        remediation = _open_failed(tried, readable)
    return tool_error(pattern.code, message, tool=tool, remediation=remediation)


def _failure_message(failure: dict[str, Any] | None) -> str:
    """The message of a structured failure, or ``""``."""
    error = (failure or {}).get("error")
    return str(error.get("message") or "") if isinstance(error, dict) else ""


def _open_first(readable: str | None) -> str:
    """The open-first advice, naming the path radare2 can open when it is known."""
    return _R2_OPEN_FIRST.remediation_for(readable)


def _open_failed(tried: str, readable: str | None) -> str:
    """What a failed open is told: the path it tried, and the one radare2 can open."""
    if readable and readable != tried:
        return _R2_OPEN_FAILED_AT.format(tried=tried, readable=readable)
    return _R2_OPEN_FAILED_ON_ITS_OWN.format(tried=tried)


def _reading_error_replies(
    tool: Any,
    readable: Callable[[], str | None] | None = None,
    run_command: Callable[..., Awaitable[Any]] | None = None,
    patterns: Sequence[ErrorPattern] = _R2_PATTERNS,
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
            patterns=patterns,
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
                    patterns=patterns,
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

    # What the console calls this provider and says about it, and its test's label.
    title = "radare2 MCP"
    description = "A local radare2 binary answers disassembly questions over its MCP server."
    probe_label = "Test radare2 MCP"
    settings_intro = "Where the radare2 binary lives; the MCP server is launched from it."

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # This adapter reads its block's declared error patterns itself, by the
        # same function, to add its own remediations and the analyse-and-ask-again
        # step (``_reading_error_replies``).
        self._handle.reads_own_errors = True

    def _error_patterns(self) -> tuple[ErrorPattern, ...]:
        """The radare2 block's declared error patterns; the shipped ones with no block."""
        config = getattr(self._handle, "config", None)
        if config is None:
            return _R2_PATTERNS
        return tuple(getattr(config, "error_patterns", None) or ())

    @property
    def declaration_source(self) -> str:
        """radare2's own block, not a registry server: ``provider:r2``."""
        return f"provider:{self.id}"

    # The workflow prompt is the radare2 declaration's text (``core.builtin_declarations``).
    R2_PROMPT_FRAGMENT: ClassVar[str] = builtin_declarations.R2_PROMPT_FRAGMENT

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

    async def probe(self) -> ProviderProbe:
        """Find r2mcp as a job finds it, then hold an MCP handshake with it.

        A stdio handshake is the only honest test of a subprocess-backed
        server: a binary that exists but cannot serve MCP is exactly the
        failure an operator needs named before a job fails on it.
        """
        import time

        from maljan.core.config import MCPServerConfig
        from maljan.providers.server_probe import PROBE_BUDGET_SECONDS, handshake

        t0 = time.perf_counter()

        def _ms() -> int:
            return int((time.perf_counter() - t0) * 1000)

        configured = str(self._handle.config.command or "r2mcp")
        binary = resolve_r2_binary(configured)
        if binary.path is None:
            return ProviderProbe(
                False, f"{configured!r} was not found; looked in: {binary.described()}", _ms()
            )
        command = binary.path
        config = MCPServerConfig(enabled=True, transport="stdio", command=command)
        try:
            names, _capabilities = await handshake(config, "r2")
        except TimeoutError:
            return ProviderProbe(
                False, f"no MCP handshake within {PROBE_BUDGET_SECONDS:.0f} s", _ms()
            )
        except FileNotFoundError:
            return ProviderProbe(False, f"{command!r} not found on PATH", _ms())
        except Exception as exc:  # noqa: BLE001 — reported to the operator, never raised
            return ProviderProbe(False, f"{type(exc).__name__}: {exc}", _ms())
        return ProviderProbe(True, f"{len(names)} tools offered by {command!r}", _ms(), names)

    def get_tools(self) -> list[BaseTool]:
        tools = super().get_tools()
        runner = next((t for t in tools if t.name == _R2_RUN_COMMAND), None)
        run_command = getattr(runner, "coroutine", None)
        return [
            _reading_error_replies(
                tool,
                self._held_path,
                run_command if tool.name in _R2_FUNCTION_TOOLS else None,
                self._error_patterns(),
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
        """r2's own mirror directory (``mirror_dir``), seen at its block's ``sample_mount``.

        A stdio r2mcp shares the worker's filesystem, which the shipped empty
        mount says; a block that declares a mount is handed the path under it.
        """
        return MirrorSpec(
            work_subdir=Path(self._mirror_dir).name,
            container_prefix=str(self._cfg.sample_mount or ""),
        )
