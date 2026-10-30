"""The environment an MCP sidecar is started with.

A child process gets what it needs to run and nothing it has no business
reading: no LLM keys, no database URL, no encryption key. Each agent adds
its explicit ``mcp.<server>.env`` mapping and, where the sidecar genuinely
reads a credential (threatintel-mcp reads the two intel keys), names it.

The platform's own bootstrap variables (``core.platform_secrets``) never reach
a child, whatever its block asks for: settings validation refuses a block that
names one, and a block that reached a spawn some other way, built in code say,
has the name dropped here, with a warning naming the variable and the server.

How a stdio block's child is started as a whole, its rooted arguments and
working directory beside that environment, is read once here
(:func:`stdio_launch`), by the launch and by what a trust grant holds for.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from maljan.core.logger import logger
from maljan.core.platform_secrets import is_platform_secret

BASE_KEYS = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TZ",
    "JAVA_HOME",
    "PYTHONIOENCODING",
    "VIRTUAL_ENV",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
)


def child_env(
    extra: Mapping[str, str] | None = None,
    *,
    allow: Iterable[str] = (),
    source: Mapping[str, str] | None = None,
    server: str = "",
) -> dict[str, str]:
    """Build the environment for an MCP sidecar subprocess.

    Starts from ``BASE_KEYS`` present in ``source`` (defaults to
    ``os.environ``), adds only the named ``allow`` keys (for a server
    documented to read a specific credential), then applies ``extra`` (the
    server's own explicit ``mcp.<server>.env`` mapping) on top. A name in
    ``allow`` or ``extra`` that is one of the platform's own bootstrap
    variables is left out, and ``server`` is the name the warning gives.
    """
    src = os.environ if source is None else source
    env = {k: src[k] for k in BASE_KEYS if k in src}
    for name in allow:
        if _withheld(name, server):
            continue
        if name in src:
            env[name] = src[name]
    for name, value in (extra or {}).items():
        if not _withheld(name, server):
            env[name] = value
    return env


def _withheld(name: str, server: str) -> bool:
    """Whether ``name`` is kept from the child, said in a warning when it is."""
    if not is_platform_secret(name):
        return False
    logger.warning(
        "Tool server %s is started without %s: the platform's own bootstrap variables, "
        "which open its stores, never reach a tool server's environment.",
        server or "(unnamed)",
        name,
    )
    return True


class LaunchCwdError(ValueError):
    """A block's working directory that does not exist, or escapes the project."""


@dataclass(frozen=True)
class StdioLaunch:
    """How a stdio block's child is started: its arguments, environment and working directory.

    Read by the launch itself (``providers.servers``) and by what a console
    trust grant is recorded with (``tool_declarations.granted_launch``), so
    both read one launch.
    """

    args: list[str]
    env: dict[str, str]
    cwd: str | None


def launch_cwd(cwd: str | None) -> str | None:
    """A block's working directory as the child is started in it; ``None`` for the parent's.

    ``cwd`` is an operator setting that becomes a subprocess's working
    directory, so it gets the same treatment every other path-shaped setting
    gets: a relative value is rooted at the project directory and must stay
    inside it; an absolute value is allowed but must exist. Neither check is
    a sandbox; a typo fails loudly at attach time instead of starting a
    server in an unexpected directory. :class:`LaunchCwdError` otherwise.
    """
    from maljan.core.paths import get_project_root

    if not cwd:
        return None
    root = Path(get_project_root()).resolve()
    candidate = Path(cwd)
    if candidate.is_absolute():
        resolved = candidate.resolve()
        if not resolved.is_dir():
            raise LaunchCwdError(f"cwd {resolved} does not exist")
        return str(resolved)
    resolved = (root / candidate).resolve()
    if not resolved.is_relative_to(root):
        raise LaunchCwdError(f"cwd {cwd!r} resolves outside the project")
    if not resolved.is_dir():
        raise LaunchCwdError(f"cwd {resolved} does not exist")
    return str(resolved)


def stdio_launch(config: Any, *, server: str = "") -> StdioLaunch:
    """How ``config``'s child is started: :func:`child_env`, rooted arguments, :func:`launch_cwd`.

    Its arguments as ``core.paths.resolve_mcp_args`` roots them; its
    environment the block's ``env`` and ``env_allow`` give
    (:func:`child_env`), before what a job adds; its working directory as
    :func:`launch_cwd` reads it (:class:`LaunchCwdError` for one it refuses).
    """
    from maljan.core.paths import resolve_mcp_args

    env = child_env(
        getattr(config, "env", None) or {},
        allow=tuple(getattr(config, "env_allow", None) or ()),
        server=server,
    )
    args = resolve_mcp_args([str(arg) for arg in getattr(config, "args", None) or ()])
    return StdioLaunch(args=args, env=env, cwd=launch_cwd(getattr(config, "cwd", None)))
