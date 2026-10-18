"""The environment an MCP sidecar is started with.

A child process gets what it needs to run and nothing it has no business
reading: no LLM keys, no database URL, no encryption key. Each agent adds
its explicit ``mcp.<server>.env`` mapping and, where the sidecar genuinely
reads a credential (threatintel-mcp reads the two intel keys), names it.

The platform's own bootstrap variables (``core.platform_secrets``) never reach
a child, whatever its block asks for: settings validation refuses a block that
names one, and a block that reached a spawn some other way, built in code say,
has the name dropped here, with a warning naming the variable and the server.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping

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
