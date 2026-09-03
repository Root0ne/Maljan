"""The environment an MCP sidecar is started with.

A child process gets what it needs to run and nothing it has no business
reading: no LLM keys, no database URL, no encryption key. Each agent adds
its explicit ``mcp.<server>.env`` mapping and, where the sidecar genuinely
reads a credential (threatintel-mcp reads the two intel keys), names it.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping

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
) -> dict[str, str]:
    """Build the environment for an MCP sidecar subprocess.

    Starts from ``BASE_KEYS`` present in ``source`` (defaults to
    ``os.environ``), adds only the named ``allow`` keys (for a server
    documented to read a specific credential), then applies ``extra`` (the
    server's own explicit ``mcp.<server>.env`` mapping) on top.
    """
    src = os.environ if source is None else source
    env = {k: src[k] for k in BASE_KEYS if k in src}
    for key in allow:
        if key in src:
            env[key] = src[key]
    if extra:
        env.update(extra)
    return env
