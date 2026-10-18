"""Keep log lines off standard output in a process that speaks MCP over stdio.

A stdio MCP server's standard output carries JSON-RPC and nothing else; a log
line on it makes the client log "Failed to parse JSONRPC message". Every
sidecar entrypoint calls ``route_logging_to_stderr`` first, before any import
that can log. This module imports nothing from ``maljan`` so calling it cannot
itself start a logger.
"""

from __future__ import annotations

import logging
import sys

_to_stderr = False
# The line format ``maljan.core.logger`` gives its own handler, so a routed
# process writes the same text it always did.
_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


def is_routed() -> bool:
    """Whether the root handler on standard error already carries ``maljan`` lines."""
    return _to_stderr


def route_logging_to_stderr() -> None:
    """Send the root handler and every ``maljan`` handler to standard error."""
    global _to_stderr
    _to_stderr = True
    root = logging.getLogger()
    if not any(
        isinstance(h, logging.StreamHandler) and getattr(h, "stream", None) is sys.stderr
        for h in root.handlers
    ):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(_FORMAT, datefmt=_DATEFMT))
        root.addHandler(handler)
    # ``maljan`` lines propagate to the root handler above; a handler of the
    # logger's own, were it already installed, would write each line twice.
    maljan = logging.getLogger("maljan")
    for own in list(maljan.handlers):
        if own.get_name() == "maljan.default":
            maljan.removeHandler(own)
    for held in root.handlers:
        if isinstance(held, logging.StreamHandler) and held.stream is sys.stdout:
            held.setStream(sys.stderr)
