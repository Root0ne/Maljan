"""Ask a declared tool server's tool on behalf of an enrichment source.

An enrichment source may be a tool of a server in ``mcp.servers``: a server
tagged ``reputation`` (``MCPServerConfig.roles``) whose tool takes the
indicator in the argument its declaration names for that kind
(``ToolFacts.arguments``). Each server is attached once per enrichment, on
first use, through the same ``ServerHandle`` a run attaches it with, and
closed when the enrichment ends.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

from maljan.core.logger import logger

# The role a server declares to be asked as a reputation source.
REPUTATION_ROLE = "reputation"
# How long one tool call of an enrichment source may take.
CALL_TIMEOUT_SECONDS = 60.0


class ServerToolCaller:
    """Calls one tool of a configured server; ``None`` for anything that cannot be asked."""

    def __init__(self, settings: Any, *, job_key: str) -> None:
        self._settings = settings
        self._job_key = job_key
        self._handles: dict[str, Any] = {}
        self._failed: set[str] = set()

    def servers(self) -> Mapping[str, Any]:
        """The tool servers in force, by key."""
        servers = getattr(getattr(self._settings, "mcp", None), "servers", None) or {}
        return servers if isinstance(servers, Mapping) else {}

    def _config(self, server: str) -> Any:
        return self.servers().get(server)

    def arguments(self, server: str, tool: str) -> Mapping[str, str]:
        """The argument per indicator kind the server's declaration names for ``tool``."""
        cfg = self._config(server)
        facts = (getattr(cfg, "tool_facts", None) or {}).get(tool)
        return dict(getattr(facts, "arguments", None) or {})

    async def _handle(self, server: str) -> Any:
        if server in self._handles:
            return self._handles[server]
        if server in self._failed:
            return None
        cfg = self._config(server)
        if cfg is None or not cfg.enabled or REPUTATION_ROLE not in (cfg.roles or []):
            logger.warning(
                "enrich: a source names a server that is not an enabled reputation server."
            )
            self._failed.add(server)
            return None
        from maljan.providers.servers import ServerHandle

        handle = ServerHandle(server, cfg)
        try:
            await handle.aopen(self._job_key)
        except Exception as exc:  # noqa: BLE001 — a server that will not attach is no answer
            logger.warning("enrich: a source's server did not attach (%s).", type(exc).__name__)
            self._failed.add(server)
            return None
        self._handles[server] = handle
        return handle

    async def __call__(self, server: str, tool: str, args: dict[str, Any]) -> Any:
        handle = await self._handle(server)
        if handle is None:
            return None
        picked = [t for t in handle.tools() if str(getattr(t, "name", "")) == tool]
        if not picked:
            logger.warning("enrich: a source's server offers no tool of the name it declares.")
            return None
        answer = await asyncio.wait_for(picked[0].ainvoke(args), CALL_TIMEOUT_SECONDS)
        return answer if isinstance(answer, dict | list) else str(answer)

    async def aclose(self) -> None:
        for handle in self._handles.values():
            try:
                await handle.aclose()
            except Exception as exc:  # noqa: BLE001 — closing never fails the enrichment
                logger.warning("enrich: closing a server failed (%s).", type(exc).__name__)
        self._handles.clear()


__all__ = ["REPUTATION_ROLE", "ServerToolCaller"]
