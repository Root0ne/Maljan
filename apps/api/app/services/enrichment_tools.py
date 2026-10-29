"""Ask a declared tool server's tool on behalf of an enrichment source.

An enrichment source may be a tool of a server in ``mcp.servers``: a server
tagged ``reputation`` (``MCPServerConfig.roles``) whose tool takes the
indicator in the argument its declaration names for that kind
(``ToolFacts.arguments``). Each server is attached once per enrichment, on
first use, through the same ``ServerHandle`` a run attaches it with, and
closed when the enrichment ends.

What a server's tool is, is read from the declarations in force for its block
(``core.declared_reading.tools_in_force``): the block's own, what the server
declares of itself, and what the platform read of its listing
(``core.derived_declarations``), never from a tool's or a server's name. A
source that names no tool is asked through the server's indicator lookup for
the kind (:meth:`ServerToolCaller.indicator_lookups`).
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
        # The source tools their host withheld, by ``(server, tool)``, with the
        # manifest's reason: the enrichment's disclosure records them
        # (``analysis.disclosure.with_enrichment_asked``), not only the log.
        self._withheld: dict[tuple[str, str], str] = {}

    def withheld_rows(self) -> list[dict[str, str]]:
        """The source tools their host withheld: ``server``, ``tool`` and ``reason`` each."""
        return [
            {"server": server, "tool": tool, "reason": reason}
            for (server, tool), reason in sorted(self._withheld.items())
        ]

    def servers(self) -> Mapping[str, Any]:
        """The tool servers in force, by key."""
        servers = getattr(getattr(self._settings, "mcp", None), "servers", None) or {}
        return servers if isinstance(servers, Mapping) else {}

    def _config(self, server: str) -> Any:
        return self.servers().get(server)

    def _tools_in_force(self, server: str) -> Mapping[str, Any]:
        """``server``'s tool declarations in force: its block's, its own and what is read of it."""
        from maljan.core.declared_reading import tools_in_force

        cfg = self._config(server)
        if cfg is None:
            return {}
        return tools_in_force(f"mcp:{server}", cfg)

    def arguments(self, server: str, tool: str) -> Mapping[str, str]:
        """The argument per indicator kind the server's declarations in force name for ``tool``."""
        facts = self._tools_in_force(server).get(tool)
        return dict(getattr(facts, "arguments", None) or {})

    async def indicator_lookups(
        self, server: str, kind: str, tool: str = ""
    ) -> list[tuple[str, str, Any]]:
        """The tools ``server`` may be asked about a ``kind`` indicator with: name, argument, facts.

        ``tool`` alone where the source names one, with what its declaration
        in force says of it. Otherwise every tool, in the order the server
        declares them (the asker falls back to the next when one fails), that
        the block's tools list ticks (where it names one), whose declaration in
        force is a lookup about an indicator
        (``core.reputation.INDICATOR_LOOKUP_KINDS``) and names an argument for
        ``kind``, and that sends nothing of the sample to a third party: not by
        its declaration in force, nor by what is read of its listing
        (``core.served_declarations.derived``), which no declaration over it
        lifts here. A tool whose listing requires an argument other than the
        indicator's is left out too: it cannot be asked with the indicator
        alone. The server is attached first, so what is read of its listing on
        a first attach is read here too.
        """
        from maljan.core.reputation import INDICATOR_LOOKUP_KINDS
        from maljan.core.served_declarations import derived
        from maljan.core.tool_declarations import THIRD_PARTY_BYTES, THIRD_PARTY_HASH

        handle = await self._handle(server)
        if handle is None:
            return []
        held = self._tools_in_force(server)
        if tool:
            facts = held.get(tool)
            argument = str((getattr(facts, "arguments", None) or {}).get(kind) or "")
            return [(tool, argument, facts)]
        read = derived(f"mcp:{server}")
        required = _required_arguments(handle)
        ticked = getattr(self._config(server), "tools", None)
        out: list[tuple[str, str, Any]] = []
        for name, facts in held.items():
            if ticked is not None and str(name) not in set(ticked):
                continue
            if getattr(facts, "kind", "") not in INDICATOR_LOOKUP_KINDS:
                continue
            sends = False
            for reading in (facts, read.get(name)):
                effects = getattr(reading, "effects", None)
                third_party = str(getattr(effects, "third_party", "") or "")
                sends = sends or bool(getattr(reading, "discloses_sample", False))
                sends = sends or third_party in (THIRD_PARTY_HASH, THIRD_PARTY_BYTES)
            if sends:
                continue
            argument = str((getattr(facts, "arguments", None) or {}).get(kind) or "")
            if not argument or required.get(str(name), set()) - {argument}:
                continue
            out.append((str(name), argument, facts))
        return out

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

    async def withheld_reason(self, server: str, tool: str) -> str | None:
        """Why the host withholds ``tool``, recorded for the disclosure; ``None`` when it does not.

        Asked before a question is told (``SourceAsker._ask_server``), so a
        withheld source shows only as withheld, never as asked.
        """
        handle = await self._handle(server)
        if handle is None:
            return None
        reason = handle.withheld_reason(tool)
        if reason:
            self._withheld[(server, tool)] = reason
        return str(reason) if reason else None

    async def __call__(self, server: str, tool: str, args: dict[str, Any]) -> Any:
        handle = await self._handle(server)
        if handle is None:
            return None
        picked = [t for t in handle.tools() if str(getattr(t, "name", "")) == tool]
        if not picked:
            withheld = handle.withheld_reason(tool)
            if withheld:
                logger.warning("enrich: a source's tool is withheld on this host: %s", withheld)
                self._withheld[(server, tool)] = withheld
            else:
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


def _required_arguments(handle: Any) -> dict[str, set[str]]:
    """Per tool the handle lists, the arguments its input schema requires; none for one unread."""
    out: dict[str, set[str]] = {}
    try:
        listed = list(handle.tools())
    except Exception:  # noqa: BLE001 — a listing that cannot be read requires nothing known
        return out
    for item in listed:
        schema = getattr(item, "args_schema", None)
        if not isinstance(schema, Mapping):
            dump = getattr(schema, "model_json_schema", None)
            try:
                schema = dump() if callable(dump) else None
            except Exception:  # noqa: BLE001
                schema = None
        required = schema.get("required") if isinstance(schema, Mapping) else None
        if isinstance(required, list):
            out[str(getattr(item, "name", ""))] = {str(name) for name in required}
    return out


__all__ = ["REPUTATION_ROLE", "ServerToolCaller"]
