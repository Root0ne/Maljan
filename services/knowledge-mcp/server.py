"""Reference lookups over stdio MCP: ATT&CK, API behaviour, LOLBins, prior cases.

Delegates to ``maljan.tools.knowledge``, which owns the indices and the
degradation contract: a lookup whose backend is missing answers with an empty
result and a ``reason``, never an exception. This file adds the tool manifest
and the same returned-error guard the analysis sidecar uses.

Indices are built on first call and kept warm for the process lifetime. The
ATT&CK bundle is tens of megabytes and the embedding model takes seconds to
load — paying that once per sidecar rather than once per call is the whole
reason this is a long-lived server and not a script.
"""

from __future__ import annotations

import copy
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from maljan.tools import knowledge as knowledge_tools
from maljan.tools.capabilities import CAPABILITIES_TOOL, ToolNeeds, manifest, module
from maljan.tools.errors import code_for_exception, normalise_error, tool_error

mcp = FastMCP("KnowledgeMCP")


def _apply_index_retry() -> None:
    """How long a failed ATT&CK index build is believed here.

    This is the process where the build actually happens, so it is the process
    the operator's ``validation.index_retry_seconds`` has to reach. It arrives
    as ``MALJAN_INDEX_RETRY_SECONDS`` because a sidecar reads its environment
    and never the settings store; an unset or unreadable value leaves the
    module's own default alone.
    """
    raw = os.environ.get(knowledge_tools.INDEX_RETRY_ENV, "").strip()
    if not raw:
        return
    try:
        knowledge_tools.set_index_retry_after(int(raw))
    except ValueError:
        pass


_apply_index_retry()

# The two retrievals over a vector store need its client; every other lookup
# reads the vendored catalogues.
TOOL_NEEDS: list[ToolNeeds] = [
    ToolNeeds("resolve_technique"),
    ToolNeeds("attck_lookup"),
    ToolNeeds("attck_validate"),
    ToolNeeds("api_capability"),
    ToolNeeds("lolbin_lookup"),
    ToolNeeds("family_lookup", (module("qdrant_client"),)),
    ToolNeeds("similar_cases", (module("qdrant_client"),)),
]
CAPABILITIES = manifest("knowledge", TOOL_NEEDS)


def _guard(tool: str, call: Any, **kwargs: Any) -> dict[str, Any]:
    """Run one lookup, turning any exception into a returned error with a remedy."""
    try:
        return dict(normalise_error(dict(call(**kwargs))))
    except Exception as exc:  # noqa: BLE001 — a tool server answers, it does not raise
        return tool_error(code_for_exception(exc), f"{type(exc).__name__}: {exc}", tool=tool)


@mcp.tool(name=CAPABILITIES_TOOL)
def capabilities() -> dict[str, Any]:
    """What this server can do on this host.

    Each tool, its optional dependency, and whether it is available.
    """
    # Deep, so "computed once when the server started" also means a
    # caller cannot reach in and change what it says.
    return copy.deepcopy(CAPABILITIES)


@mcp.tool()
def resolve_technique(text: str, k: int = 5, domain: str = "") -> dict[str, Any]:
    """Rank ATT&CK techniques against a behavioural description."""
    return _guard(
        "resolve_technique",
        knowledge_tools.resolve_technique,
        text=text,
        k=k,
        domain=domain or None,
    )


@mcp.tool()
def attck_lookup(technique_id: str) -> dict[str, Any]:
    """Look up one ATT&CK technique: name, domain, platforms, tactics, url."""
    return _guard("attck_lookup", knowledge_tools.attck_lookup, technique_id=technique_id)


@mcp.tool()
def attck_validate(ids: list[str]) -> dict[str, Any]:
    """Report which technique ids do not exist, with likely intended ids."""
    return _guard("attck_validate", knowledge_tools.attck_validate, ids=ids)


@mcp.tool()
def api_capability(api_names: list[str], platform: str = "windows") -> dict[str, Any]:
    """Look up what named APIs do and which techniques the catalogue associates them with.

    A reference association, not an observation of the technique. ``platform``
    is the vocabulary to ask: "windows" for a PE's imports, "linux" for an
    ELF's dynamic symbols. The two share names, so the wrong one answers about
    the wrong system.
    """
    return _guard(
        "api_capability",
        knowledge_tools.api_capability,
        api_names=api_names,
        platform=platform,
    )


@mcp.tool()
def lolbin_lookup(command_lines: list[str]) -> dict[str, Any]:
    """Match command lines against the signed-proxy-execution (LOLBin) table."""
    return _guard("lolbin_lookup", knowledge_tools.lolbin_lookup, command_lines=command_lines)


@mcp.tool()
def family_lookup(query: str, k: int = 5) -> dict[str, Any]:
    """Retrieve malware families whose fingerprint is closest to the query."""
    return _guard("family_lookup", knowledge_tools.family_lookup, query=query, k=k)


@mcp.tool()
def similar_cases(text: str, k: int = 5) -> dict[str, Any]:
    """Retrieve prior cases with similar behaviour, and the techniques they share."""
    return _guard("similar_cases", knowledge_tools.similar_cases, query=text, k=k)


if __name__ == "__main__":
    mcp.run(transport="stdio")
