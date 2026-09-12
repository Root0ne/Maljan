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

from typing import Any

from mcp.server.fastmcp import FastMCP

from maljan.tools import knowledge as knowledge_tools

mcp = FastMCP("KnowledgeMCP")


def _guard(tool: str, call: Any, **kwargs: Any) -> dict[str, Any]:
    """Run one lookup, turning any exception into a returned error."""
    try:
        return dict(call(**kwargs))
    except Exception as exc:  # noqa: BLE001 — a tool server answers, it does not raise
        return {"error": f"{type(exc).__name__}: {exc}", "tool": tool}


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
def api_capability(api_names: list[str]) -> dict[str, Any]:
    """Look up what named APIs do and which techniques cite them as evidence."""
    return _guard("api_capability", knowledge_tools.api_capability, api_names=api_names)


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
