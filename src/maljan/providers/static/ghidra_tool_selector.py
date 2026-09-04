"""Dynamic, per-sample Ghidra MCP tool selection (2026-07 round 3).

Exposing all ~165 Ghidra tools to the local model made each ReAct step re-prefill
a ~15-25K-token manifest — 5-6x slower and measurably noisier (the model
hallucinated capabilities like process injection with no supporting imports).
Research on the "too many tools" problem (ScaleMCP, MemTool, lunar.dev) shows
selection quality drops sharply past ~30-50 visible tools; the fix is tool-RAG:
keep the full catalogue reachable but present only the *relevant* subset per run.

This module implements a lightweight, deterministic (no-embedding) relevance
selector: an always-present CORE triage set, plus the tools whose name/description
match the capability categories the sample actually exhibits (derived cheaply from
its PE import classification). Any of the 165 tools is reachable — it is selected
whenever its capability is relevant to the sample — but the model only ever sees
~30-40 focused tools.
"""

from __future__ import annotations

from typing import Any

# Universal triage tools — always presented regardless of sample. These cover
# load/inspect/decompile/xref/strings/imports/IOCs/behaviour, i.e. the backbone
# of any static analysis. Names match the Ghidra MCP tool ids (lowercased).
_CORE_TOOLS: frozenset[str] = frozenset(
    {
        "load_program",
        "get_current_program_info",
        "get_entry_points",
        "detect_malware_behaviors",
        "analyze_api_call_chains",
        "find_anti_analysis_techniques",
        "extract_iocs_with_context",
        "list_imports",
        "list_strings",
        "list_segments",
        "decompile_function",
        "get_xrefs_to",
        "analyze_dataflow",
        "get_function_hash",
        "analyze_function_complete",
    }
)

# Capability category -> keywords matched against tool name + description. The
# sample's categories come from its import classification
# (pe_extractor._SUSPICIOUS_IMPORTS -> import_capability_layer._imports_by_category).
_CATEGORY_KEYWORDS: dict[str, frozenset[str]] = {
    "network": frozenset(
        {"network", "socket", "connect", "http", "dns", "url", "c2", "packet", "wsa", "winsock"}
    ),
    "crypto": frozenset(
        {"crypto", "encrypt", "decrypt", "hash", "aes", "rc4", "xor", "cipher", "key", "base64"}
    ),
    "process_injection": frozenset(
        {
            "inject",
            "thread",
            "memory",
            "virtualalloc",
            "writeprocess",
            "remote",
            "hook",
            "apc",
            "shellcode",
            "hollow",
        }
    ),
    "registry": frozenset({"registry", "regkey", "persist", "autorun", "startup", "service"}),
    "filesystem": frozenset({"file", "directory", "path", "dropper", "write", "resource"}),
    "anti_debug": frozenset(
        {"anti", "debug", "vm", "sandbox", "evasion", "obfusc", "emulat", "packer", "unpack"}
    ),
    "execution": frozenset({"exec", "command", "process", "spawn", "shell", "lolbin", "script"}),
    "privilege": frozenset({"privilege", "token", "elevat", "uac", "impersonat"}),
}

_DEFAULT_MAX_TOOLS = 40


def _tool_name(tool: Any) -> str:
    return str(getattr(tool, "name", "")).lower()


def _tool_text(tool: Any) -> str:
    return f"{_tool_name(tool)} {str(getattr(tool, 'description', '')).lower()}"


def _relevance_score(tool_text: str, categories: set[str]) -> int:
    """Count keyword hits for the sample's active categories in a tool's text."""
    score = 0
    for cat in categories:
        for kw in _CATEGORY_KEYWORDS.get(cat, frozenset()):
            if kw in tool_text:
                score += 1
    return score


def select_relevant_ghidra_tools(
    all_tools: list[Any],
    sample_categories: set[str] | None,
    max_tools: int = _DEFAULT_MAX_TOOLS,
) -> list[Any]:
    """Return CORE tools + the tools most relevant to ``sample_categories``.

    Every one of ``all_tools`` remains reachable: a tool is included whenever it
    scores against a category the sample exhibits. The result is capped at
    ``max_tools`` (the ~30-50 sweet spot) so the model's manifest stays lean.
    Fail-safe: on any error or when the pool is already small, the full pool is
    returned unchanged.
    """
    if not all_tools:
        return []
    # Nothing to trim.
    if len(all_tools) <= max_tools:
        return list(all_tools)

    categories = {c for c in (sample_categories or set()) if c}

    core: list[Any] = []
    rest: list[tuple[int, int, Any]] = []  # (score, orig_index, tool)
    for idx, tool in enumerate(all_tools):
        if _tool_name(tool) in _CORE_TOOLS:
            core.append(tool)
            continue
        score = _relevance_score(_tool_text(tool), categories) if categories else 0
        rest.append((score, idx, tool))

    # Keep only positively-relevant non-core tools, best first (stable by index).
    ranked = sorted((r for r in rest if r[0] > 0), key=lambda r: (-r[0], r[1]))
    selected = list(core)
    for _score, _idx, tool in ranked:
        if len(selected) >= max_tools:
            break
        selected.append(tool)

    # If categories gave us nothing (unknown sample), fall back to CORE only —
    # still a coherent triage set, never the full 165.
    return selected
