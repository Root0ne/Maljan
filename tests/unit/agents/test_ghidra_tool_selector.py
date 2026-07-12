"""Tests for dynamic per-sample Ghidra tool selection (2026-07 round 3).

Keeps all tools reachable but presents only the CORE triage set + the tools
relevant to the sample's capability categories, so the local model isn't
overwhelmed (measured: all 165 tools -> 5-6x slower + more hallucination).
"""

from __future__ import annotations

from maljan.agents.ghidra_tool_selector import (
    _CORE_TOOLS,
    select_relevant_ghidra_tools,
)


class _Tool:
    def __init__(self, name: str, description: str = "") -> None:
        self.name = name
        self.description = description


def _pool(n_noise: int = 60) -> list[_Tool]:
    noise = [_Tool(f"misc_tool_{i}", "generic helper") for i in range(n_noise)]
    named = [
        _Tool("load_program"),
        _Tool("list_imports"),
        _Tool("decompile_function"),
        _Tool("analyze_network_traffic", "inspect socket connect http dns"),
        _Tool("detect_crypto_constants", "aes rc4 xor encrypt key"),
        _Tool("find_registry_persistence", "registry autorun startup"),
    ]
    return noise + named


def _names(tools: list[_Tool]) -> set[str]:
    return {t.name for t in tools}


class TestSelection:
    def test_core_always_present(self) -> None:
        sel = select_relevant_ghidra_tools(_pool(), {"network"})
        # every CORE tool that exists in the pool is kept
        assert "load_program" in _names(sel)
        assert "list_imports" in _names(sel)
        assert "decompile_function" in _names(sel)

    def test_category_relevant_included(self) -> None:
        sel = select_relevant_ghidra_tools(_pool(), {"network"})
        assert "analyze_network_traffic" in _names(sel)
        # a crypto tool is NOT pulled in for a network-only sample
        assert "detect_crypto_constants" not in _names(sel)

    def test_multiple_categories(self) -> None:
        sel = select_relevant_ghidra_tools(_pool(), {"crypto", "registry"})
        names = _names(sel)
        assert "detect_crypto_constants" in names
        assert "find_registry_persistence" in names
        assert "analyze_network_traffic" not in names

    def test_noise_excluded(self) -> None:
        sel = select_relevant_ghidra_tools(_pool(), {"network"})
        assert not any(n.startswith("misc_tool_") for n in _names(sel))

    def test_empty_categories_yields_core_only(self) -> None:
        sel = select_relevant_ghidra_tools(_pool(), set())
        # only CORE tools present in the pool survive
        assert _names(sel) <= _CORE_TOOLS

    def test_small_pool_returned_unchanged(self) -> None:
        pool = [_Tool("a"), _Tool("b")]
        assert select_relevant_ghidra_tools(pool, {"network"}) == pool

    def test_capped_at_max(self) -> None:
        # 100 network-matching tools + CORE, cap at 40
        pool = [_Tool(f"network_scan_{i}", "socket connect http") for i in range(100)]
        pool += [_Tool(n) for n in ("load_program", "list_imports")]
        sel = select_relevant_ghidra_tools(pool, {"network"}, max_tools=40)
        assert len(sel) == 40

    def test_none_categories_safe(self) -> None:
        sel = select_relevant_ghidra_tools(_pool(), None)
        assert _names(sel) <= _CORE_TOOLS
