"""The providers' shared code reads no vendor's module or vocabulary (T-418 PR7).

* A server's declared anti-analysis scan (``providers.static.declared_prepass``)
  read its rows with the reading and the rule sentence of Ghidra's own pass,
  imported from Ghidra's module. Both are the platform's, the same for every
  scan, and live in ``analysis.anti_analysis``; Ghidra's pass and a declared
  scan import them from there, and a declared scan works where Ghidra's
  module is absent.
* The sandbox submit helpers (``providers.sandbox.formats``) held CAPE's guest
  platform names. They are the CAPE adapter's own words and sit in it.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
STATIC = ROOT / "src" / "maljan" / "providers" / "static"


def _imported(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
        elif isinstance(node, ast.Import):
            out.update(alias.name for alias in node.names)
    return out


def test_a_declared_scan_imports_nothing_of_ghidra() -> None:
    imported = _imported(STATIC / "declared_prepass.py")
    assert not any("ghidra" in module for module in imported), imported


def test_ghidra_s_pass_and_a_declared_scan_state_by_the_same_rule() -> None:
    from maljan.analysis import anti_analysis
    from maljan.providers.static.ghidra import passes

    assert passes.STATED_RULE is anti_analysis.STATED_RULE
    assert passes.read_findings is anti_analysis.read_findings


def test_a_declared_scan_reads_its_rows_with_ghidra_s_module_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.providers.static.declared_prepass import DeclaredScan

    # Importing ``maljan.providers.static.ghidra.passes`` now fails.
    monkeypatch.setitem(sys.modules, "maljan.providers.static.ghidra.passes", None)
    rows: list[dict[str, Any]] = [
        {
            "category": "suspicious_instruction",
            "technique": "RDTSC",
            "instruction": "RDTSC",
            "offset": "0x401000",
        },
    ]
    scan = DeclaredScan(
        provider="acme", formats=frozenset({"pe"}), tool="scan_for_tricks", call=lambda: rows
    )
    answer = scan.anti_analysis()
    from maljan.analysis.anti_analysis import STATED_RULE

    assert answer["how"] == STATED_RULE
    assert answer["server"] == "acme"
    assert [row["what"] for row in answer["stated"]] == ["RDTSC"]


def test_the_shared_submit_helpers_hold_no_sandbox_s_vocabulary() -> None:
    from maljan.providers.sandbox import cape2, formats

    assert not hasattr(formats, "CAPE_PLATFORMS")
    assert not hasattr(formats, "cape_platform")
    assert cape2.cape_platform("Windows") == "windows"
    assert cape2.cape_platform("macos") == ""
