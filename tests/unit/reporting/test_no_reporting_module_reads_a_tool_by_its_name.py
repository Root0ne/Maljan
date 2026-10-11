"""No module in ``maljan.reporting`` reads an entry's tool by a tool's name.

The report reads a tool by the kind it declares (``reporting.tool_kinds``).
The tables that read an entry with no recorded source by name live in one
marked module, ``reporting.legacy_tool_names``, and nowhere else. This guard
reads every other module's syntax tree and fails on:

* a comparison (``==``, ``!=``, ``in``, ``not in``) of an expression that
  reads an entry's tool with a tool's name, a collection holding one, or a
  module constant holding one;
* ``startswith`` / ``endswith`` on such an expression with a literal;
* a lookup of such an expression in a module dict keyed by tool names;
* a module constant named for tools that holds a tool's name.

A tool's name is any name a built-in source declares, and the names the
consumer tables kept for tools no built-in has.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from maljan.core.builtin_declarations import CONSUMER_KINDS
from maljan.reporting import legacy_tool_names

REPORTING = Path(__file__).resolve().parents[3] / "src" / "maljan" / "reporting"
LEGACY = "legacy_tool_names.py"


def _tool_names() -> frozenset[str]:
    names = set(legacy_tool_names._builtin_by_name())
    for spec in CONSUMER_KINDS.values():
        names |= set(spec.get("legacy_names", ()))
    return frozenset(names)


TOOL_NAMES = _tool_names()


def _reads_a_tool(node: ast.AST) -> bool:
    """Whether an expression reads an entry's tool: ``.tool``, ``tool_name``, ``tool_of(...)``."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr in ("tool", "tool_name"):
            return True
        if isinstance(sub, ast.Name) and (
            sub.id in ("tool", "tool_name") or sub.id.endswith("_tool")
        ):
            return True
        if isinstance(sub, ast.Call):
            func = sub.func
            called = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if called == "tool_of":
                return True
            if called == "get" and any(
                isinstance(a, ast.Constant) and a.value in ("tool", "tool_name") for a in sub.args
            ):
                return True
    return False


def _literal_names(node: ast.AST) -> set[str]:
    return {
        sub.value
        for sub in ast.walk(node)
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and sub.value in TOOL_NAMES
    }


def _module_constants(tree: ast.Module) -> dict[str, ast.AST]:
    held: dict[str, ast.AST] = {}
    for stmt in tree.body:
        targets: list[ast.expr] = []
        value: ast.AST | None = None
        if isinstance(stmt, ast.Assign):
            targets, value = list(stmt.targets), stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            targets, value = [stmt.target], stmt.value
        for target in targets:
            if isinstance(target, ast.Name) and value is not None:
                held[target.id] = value
    return held


def violations(source: str, label: str = "<module>") -> list[str]:
    """Every place ``source`` reads an entry's tool by a tool's name."""
    tree = ast.parse(source)
    constants = _module_constants(tree)
    named = {name for name, value in constants.items() if _literal_names(value)}
    found: list[str] = []

    def _names_a_tool(node: ast.AST) -> bool:
        if _literal_names(node):
            return True
        return isinstance(node, ast.Name) and node.id in named

    for name, value in constants.items():
        if "TOOL" in name.upper() and _literal_names(value):
            found.append(f"{label}: constant {name} holds {sorted(_literal_names(value))}")
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            sides = [node.left, *node.comparators]
            if any(_reads_a_tool(s) for s in sides) and any(
                _names_a_tool(s) for s in sides if not _reads_a_tool(s)
            ):
                found.append(f"{label}:{node.lineno}: compares a tool with a tool's name")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr, owner = node.func.attr, node.func.value
            if attr in ("startswith", "endswith") and _reads_a_tool(owner):
                if any(isinstance(sub, ast.Constant) for a in node.args for sub in ast.walk(a)):
                    found.append(f"{label}:{node.lineno}: {attr} on a tool with a literal")
                elif any(_names_a_tool(a) for a in node.args):
                    found.append(f"{label}:{node.lineno}: {attr} on a tool with a name table")
            if (
                attr == "get"
                and isinstance(owner, ast.Name)
                and owner.id in named
                and any(_reads_a_tool(a) for a in node.args)
            ):
                found.append(f"{label}:{node.lineno}: looks a tool up in {owner.id}")
        elif isinstance(node, ast.Subscript):
            if (
                isinstance(node.value, ast.Name)
                and node.value.id in named
                and _reads_a_tool(node.slice)
            ):
                found.append(f"{label}:{node.lineno}: looks a tool up in {node.value.id}")
    return found


def _modules() -> list[Path]:
    return sorted(p for p in REPORTING.rglob("*.py") if p.name != LEGACY)


@pytest.mark.parametrize("path", _modules(), ids=lambda p: str(p.relative_to(REPORTING)))
def test_no_reporting_module_reads_a_tool_by_its_name(path: Path) -> None:
    assert violations(path.read_text(encoding="utf-8"), path.name) == []


def test_the_legacy_module_is_the_one_that_holds_the_names() -> None:
    held = violations((REPORTING / LEGACY).read_text(encoding="utf-8"), LEGACY)
    assert held, "the legacy module keeps the tables, so the guard must see them there"


@pytest.mark.parametrize(
    "snippet",
    [
        '_FUNCTION_TOOLS = frozenset({"pdf"})\nok = entry.tool in _FUNCTION_TOOLS\n',
        'skip = o.get("tool_name") != "decompile_function"\n',
        'sandbox = str(row.tool or "").startswith(("sandbox_", "pcap"))\n',
        '_BUILDERS = {"capa": 1}\nbuilder = _BUILDERS.get(entry.tool)\n',
        'if tool == "floss":\n    pass\n',
        'found = tool_of(row) in ("strings", "iocs_from_file")\n',
    ],
)
def test_the_guard_sees_each_way_a_name_was_read(snippet: str) -> None:
    assert violations(snippet)


def test_the_guard_lets_kinds_and_section_keys_be(snippet: str = "") -> None:
    clean = (
        '_KIND_SHAPE = {"strings": ("/strings/*", "/text")}\n'
        'ok = facts.kind in ("strings", "emulated_strings")\n'
        'section = acc.get("sandbox_processes", "Processes observed", "table")\n'
        'same = row.source == "strings"\n'
    )
    assert violations(clean) == []
