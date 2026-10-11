"""No module of the reading half compares an entry's tool against a literal tool name.

The reading half (``pipeline/``, ``analysis/``, ``agents/``) reads what an
entry is from its tool's declared kind (``core.declared_reading``). A
comparison of an entry's tool (``entry.tool``, a ``tool`` or ``tool_name``
variable, ``_tool(entry)``, ``bare_name(...)``, ``.get("tool")``) with a
string literal, a collection of literals, or a module constant holding them
fails here. The legacy record of the old tables lives in
``core.legacy_tool_tables``, outside these packages.

``STILL_BY_NAME`` lists the comparisons whose own change is another branch's
(the one reputation path; the triage pack's own steps, which the pack writes
itself), each with its reason. The list may only shrink: a new comparison, or
one moved, fails.
"""

from __future__ import annotations

import ast
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ("pipeline", "analysis", "agents")

_TOOL_NAMES = frozenset({"tool", "tool_name"})
_TOOL_CALLS = frozenset({"_tool", "_base_tool_name", "bare_name"})
# A constant imported from elsewhere that names tools: ``INDEX_TOOL``, ``PASS_TOOLS``.
_TOOL_CONSTANT = re.compile(r"^(?:[A-Z][A-Z0-9_]*_)?TOOLS?$")

# (module, the comparison as written) -> why it is still by name.
_REPUTATION = "the reputation tables; the one reputation path replaces them"
_PACK_STEP = (
    "the triage pack reading the entry its own step just wrote, by that step's name; "
    "the pack as a declared step list replaces it"
)
STILL_BY_NAME: dict[tuple[str, str], str] = {
    ("pipeline/run_state.py", "e.tool in ('get_file_report', 'check_hash', 'reputation')"): (
        _REPUTATION
    ),
    ("pipeline/triage_pack.py", "entry.tool in ('get_file_report', 'check_hash')"): _REPUTATION,
    ("pipeline/triage_pack.py", "tool in _REPUTATION_TOOLS"): _REPUTATION,
    ("pipeline/triage_pack.py", "tool == 'pack'"): _PACK_STEP,
    ("pipeline/triage_pack.py", "entry.tool == 'capa'"): _PACK_STEP,
    ("pipeline/triage_pack.py", "entry.tool != 'capa'"): _PACK_STEP,
    ("pipeline/triage_pack.py", "e.tool == INDEX_TOOL"): _PACK_STEP,
    ("pipeline/triage_pack.py", "entry.tool == INDEX_TOOL"): _PACK_STEP,
    ("pipeline/triage_pack.py", "entry.tool != INDEX_TOOL"): _PACK_STEP,
    ("pipeline/triage_pack.py", "made[-1].tool == artefact_index.TOOL"): _PACK_STEP,
    ("pipeline/triage_pack.py", "entry.tool != sandbox_sections.SECTIONS_TOOL"): _PACK_STEP,
    ("pipeline/triage_pack.py", "entry.tool == ANTI_ANALYSIS_TOOL"): _PACK_STEP,
    ("pipeline/triage_pack.py", "entry.tool == crypto_constants.TOOL"): _PACK_STEP,
    ("pipeline/triage_pack.py", "entry.tool in PASS_TOOLS"): _PACK_STEP,
    ("pipeline/triage_pack.py", "entry.tool not in PASS_TOOLS"): _PACK_STEP,
}


def _module_constants(tree: ast.Module) -> dict[str, bool]:
    """Module-level names bound to a string or a collection of strings."""
    out: dict[str, bool] = {}
    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        for target in targets:
            if isinstance(target, ast.Name) and value is not None and _literal(value, {}):
                out[target.id] = True
    return out


def _literal(node: ast.expr, constants: dict[str, bool]) -> bool:
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str) and bool(node.value)
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return bool(node.elts) and all(_literal(e, constants) for e in node.elts)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id in ("frozenset", "set", "tuple") and len(node.args) == 1:
            return _literal(node.args[0], constants)
    if isinstance(node, ast.Name):
        return constants.get(node.id, False) or bool(_TOOL_CONSTANT.match(node.id))
    if isinstance(node, ast.Attribute):
        return bool(_TOOL_CONSTANT.match(node.attr))
    return False


def _names_a_tool(node: ast.expr) -> bool:
    if isinstance(node, ast.Attribute):
        return node.attr in _TOOL_NAMES
    if isinstance(node, ast.Name):
        return node.id in _TOOL_NAMES
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in _TOOL_CALLS:
            return True
        if isinstance(func, ast.Attribute) and func.attr == "get" and node.args:
            first = node.args[0]
            return isinstance(first, ast.Constant) and first.value in _TOOL_NAMES
        if isinstance(func, ast.Name) and func.id == "str" and node.args:
            return _names_a_tool(node.args[0])
    if isinstance(node, ast.BoolOp):
        return any(_names_a_tool(v) for v in node.values)
    return False


def _compares_a_tool(node: ast.Compare, constants: dict[str, bool]) -> bool:
    """Whether ``node`` compares a tool with a literal name.

    A word looked for inside a tool's name (``'decompil' in tool``) is a
    reading of the name's text, not a comparison with a tool name.
    """
    sides = [node.left, *node.comparators]
    if (
        len(node.ops) == 1
        and isinstance(node.ops[0], ast.In | ast.NotIn)
        and isinstance(node.left, ast.Constant)
        and _names_a_tool(node.comparators[0])
    ):
        return False
    return any(_names_a_tool(s) for s in sides) and any(_literal(s, constants) for s in sides)


def _comparisons() -> Counter[tuple[str, str]]:
    found: Counter[tuple[str, str]] = Counter()
    for package in PACKAGES:
        for path in sorted((ROOT / "src" / "maljan" / package).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            constants = _module_constants(tree)
            module = path.relative_to(ROOT / "src" / "maljan").as_posix()
            for node in ast.walk(tree):
                if not isinstance(node, ast.Compare):
                    continue
                if _compares_a_tool(node, constants):
                    found[(module, ast.unparse(node))] += 1
    return found


def test_no_module_of_the_reading_half_compares_a_tool_with_a_literal_name() -> None:
    unexpected = sorted(set(_comparisons()) - set(STILL_BY_NAME))
    assert not unexpected, unexpected


def test_the_list_of_comparisons_still_by_name_only_shrinks() -> None:
    stale = sorted(set(STILL_BY_NAME) - set(_comparisons()))
    assert not stale, stale


def test_the_guard_sees_each_way_a_tool_is_compared() -> None:
    source = (
        "TOOLS = ('a', 'b')\n"
        "def f(entry, tool):\n"
        "    return (entry.tool == 'x', tool in TOOLS, _tool(entry) in ('y',),\n"
        "            entry.get('tool') != 'z', str(entry.tool or '') == 'w',\n"
        "            facts.kind == 'strings', 'decompil' in tool,\n"
        "            entry.tool == artefact_index.TOOL)\n"
    )
    tree = ast.parse(source)
    constants = _module_constants(tree)
    hits = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Compare) and _compares_a_tool(node, constants)
    ]
    assert len(hits) == 6
