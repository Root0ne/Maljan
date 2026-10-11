"""No module in ``maljan.reporting`` reads an entry's tool by a tool's name.

The report reads a tool by the kind it declares (``reporting.tool_kinds``).
The tables that read an entry with no recorded source by name live in one
module, ``reporting/legacy_tool_names.py`` (exempt by its exact path), which
only ``reporting/tool_kinds.py`` imports, and only on its branches for an
entry with no source (``source_of(...) is None``) or in its ``stored_*``
functions, which serve records written before sources.

Everywhere else this guard follows each value read from an entry's tool
(``.tool``, ``tool_name``, ``tool_of(...)``, ``section_tool(...)``,
``getattr(x, "tool")``, ``x["tool"]``, ``x.get("tool")``, and any local
assigned from one, through ``str``, ``lower``, ``strip``, ``removeprefix``,
``split``, ``or`` and f-strings) and fails on:

* a comparison or membership test of such a value with anything that is not
  itself a tool read (a literal, a collection, a constant, an imported name);
* ``startswith``, ``endswith``, ``find``, ``index`` or ``count`` on it;
* a ``match`` on it;
* ``getattr`` or ``hasattr`` with it as the attribute;
* a lookup of it (``x[tool]``, ``x.get(tool)``, ``x.pop(tool)``) in a
  dictionary that is not a local one the code itself keys by tool reads.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPORTING = Path(__file__).resolve().parents[3] / "src" / "maljan" / "reporting"
EXEMPT = REPORTING / "legacy_tool_names.py"
GATEWAY = REPORTING / "tool_kinds.py"
LEGACY_MODULE = "legacy_tool_names"

_TOOL_FIELDS = ("tool", "tool_name")
_TOOL_CALLS = ("tool_of", "section_tool", "declared_name")
_STRING_METHODS = (
    "lower",
    "upper",
    "casefold",
    "strip",
    "lstrip",
    "rstrip",
    "removeprefix",
    "removesuffix",
    "split",
    "rsplit",
    "partition",
    "rpartition",
)
_NAME_TESTS = ("startswith", "endswith", "find", "rfind", "index", "rindex", "count")
_LOOKUPS = ("get", "pop")
_KEYING = ("setdefault", "add", "append", "discard", "remove")


def _called(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    return func.id if isinstance(func, ast.Name) else ""


def _const_field(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value in _TOOL_FIELDS


class _Scope:
    """One function's (or the module's) values that hold an entry's tool."""

    def __init__(self, params: list[str], parent: _Scope | None = None) -> None:
        # A nested function or lambda sees the values its enclosing scope holds.
        self.tainted = set(parent.tainted) if parent else set()
        self.keyed = set(parent.keyed) if parent else set()
        self.tainted |= {p for p in params if p in _TOOL_FIELDS or p.endswith("_tool")}

    def reads(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Attribute):
            return node.attr in _TOOL_FIELDS
        if isinstance(node, ast.Name):
            return node.id in self.tainted or node.id in self.keyed
        if isinstance(node, ast.Call):
            name = _called(node)
            if name in _TOOL_CALLS:
                return True
            if name in ("getattr",) and len(node.args) > 1 and _const_field(node.args[1]):
                return True
            if name == "get" and node.args and _const_field(node.args[0]):
                return True
            if name == "str" and node.args:
                return self.reads(node.args[0])
            if isinstance(node.func, ast.Attribute) and name in _STRING_METHODS:
                return self.reads(node.func.value)
            return False
        if isinstance(node, ast.Subscript):
            return _const_field(node.slice) or self.reads(node.value)
        if isinstance(node, ast.BoolOp):
            return any(self.reads(v) for v in node.values)
        if isinstance(node, ast.IfExp):
            return self.reads(node.body) or self.reads(node.orelse)
        if isinstance(node, ast.JoinedStr):
            return any(
                self.reads(v.value) for v in node.values if isinstance(v, ast.FormattedValue)
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.reads(node.left) or self.reads(node.right)
        return False

    def learn(self, nodes: list[ast.AST]) -> None:
        """Mark the locals assigned from tool reads, and the dicts keyed by them."""
        for _ in range(3):
            for node in nodes:
                if isinstance(node, ast.Assign | ast.AnnAssign | ast.NamedExpr):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    value = node.value
                    for target in targets:
                        if isinstance(target, ast.Name) and self.reads(value):
                            self.tainted.add(target.id)
                        if (
                            isinstance(target, ast.Subscript)
                            and isinstance(target.value, ast.Name)
                            and self.reads(target.slice)
                        ):
                            self.keyed.add(target.value.id)
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in _KEYING
                    and isinstance(node.func.value, ast.Name)
                    and node.args
                    and self.reads(node.args[0])
                ):
                    self.keyed.add(node.func.value.id)


def _legacy_aliases(tree: ast.Module) -> tuple[set[str], list[int]]:
    """The names the legacy module is bound to, and the lines that import it."""
    aliases: set[str] = set()
    lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.endswith(LEGACY_MODULE):
                lines.append(node.lineno)
                aliases |= {a.asname or a.name for a in node.names}
            for alias in node.names:
                if alias.name == LEGACY_MODULE:
                    lines.append(node.lineno)
                    aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.endswith(LEGACY_MODULE):
                    lines.append(node.lineno)
                    aliases.add(alias.asname or alias.name.rsplit(".", 1)[-1])
    return aliases, lines


def _no_source_test(test: ast.AST, from_source: set[str]) -> str:
    """``"body"`` when an ``if`` test says no source was recorded, ``"orelse"`` for its negation."""
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1):
        return ""
    left, right, op = test.left, test.comparators[0], test.ops[0]
    if not (isinstance(right, ast.Constant) and right.value is None):
        return ""
    from_source_call = isinstance(left, ast.Call) and _called(left) == "source_of"
    named = isinstance(left, ast.Name) and left.id in from_source
    if not (from_source_call or named):
        return ""
    if isinstance(op, ast.Is):
        return "body"
    return "orelse" if isinstance(op, ast.IsNot) else ""


def _legacy_branches(func: ast.AST) -> set[int]:
    """The ids of the nodes inside a function's branches for an entry with no source."""
    from_source = {
        t.id
        for n in ast.walk(func)
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
        if _called(n.value) == "source_of"
        for t in n.targets
        if isinstance(t, ast.Name)
    }
    inside: set[int] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.If):
            where = _no_source_test(node.test, from_source)
            for stmt in getattr(node, where, []) if where else []:
                inside |= {id(n) for n in ast.walk(stmt)}
    return inside


_NESTED = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _functions(tree: ast.Module) -> list[ast.AST]:
    return [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]


def _own(roots: list[ast.AST]) -> tuple[list[ast.AST], list[ast.AST]]:
    """A scope's own nodes, and the functions and lambdas nested directly in it."""
    own: list[ast.AST] = []
    nested: list[ast.AST] = []
    stack = list(reversed(roots))
    while stack:
        node = stack.pop()
        if isinstance(node, _NESTED):
            nested.append(node)
            continue
        own.append(node)
        stack.extend(reversed(list(ast.iter_child_nodes(node))))
    return own, nested


def _scopes(tree: ast.Module) -> list[tuple[_Scope, list[ast.AST]]]:
    """Each scope with its own nodes, a nested scope seeing its parent's values."""
    out: list[tuple[_Scope, list[ast.AST]]] = []
    pending: list[tuple[list[str], list[ast.AST], _Scope | None]] = [([], list(tree.body), None)]
    while pending:
        params, roots, parent = pending.pop()
        own, nested = _own(roots)
        scope = _Scope(params, parent)
        scope.learn(own)
        out.append((scope, own))
        for node in nested:
            assert isinstance(node, _NESTED)
            args = node.args
            names = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
            body: list[ast.AST] = [node.body] if isinstance(node, ast.Lambda) else list(node.body)
            defaults = [*args.defaults, *(d for d in args.kw_defaults if d is not None)]
            pending.append((names, [*body, *defaults], scope))
    return out


def violations(source: str, label: str = "<module>", *, gateway: bool = False) -> list[str]:
    """Every place ``source`` reads an entry's tool by a tool's name."""
    tree = ast.parse(source)
    found: list[str] = []
    aliases, import_lines = _legacy_aliases(tree)
    if import_lines and not gateway:
        found += [f"{label}:{n}: imports {LEGACY_MODULE}" for n in import_lines]

    exempt: set[int] = set()
    if gateway:
        for func in _functions(tree):
            if isinstance(func, ast.FunctionDef) and func.name.startswith("stored_"):
                exempt |= {id(n) for n in ast.walk(func)}
            else:
                exempt |= _legacy_branches(func)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Name)
                and node.id in aliases
                and id(node) not in exempt
                and not isinstance(node.ctx, ast.Store)
            ):
                found.append(
                    f"{label}:{node.lineno}: reads {LEGACY_MODULE} outside a no-source branch"
                )

    seen: set[tuple[int, int, str]] = set()

    def flag(node: ast.AST, what: str) -> None:
        key = (getattr(node, "lineno", 0), getattr(node, "col_offset", 0), what)
        if key not in seen and id(node) not in exempt:
            seen.add(key)
            found.append(f"{label}:{key[0]}: {what}")

    for scope, nodes in _scopes(tree):
        for node in nodes:
            if isinstance(node, ast.Compare):
                sides = [node.left, *node.comparators]
                if any(scope.reads(s) for s in sides) and any(
                    not scope.reads(s) and not (isinstance(s, ast.Constant) and s.value is None)
                    for s in sides
                ):
                    flag(node, "compares a tool with something that is not a tool")
            elif isinstance(node, ast.Match) and scope.reads(node.subject):
                flag(node, "matches on a tool")
            elif isinstance(node, ast.Call):
                name = _called(node)
                func_node = node.func
                if (
                    isinstance(func_node, ast.Attribute)
                    and name in _NAME_TESTS
                    and scope.reads(func_node.value)
                ):
                    flag(node, f"{name} on a tool")
                elif name in ("getattr", "hasattr") and len(node.args) > 1:
                    if scope.reads(node.args[1]):
                        flag(node, f"{name} with a tool")
                elif (
                    isinstance(func_node, ast.Attribute)
                    and name in _LOOKUPS
                    and 1 <= len(node.args) <= 2
                    and scope.reads(node.args[0])
                    and not scope.reads(func_node.value)
                ):
                    flag(node, "looks a tool up")
            elif (
                isinstance(node, ast.Subscript)
                and isinstance(node.ctx, ast.Load)
                and scope.reads(node.slice)
                and not scope.reads(node.value)
            ):
                flag(node, "looks a tool up")
    return found


def _modules() -> list[Path]:
    return sorted(p for p in REPORTING.rglob("*.py") if p != EXEMPT)


@pytest.mark.parametrize("path", _modules(), ids=lambda p: str(p.relative_to(REPORTING)))
def test_no_reporting_module_reads_a_tool_by_its_name(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    assert violations(source, path.name, gateway=path == GATEWAY) == []


def test_the_exemption_is_the_one_module_by_its_path() -> None:
    assert EXEMPT.is_file()
    assert [p for p in REPORTING.rglob("*.py") if p.name == EXEMPT.name] == [EXEMPT]


def test_the_legacy_module_is_the_one_that_names_tools() -> None:
    source = EXEMPT.read_text(encoding="utf-8")
    assert violations(source, EXEMPT.name), "the guard must see the tables there"


@pytest.mark.parametrize(
    "snippet",
    [
        '_FUNCTION_TOOLS = frozenset({"pdf"})\nok = entry.tool in _FUNCTION_TOOLS\n',
        'skip = o.get("tool_name") != "decompile_function"\n',
        'sandbox = str(row.tool or "").startswith(("sandbox_", "pcap"))\n',
        '_BUILDERS = {"capa": 1}\nbuilder = _BUILDERS.get(entry.tool)\n',
        'def f(tool):\n    if tool == "floss":\n        pass\n',
        'found = tool_of(row) in ("strings", "iocs_from_file")\n',
        'name = entry.tool\nif name == "capa":\n    pass\n',
        "from maljan.analysis.sandbox_sections import ITEMS_TOOL\nok = row.tool == ITEMS_TOOL\n",
        "def f(entry):\n    names = {'capa'}\n    return entry.tool in names\n",
        'match entry.tool:\n    case "capa":\n        pass\n',
        'x = {"capa": 1}.get(entry.tool)\n',
        'ok = getattr(entry, "tool") == "capa"\n',
        'ok = entry.tool == f"ca{p}a"\n',
        'ok = entry.tool in CONSUMER_KINDS["x"]["legacy_names"]\n',
        'ok = entry.tool.lower().removeprefix("x") == "capa"\n',
        "value = getattr(module, entry.tool)\n",
        'ok = entry["tool"] in BUILDERS\n',
        "x = TABLE[str(entry.tool)]\n",
        "from maljan.reporting import legacy_tool_names as legacy\nok = legacy.X\n",
    ],
)
def test_the_guard_sees_each_way_a_name_is_read(snippet: str) -> None:
    assert violations(snippet)


def test_the_gateway_reads_legacy_only_on_its_no_source_branch() -> None:
    bad = (
        "from maljan.reporting import legacy_tool_names as legacy\n"
        "def is_of(entry, consumer):\n"
        "    return legacy.in_table(consumer, tool_of(entry))\n"
    )
    good = (
        "from maljan.reporting import legacy_tool_names as legacy\n"
        "def is_of(entry, consumer):\n"
        "    if source_of(entry) is None:\n"
        "        return legacy.in_table(consumer, tool_of(entry))\n"
        "    return False\n"
        "def facts(entry):\n"
        "    ref = source_of(entry)\n"
        "    if ref is None:\n"
        "        return legacy.BUILDERS.get(tool_of(entry))\n"
        "def stored_word(kind):\n"
        "    return legacy.WORDS.get(kind)\n"
    )
    assert violations(bad, gateway=True)
    assert violations(good, gateway=True) == []


def test_the_guard_lets_kinds_section_keys_and_tool_to_tool_be() -> None:
    clean = (
        '_KIND_SHAPE = {"strings": ("/strings/*", "/text")}\n'
        'ok = facts.kind in ("strings", "emulated_strings")\n'
        'section = acc.get("sandbox_processes", "Processes observed", "table")\n'
        'opened = acc.get(f"tool_{entry.tool}", entry.tool.capitalize(), "kv")\n'
        'same = row.source == "strings"\n'
        "def f(rows, section):\n"
        "    ranked = {}\n"
        "    for row in rows:\n"
        "        if str(row.tool) not in ranked:\n"
        "            ranked[str(row.tool)] = 1\n"
        "    return tool_of(rows[0]) == section_tool(section)\n"
    )
    assert violations(clean) == []
