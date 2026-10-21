"""Where a module reads an entry's tool by a tool's name: the detection both guards share.

The reading half (``pipeline/``, ``analysis/``, ``agents/``) and the report
(``reporting/``) read a tool by the kind it declares. Their guards
(``tests/unit/test_the_reading_half_names_no_tool.py``,
``tests/unit/reporting/test_no_reporting_module_reads_a_tool_by_its_name.py``)
call :func:`findings` on each module's source.

It follows each value read from an entry's tool (``.tool``, ``tool_name``, a
parameter named ``tool`` or ``*_tool``, ``tool_of(...)``, ``section_tool(...)``,
``declared_name(...)``, ``_tool(...)``, ``bare_name(...)``,
``getattr(x, "tool")``, ``x["tool"]``, ``x.get("tool")``, and any local
assigned from one, through ``str``, ``lower``, ``strip``, ``removeprefix``,
``split``, ``or``, ``+``, f-strings, tuple unpacking and comprehensions over
them) and reports:

* a comparison or membership test of such a value with anything that is not
  itself a tool read (a literal, a collection, a constant, an imported name);
* ``startswith``, ``endswith``, ``find``, ``index`` or ``count`` on it;
* a ``match`` on it;
* ``getattr`` or ``hasattr`` with it as the attribute;
* a lookup of it (``x[tool]``, ``x.get(tool)``, ``x.pop(tool)``) in a
  dictionary that is not a local one the code itself keys by tool reads;
* a tool read handed to a pattern matcher (``re.*``, a compiled pattern's
  ``match``/``search``/``sub``..., ``fnmatch.*``);
* a string literal handed to a parameter named ``tool`` or ``*_tool`` (by
  position or by keyword), or given as such a parameter's default;
* a ``.server`` read held against a literal, and a ``.source`` read held against
  an ``mcp:<server>`` literal (the registry key, spelled out);
* an import of a legacy table module (``legacy_modules``), except in a
  gateway module, whose reads of it must sit on a branch for an entry with no
  recorded source (``source_of(...) is None``) or in a ``stored_*`` function.

A word looked for inside a tool's name (``"decompil" in tool``) is a
membership test like any other and is reported.
"""

from __future__ import annotations

import ast
from typing import NamedTuple

LEGACY_MODULES = ("legacy_tool_names", "legacy_tool_tables", "legacy_reputation")

_TOOL_FIELDS = ("tool", "tool_name")
_TOOL_CALLS = ("tool_of", "section_tool", "declared_name", "_tool", "bare_name", "_base_tool_name")
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
_PATTERN_CALLS = (
    "match",
    "search",
    "fullmatch",
    "sub",
    "subn",
    "fnmatch",
    "fnmatchcase",
)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.GeneratorExp)
_SERVER_FIELDS = ("server", "server_name")
_KEYING = ("setdefault", "add", "append", "discard", "remove")


class Finding(NamedTuple):
    """One read of a tool by name: where, what kind of read, and the code as written."""

    label: str
    line: int
    what: str
    text: str

    def __str__(self) -> str:
        return f"{self.label}:{self.line}: {self.what}"


def _called(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    return func.id if isinstance(func, ast.Name) else ""


def _tool_param(name: str) -> bool:
    return name in _TOOL_FIELDS or name.endswith("_tool")


def _str_literal(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _literals_only(node: ast.AST) -> bool:
    """Whether ``node`` is a string, or a collection of strings, written out."""
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return bool(node.elts) and all(_str_literal(e) for e in node.elts)
    return _str_literal(node)


def _spells_a_registry_key(node: ast.AST) -> bool:
    elements = node.elts if isinstance(node, ast.Tuple | ast.List | ast.Set) else [node]
    return any(
        _str_literal(e) and isinstance(e, ast.Constant) and str(e.value).startswith("mcp:")
        for e in elements
    )


def _spells_a_server(node: ast.Compare) -> bool:
    """Whether a comparison holds ``.server`` and a literal, or ``.source`` and ``mcp:*``."""
    sides = [node.left, *node.comparators]
    for side, others in ((s, [o for o in sides if o is not s]) for s in sides):
        if not isinstance(side, ast.Attribute):
            continue
        if side.attr in _SERVER_FIELDS and any(_literals_only(o) for o in others):
            return True
        if side.attr == "source" and any(_spells_a_registry_key(o) for o in others):
            return True
    return False


def _literal_to_a_tool_parameter(
    node: ast.Call, tool_params: dict[str, tuple[list[int], set[str]]]
) -> bool:
    positions, keywords = tool_params.get(_called(node), ([], set()))
    if any(k.arg in keywords and _str_literal(k.value) for k in node.keywords):
        return True
    return any(i < len(node.args) and _str_literal(node.args[i]) for i in positions)


def _const_field(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value in _TOOL_FIELDS


class _Scope:
    """One function's (or the module's) values that hold an entry's tool."""

    def __init__(self, params: list[str], parent: _Scope | None = None) -> None:
        # A nested function or lambda sees the values its enclosing scope holds.
        self.tainted: set[str] = set(parent.tainted) if parent else set()
        self.keyed: set[str] = set(parent.keyed) if parent else set()
        self.tainted |= {p for p in params if _tool_param(p)}

    def reads(self, node: ast.AST | None, *, keyed: bool = True) -> bool:
        """Whether ``node`` holds a tool read; with ``keyed``, a container keyed by them too."""
        if node is None:
            return False
        if isinstance(node, ast.Attribute):
            return node.attr in _TOOL_FIELDS or (keyed and ast.unparse(node) in self.keyed)
        if isinstance(node, ast.Name):
            return node.id in self.tainted or (keyed and node.id in self.keyed)
        if isinstance(node, ast.Call):
            name = _called(node)
            if name in _TOOL_CALLS:
                return True
            if name == "getattr" and len(node.args) > 1 and _const_field(node.args[1]):
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
        if isinstance(node, _COMPREHENSIONS):
            return self.reads(node.elt, keyed=False)
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

    def _taint(self, target: ast.AST) -> None:
        for name in ast.walk(target):
            if isinstance(name, ast.Name):
                self.tainted.add(name.id)

    def _bind(self, target: ast.AST, value: ast.AST | None) -> None:
        """Taint what ``target`` binds from a tool read, a tuple's names one by one."""
        if isinstance(target, ast.Name):
            if self.reads(value):
                self.tainted.add(target.id)
        elif isinstance(target, ast.Tuple | ast.List):
            if isinstance(value, ast.Tuple | ast.List) and len(value.elts) == len(target.elts):
                for sub, part in zip(target.elts, value.elts, strict=True):
                    self._bind(sub, part)
            elif self.reads(value):
                self._taint(target)
        elif isinstance(target, ast.Starred):
            self._bind(target.value, value)

    def learn(self, nodes: list[ast.AST]) -> None:
        """Mark the locals assigned from tool reads, and the dicts keyed by them."""
        for _ in range(3):
            for node in nodes:
                if isinstance(node, ast.Assign | ast.AnnAssign | ast.NamedExpr):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    value = node.value
                    for target in targets:
                        self._bind(target, value)
                        if (
                            isinstance(target, ast.Name)
                            and isinstance(value, ast.DictComp)
                            and self.reads(value.key, keyed=False)
                        ):
                            self.keyed.add(target.id)
                        if (
                            isinstance(target, ast.Subscript)
                            and isinstance(target.value, ast.Name)
                            and self.reads(target.slice)
                        ):
                            self.keyed.add(target.value.id)
                if isinstance(node, ast.For | ast.comprehension) and self.reads(node.iter):
                    self._taint(node.target)
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in _KEYING
                    and isinstance(node.func.value, ast.Name | ast.Attribute)
                    and node.args
                    and self.reads(node.args[0])
                ):
                    self.keyed.add(ast.unparse(node.func.value))


def _legacy_aliases(
    tree: ast.Module, legacy_modules: tuple[str, ...]
) -> tuple[set[str], list[int]]:
    """The names a legacy module is bound to, and the lines that import it."""
    aliases: set[str] = set()
    lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.rsplit(".", 1)[-1] in legacy_modules:
                lines.append(node.lineno)
                aliases |= {a.asname or a.name for a in node.names}
            for alias in node.names:
                if alias.name in legacy_modules:
                    lines.append(node.lineno)
                    aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.rsplit(".", 1)[-1] in legacy_modules:
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


def findings(
    source: str,
    label: str = "<module>",
    *,
    gateway: bool = False,
    legacy_modules: tuple[str, ...] = LEGACY_MODULES,
) -> list[Finding]:
    """Every place ``source`` reads an entry's tool by a tool's name."""
    tree = ast.parse(source)
    found: list[Finding] = []
    lines = source.splitlines()

    def text_at(line: int) -> str:
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""

    aliases, import_lines = _legacy_aliases(tree, legacy_modules)
    if import_lines and not gateway:
        found += [Finding(label, n, "imports a legacy table", text_at(n)) for n in import_lines]

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
                    Finding(
                        label,
                        node.lineno,
                        "reads a legacy table outside a no-source branch",
                        text_at(node.lineno),
                    )
                )

    # Each function this source defines that takes a tool, by name: the
    # positions (self and cls dropped) of its parameters named for one.
    tool_params: dict[str, tuple[list[int], set[str]]] = {}
    for func in _functions(tree):
        assert isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef)
        args = func.args
        names = [a.arg for a in (*args.posonlyargs, *args.args)]
        if names[:1] in (["self"], ["cls"]):
            names = names[1:]
        # Only a parameter the function holds against something (a writer
        # that just stores the name it is given reads nothing).
        held = {
            n.id
            for c in ast.walk(func)
            if isinstance(c, ast.Compare)
            for n in ast.walk(c)
            if isinstance(n, ast.Name)
        }
        positions = [i for i, n in enumerate(names) if _tool_param(n) and n in held]
        keywords = {
            a.arg for a in (*args.args, *args.kwonlyargs) if _tool_param(a.arg) and a.arg in held
        }
        if positions or keywords:
            at, by = tool_params.setdefault(func.name, ([], set()))
            at.extend(positions)
            by |= keywords
        defaults = list(zip(reversed(args.args), reversed(args.defaults), strict=False))
        defaults += [
            (a, d) for a, d in zip(args.kwonlyargs, args.kw_defaults, strict=True) if d is not None
        ]
        for arg, default in defaults:
            if (
                _tool_param(arg.arg)
                and arg.arg in held
                and isinstance(default, ast.Constant)
                and default.value
                and _str_literal(default)
            ):
                found.append(
                    Finding(
                        label,
                        default.lineno,
                        "defaults a tool parameter to a name",
                        text_at(default.lineno),
                    )
                )

    seen: set[tuple[int, int, str]] = set()

    def flag(node: ast.AST, what: str) -> None:
        key = (getattr(node, "lineno", 0), getattr(node, "col_offset", 0), what)
        if key not in seen and id(node) not in exempt:
            seen.add(key)
            found.append(Finding(label, key[0], what, ast.unparse(node)))

    for scope, nodes in _scopes(tree):
        for node in nodes:
            if isinstance(node, ast.Compare):
                sides = [node.left, *node.comparators]
                # A tool read (a container the code keys by tool reads is not
                # one: a sentence looked for in a list of lines is no tool)
                # held against anything that is not itself a tool read.
                if any(scope.reads(s, keyed=False) for s in sides) and any(
                    not scope.reads(s) and not (isinstance(s, ast.Constant) and s.value is None)
                    for s in sides
                ):
                    flag(node, "compares a tool with something that is not a tool")
                elif _spells_a_server(node):
                    flag(node, "compares a server with a literal")
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
                elif name in _PATTERN_CALLS and any(
                    scope.reads(a, keyed=False)
                    for a in (*node.args, *(k.value for k in node.keywords))
                ):
                    flag(node, f"{name} matches a pattern against a tool")
                elif _literal_to_a_tool_parameter(node, tool_params):
                    flag(node, "hands a tool's name to a parameter that takes a tool")
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


def violations(
    source: str,
    label: str = "<module>",
    *,
    gateway: bool = False,
    legacy_modules: tuple[str, ...] = LEGACY_MODULES,
) -> list[str]:
    """:func:`findings` as ``label:line: what`` lines."""
    return [str(f) for f in findings(source, label, gateway=gateway, legacy_modules=legacy_modules)]


# The ways a name is read that each guard holds the detection to.
NAME_READ_SNIPPETS: tuple[str, ...] = (
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
    'ok = str(getattr(entry, "tool", "") or "") != "function_index"\n',
    'ok = getattr(entry, "tool", None) == "capa"\n',
    "ok = bare_name(entry.tool) in ASSERTING_SOURCES\n",
    'ok = entry.tool in {"capa": 1}\n',
    'ok = entry.tool.lower() == "capa"\n',
    'ok = entry["tool"] == "capa"\n',
    'ok = _tool(entry) == "pe_info"\n',
    "from maljan.core.legacy_tool_tables import RULE_TOOLS\n",
    'ok = "decompil" in entry.tool\n',
    "from maljan.core.legacy_reputation import stored_report_counts\n",
    'tool, ok = entry.tool, entry.ok\nfound = tool == "capa"\n',
    'tool, ok = entry.tool, entry.ok\nfound = ok == tool\nbad = tool.startswith("x")\n',
    'tools = [e.tool for e in entries]\nfound = "capa" in tools\n',
    'names = {e.tool for e in entries}\nfound = "capa" in names\n',
    'for t in [e.tool for e in entries]:\n    ok = t == "capa"\n',
    'import re\nok = re.match(r"^capa", entry.tool)\n',
    'import fnmatch\nok = fnmatch.fnmatch(entry.tool, "sandbox_*")\n',
    'import re\n_PATTERN = re.compile("capa")\nok = _PATTERN.search(entry.tool)\n',
    'def find(es, tool="capa"):\n    return [e for e in es if e.tool == tool]\n',
    'def find(es, tool):\n    return [e for e in es if e.tool == tool]\nfind(es, "capa")\n',
    (
        "def find(es, *, wanted_tool):\n"
        "    return [e for e in es if e.tool == wanted_tool]\n"
        'find(es, wanted_tool="capa")\n'
    ),
    'ok = entry.server == "radare2"\n',
    'ok = entry.source == "mcp:radare2"\n',
    'ok = entry.source in ("mcp:radare2", "mcp:ghidra")\n',
)
