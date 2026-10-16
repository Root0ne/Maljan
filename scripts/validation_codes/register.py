"""Read the platform's validation codes out of its source, with ``ast`` and no import.

A validation code is the ``family.name`` string a validator files a finding
under (``isr.empty_evidence``, ``verdict.fallback``). A string is one only in a
code position — the value of a ``code=`` keyword, the value assigned to a name
ending in ``_CODE``, a member of a set or tuple bound to a name ending in
``_CODES`` — and only in that shape. The family is the part before the dot, so
the families are whatever the source uses: ``os.path`` in an import, a host
name in a list or ``"report.json"`` in a call is never a code.

A code is raised where its value is used: given as a ``code=`` keyword, passed,
returned, stored, or assigned to anything but a plain name. A plain name it is
assigned to is followed, and so are a loop over a constant collection, a
conditional or ``or`` between constants, ``str()`` of one, a lookup in a
constant mapping, an import, and a parameter fed by constants at every call
site (or by its default where a call leaves it out). A comparison, a set or
tuple of codes (something codes are looked up in) and formatted text read a
code and are not raise sites. A ``code=`` value that cannot be followed is kept
as an unresolved site with the expression seen; it is never dropped.

Nothing is imported: the source is parsed with ``ast`` and its comments read
with ``tokenize``, so the register is the same on a machine where half the
platform's dependencies are missing. One parse per file and memoised
resolution keep the work linear in the size of the tree.
"""

from __future__ import annotations

import ast
import inspect
import io
import os
import string
import tokenize
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, NamedTuple

# Where each kind of file is read, relative to the tree's root. The platform is
# what raises codes; tests and pages are read only for the codes they name.
PLATFORM_DIRS = ("src", "apps/api", "services")
TEST_DIR = "tests"
CONSOLE_DIR = "apps/web/src"
DOCS_DIR = "apps/docs/content/docs"
PAGE = f"{DOCS_DIR}/validation-codes.mdx"

# A code bound under a name with this prefix is one nothing raises any more and
# a stored run still carries; the comment on that binding says what reads it.
KEPT_PREFIX = "LEGACY_"

# The keywords a raise site's text is read from when a code's constant carries
# no comment.
TEXT_KEYWORDS = ("message", "feedback")

_PRAGMAS = ("noqa", "type:", "pragma", "pylint:", "fmt:", "mypy:", "pyright:", "ruff:", "isort:")
_COLLECTION_CALLS = ("frozenset", "set", "tuple", "list", "sorted")
_NON_STRING_TYPES = frozenset({"int", "bool", "float", "complex", "bytes", "bytearray"})


def is_code(value: object) -> bool:
    """``family.name``: two lower-case identifiers joined by one dot."""
    if not isinstance(value, str):
        return False
    family, dot, name = value.partition(".")
    return bool(dot) and _part(family) and _part(name)


def _part(text: str) -> bool:
    return text.isascii() and text.isidentifier() and text[0].isalpha() and text == text.lower()


# ---------------------------------------------------------------------------
# What the register says


@dataclass(frozen=True)
class Code:
    """One code, as the source and the tests and pages around it say."""

    code: str
    raised_at: tuple[str, ...]
    constants: tuple[str, ...]
    collections: tuple[str, ...]
    meaning: str
    # The raise site whose message the meaning is, or "" for a constant's comment.
    meaning_from: str
    # The Python tests naming the code or its constant, and the console's unit
    # tests naming it as a string.
    tests: tuple[str, ...]
    console_tests: tuple[str, ...]
    # ``(route, title)`` of every docs page naming the code.
    docs: tuple[tuple[str, str], ...]
    kept_by: tuple[str, ...]
    kept_reason: str

    @property
    def family(self) -> str:
        return self.code.partition(".")[0]


@dataclass(frozen=True)
class Unresolved:
    """A code position whose value the register could not follow."""

    site: str
    expression: str
    why: str


@dataclass(frozen=True)
class Register:
    codes: tuple[Code, ...]
    unresolved: tuple[Unresolved, ...]

    def families(self) -> list[str]:
        return sorted({code.family for code in self.codes})


# ---------------------------------------------------------------------------
# Values


@dataclass(frozen=True)
class Value:
    """What an expression can evaluate to, as far as the source says."""

    strings: frozenset[str] = frozenset()
    # Something that is not a string is possible: a number, a flag, an object.
    other: bool = False
    # Why some value could not be followed; empty when every one was.
    why: str = ""

    def __or__(self, other: Value) -> Value:
        return Value(self.strings | other.strings, self.other or other.other, self.why or other.why)


NOTHING = Value()
NOT_A_STRING = Value(other=True)
_BUSY = Value(why="a name defined through itself")
_TOO_DEEP = Value(why="a chain of names too long to follow")


# ---------------------------------------------------------------------------
# Modules and scopes


class Binding(NamedTuple):
    """One way a name gets its value: ``kind`` is value, iter, import, def or opaque."""

    kind: str
    node: Any
    scope: Scope
    statement: ast.stmt | None = None


@dataclass(frozen=True)
class Param:
    name: str
    # Its index among the positional parameters; None for a keyword-only one.
    position: int | None
    default: ast.expr | None
    annotation: ast.expr | None
    star: bool = False


@dataclass(eq=False)
class Module:
    name: str
    path: str
    package: bool
    tree: ast.Module
    # Comments by line: the ones that are a whole line, and the ones after code.
    comments: dict[int, str]
    trailing: dict[int, str]
    # The string statement right after an assignment, by the assignment's id.
    docstrings: dict[int, str]
    scope: Scope | None = None


@dataclass(eq=False)
class Scope:
    module: Module
    kind: str  # module, class, function or lambda
    qualname: str
    parent: Scope | None
    node: ast.AST | None = None
    bindings: dict[str, list[Binding]] = field(default_factory=dict)
    declared: dict[str, str] = field(default_factory=dict)
    params: dict[str, Param] = field(default_factory=dict)
    star_imports: list[str] = field(default_factory=list)
    # The calls that name this function directly, with the scope each is in.
    calls: list[tuple[ast.Call, Scope]] = field(default_factory=list)
    # Named other than as a callee: passed, stored or returned, so its callers
    # are not all known.
    escaped: bool = False

    @property
    def site(self) -> str:
        return f"{self.module.name}:{self.qualname}"


@dataclass(frozen=True, eq=False)
class Ref:
    """What a name refers to: kind is binding, param, module or unknown."""

    kind: str
    scope: Scope | None = None
    name: str = ""


def module_name(path: str) -> tuple[str, bool]:
    """The dotted name a platform file is imported under, and whether it is a package."""
    inner = path
    for base in PLATFORM_DIRS:
        if path.startswith(base + "/"):
            inner = path[len(base) + 1 :]
            break
    parts = inner[: -len(".py")].split("/")
    package = parts[-1] == "__init__"
    if package:
        parts = parts[:-1]
    return ".".join(parts), package


def _files(root: Path, base: str, suffixes: tuple[str, ...]) -> Iterator[Path]:
    """The files under ``base`` with one of ``suffixes``, in a fixed order."""
    folder = root / base
    if not folder.is_dir():
        return
    for directory, subdirectories, names in os.walk(folder):
        subdirectories[:] = sorted(
            name
            for name in subdirectories
            if not name.startswith(".") and name not in ("node_modules", "__pycache__")
        )
        for name in sorted(names):
            if name.endswith(suffixes):
                yield Path(directory) / name


def _comments(source: str) -> tuple[dict[int, str], dict[int, str]]:
    whole: dict[int, str] = {}
    trailing: dict[int, str] = {}
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type != tokenize.COMMENT:
            continue
        row, column = token.start
        text = token.string[1:]
        if text.startswith(" "):
            text = text[1:]
        (trailing if token.line[:column].strip() else whole)[row] = text.rstrip()
    return whole, trailing


def _docstrings(tree: ast.Module) -> dict[int, str]:
    found: dict[int, str] = {}
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list):
            continue
        for statement, following in zip(body, body[1:], strict=False):
            if (
                isinstance(statement, (ast.Assign, ast.AnnAssign))
                and isinstance(following, ast.Expr)
                and isinstance(following.value, ast.Constant)
                and isinstance(following.value.value, str)
            ):
                found[id(statement)] = inspect.cleandoc(following.value.value)
    return found


def _prose(lines: Iterable[str]) -> str:
    """A comment block as text: paragraphs at its empty lines, pragmas and rules left out."""
    paragraphs: list[str] = []
    current: list[str] = []
    for line in lines:
        text = line.strip()
        if not text:
            if current:
                paragraphs.append(" ".join(current))
                current = []
            continue
        if text.lower().startswith(_PRAGMAS) or not any(ch.isalnum() for ch in text):
            continue
        current.append(text)
    if current:
        paragraphs.append(" ".join(current))
    return "\n\n".join(paragraphs)


def _never_a_string(annotation: ast.expr | None) -> bool:
    """An annotation built only of number, flag and byte types (``bool | None``)."""
    if annotation is None:
        return False
    names: set[str] = set()
    for node in ast.walk(annotation):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add("")
        elif isinstance(node, ast.Constant):
            names.add("None" if node.value is None else "")
    allowed = _NON_STRING_TYPES | {"None", "Optional", "Union"}
    return bool(names & _NON_STRING_TYPES) and names <= allowed


_SPLAT = object()
_DEFAULT = object()


def _argument(call: ast.Call, param: Param) -> object:
    """The expression a call gives ``param``, ``_DEFAULT`` when it gives none."""
    for keyword in call.keywords:
        if keyword.arg == param.name:
            return keyword.value
    if param.position is not None:
        for index, argument in enumerate(call.args):
            if isinstance(argument, ast.Starred):
                return _SPLAT
            if index == param.position:
                return argument
    if any(keyword.arg is None for keyword in call.keywords):
        return _SPLAT
    return _DEFAULT


class _ScopeBuilder(ast.NodeVisitor):
    """One walk of a module: its scopes, what binds each name, and its code positions."""

    def __init__(self, reader: Reader, module: Module) -> None:
        self.reader = reader
        self.module = module
        self.scope = Scope(module, "module", "<module>", None, module.tree)
        module.scope = self.scope
        reader.scopes[id(module.tree)] = self.scope

    def _bind(self, name: str, kind: str, node: Any, statement: ast.stmt | None = None) -> None:
        scope = self.scope
        declared = scope.declared.get(name)
        if declared == "global" and self.module.scope is not None:
            scope = self.module.scope
        elif declared == "nonlocal":
            outer = scope.parent
            while outer is not None and outer.kind not in ("function", "lambda"):
                outer = outer.parent
            scope = outer or scope
        scope.bindings.setdefault(name, []).append(Binding(kind, node, self.scope, statement))

    def _bind_target(self, target: ast.expr, kind: str, node: Any, statement: ast.stmt) -> None:
        if isinstance(target, ast.Name):
            self._bind(target.id, kind, node, statement)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind_target(element, "opaque", None, statement)
        elif isinstance(target, ast.Starred):
            self._bind_target(target.value, "opaque", None, statement)

    def _position(self, target: ast.expr, value: ast.expr, statement: ast.stmt) -> None:
        if isinstance(target, ast.Name) and target.id.endswith(("_CODE", "_CODES")):
            self.reader.positions.append((statement, target.id, value, self.scope))

    def _enter(self, node: ast.AST, kind: str, name: str) -> Scope:
        parent = self.scope
        if kind == "lambda":
            qualname = parent.qualname
        elif parent.kind == "module":
            qualname = name
        else:
            qualname = f"{parent.qualname}.{name}"
        child = Scope(self.module, kind, qualname, parent, node)
        self.reader.scopes[id(node)] = child
        return child

    def _params(self, args: ast.arguments, scope: Scope) -> None:
        positional = [*args.posonlyargs, *args.args]
        first_default = len(positional) - len(args.defaults)
        for index, arg in enumerate(positional):
            default = args.defaults[index - first_default] if index >= first_default else None
            scope.params[arg.arg] = Param(arg.arg, index, default, arg.annotation)
        for arg, keyword_default in zip(args.kwonlyargs, args.kw_defaults, strict=True):
            scope.params[arg.arg] = Param(arg.arg, None, keyword_default, arg.annotation)
        for star in (args.vararg, args.kwarg):
            if star is not None:
                scope.params[star.arg] = Param(star.arg, None, None, star.annotation, star=True)

    def _outer_parts(self, args: ast.arguments) -> None:
        """Defaults and annotations: they run in the scope the definition is in."""
        for default in [*args.defaults, *args.kw_defaults]:
            if default is not None:
                self.visit(default)
        for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
            if arg is not None and arg.annotation is not None:
                self.visit(arg.annotation)

    def _body(self, child: Scope, statements: Iterable[ast.AST]) -> None:
        outer, self.scope = self.scope, child
        for statement in statements:
            self.visit(statement)
        self.scope = outer

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        self._outer_parts(node.args)
        if node.returns is not None:
            self.visit(node.returns)
        child = self._enter(node, "function", node.name)
        self._bind(node.name, "def", child, node)
        self._params(node.args, child)
        self._body(child, node.body)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._outer_parts(node.args)
        child = self._enter(node, "lambda", "<lambda>")
        self._params(node.args, child)
        self._body(child, [node.body])

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for part in [*node.decorator_list, *node.bases, *node.keywords]:
            self.visit(part)
        child = self._enter(node, "class", node.name)
        self._bind(node.name, "def", child, node)
        self._body(child, node.body)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            self._bind_target(target, "value", node.value, node)
            self._position(target, node.value, node)
            self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
            self._bind_target(node.target, "value", node.value, node)
            self._position(node.target, node.value, node)
        self.visit(node.target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        self._bind_target(node.target, "opaque", None, node)
        self.visit(node.target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._bind(node.target.id, "value", node.value)

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        self._loop_target(node.target, node.iter, node)
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)

    visit_AsyncFor = visit_For

    def visit_comprehension(self, node: ast.comprehension) -> None:
        # Folded into the enclosing scope, which Python does not do: a
        # comprehension's variable rarely shares its name with one the
        # register reads.
        self.visit(node.iter)
        self._loop_target(node.target, node.iter, None)
        for condition in node.ifs:
            self.visit(condition)

    def _loop_target(
        self, target: ast.expr, iterable: ast.expr, statement: ast.stmt | None
    ) -> None:
        if isinstance(target, ast.Name):
            self._bind(target.id, "iter", iterable, statement)
        else:
            for name in ast.walk(target):
                if isinstance(name, ast.Name):
                    self._bind(name.id, "opaque", None, statement)
        self.visit(target)

    def visit_withitem(self, node: ast.withitem) -> None:
        self.visit(node.context_expr)
        if node.optional_vars is not None:
            for name in ast.walk(node.optional_vars):
                if isinstance(name, ast.Name):
                    self._bind(name.id, "opaque", None)
            self.visit(node.optional_vars)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name:
            self._bind(node.name, "opaque", None)
        for statement in node.body:
            self.visit(statement)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                self._bind(alias.asname, "import", (alias.name, None), node)
            else:
                top = alias.name.partition(".")[0]
                self._bind(top, "import", (top, None), node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        base = self.reader.absolute(self.module, node.level, node.module)
        for alias in node.names:
            if alias.name == "*":
                self.scope.star_imports.append(base)
            else:
                self._bind(alias.asname or alias.name, "import", (base, alias.name), node)

    def visit_Global(self, node: ast.Global) -> None:
        for name in node.names:
            self.scope.declared[name] = "global"

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        for name in node.names:
            self.scope.declared[name] = "nonlocal"

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.pattern is not None:
            self.visit(node.pattern)
        if node.name:
            self._bind(node.name, "opaque", None)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self._bind(node.name, "opaque", None)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        self.generic_visit(node)
        if node.rest:
            self._bind(node.rest, "opaque", None)

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        for keyword in node.keywords:
            if keyword.arg == "code":
                self.reader.keywords.append((node, keyword, self.scope))


# ---------------------------------------------------------------------------
# The reader


@dataclass
class _Record:
    raised: set[str] = field(default_factory=set)
    constants: set[str] = field(default_factory=set)
    collections: set[str] = field(default_factory=set)
    # ``(sort key, text, the site a message came from)``; the lowest key wins.
    meanings: list[tuple[tuple[Any, ...], str, str]] = field(default_factory=list)
    kept_by: dict[str, str] = field(default_factory=dict)
    tests: set[str] = field(default_factory=set)
    console_tests: set[str] = field(default_factory=set)
    docs: set[tuple[str, str]] = field(default_factory=set)


class Reader:
    """The platform's source as scopes and bindings, and the codes read out of it."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.modules: dict[str, Module] = {}
        self.scopes: dict[int, Scope] = {}
        self.positions: list[tuple[ast.stmt, str, ast.expr, Scope]] = []
        self.keywords: list[tuple[ast.Call, ast.keyword, Scope]] = []
        self.codes: dict[str, _Record] = {}
        self.unresolved: set[Unresolved] = set()
        self._memo: dict[tuple[str, int, str], Value] = {}
        self._carried: dict[tuple[int, str], tuple[str, frozenset[str]]] = {}
        self._returned: dict[int, str] = {}
        self._code_set: frozenset[str] | None = None

    # -- reading -------------------------------------------------------------

    def read_platform(self) -> None:
        for base in PLATFORM_DIRS:
            for path in _files(self.root, base, (".py",)):
                rel = path.relative_to(self.root).as_posix()
                name, package = module_name(rel)
                if name in self.modules:
                    raise ValueError(f"{rel} and {self.modules[name].path} both read as {name}")
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=rel)
                whole, trailing = _comments(source)
                self.modules[name] = Module(
                    name, rel, package, tree, whole, trailing, _docstrings(tree)
                )
        for module in self.modules.values():
            builder = _ScopeBuilder(self, module)
            for statement in module.tree.body:
                builder.visit(statement)

    def absolute(self, module: Module, level: int, name: str | None) -> str:
        """The module a ``from … import`` names, relative levels resolved."""
        if level == 0:
            return name or ""
        parts = module.name.split(".")
        if not module.package:
            parts = parts[:-1]
        if level > 1:
            parts = parts[: max(len(parts) - (level - 1), 0)]
        base = ".".join(parts)
        return f"{base}.{name}" if name and base else (name or base)

    # -- names ---------------------------------------------------------------

    def lookup(self, scope: Scope, name: str) -> Ref:
        current: Scope | None = scope
        while current is not None:
            if current is not scope and current.kind == "class":
                current = current.parent
                continue
            declared = current.declared.get(name)
            if declared == "nonlocal":
                current = current.parent
                continue
            if declared == "global" and current.module.scope is not None:
                current = current.module.scope
            if name in current.params:
                return Ref("param", current, name)
            if name in current.bindings:
                return Ref("binding", current, name)
            if current.kind == "module":
                for base in current.star_imports:
                    target = self.import_target(base, name)
                    if target.kind != "unknown":
                        return target
            current = current.parent
        return Ref("unknown", None, name)

    def import_target(self, module: str, name: str | None) -> Ref:
        if name is None:
            return Ref("module", None, module)
        found = self.modules.get(module)
        if found is not None and found.scope is not None and name in found.scope.bindings:
            return Ref("binding", found.scope, name)
        if f"{module}.{name}" in self.modules:
            return Ref("module", None, f"{module}.{name}")
        return Ref("unknown", None, f"{module}.{name}")

    def follow(self, ref: Ref) -> Ref:
        """Through names that are only an import of another name."""
        seen: set[tuple[int, str]] = set()
        while ref.kind == "binding" and ref.scope is not None:
            bindings = ref.scope.bindings.get(ref.name, [])
            if len(bindings) != 1 or bindings[0].kind != "import":
                return ref
            key = (id(ref.scope), ref.name)
            if key in seen:
                return Ref("unknown", None, ref.name)
            seen.add(key)
            ref = self.import_target(*bindings[0].node)
        return ref

    def module_of(self, node: ast.expr, scope: Scope) -> str | None:
        """The platform or library module an expression names, if it names one."""
        if isinstance(node, ast.Name):
            ref = self.follow(self.lookup(scope, node.id))
        elif isinstance(node, ast.Attribute):
            base = self.module_of(node.value, scope)
            if base is None:
                return None
            ref = self.follow(self.import_target(base, node.attr))
        else:
            return None
        return ref.name if ref.kind == "module" else None

    def attribute_ref(self, node: ast.Attribute, scope: Scope) -> Ref | None:
        base = self.module_of(node.value, scope)
        return None if base is None else self.import_target(base, node.attr)

    def ref_of(self, node: ast.expr, scope: Scope) -> Ref | None:
        if isinstance(node, ast.Name):
            return self.lookup(scope, node.id)
        if isinstance(node, ast.Attribute):
            return self.attribute_ref(node, scope)
        return None

    def def_of(self, ref: Ref | None) -> Scope | None:
        """The function or class a name is bound to, when that is all it is bound to."""
        if ref is None:
            return None
        ref = self.follow(ref)
        if ref.kind != "binding" or ref.scope is None:
            return None
        bindings = ref.scope.bindings[ref.name]
        if len(bindings) == 1 and bindings[0].kind == "def":
            found: Scope = bindings[0].node
            return found
        return None

    def builtin(self, func: ast.expr, scope: Scope, *names: str) -> bool:
        return (
            isinstance(func, ast.Name)
            and func.id in names
            and self.lookup(scope, func.id).kind == "unknown"
        )

    # -- values --------------------------------------------------------------

    def entry(self, compute: Callable[[], Value]) -> Value:
        """A resolution from the outside: a chain too deep to follow is a reason, not a crash."""
        try:
            return compute()
        except RecursionError:
            return _TOO_DEEP

    def _memoised(self, key: tuple[str, int, str], compute: Callable[[], Value]) -> Value:
        found = self._memo.get(key)
        if found is not None:
            return found
        self._memo[key] = _BUSY
        try:
            value = compute()
        except RecursionError:
            self._memo[key] = _TOO_DEEP
            raise
        self._memo[key] = value
        return value

    def value_of(self, node: ast.expr, scope: Scope) -> Value:
        if isinstance(node, ast.Constant):
            return Value(frozenset({node.value})) if isinstance(node.value, str) else NOT_A_STRING
        if isinstance(node, ast.Name):
            return self.value_of_ref(self.lookup(scope, node.id))
        if isinstance(node, ast.Attribute):
            ref = self.attribute_ref(node, scope)
            if ref is None:
                return Value(why="an attribute of a value")
            return self.value_of_ref(ref)
        if isinstance(node, ast.IfExp):
            return self.value_of(node.body, scope) | self.value_of(node.orelse, scope)
        if isinstance(node, ast.BoolOp):
            result = NOTHING
            for value in node.values:
                result = result | self.value_of(value, scope)
            return result
        if isinstance(node, ast.NamedExpr):
            return self.value_of(node.value, scope)
        if isinstance(node, (ast.Compare, ast.UnaryOp)):
            return NOT_A_STRING
        if isinstance(
            node,
            (
                ast.Tuple,
                ast.List,
                ast.Set,
                ast.Dict,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
                ast.Lambda,
            ),
        ):
            return NOT_A_STRING
        if isinstance(node, ast.Call):
            if self.builtin(node.func, scope, "str") and len(node.args) == 1 and not node.keywords:
                return self.value_of(node.args[0], scope)
            looked_up = self._mapping_lookup(node, scope)
            return looked_up if looked_up is not None else Value(why="the result of a call")
        if isinstance(node, ast.Subscript):
            looked_up = self._mapping_lookup(node, scope)
            return looked_up if looked_up is not None else Value(why="an item of a value")
        if isinstance(node, ast.JoinedStr):
            return Value(why="a formatted string")
        if isinstance(node, ast.BinOp):
            return Value(why="a computed value")
        return Value(why="an expression the register does not follow")

    def value_of_ref(self, ref: Ref) -> Value:
        ref = self.follow(ref)
        if ref.kind == "module":
            return NOT_A_STRING
        if ref.kind == "unknown" or ref.scope is None:
            return Value(why=f"`{ref.name}`, which the platform's source does not define")
        scope = ref.scope
        if ref.kind == "param":
            return self._memoised(
                ("param", id(scope), ref.name), lambda: self._param_value(scope, ref.name)
            )
        return self._memoised(
            ("value", id(scope), ref.name), lambda: self._bindings_value(scope, ref.name)
        )

    def _bindings_value(self, scope: Scope, name: str) -> Value:
        result = NOTHING
        for binding in scope.bindings[name]:
            if binding.kind == "value":
                result = result | self.value_of(binding.node, binding.scope)
            elif binding.kind == "iter":
                result = result | self.members_of(binding.node, binding.scope)
            elif binding.kind == "import":
                result = result | self.value_of_ref(self.import_target(*binding.node))
            elif binding.kind == "def":
                result = result | NOT_A_STRING
            else:
                result = result | Value(
                    why=f"`{name}`, bound by unpacking, `+=`, `with` or `except`"
                )
        return result

    def members_of(self, node: ast.expr, scope: Scope) -> Value:
        """What iterating ``node`` gives."""
        if isinstance(node, (ast.Set, ast.Tuple, ast.List)):
            result = NOTHING
            for element in node.elts:
                if isinstance(element, ast.Starred):
                    result = result | self.members_of(element.value, scope)
                else:
                    result = result | self.value_of(element, scope)
            return result
        if isinstance(node, ast.Dict):
            result = NOTHING
            for key in node.keys:
                result = result | (
                    self.value_of(key, scope)
                    if key is not None
                    else Value(why="a mapping unpacked into another")
                )
            return result
        if isinstance(node, ast.Call) and self.builtin(node.func, scope, *_COLLECTION_CALLS):
            if not node.args and not node.keywords:
                return NOTHING
            if len(node.args) == 1 and not node.keywords:
                return self.members_of(node.args[0], scope)
        if isinstance(node, ast.IfExp):
            return self.members_of(node.body, scope) | self.members_of(node.orelse, scope)
        if isinstance(node, (ast.Name, ast.Attribute)):
            ref = self.ref_of(node, scope)
            if ref is not None:
                return self._members_of_ref(ref)
        return Value(why="a collection the register does not follow")

    def _members_of_ref(self, ref: Ref) -> Value:
        ref = self.follow(ref)
        if ref.kind != "binding" or ref.scope is None:
            return Value(why=f"the members of `{ref.name}`")
        scope = ref.scope

        def compute() -> Value:
            result = NOTHING
            for binding in scope.bindings[ref.name]:
                if binding.kind == "value":
                    result = result | self.members_of(binding.node, binding.scope)
                elif binding.kind == "import":
                    result = result | self._members_of_ref(self.import_target(*binding.node))
                else:
                    result = result | Value(why=f"the members of `{ref.name}`")
            return result

        return self._memoised(("members", id(scope), ref.name), compute)

    def _dict_displays(self, node: ast.expr, scope: Scope) -> list[tuple[ast.Dict, Scope]] | None:
        """The dict displays a name is bound to, when every binding is one."""
        if isinstance(node, ast.Dict):
            return [(node, scope)]
        ref = self.ref_of(node, scope)
        if ref is None:
            return None
        ref = self.follow(ref)
        if ref.kind != "binding" or ref.scope is None:
            return None
        displays: list[tuple[ast.Dict, Scope]] = []
        for binding in ref.scope.bindings[ref.name]:
            if binding.kind != "value" or not isinstance(binding.node, ast.Dict):
                return None
            displays.append((binding.node, binding.scope))
        return displays

    def _mapping_lookup(self, node: ast.Call | ast.Subscript, scope: Scope) -> Value | None:
        """``MAPPING[key]`` or ``MAPPING.get(key, default)`` over a constant mapping."""
        default: ast.expr | None = None
        getter = False
        if isinstance(node, ast.Subscript):
            container = node.value
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and 1 <= len(node.args) <= 2
            and not node.keywords
        ):
            container = node.func.value
            default = node.args[1] if len(node.args) == 2 else None
            getter = True
        else:
            return None
        displays = self._dict_displays(container, scope)
        if displays is None:
            return None
        result = NOTHING
        for display, display_scope in displays:
            result = result | self._mapping_values(display, display_scope)
        if getter:
            result = result | (
                self.value_of(default, scope) if default is not None else NOT_A_STRING
            )
        return result

    def _mapping_values(self, display: ast.Dict, scope: Scope) -> Value:
        result = NOTHING
        for key, value in zip(display.keys, display.values, strict=True):
            result = result | (
                self.value_of(value, scope)
                if key is not None
                else Value(why="a mapping unpacked into another")
            )
        return result

    def _param_value(self, function: Scope, name: str) -> Value:
        param = function.params[name]
        if _never_a_string(param.annotation):
            return NOT_A_STRING
        if param.star:
            return Value(why=f"`{name}`, which collects a call's extra arguments")
        if function.kind == "lambda":
            return Value(why=f"`{name}`, a parameter of a lambda")
        if function.parent is not None and function.parent.kind == "class":
            return Value(why=f"`{name}`, a parameter of a method, whose callers are not all known")
        if function.escaped:
            return Value(
                why=f"`{name}`, a parameter of a function passed as a value, whose callers "
                "are not all known"
            )
        if not function.calls:
            return Value(why=f"`{name}`, a parameter of a function nothing in the platform calls")
        result = NOTHING
        for call, caller in function.calls:
            argument = _argument(call, param)
            if argument is _SPLAT:
                result = result | Value(
                    why=f"`{name}`, which a call fills from `*args` or `**kwargs`"
                )
            elif argument is _DEFAULT:
                if param.default is not None and function.parent is not None:
                    result = result | self.value_of(param.default, function.parent)
            elif isinstance(argument, ast.expr):
                result = result | self.value_of(argument, caller)
        return result

    # -- what a name carries, for its uses -----------------------------------

    def kind_of(self, node: ast.expr, name: str, scope: Scope) -> str:
        """scalar, collection (looked up in) or mapping (its values are read out)."""
        if isinstance(node, ast.Dict):
            return "mapping"
        if isinstance(node, (ast.Set, ast.SetComp)) or name.endswith("_CODES"):
            return "collection"
        if isinstance(node, ast.Call) and self.builtin(node.func, scope, "frozenset", "set"):
            return "collection"
        if isinstance(node, (ast.Tuple, ast.List)) and self.all_codes(node.elts, scope):
            return "collection"
        return "scalar"

    def carried(self, ref: Ref) -> tuple[str, frozenset[str]]:
        """The codes a name's value can hold, and how the name holds them."""
        ref = self.follow(ref)
        if ref.kind != "binding" or ref.scope is None:
            return ("scalar", frozenset())
        key = (id(ref.scope), ref.name)
        found = self._carried.get(key)
        if found is not None:
            return found
        self._carried[key] = ("scalar", frozenset())
        kinds: set[str] = set()
        codes: set[str] = set()
        for binding in ref.scope.bindings[ref.name]:
            if binding.kind == "value":
                kind = self.kind_of(binding.node, ref.name, binding.scope)
                if kind == "collection":
                    value = self.entry(partial(self.members_of, binding.node, binding.scope))
                elif kind == "mapping":
                    value = self.entry(partial(self._mapping_values, binding.node, binding.scope))
                else:
                    value = self.entry(partial(self.value_of, binding.node, binding.scope))
            elif binding.kind == "iter":
                kind = "scalar"
                value = self.entry(partial(self.members_of, binding.node, binding.scope))
            elif binding.kind == "import":
                kind, held = self.carried(self.import_target(*binding.node))
                kinds.add(kind)
                codes |= held
                continue
            else:
                continue
            kinds.add(kind)
            codes |= value.strings
        result = (kinds.pop() if len(kinds) == 1 else "scalar", frozenset(codes) & self.code_set)
        self._carried[key] = result
        return result

    def all_codes(self, elements: list[ast.expr], scope: Scope) -> bool:
        """Every element is a code or a name holding one: a collection of codes, not a row."""
        if not elements:
            return False
        for element in elements:
            if isinstance(element, ast.Constant):
                if element.value not in self.code_set:
                    return False
                continue
            ref = self.ref_of(element, scope)
            if ref is None:
                return False
            kind, codes = self.carried(ref)
            if kind != "scalar" or not codes:
                return False
        return True

    @property
    def code_set(self) -> frozenset[str]:
        if self._code_set is None:
            self._code_set = frozenset(self.codes)
        return self._code_set

    # -- the codes -----------------------------------------------------------

    def record(self, code: str) -> _Record:
        if code not in self.codes:
            self.codes[code] = _Record()
            self._code_set = None
        return self.codes[code]

    def label(self, scope: Scope, name: str) -> str:
        if scope.kind == "module":
            return f"{scope.module.name}:{name}"
        return f"{scope.site}.{name}"

    def attached(self, module: Module, statement: ast.stmt | None) -> str:
        """The comment block right above a statement, or its trailing comment or docstring."""
        if statement is None:
            return ""
        lines: list[str] = []
        row = statement.lineno - 1
        while row in module.comments:
            lines.append(module.comments[row])
            row -= 1
        lines.reverse()
        if not lines and statement.lineno in module.trailing:
            lines = [module.trailing[statement.lineno]]
        return _prose(lines) or _prose(module.docstrings.get(id(statement), "").splitlines())

    def read_positions(self) -> None:
        """Codes assigned to ``_CODE`` names and listed in ``_CODES`` collections."""
        for statement, name, value, scope in self.positions:
            label = self.label(scope, name)
            comment = self.attached(scope.module, statement)
            if name.endswith("_CODE"):
                found = self.entry(partial(self.value_of, value, scope))
                chain = list(self._alias_chain(value, scope))
                for code in sorted(text for text in found.strings if is_code(text)):
                    record = self.record(code)
                    record.constants.add(label)
                    record.meanings.append(((0, label), comment, ""))
                    for alias, alias_comment in chain:
                        record.constants.add(alias)
                        record.meanings.append(((1, alias), alias_comment, ""))
                    if name.startswith(KEPT_PREFIX):
                        record.kept_by[label] = comment
            else:
                found = self.entry(partial(self.members_of, value, scope))
                for code in sorted(text for text in found.strings if is_code(text)):
                    record = self.record(code)
                    record.collections.add(label)
                    record.meanings.append(((2, label), comment, ""))
                    if name.startswith(KEPT_PREFIX):
                        record.kept_by[label] = comment
            if found.why:
                self.unresolved.add(Unresolved(label, f"{name} = {ast.unparse(value)}", found.why))

    def _alias_chain(self, value: ast.expr, scope: Scope) -> Iterator[tuple[str, str]]:
        """The constants a ``_CODE`` name is an alias of, nearest first, with their comments."""
        seen: set[tuple[int, str]] = set()
        while isinstance(value, (ast.Name, ast.Attribute)):
            ref = self.ref_of(value, scope)
            if ref is None:
                return
            ref = self.follow(ref)
            if ref.kind != "binding" or ref.scope is None:
                return
            bindings = ref.scope.bindings[ref.name]
            key = (id(ref.scope), ref.name)
            if len(bindings) != 1 or bindings[0].kind != "value" or key in seen:
                return
            seen.add(key)
            yield (
                self.label(ref.scope, ref.name),
                self.attached(ref.scope.module, bindings[0].statement),
            )
            value, scope = bindings[0].node, bindings[0].scope

    def read_keywords(self) -> None:
        """Every ``code=`` keyword: what it resolves to, or the expression it could not."""
        for call, keyword, scope in self.keywords:
            found = self.entry(partial(self.value_of, keyword.value, scope))
            codes = sorted(text for text in found.strings if is_code(text))
            text = self._text_of_call(call, scope) if codes else ""
            for code in codes:
                record = self.record(code)
                record.raised.add(scope.site)
                record.meanings.append(
                    ((3, scope.site, call.lineno, call.col_offset), text, scope.site)
                )
            if found.why:
                self.unresolved.add(
                    Unresolved(scope.site, f"code={ast.unparse(keyword.value)}", found.why)
                )

    def _text_of_call(self, call: ast.Call, scope: Scope) -> str:
        for keyword in call.keywords:
            if keyword.arg in TEXT_KEYWORDS:
                return self._text(keyword.value, scope)
        return ""

    def _text(self, node: ast.expr, scope: Scope, seen: frozenset[int] = frozenset()) -> str:
        """The words an expression spells, each interpolated value as ``<name>``.

        Followed through a name bound once, the first branch of a conditional,
        ``.format()`` of a constant, and the first ``return`` of the helper a
        message is built by; anything else spells nothing.
        """
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else ""
        if isinstance(node, ast.JoinedStr):
            return "".join(
                str(part.value) if isinstance(part, ast.Constant) else f"<{_placeholder(part)}>"
                for part in node.values
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self._text(node.left, scope, seen), self._text(node.right, scope, seen)
            return left + right if left and right else ""
        if isinstance(node, ast.IfExp):
            return self._text(node.body, scope, seen) or self._text(node.orelse, scope, seen)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return _fields_named(self._text(node.func.value, scope, seen))
            function = self.def_of(self.ref_of(node.func, scope))
            if function is not None and function.kind == "function" and id(function) not in seen:
                return self._returned_text(function, seen | {id(function)})
            return ""
        if isinstance(node, (ast.Name, ast.Attribute)):
            ref = self.ref_of(node, scope)
            ref = self.follow(ref) if ref is not None else None
            if ref is not None and ref.kind == "param":
                found = self.entry(partial(self.value_of_ref, ref))
                one = len(found.strings) == 1 and not found.why
                return next(iter(found.strings)) if one else ""
            if ref is None or ref.kind != "binding" or ref.scope is None:
                return ""
            bindings = ref.scope.bindings[ref.name]
            if len(bindings) == 1 and bindings[0].kind == "value":
                bound = bindings[0]
                if id(bound.node) not in seen:
                    return self._text(bound.node, bound.scope, seen | {id(bound.node)})
        return ""

    def _returned_text(self, function: Scope, seen: frozenset[int]) -> str:
        if id(function) in self._returned:
            return self._returned[id(function)]
        self._returned[id(function)] = ""
        text = ""
        body = getattr(function.node, "body", [])
        for statement in _own_statements(body if isinstance(body, list) else []):
            if isinstance(statement, ast.Return) and statement.value is not None:
                text = self._text(statement.value, function, seen)
                if text.strip():
                    break
        self._returned[id(function)] = text
        return text

    def read_uses(self) -> None:
        uses = _Uses(self)
        for module in self.modules.values():
            if module.scope is not None:
                for statement in module.tree.body:
                    uses.statement(statement, module.scope)

    def index_calls(self) -> None:
        index = _Index(self)
        for module in self.modules.values():
            if module.scope is not None:
                for statement in module.tree.body:
                    index.walk(statement, module.scope)

    # -- tests and pages -----------------------------------------------------

    def read_tests(self) -> None:
        for path in _files(self.root, TEST_DIR, (".py",)):
            if not (path.name.startswith("test_") or path.name.endswith("_test.py")):
                continue
            rel = path.relative_to(self.root).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
            for code in self._named_in(tree):
                self.codes[code].tests.add(rel)

    def _named_in(self, tree: ast.Module) -> set[str]:
        """The codes a test names: in a string, or by a constant imported from the platform.

        A string names a code it holds as a whole word (``"[isr.empty_evidence]"``
        does); a docstring is prose about the test and names nothing.
        """
        known = self.code_set
        named: set[str] = set()
        modules: dict[str, str] = {}
        attributes: list[ast.Attribute] = []
        prose = _docstring_ids(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if id(node) not in prose:
                    named |= _words(node.value) & known
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    ref = self.follow(self.import_target(node.module, alias.name))
                    if ref.kind == "module":
                        modules[alias.asname or alias.name] = ref.name
                    else:
                        named |= self._scalar_codes(ref)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.partition(".")[0]
                    modules[alias.asname or top] = alias.name if alias.asname else top
            elif isinstance(node, ast.Attribute):
                attributes.append(node)
        for node in attributes:
            dotted = _dotted(node.value)
            if dotted is None:
                continue
            head, _, rest = dotted.partition(".")
            if head in modules:
                module = modules[head] + (f".{rest}" if rest else "")
                named |= self._scalar_codes(self.follow(self.import_target(module, node.attr)))
        return named

    def _scalar_codes(self, ref: Ref) -> frozenset[str]:
        kind, codes = self.carried(ref)
        return codes if kind == "scalar" else frozenset()

    def read_console_tests(self) -> None:
        known = self.code_set
        for path in _files(self.root, CONSOLE_DIR, (".test.ts", ".test.tsx")):
            rel = path.relative_to(self.root).as_posix()
            words: set[str] = set()
            for literal in _quoted(path.read_text(encoding="utf-8")):
                words |= _words(literal)
            for code in words & known:
                self.codes[code].console_tests.add(rel)

    def read_docs(self) -> None:
        known = self.code_set
        for path in _files(self.root, DOCS_DIR, (".mdx",)):
            rel = path.relative_to(self.root).as_posix()
            if rel == PAGE:
                continue
            text = path.read_text(encoding="utf-8")
            page = (_route(rel[len(DOCS_DIR) + 1 :]), _title(text) or rel)
            for code in _words(text) & known:
                self.codes[code].docs.add(page)

    # -- the result ----------------------------------------------------------

    def register(self) -> Register:
        codes: list[Code] = []
        for code in sorted(self.codes):
            record = self.codes[code]
            meaning, meaning_from = "", ""
            for _key, text, site in sorted(record.meanings, key=lambda item: item[0]):
                if text.strip():
                    meaning, meaning_from = text.strip(), site
                    break
            codes.append(
                Code(
                    code=code,
                    raised_at=tuple(sorted(record.raised)),
                    constants=tuple(sorted(record.constants)),
                    collections=tuple(sorted(record.collections)),
                    meaning=meaning,
                    meaning_from=meaning_from,
                    tests=tuple(sorted(record.tests)),
                    console_tests=tuple(sorted(record.console_tests)),
                    docs=tuple(sorted(record.docs)),
                    kept_by=tuple(sorted(record.kept_by)),
                    kept_reason=next(
                        (reason for _, reason in sorted(record.kept_by.items()) if reason), ""
                    ),
                )
            )
        unresolved = sorted(self.unresolved, key=lambda u: (u.site, u.expression, u.why))
        return Register(tuple(codes), tuple(unresolved))


# Contexts a value is used in. Only ``RAISE`` makes a raise site; ``ATTR`` is the
# base of an attribute or an item, which reads a mapping's values out.
RAISE, READ, BIND, ITER, ATTR = "raise", "read", "bind", "iter", "attr"


class _Index:
    """Who calls each function by name, and which functions are passed as values."""

    def __init__(self, reader: Reader) -> None:
        self.reader = reader

    def arguments(self, args: ast.arguments, scope: Scope) -> None:
        for default in [*args.defaults, *args.kw_defaults]:
            if default is not None:
                self.walk(default, scope)
        for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
            if arg is not None and arg.annotation is not None:
                self.walk(arg.annotation, scope)

    def walk(self, node: ast.AST, scope: Scope) -> None:
        reader = self.reader
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                self.walk(decorator, scope)
            self.arguments(node.args, scope)
            if node.returns is not None:
                self.walk(node.returns, scope)
            inner = reader.scopes[id(node)]
            for statement in node.body:
                self.walk(statement, inner)
        elif isinstance(node, ast.Lambda):
            self.arguments(node.args, scope)
            self.walk(node.body, reader.scopes[id(node)])
        elif isinstance(node, ast.ClassDef):
            for part in [*node.decorator_list, *node.bases, *(k.value for k in node.keywords)]:
                self.walk(part, scope)
            inner = reader.scopes[id(node)]
            for statement in node.body:
                self.walk(statement, inner)
        elif isinstance(node, ast.Call):
            target = reader.def_of(reader.ref_of(node.func, scope))
            if target is not None and target.kind == "function":
                target.calls.append((node, scope))
            else:
                self.walk(node.func, scope)
            for argument in node.args:
                self.walk(argument, scope)
            for keyword in node.keywords:
                self.walk(keyword.value, scope)
        elif isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                target = reader.def_of(reader.lookup(scope, node.id))
                if target is not None:
                    target.escaped = True
        elif isinstance(node, ast.Attribute) and (ref := reader.attribute_ref(node, scope)):
            target = reader.def_of(ref)
            if target is not None and isinstance(node.ctx, ast.Load):
                target.escaped = True
        else:
            for child in ast.iter_child_nodes(node):
                self.walk(child, scope)


class _Uses:
    """Every use of a name that holds codes, sorted into raises and reads."""

    def __init__(self, reader: Reader) -> None:
        self.reader = reader
        # A parameter's default is evaluated outside its function and used inside it.
        self.site: str | None = None

    def raise_at(self, codes: Iterable[str], scope: Scope) -> None:
        for code in codes:
            self.reader.codes[code].raised.add(self.site or scope.site)

    def load(self, ref: Ref, scope: Scope, context: str) -> None:
        kind, codes = self.reader.carried(ref)
        if not codes or kind == "collection":
            # A collection of codes is looked up in wherever it goes; a loop
            # over one binds a name that is followed in its own right.
            return
        if context == RAISE or (kind == "mapping" and context == ATTR):
            self.raise_at(codes, scope)

    def arguments(self, args: ast.arguments, scope: Scope, inner: Scope) -> None:
        outer_site, self.site = self.site, inner.site
        for default in [*args.defaults, *args.kw_defaults]:
            if default is not None:
                self.expr(default, scope, RAISE)
        self.site = outer_site
        for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
            if arg is not None and arg.annotation is not None:
                self.expr(arg.annotation, scope, READ)

    def statement(self, node: ast.stmt, scope: Scope) -> None:  # noqa: C901 — one case per statement kind
        reader = self.reader
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            inner = reader.scopes[id(node)]
            for decorator in node.decorator_list:
                self.expr(decorator, scope, RAISE)
            self.arguments(node.args, scope, inner)
            if node.returns is not None:
                self.expr(node.returns, scope, READ)
            self.body(node.body, inner)
        elif isinstance(node, ast.ClassDef):
            for part in [*node.decorator_list, *node.bases, *(k.value for k in node.keywords)]:
                self.expr(part, scope, RAISE)
            self.body(node.body, reader.scopes[id(node)])
        elif isinstance(node, ast.Assign):
            followed = scope.kind != "class" and all(isinstance(t, ast.Name) for t in node.targets)
            self.expr(node.value, scope, BIND if followed else RAISE)
            for target in node.targets:
                self.target(target, scope)
        elif isinstance(node, ast.AnnAssign):
            self.expr(node.annotation, scope, READ)
            if node.value is not None:
                followed = scope.kind != "class" and isinstance(node.target, ast.Name)
                self.expr(node.value, scope, BIND if followed else RAISE)
            self.target(node.target, scope)
        elif isinstance(node, ast.AugAssign):
            self.target(node.target, scope)
            self.expr(node.value, scope, RAISE)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self.expr(node.iter, scope, ITER if isinstance(node.target, ast.Name) else RAISE)
            self.target(node.target, scope)
            self.body([*node.body, *node.orelse], scope)
        elif isinstance(node, (ast.While, ast.If)):
            self.expr(node.test, scope, READ)
            self.body([*node.body, *node.orelse], scope)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self.expr(item.context_expr, scope, RAISE)
                if item.optional_vars is not None:
                    self.target(item.optional_vars, scope)
            self.body(node.body, scope)
        elif isinstance(node, ast.Return):
            if node.value is not None:
                self.expr(node.value, scope, RAISE)
        elif isinstance(node, ast.Expr):
            self.expr(node.value, scope, READ)
        elif isinstance(node, ast.Raise):
            for raised in (node.exc, node.cause):
                if raised is not None:
                    self.expr(raised, scope, RAISE)
        elif isinstance(node, ast.Assert):
            self.expr(node.test, scope, READ)
            if node.msg is not None:
                self.expr(node.msg, scope, READ)
        elif isinstance(node, (ast.Try, ast.TryStar)):
            self.body(node.body, scope)
            for handler in node.handlers:
                if handler.type is not None:
                    self.expr(handler.type, scope, READ)
                self.body(handler.body, scope)
            self.body([*node.orelse, *node.finalbody], scope)
        elif isinstance(node, ast.Delete):
            for target in node.targets:
                self.target(target, scope)
        elif isinstance(node, ast.Match):
            self.expr(node.subject, scope, READ)
            for case in node.cases:
                self.pattern(case.pattern, scope)
                if case.guard is not None:
                    self.expr(case.guard, scope, READ)
                self.body(case.body, scope)
        elif isinstance(node, ast.TypeAlias):
            self.expr(node.value, scope, READ)
        # Imports, global and nonlocal declarations, pass, break and continue
        # use no value.

    def body(self, statements: Iterable[ast.stmt], scope: Scope) -> None:
        for statement in statements:
            self.statement(statement, scope)

    def target(self, node: ast.expr, scope: Scope) -> None:
        # What is written into is read, not raised; a key written under is used.
        if isinstance(node, ast.Attribute):
            self.expr(node.value, scope, READ)
        elif isinstance(node, ast.Subscript):
            self.expr(node.value, scope, READ)
            self.expr(node.slice, scope, RAISE)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for element in node.elts:
                self.target(element, scope)
        elif isinstance(node, ast.Starred):
            self.target(node.value, scope)

    def pattern(self, node: ast.pattern, scope: Scope) -> None:
        if isinstance(node, ast.MatchValue):
            self.expr(node.value, scope, READ)
        elif isinstance(node, ast.MatchClass):
            self.expr(node.cls, scope, READ)
        elif isinstance(node, ast.MatchMapping):
            for key in node.keys:
                self.expr(key, scope, READ)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.pattern):
                self.pattern(child, scope)

    def expr(self, node: ast.expr, scope: Scope, context: str) -> None:  # noqa: C901
        reader = self.reader
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                self.load(reader.lookup(scope, node.id), scope, context)
        elif isinstance(node, ast.Attribute):
            ref = reader.attribute_ref(node, scope)
            if ref is not None:
                self.load(ref, scope, context)
            else:
                self.expr(node.value, scope, ATTR)
        elif isinstance(node, ast.Constant):
            return
        elif isinstance(node, ast.Compare):
            self.expr(node.left, scope, READ)
            for comparator in node.comparators:
                self.expr(comparator, scope, READ)
        elif isinstance(node, ast.BoolOp):
            for value in node.values:
                self.expr(value, scope, context)
        elif isinstance(node, ast.IfExp):
            self.expr(node.test, scope, READ)
            self.expr(node.body, scope, context)
            self.expr(node.orelse, scope, context)
        elif isinstance(node, (ast.UnaryOp, ast.BinOp)):
            # Arithmetic, set algebra and text built with ``+`` read their operands.
            for operand in ast.iter_child_nodes(node):
                if isinstance(operand, ast.expr):
                    self.expr(operand, scope, READ)
        elif isinstance(node, ast.NamedExpr):
            self.expr(node.value, scope, BIND)
        elif isinstance(node, ast.Starred):
            self.expr(node.value, scope, context)
        elif isinstance(node, ast.Call):
            self.call(node, scope, context)
        elif isinstance(node, ast.Set):
            for element in node.elts:
                self.expr(element, scope, READ)
        elif isinstance(node, (ast.Tuple, ast.List)):
            if reader.all_codes(node.elts, scope) or context in (READ, ITER):
                element_context = READ
            else:
                element_context = RAISE
            for element in node.elts:
                self.expr(element, scope, element_context)
        elif isinstance(node, ast.Dict):
            value_context = {READ: READ, ITER: READ, BIND: BIND}.get(context, RAISE)
            for key, value in zip(node.keys, node.values, strict=True):
                if key is not None:
                    self.expr(key, scope, READ)
                self.expr(value, scope, value_context if key is not None else RAISE)
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            for generator in node.generators:
                looped = isinstance(generator.target, ast.Name)
                self.expr(generator.iter, scope, ITER if looped else RAISE)
                self.target(generator.target, scope)
                for condition in generator.ifs:
                    self.expr(condition, scope, READ)
            produced = READ if context == READ else RAISE
            if isinstance(node, ast.DictComp):
                self.expr(node.key, scope, READ)
                self.expr(node.value, scope, produced)
            else:
                self.expr(node.elt, scope, READ if isinstance(node, ast.SetComp) else produced)
        elif isinstance(node, ast.Lambda):
            inner = reader.scopes[id(node)]
            self.arguments(node.args, scope, inner)
            self.expr(node.body, inner, RAISE)
        elif isinstance(node, (ast.JoinedStr, ast.FormattedValue)):
            for part in ast.iter_child_nodes(node):
                if isinstance(part, ast.expr):
                    self.expr(part, scope, READ)
        elif isinstance(node, ast.Subscript):
            self.expr(node.value, scope, ATTR)
            self.expr(node.slice, scope, RAISE)
        elif isinstance(node, ast.Slice):
            for bound in (node.lower, node.upper, node.step):
                if bound is not None:
                    self.expr(bound, scope, READ)
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self.expr(child, scope, RAISE)

    def call(self, node: ast.Call, scope: Scope, context: str) -> None:
        reader = self.reader
        if reader.builtin(node.func, scope, "frozenset", "set"):
            for argument in node.args:
                self.expr(argument, scope, READ)
            return
        if (
            reader.builtin(node.func, scope, "str", "tuple", "list", "sorted")
            and len(node.args) == 1
            and not node.keywords
        ):
            self.expr(node.args[0], scope, context)
            return
        self.expr(node.func, scope, ATTR)
        for argument in node.args:
            self.expr(argument, scope, RAISE)
        for keyword in node.keywords:
            self.expr(keyword.value, scope, RAISE)


def _placeholder(node: ast.expr) -> str:
    """What an interpolated value is called: ``{safe_finding_value(tid)!r}`` is tid."""
    if isinstance(node, ast.FormattedValue):
        return _placeholder(node.value)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        return _placeholder(node.value)
    if isinstance(node, ast.Call):
        for argument in node.args:
            name = _placeholder(argument)
            if name != "…":
                return name
        return _placeholder(node.func)
    return "…"


def _fields_named(template: str) -> str:
    """A ``str.format`` template with each field written ``<name>``."""
    try:
        parsed = list(string.Formatter().parse(template))
    except ValueError:
        return template
    return "".join(
        literal + (f"<{name or '…'}>" if name is not None else "")
        for literal, name, _spec, _conversion in parsed
    )


def _own_statements(body: list[ast.stmt]) -> Iterator[ast.stmt]:
    """A function's statements in source order, nested definitions left out."""
    for statement in body:
        yield statement
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for name in ("body", "orelse", "finalbody", "handlers", "cases"):
            inner = getattr(statement, name, None)
            if not isinstance(inner, list):
                continue
            for item in inner:
                if isinstance(item, ast.stmt):
                    yield from _own_statements([item])
                elif isinstance(item, (ast.ExceptHandler, ast.match_case)):
                    yield from _own_statements(item.body)


def _docstring_ids(tree: ast.Module) -> set[int]:
    """The string statements that open a module, a class or a function."""
    found: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0] if node.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                found.add(id(first.value))
    return found


def _dotted(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return None if base is None else f"{base}.{node.attr}"
    return None


def _quoted(text: str) -> set[str]:
    """The string literals of a TypeScript file, comments skipped."""
    found: set[str] = set()
    index, size = 0, len(text)
    while index < size:
        char = text[index]
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = size if end < 0 else end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = size if end < 0 else end + 2
        elif char in "'\"`":
            end = index + 1
            while end < size and text[end] != char:
                if text[end] == "\\":
                    end += 1
                elif text[end] == "\n" and char != "`":
                    break
                end += 1
            found.add(text[index + 1 : end])
            index = end + 1
        else:
            index += 1
    return found


class _CodeCharacters(dict[int, int]):
    """A translation table that turns every character a code cannot hold into a space."""

    _ALLOWED = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_.")

    def __missing__(self, key: int) -> int:
        value = key if chr(key) in self._ALLOWED else ord(" ")
        self[key] = value
        return value


_TABLE = _CodeCharacters()


def _words(text: str) -> set[str]:
    """The runs of code characters in a page, with a sentence's full stop taken off."""
    return {word.strip(".") for word in text.translate(_TABLE).split()}


def _route(path: str) -> str:
    """The address a docs page under ``content/docs`` is served at."""
    stem = path[: -len(".mdx")]
    if stem == "index":
        return "/"
    if stem.endswith("/index"):
        stem = stem[: -len("/index")]
    return f"/{stem}/"


def _title(text: str) -> str:
    if not text.startswith("---"):
        return ""
    end = text.find("\n---", 3)
    for line in text[3 : end if end >= 0 else len(text)].splitlines():
        key, colon, value = line.partition(":")
        if colon and key.strip() == "title":
            return value.strip().strip("\"'")
    return ""


def build(root: Path) -> Register:
    """The register of the tree at ``root``."""
    reader = Reader(root)
    reader.read_platform()
    reader.index_calls()
    reader.read_positions()
    reader.read_keywords()
    reader.read_uses()
    reader.read_tests()
    reader.read_console_tests()
    reader.read_docs()
    return reader.register()
