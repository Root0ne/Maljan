"""Read the platform's validation codes out of its source, with ``ast`` and no import.

A validation code is the ``family.name`` string a validator files a finding
under (``isr.empty_evidence``, ``verdict.fallback``). A string is one only in a
code position — the value of a ``code=`` keyword, the value assigned to a name
ending in ``_CODE``, a member of a set or tuple bound to a name ending in
``_CODES``, or the code slot of a finding the platform builds (below) — and only
in that shape. The family is the part before the dot, so the families are
whatever the source uses: ``os.path`` in an import, a host name in a list or
``"report.json"`` in a call is never a code.

A code is *raised* only where the platform puts it into a finding it emits:

* a call that builds a finding: a class whose instances carry ``code`` (a
  ``code`` field or a ``code`` parameter of ``__init__``/``__new__``), with the
  code given as ``code=`` or in that parameter's positional place;
* a dict display with a ``"code"`` key, and a tuple display shaped like a
  finding class that is itself a tuple (the code in the same place);
* a call to a factory: a platform function one of whose parameters reaches such
  a slot (found by following every parameter through the code, not by name);
* a call to a callback the function was handed: the code leaves for a listener
  the register cannot see;

and only inside code something calls. A code stored, forwarded or returned
anywhere else *passes on*, and is listed apart; a comparison, a lookup or count
keyed by it, a string test, a log line, a filter, a default that reaches no
slot and formatted text *read* it and are not listed. A value is followed
through plain names, a loop over a constant collection, a conditional or ``or``,
``str()``, a lookup in a constant mapping, imports, and a parameter fed by
constants at every call site (or by its default). A code slot whose value cannot
be followed is kept as an unresolved site with the expression seen, and so is a
code-shaped string of a known family in a position that is neither a code
position nor a read; neither is dropped.

Nothing is imported: the source is parsed with ``ast`` and its comments read
with ``tokenize``. In a git checkout only tracked files are read, so the page is
the same here and in CI. One parse per file, memoised resolution and a
worklist over parameters keep the work linear in the size of the tree.
"""

from __future__ import annotations

import ast
import inspect
import io
import os
import string
import subprocess
import sys
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

# The keywords and dict keys a finding's text is read from.
TEXT_KEYWORDS = ("message", "feedback")

# How many names a value is followed through before it is called too deep to
# follow. Counted by the register itself, so the answer does not depend on how
# deep the caller's own stack already is.
MAX_CHAIN = 1000

# The methods that store a value in a container: a code handed to one passes on.
STORING_METHODS = ("append", "appendleft", "add", "insert", "extend", "update", "setdefault")

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
    # Sites that store or forward the code without filing it, and sites that
    # would raise it but sit in code nothing calls.
    passes_on: tuple[str, ...]
    uncalled: tuple[str, ...]
    constants: tuple[str, ...]
    collections: tuple[str, ...]
    meaning: str
    # comment, message, group, pointer, or "" when nothing says.
    meaning_kind: str
    # The constant or site the meaning was read from.
    meaning_from: str
    # The Python tests naming the code or its constant, and the console's unit
    # tests naming it in a string. Kept in memory for the guard and --tests.
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
_TOO_DEEP = Value(why=f"a chain of more than {MAX_CHAIN} names")


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
    # Every statement's body and place in it, by the statement's id.
    places: dict[int, tuple[list[ast.stmt], int]]
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
    # The positional parameters in order, and the star parameters by kind.
    order: list[str] = field(default_factory=list)
    stars: dict[str, str] = field(default_factory=dict)
    star_imports: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    # The calls that name this function directly, with the scope each is in.
    calls: list[tuple[ast.Call, Scope]] = field(default_factory=list)
    # Named other than as a callee: passed, stored or returned, so its callers
    # are not all known.
    escaped: bool = False
    # Named anywhere outside its own body.
    referenced: bool = False

    @property
    def site(self) -> str:
        return f"{self.module.name}:{self.qualname}"

    @property
    def name(self) -> str:
        return self.qualname.rpartition(".")[2]


@dataclass(frozen=True, eq=False)
class Ref:
    """What a name refers to: kind is binding, param, module or unknown."""

    kind: str
    scope: Scope | None = None
    name: str = ""


@dataclass(frozen=True)
class FindingType:
    """A platform class whose instances carry a code, and where the code goes."""

    scope: Scope
    # The positional places of the code and of its text; None where keyword only.
    code_index: int | None
    text_index: int | None
    text_name: str
    # The number of items, for a finding class that is a tuple.
    arity: int | None
    skip_first: bool


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


def tracked_files(root: Path) -> set[str] | None:
    """The files git tracks under ``root``, or None where ``root`` is not a git checkout."""
    if not (root / ".git").exists():
        return None
    try:
        listed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=True,
            timeout=120,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return {part.decode("utf-8") for part in listed.split(b"\0") if part}


def _files(
    root: Path, base: str, suffixes: tuple[str, ...], tracked: set[str] | None
) -> Iterator[Path]:
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
            path = Path(directory) / name
            if name.endswith(suffixes) and (
                tracked is None or path.relative_to(root).as_posix() in tracked
            ):
                yield path


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


def _bodies(
    tree: ast.Module,
) -> tuple[dict[int, str], dict[int, tuple[list[ast.stmt], int]]]:
    """Each assignment's docstring, and every statement's body and place in it."""
    docstrings: dict[int, str] = {}
    places: dict[int, tuple[list[ast.stmt], int]] = {}
    for node in ast.walk(tree):
        for name in ("body", "orelse", "finalbody"):
            body = getattr(node, name, None)
            if not isinstance(body, list):
                continue
            for index, statement in enumerate(body):
                if not isinstance(statement, ast.stmt):
                    continue
                places[id(statement)] = (body, index)
                following = body[index + 1] if index + 1 < len(body) else None
                if (
                    isinstance(statement, (ast.Assign, ast.AnnAssign))
                    and isinstance(following, ast.Expr)
                    and isinstance(following.value, ast.Constant)
                    and isinstance(following.value.value, str)
                ):
                    docstrings[id(statement)] = inspect.cleandoc(following.value.value)
    return docstrings, places


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


def _is_str(annotation: ast.expr | None) -> bool:
    return isinstance(annotation, ast.Name) and annotation.id == "str"


def _position_name(statement: ast.stmt) -> str | None:
    """The ``_CODE`` or ``_CODES`` name a statement assigns, if it assigns one."""
    if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
        target: ast.expr = statement.targets[0]
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        target = statement.target
    else:
        return None
    if isinstance(target, ast.Name) and target.id.endswith(("_CODE", "_CODES")):
        return target.id
    return None


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


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


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
            scope.order.append(arg.arg)
        for arg, keyword_default in zip(args.kwonlyargs, args.kw_defaults, strict=True):
            scope.params[arg.arg] = Param(arg.arg, None, keyword_default, arg.annotation)
        for star, kind in ((args.vararg, "args"), (args.kwarg, "kwargs")):
            if star is not None:
                scope.params[star.arg] = Param(star.arg, None, None, star.annotation, star=True)
                scope.stars[kind] = star.arg

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
        child.decorators = [_decorator_name(d) for d in node.decorator_list]
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
        child.decorators = [_decorator_name(d) for d in node.decorator_list]
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
    passes_on: set[str] = field(default_factory=set)
    uncalled: set[str] = field(default_factory=set)
    constants: set[str] = field(default_factory=set)
    collections: set[str] = field(default_factory=set)
    # ``(sort key, text, kind, source)``; the lowest key wins.
    meanings: list[tuple[tuple[Any, ...], str, str, str]] = field(default_factory=list)
    kept_by: dict[str, str] = field(default_factory=dict)
    tests: set[str] = field(default_factory=set)
    console_tests: set[str] = field(default_factory=set)
    docs: set[tuple[str, str]] = field(default_factory=set)


# How strongly a parameter is used: read only, passed on, or put in a code slot.
_READ_LEVEL, _PASS_LEVEL, _SLOT_LEVEL = 0, 1, 2

_Key = tuple[int, str]


class Reader:
    """The platform's source as scopes and bindings, and the codes read out of it."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.tracked = tracked_files(root)
        self.modules: dict[str, Module] = {}
        self.scopes: dict[int, Scope] = {}
        self.positions: list[tuple[ast.stmt, str, ast.expr, Scope]] = []
        self.keywords: list[tuple[ast.Call, ast.keyword, Scope]] = []
        self.codes: dict[str, _Record] = {}
        self.unresolved: set[Unresolved] = set()
        self.attribute_names: set[str] = set()
        self.types: dict[int, FindingType | None] = {}
        self.shapes: dict[int, FindingType] = {}
        self._memo: dict[tuple[str, int, str], Value] = {}
        self._carried: dict[_Key, tuple[str, frozenset[str]]] = {}
        self._followed: dict[_Key, Ref] = {}
        self._chains: dict[_Key, list[tuple[str, str, str, str]]] = {}
        self._position_scopes: dict[int, Scope] | None = None
        self._attached: dict[int, str] = {}
        self._groups: dict[int, tuple[str, str]] = {}
        self._grouped: set[int] = set()
        self._returned: dict[int, str] = {}
        self._called: dict[int, bool] = {}
        self._fed: dict[_Key, Value] = {}
        self._code_set: frozenset[str] | None = None
        self._depth = 0
        # The parameter flow graph: each name's own strongest use, the names whose
        # use flows back into it, and the settled levels.
        self._base: dict[_Key, int] = {}
        self._backward: dict[_Key, list[_Key]] = {}
        self._levels: dict[_Key, int] = {}
        self._deferred_loads: list[tuple[Ref, Scope, str]] = []
        self._deferred_literals: list[tuple[str, Scope, str]] = []
        self._deferred_known: list[tuple[ast.expr, Scope, str, ast.expr | None]] = []
        # What each slot target is seen to receive, and the unresolved sites
        # waiting on it: a target that receives only strings not shaped as
        # codes files another kind of code (a team rule, a tool error).
        self._shaped: set[tuple[Any, ...]] = set()
        self._unshaped: set[tuple[Any, ...]] = set()
        self._pending: list[tuple[tuple[Any, ...], Unresolved]] = []

    # -- reading -------------------------------------------------------------

    def read_platform(self) -> None:
        for base in PLATFORM_DIRS:
            for path in _files(self.root, base, (".py",), self.tracked):
                rel = path.relative_to(self.root).as_posix()
                name, package = module_name(rel)
                if name in self.modules:
                    raise ValueError(f"{rel} and {self.modules[name].path} both read as {name}")
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=rel)
                whole, trailing = _comments(source)
                docstrings, places = _bodies(tree)
                self.modules[name] = Module(
                    name, rel, package, tree, whole, trailing, docstrings, places
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
        """Through names that are only an import of another name, memoised along the way."""
        passed: list[_Key] = []
        while ref.kind == "binding" and ref.scope is not None:
            holder = ref.scope
            key = (id(holder), ref.name)
            known = self._followed.get(key)
            if known is not None:
                ref = known
                break
            bindings = holder.bindings.get(ref.name, [])
            if len(bindings) != 1 or bindings[0].kind != "import":
                self._followed[key] = ref
                break
            if key in passed:
                ref = Ref("unknown", None, ref.name)
                break
            passed.append(key)
            ref = self.import_target(*bindings[0].node)
        for key in passed:
            self._followed[key] = ref
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
        if self._depth >= MAX_CHAIN:
            self._memo[key] = _TOO_DEEP
            return _TOO_DEEP
        self._memo[key] = _BUSY
        self._depth += 1
        try:
            value = compute()
        except RecursionError:
            self._memo[key] = _TOO_DEEP
            raise
        finally:
            self._depth -= 1
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

    def dict_displays(self, node: ast.expr, scope: Scope) -> list[tuple[ast.Dict, Scope]] | None:
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
        displays = self.dict_displays(container, scope)
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

    def _unknown_callers(self, function: Scope, name: str) -> Value | None:
        """Why a parameter's callers cannot all be known, or None when they can."""
        param = function.params[name]
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
        return None

    def _param_value(self, function: Scope, name: str) -> Value:
        param = function.params[name]
        if _never_a_string(param.annotation):
            return NOT_A_STRING
        unknown = self._unknown_callers(function, name)
        if unknown is not None:
            return unknown
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

    def fed_codes(self, function: Scope, name: str) -> Value:
        """What a factory's code parameter is fed: each caller reports its own unfollowed value."""
        key = (id(function), name)
        found = self._fed.get(key)
        if found is not None:
            return found
        param = function.params[name]
        unknown = self._unknown_callers(function, name)
        if _never_a_string(param.annotation):
            result = NOT_A_STRING
        elif unknown is not None:
            result = unknown
        else:
            result = NOTHING
            for call, caller in function.calls:
                argument = _argument(call, param)
                if argument is _DEFAULT and param.default is not None and function.parent:
                    value = self.entry(partial(self.value_of, param.default, function.parent))
                elif isinstance(argument, ast.expr):
                    value = self.entry(partial(self.value_of, argument, caller))
                else:
                    continue
                result = result | Value(value.strings, value.other)
        self._fed[key] = result
        return result

    def slot_value(self, node: ast.expr, scope: Scope, seen: frozenset[int] = frozenset()) -> Value:
        """The value in a code slot; a factory's own parameter is fed by its callers."""
        if isinstance(node, ast.IfExp):
            return self.slot_value(node.body, scope, seen) | self.slot_value(
                node.orelse, scope, seen
            )
        if isinstance(node, ast.BoolOp):
            result = NOTHING
            for value in node.values:
                result = result | self.slot_value(value, scope, seen)
            return result
        if isinstance(node, ast.NamedExpr):
            return self.slot_value(node.value, scope, seen)
        if (
            isinstance(node, ast.Call)
            and self.builtin(node.func, scope, "str")
            and len(node.args) == 1
            and not node.keywords
        ):
            return self.slot_value(node.args[0], scope, seen)
        if isinstance(node, ast.Name):
            ref = self.lookup(scope, node.id)
            if ref.kind == "param" and ref.scope is not None:
                if self.level(ref.scope, ref.name) == _SLOT_LEVEL:
                    return self.fed_codes(ref.scope, ref.name)
            elif (
                ref.kind == "binding"
                and ref.scope is not None
                and ref.scope.kind in ("function", "lambda")
            ):
                bindings = ref.scope.bindings[ref.name]
                if (
                    len(bindings) == 1
                    and bindings[0].kind == "value"
                    and id(bindings[0].node) not in seen
                ):
                    bound = bindings[0]
                    return self.slot_value(bound.node, bound.scope, seen | {id(bound.node)})
        return self.entry(partial(self.value_of, node, scope))

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
        """Every element holds only code-shaped strings: a collection of codes, not a row."""
        if not elements:
            return False
        for element in elements:
            if isinstance(element, ast.Starred):
                return False
            if isinstance(element, ast.Constant):
                if not is_code(element.value):
                    return False
                continue
            if not isinstance(element, (ast.Name, ast.Attribute)):
                return False
            value = self.entry(partial(self.value_of, element, scope))
            if value.why or value.other or not value.strings:
                return False
            if not all(is_code(text) for text in value.strings):
                return False
        return True

    @property
    def code_set(self) -> frozenset[str]:
        if self._code_set is None:
            self._code_set = frozenset(self.codes)
        return self._code_set

    # -- finding types, callees and who calls what ----------------------------

    def finding_type(self, scope: Scope) -> FindingType | None:
        """The class as a finding type, when its instances carry a code."""
        if id(scope) in self.types:
            return self.types[id(scope)]
        self.types[id(scope)] = None
        node = scope.node
        found: FindingType | None = None
        if isinstance(node, ast.ClassDef):
            found = self._own_finding_type(scope, node)
            if found is None:
                for base in node.bases:
                    inherited = self.def_of(self.ref_of(base, scope.parent or scope))
                    if inherited is not None and inherited.kind == "class":
                        parent = self.finding_type(inherited)
                        if parent is not None:
                            found = FindingType(
                                scope,
                                parent.code_index,
                                parent.text_index,
                                parent.text_name,
                                parent.arity,
                                parent.skip_first,
                            )
                            break
        self.types[id(scope)] = found
        return found

    def _own_finding_type(self, scope: Scope, node: ast.ClassDef) -> FindingType | None:
        arity: int | None = None
        for base in node.bases:
            if (
                isinstance(base, ast.Subscript)
                and _decorator_name(base.value) in ("tuple", "Tuple")
                and isinstance(base.slice, ast.Tuple)
            ):
                arity = len(base.slice.elts)
        named_tuple = any(_decorator_name(base) == "NamedTuple" for base in node.bases)
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in (
                "__init__",
                "__new__",
            ):
                init = self.scopes.get(id(item))
                if init is not None and "code" in init.params:
                    order = init.order[1:]
                    code_index = order.index("code") if "code" in order else None
                    text_name, text_index = "", None
                    for name in TEXT_KEYWORDS:
                        if name in init.params:
                            text_name = name
                    if code_index is not None and code_index + 1 < len(order):
                        following = order[code_index + 1]
                        if not text_name and _is_str(init.params[following].annotation):
                            text_name = following
                    if text_name in order:
                        text_index = order.index(text_name)
                    return FindingType(scope, code_index, text_index, text_name, arity, True)
        fields: list[tuple[str, ast.expr]] = []
        for item in node.body:
            if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                if "ClassVar" not in ast.unparse(item.annotation):
                    fields.append((item.target.id, item.annotation))
        names = [name for name, _annotation in fields]
        if "code" not in names:
            return None
        positional = named_tuple or "dataclass" in scope.decorators
        code_at = names.index("code")
        text_name = next((name for name in TEXT_KEYWORDS if name in names), "")
        if not text_name and code_at + 1 < len(fields) and _is_str(fields[code_at + 1][1]):
            text_name = names[code_at + 1]
        return FindingType(
            scope,
            code_at if positional else None,
            names.index(text_name) if positional and text_name else None,
            text_name,
            len(names) if named_tuple else arity,
            False,
        )

    def discover_types(self) -> None:
        for scope in list(self.scopes.values()):
            if scope.kind == "class":
                found = self.finding_type(scope)
                if found is not None and found.arity is not None and found.code_index is not None:
                    self.shapes.setdefault(found.arity, found)

    def method_of(self, cls: Scope, name: str, seen: frozenset[int] = frozenset()) -> Scope | None:
        if id(cls) in seen:
            return None
        bindings = cls.bindings.get(name, [])
        if len(bindings) == 1 and bindings[0].kind == "def":
            found: Scope = bindings[0].node
            return found if found.kind == "function" else None
        node = cls.node
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                parent = self.def_of(self.ref_of(base, cls.parent or cls))
                if parent is not None and parent.kind == "class":
                    method = self.method_of(parent, name, seen | {id(cls)})
                    if method is not None:
                        return method
        return None

    def callee(self, func: ast.expr, scope: Scope) -> tuple[str, Any, bool]:
        """What a call calls: a finding type, a platform function, a callback, or other."""
        if isinstance(func, ast.Name):
            ref = self.lookup(scope, func.id)
            if ref.kind == "param":
                return ("callback", None, False)
            target = self.def_of(ref)
        elif isinstance(func, ast.Attribute):
            ref_or_none = self.attribute_ref(func, scope)
            if ref_or_none is not None:
                target = self.def_of(ref_or_none)
            else:
                method = self._receiver_method(func, scope)
                if method is not None:
                    return method
                kind = "store" if func.attr in STORING_METHODS else "method"
                return (kind, None, False)
        else:
            return ("other", None, False)
        if target is None:
            return ("other", None, False)
        if target.kind == "class":
            found = self.finding_type(target)
            return ("type", found, False) if found is not None else ("other", None, False)
        return ("function", target, False)

    def _receiver_method(self, func: ast.Attribute, scope: Scope) -> tuple[str, Any, bool] | None:
        """``self.name(…)`` or ``Class.name(…)`` resolved to the method it calls."""
        receiver = func.value
        if not isinstance(receiver, ast.Name):
            return None
        ref = self.lookup(scope, receiver.id)
        if ref.kind == "param" and ref.scope is not None:
            method_scope = ref.scope
            cls = method_scope.parent
            if (
                cls is None
                or cls.kind != "class"
                or not method_scope.order
                or method_scope.order[0] != receiver.id
                or "staticmethod" in method_scope.decorators
            ):
                return None
            method = self.method_of(cls, func.attr)
            if method is None:
                return None
            return ("function", method, "staticmethod" not in method.decorators)
        cls = self.def_of(ref)
        if cls is not None and cls.kind == "class":
            method = self.method_of(cls, func.attr)
            if method is not None:
                return ("function", method, "classmethod" in method.decorators)
        return None

    def bind_args(
        self, call: ast.Call, function: Scope, skip_first: bool
    ) -> list[tuple[ast.expr, str | None]]:
        """Each argument of a call with the parameter of ``function`` it fills, if known."""
        order = function.order[1:] if skip_first else function.order
        bound: list[tuple[ast.expr, str | None]] = []
        splat = False
        for index, argument in enumerate(call.args):
            if isinstance(argument, ast.Starred):
                splat = True
                bound.append((argument.value, None))
            elif splat:
                bound.append((argument, None))
            elif index < len(order):
                bound.append((argument, order[index]))
            else:
                bound.append((argument, function.stars.get("args")))
        for keyword in call.keywords:
            if keyword.arg is None:
                bound.append((keyword.value, None))
            elif keyword.arg in function.params:
                bound.append((keyword.value, keyword.arg))
            else:
                bound.append((keyword.value, function.stars.get("kwargs")))
        return bound

    def called(self, scope: Scope) -> bool:
        """Whether anything in the platform calls the code this scope holds."""
        found = self._called.get(id(scope))
        if found is not None:
            return found
        if scope.kind in ("module", "class"):
            result = True
        elif scope.parent is None or not self.called(scope.parent):
            result = False
        elif scope.kind == "lambda":
            result = True
        else:
            name = scope.name
            result = (
                bool(scope.decorators)
                or (name.startswith("__") and name.endswith("__"))
                or scope.referenced
                or (scope.parent.kind == "class" and name in self.attribute_names)
            )
        self._called[id(scope)] = result
        return result

    # -- the parameter flow graph ---------------------------------------------

    def flow_key(self, ref: Ref) -> _Key | None:
        """A name the flow graph tracks: a parameter or a local of a function."""
        if ref.scope is None:
            return None
        if ref.kind == "param" or (
            ref.kind == "binding" and ref.scope.kind in ("function", "lambda")
        ):
            return (id(ref.scope), ref.name)
        return None

    def flow_use(self, key: _Key, level: int) -> None:
        if level > self._base.get(key, _READ_LEVEL):
            self._base[key] = level

    def flow_edge(self, source: _Key, target: _Key) -> None:
        """``source``'s value goes into ``target``: target's use is source's use too."""
        self._backward.setdefault(target, []).append(source)

    def settle(self) -> None:
        """Propagate every use back along the edges, each name rising at most twice."""
        levels = dict(self._base)
        work = [key for key, level in levels.items() if level > _READ_LEVEL]
        while work:
            key = work.pop()
            level = levels[key]
            for source in self._backward.get(key, ()):
                if levels.get(source, _READ_LEVEL) < level:
                    levels[source] = level
                    work.append(source)
        self._levels = levels

    def level(self, function: Scope, name: str) -> int:
        return self._levels.get((id(function), name), _READ_LEVEL)

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

    def _block(self, module: Module, statement: ast.stmt) -> list[str]:
        lines: list[str] = []
        row = statement.lineno - 1
        while row in module.comments:
            lines.append(module.comments[row])
            row -= 1
        lines.reverse()
        return lines

    def attached(self, module: Module, statement: ast.stmt | None) -> str:
        """A statement's own comment: the block right above it, its trailing comment or docstring.

        A block that heads a group of constants is not one constant's own
        comment; ``group_comment`` reads it.
        """
        if statement is None:
            return ""
        found = self._attached.get(id(statement))
        if found is not None:
            return found
        text = ""
        if not self.group_comment(module, statement)[0]:
            lines = self._block(module, statement)
            if not lines and statement.lineno in module.trailing:
                lines = [module.trailing[statement.lineno]]
            text = _prose(lines)
        text = text or _prose(module.docstrings.get(id(statement), "").splitlines())
        self._attached[id(statement)] = text
        return text

    def group_comment(self, module: Module, statement: ast.stmt) -> tuple[str, str]:
        """The comment heading a group of constants this one is in, and the constant it sits on.

        A comment sits on a group when the constant it is written above is
        followed, with no blank line, by constants with no comment of their
        own; or when it opens a run of constants written one after another.
        """
        place = module.places.get(id(statement))
        if place is None or _position_name(statement) is None:
            return ("", "")
        body, _index = place
        if id(body) not in self._grouped:
            self._group_body(module, body)
        return self._groups.get(id(statement), ("", ""))

    def _group_body(self, module: Module, body: list[ast.stmt]) -> None:
        """Every group of constants in one body, in one pass over it."""
        self._grouped.add(id(body))
        size = len(body)
        position = [_position_name(statement) is not None for statement in body]
        blocks = [
            self._block(module, statement) if position[i] else []
            for i, statement in enumerate(body)
        ]

        def adjacent(index: int) -> bool:
            """Whether ``body[index]`` follows the statement before it with no blank line."""
            if index == 0:
                return False
            previous, current = body[index - 1], body[index]
            top = current.lineno - len(blocks[index])
            return top == (previous.end_lineno or previous.lineno) + 1

        index = 0
        while index < size:
            if not position[index] or not blocks[index]:
                index += 1
                continue
            head = index
            run = head + 1
            while run < size and position[run] and adjacent(run) and not blocks[run]:
                run += 1
            opens = (
                not (head > 0 and position[head - 1] and adjacent(head))
                and head + 1 < size
                and position[head + 1]
                and adjacent(head + 1)
            )
            members = (
                range(head, run)
                if run - head > 1
                else (range(head, head + 1) if opens else range(0))
            )
            if members:
                scope = self._scope_of(module, body[head])
                name = _position_name(body[head]) or ""
                label = self.label(scope, name) if scope is not None else name
                text = _prose(blocks[head])
                for member in members:
                    self._groups[id(body[member])] = (text, label)
            index = run

    def _scope_of(self, module: Module, statement: ast.stmt) -> Scope | None:
        if self._position_scopes is None:
            self._position_scopes = {id(item[0]): item[3] for item in self.positions}
        return self._position_scopes.get(id(statement), module.scope)

    def read_positions(self) -> None:
        """Codes assigned to ``_CODE`` names and listed in ``_CODES`` collections."""
        for statement, name, value, scope in self.positions:
            label = self.label(scope, name)
            module = scope.module
            comment = self.attached(module, statement)
            group, head = self.group_comment(module, statement)
            if name.endswith("_CODE"):
                found = self.entry(partial(self.value_of, value, scope))
                chain = self._alias_chain(value, scope)
                for code in sorted(text for text in found.strings if is_code(text)):
                    record = self.record(code)
                    record.constants.add(label)
                    record.meanings.append(((0, label), comment, "comment", label))
                    record.meanings.append(((3, head), group, "group", head))
                    for alias, alias_comment, alias_group, alias_head in chain:
                        record.constants.add(alias)
                        record.meanings.append(((1, alias), alias_comment, "comment", alias))
                        record.meanings.append(((3, alias_head), alias_group, "group", alias_head))
                    if name.startswith(KEPT_PREFIX):
                        record.kept_by[label] = comment or group
            else:
                found = self.entry(partial(self.members_of, value, scope))
                collection_comment = comment or group
                for code in sorted(text for text in found.strings if is_code(text)):
                    record = self.record(code)
                    record.collections.add(label)
                    record.meanings.append(((3, label), collection_comment, "group", label))
                    if name.startswith(KEPT_PREFIX):
                        record.kept_by[label] = collection_comment
            if found.why:
                self.unresolved.add(Unresolved(label, f"{name} = {ast.unparse(value)}", found.why))

    def _alias_chain(self, value: ast.expr, scope: Scope) -> list[tuple[str, str, str, str]]:
        """The constants a ``_CODE`` name is an alias of, nearest first, with their comments."""
        ref = self.ref_of(value, scope) if isinstance(value, (ast.Name, ast.Attribute)) else None
        if ref is None:
            return []
        ref = self.follow(ref)
        if ref.kind != "binding" or ref.scope is None:
            return []
        start = (id(ref.scope), ref.name)
        if start in self._chains:
            return self._chains[start]
        walked: list[tuple[_Key, tuple[str, str, str, str]]] = []
        seen: set[_Key] = set()
        tail: list[tuple[str, str, str, str]] = []
        current: Ref | None = ref
        while current is not None and current.kind == "binding" and current.scope is not None:
            key = (id(current.scope), current.name)
            if key in self._chains:
                tail = self._chains[key]
                break
            bindings = current.scope.bindings[current.name]
            if len(bindings) != 1 or bindings[0].kind != "value" or key in seen:
                break
            seen.add(key)
            module = current.scope.module
            statement = bindings[0].statement
            if statement is not None and (_position_name(statement) or "").endswith("_CODE"):
                # A constant that is itself a code position files itself and the
                # rest of its chain, so each name is filed once.
                break
            group, head = (
                self.group_comment(module, statement) if statement is not None else ("", "")
            )
            walked.append(
                (
                    key,
                    (
                        self.label(current.scope, current.name),
                        self.attached(module, statement),
                        group,
                        head,
                    ),
                )
            )
            node, node_scope = bindings[0].node, bindings[0].scope
            nxt = (
                self.ref_of(node, node_scope)
                if isinstance(node, (ast.Name, ast.Attribute))
                else None
            )
            current = self.follow(nxt) if nxt is not None else None
        chain = list(tail)
        for key, entry in reversed(walked):
            chain = [entry, *chain]
            self._chains[key] = chain
        return chain

    def read_keywords(self) -> None:
        """``code=`` keywords that build no finding: their codes exist, unread values are named."""
        for call, keyword, scope in self.keywords:
            if self._keyword_is_slot(call, keyword, scope):
                continue
            found = self.entry(partial(self.value_of, keyword.value, scope))
            for code in sorted(text for text in found.strings if is_code(text)):
                self.record(code)
            if found.why:
                self.unresolved.add(
                    Unresolved(scope.site, f"code={ast.unparse(keyword.value)}", found.why)
                )

    def _keyword_is_slot(self, call: ast.Call, keyword: ast.keyword, scope: Scope) -> bool:
        kind, target, skip = self.callee(call.func, scope)
        if kind in ("type", "callback"):
            return True
        if kind == "function":
            for argument, param in self.bind_args(call, target, skip):
                if argument is keyword.value and param is not None:
                    return self.level(target, param) == _SLOT_LEVEL
        return False

    def text(self, node: ast.expr | None, scope: Scope) -> str:
        return "" if node is None else self._text(node, scope)

    def _text(self, node: ast.expr, scope: Scope, seen: frozenset[int] = frozenset()) -> str:
        """The words an expression spells, each interpolated value as ``<name>``.

        Followed through a name bound once, a parameter fed one string, the
        first branch of a conditional, ``.format()`` of a constant, and the first
        ``return`` of the helper a message is built by; anything else spells
        nothing.
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

    def raised(
        self,
        value: ast.expr,
        scope: Scope,
        form: str,
        text: ast.expr | None,
        site: str,
        target: tuple[Any, ...],
    ) -> None:
        """One code slot of a finding the platform builds: its codes, or what could not be read."""
        inner = self._own_parameter(value, scope)
        if inner is not None:
            target = inner
        found = self.slot_value(value, scope)
        if any(is_code(item) for item in found.strings):
            self._shaped.add(target)
        if any(not is_code(item) for item in found.strings):
            self._unshaped.add(target)
        codes = sorted(item for item in found.strings if is_code(item))
        called = self.called(scope)
        message = self.text(text, scope) if codes and called else ""
        for code in codes:
            record = self.record(code)
            if not called:
                record.uncalled.add(site)
                continue
            record.raised.add(site)
            self._message(code, message, site, value)
        if found.why:
            unresolved = Unresolved(site, form.replace("{}", ast.unparse(value), 1), found.why)
            self._pending.append((target, unresolved))

    def _own_parameter(self, value: ast.expr, scope: Scope) -> tuple[Any, ...] | None:
        """The factory parameter a slot is fed by, when its value is that parameter."""
        while (
            isinstance(value, ast.Call)
            and self.builtin(value.func, scope, "str")
            and len(value.args) == 1
        ):
            value = value.args[0]
        if isinstance(value, ast.Name):
            ref = self.lookup(scope, value.id)
            if ref.kind == "param" and ref.scope is not None:
                if self.level(ref.scope, ref.name) == _SLOT_LEVEL:
                    return ("param", id(ref.scope), ref.name)
        return None

    def _message(self, code: str, message: str, site: str, value: ast.expr) -> None:
        if not message.strip():
            return
        pointer = _placeholders_only(message)
        self.codes[code].meanings.append(
            (
                (4 if pointer else 2, site, value.lineno, value.col_offset),
                "" if pointer else message,
                "pointer" if pointer else "message",
                site,
            )
        )

    def read_flow(self) -> None:
        walk = _Walk(self, flow=True)
        for module in self.modules.values():
            if module.scope is not None:
                walk.body(module.tree.body, module.scope)
        self.settle()

    def read_uses(self) -> None:
        walk = _Walk(self, flow=False)
        for module in self.modules.values():
            if module.scope is not None:
                walk.body(module.tree.body, module.scope)
        for target, unresolved in self._pending:
            if target in self._unshaped and target not in self._shaped:
                continue
            self.unresolved.add(unresolved)
        families = {code.partition(".")[0] for code in self.code_set}
        for value, scope, site, text in self._deferred_known:
            found = self.entry(partial(self.value_of, value, scope))
            known = sorted(found.strings & self.code_set)
            if not known:
                continue
            if not self.called(scope):
                for code in known:
                    self.codes[code].uncalled.add(site)
                continue
            message = self.text(text, scope)
            for code in known:
                self.codes[code].raised.add(site)
                self._message(code, message, site, value)
        for ref, scope, site in self._deferred_loads:
            if not self.called(scope):
                continue
            kind, codes = self.carried(ref)
            if kind == "collection":
                continue
            for code in codes:
                self.codes[code].passes_on.add(site)
        for literal, scope, site in self._deferred_literals:
            if not self.called(scope):
                continue
            if literal in self.codes:
                self.codes[literal].passes_on.add(site)
            elif is_code(literal) and literal.partition(".")[0] in families:
                self.unresolved.add(
                    Unresolved(
                        site,
                        repr(literal),
                        "a code-shaped string where no code position is, nor a read",
                    )
                )

    def index_calls(self) -> None:
        index = _Index(self)
        for module in self.modules.values():
            if module.scope is not None:
                for statement in module.tree.body:
                    index.walk(statement, module.scope)

    # -- tests and pages -----------------------------------------------------

    def read_tests(self) -> None:
        for path in _files(self.root, TEST_DIR, (".py",), self.tracked):
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
        for path in _files(self.root, CONSOLE_DIR, (".test.ts", ".test.tsx"), self.tracked):
            rel = path.relative_to(self.root).as_posix()
            words: set[str] = set()
            for literal in _quoted(path.read_text(encoding="utf-8")):
                words |= _words(literal)
            for code in words & known:
                self.codes[code].console_tests.add(rel)

    def read_docs(self) -> None:
        known = self.code_set
        for path in _files(self.root, DOCS_DIR, (".mdx",), self.tracked):
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
            meaning, kind, source = "", "", ""
            for _key, text, candidate_kind, candidate_source in sorted(
                record.meanings, key=lambda item: item[0]
            ):
                if text.strip() or candidate_kind == "pointer":
                    meaning, kind, source = text.strip(), candidate_kind, candidate_source
                    break
            codes.append(
                Code(
                    code=code,
                    raised_at=tuple(sorted(record.raised)),
                    passes_on=tuple(sorted(record.passes_on - record.raised)),
                    uncalled=tuple(sorted(record.uncalled)),
                    constants=tuple(sorted(record.constants)),
                    collections=tuple(sorted(record.collections)),
                    meaning=meaning,
                    meaning_kind=kind,
                    meaning_from=source,
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


class _Index:
    """Who calls each function by name, what is named outside its own body, and which
    attribute names are used at all (a method is called through one)."""

    def __init__(self, reader: Reader) -> None:
        self.reader = reader

    def arguments(self, args: ast.arguments, scope: Scope) -> None:
        for default in [*args.defaults, *args.kw_defaults]:
            if default is not None:
                self.walk(default, scope)
        for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
            if arg is not None and arg.annotation is not None:
                self.walk(arg.annotation, scope)

    def named(self, target: Scope | None, scope: Scope) -> None:
        """``target`` is named from ``scope``: it counts unless that is its own body."""
        if target is None:
            return
        current: Scope | None = scope
        while current is not None:
            if current is target:
                return
            current = current.parent
        target.referenced = True

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
                self.named(target, scope)
                if isinstance(node.func, ast.Attribute):
                    reader.attribute_names.add(node.func.attr)
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
                    self.named(target, scope)
        elif isinstance(node, ast.Attribute):
            reader.attribute_names.add(node.attr)
            ref = reader.attribute_ref(node, scope)
            if ref is not None:
                target = reader.def_of(ref)
                if target is not None and isinstance(node.ctx, ast.Load):
                    target.escaped = True
                    self.named(target, scope)
                return
            self.walk(node.value, scope)
        else:
            for child in ast.iter_child_nodes(node):
                self.walk(child, scope)


# Contexts a value is used in. ``SLOT`` is a finding's code slot and ``PASS`` any
# other use as a value; ``BIND`` and ``ITER`` bind a name that is followed on.
READ, BIND, ITER, PASS, SLOT = "read", "bind", "iter", "pass", "slot"
_LEVELS = {READ: _READ_LEVEL, PASS: _PASS_LEVEL, SLOT: _SLOT_LEVEL}


@dataclass(frozen=True)
class _Flow:
    """A value handed to a platform function's parameter, decided once parameters are settled."""

    callee: Scope
    param: str


class _Walk:
    """One walk of the platform, deciding the context every value is used in.

    The flow walk records how each parameter and local of a function is used,
    so factories are known; the use walk then files every finding's code slot
    and every code passed on.
    """

    def __init__(self, reader: Reader, *, flow: bool) -> None:
        self.reader = reader
        self.flow = flow
        # A parameter's default is evaluated outside its function and used in it.
        self.site: str | None = None
        # The locals a value is being bound to.
        self.targets: list[_Key] = []

    # -- what each use means --------------------------------------------------

    def load(self, ref: Ref, scope: Scope, context: str | _Flow) -> None:
        reader = self.reader
        if self.flow:
            key = reader.flow_key(ref)
            if key is None:
                return
            if isinstance(context, _Flow):
                reader.flow_edge(key, (id(context.callee), context.param))
            elif context in (BIND, ITER):
                for target in self.targets:
                    if target != key:
                        reader.flow_edge(key, target)
            elif context in (PASS, SLOT):
                reader.flow_use(key, _LEVELS[context])
        elif context == PASS:
            reader._deferred_loads.append((ref, scope, self.site or scope.site))

    def literal(self, value: str, scope: Scope, context: str | _Flow) -> None:
        if not self.flow and context == PASS:
            self.reader._deferred_literals.append((value, scope, self.site or scope.site))

    def slot(
        self,
        value: ast.expr,
        scope: Scope,
        form: str,
        text: ast.expr | None,
        target: tuple[Any, ...],
    ) -> None:
        if not self.flow:
            self.reader.raised(value, scope, form, text, self.site or scope.site, target)
        self.expr(value, scope, SLOT)

    def known(self, value: ast.expr, scope: Scope, text: ast.expr | None) -> None:
        """A value handed to a callback, or put where a tuple finding keeps its code.

        Either raises a code the register already knows; neither makes a code,
        a factory or an unresolved site of its own, since a callback or a pair
        may as well carry anything else.
        """
        if not self.flow:
            self.reader._deferred_known.append((value, scope, self.site or scope.site, text))
        self.expr(value, scope, PASS)

    # -- statements -----------------------------------------------------------

    def body(self, statements: Iterable[ast.stmt], scope: Scope) -> None:
        for statement in statements:
            self.statement(statement, scope)

    def arguments(self, args: ast.arguments, scope: Scope, inner: Scope) -> None:
        outer_site, self.site = self.site, inner.site
        positional = [*args.posonlyargs, *args.args]
        defaults = list(
            zip(positional[len(positional) - len(args.defaults) :], args.defaults, strict=True)
        )
        defaults += [
            (arg, default)
            for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True)
            if default is not None
        ]
        for arg, default in defaults:
            level = self.reader.level(inner, arg.arg) if not self.flow else _READ_LEVEL
            # A default that reaches a slot is read through the parameter; one
            # that is passed on passes on in the function it belongs to.
            self.expr(default, scope, PASS if level == _PASS_LEVEL else READ)
        self.site = outer_site
        for parameter in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
            if parameter is not None and parameter.annotation is not None:
                self.expr(parameter.annotation, scope, READ)

    def statement(self, node: ast.stmt, scope: Scope) -> None:  # noqa: C901 — one case per kind
        reader = self.reader
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            inner = reader.scopes[id(node)]
            for decorator in node.decorator_list:
                self.expr(decorator, scope, READ)
            self.arguments(node.args, scope, inner)
            if node.returns is not None:
                self.expr(node.returns, scope, READ)
            self.body(node.body, inner)
        elif isinstance(node, ast.ClassDef):
            for part in [*node.decorator_list, *node.bases, *(k.value for k in node.keywords)]:
                self.expr(part, scope, READ)
            self.body(node.body, reader.scopes[id(node)])
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if isinstance(node, ast.AnnAssign):
                self.expr(node.annotation, scope, READ)
            if node.value is not None:
                followed = scope.kind != "class" and all(isinstance(t, ast.Name) for t in targets)
                if any(isinstance(t, ast.Name) and t.id.endswith("_CODES") for t in targets):
                    # A collection of codes is something codes are looked up in.
                    self.expr(node.value, scope, READ)
                elif followed:
                    self.bind(node.value, scope, [t.id for t in targets if isinstance(t, ast.Name)])
                else:
                    self.expr(node.value, scope, PASS)
            for target in targets:
                self.target(target, scope)
        elif isinstance(node, ast.AugAssign):
            self.target(node.target, scope)
            self.expr(node.value, scope, PASS)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self.loop(node.iter, node.target, scope)
            self.target(node.target, scope)
            self.body([*node.body, *node.orelse], scope)
        elif isinstance(node, (ast.While, ast.If)):
            self.expr(node.test, scope, READ)
            self.body([*node.body, *node.orelse], scope)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self.expr(item.context_expr, scope, READ)
                if item.optional_vars is not None:
                    self.target(item.optional_vars, scope)
            self.body(node.body, scope)
        elif isinstance(node, ast.Return):
            if node.value is not None:
                self.expr(node.value, scope, PASS)
        elif isinstance(node, ast.Expr):
            self.expr(node.value, scope, READ)
        elif isinstance(node, ast.Raise):
            for raised in (node.exc, node.cause):
                if raised is not None:
                    self.expr(raised, scope, READ)
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

    def loop(self, iterable: ast.expr, target: ast.expr, scope: Scope) -> None:
        """A loop: its variable is bound to what it iterates, and followed."""
        if not isinstance(target, ast.Name):
            self.expr(iterable, scope, READ)
            return
        outer, self.targets = self.targets, []
        key = self.reader.flow_key(self.reader.lookup(scope, target.id))
        if key is not None:
            self.targets.append(key)
        self.expr(iterable, scope, ITER)
        self.targets = outer

    def bind(self, value: ast.expr, scope: Scope, names: list[str]) -> None:
        outer, self.targets = self.targets, []
        for name in names:
            key = self.reader.flow_key(self.reader.lookup(scope, name))
            if key is not None:
                self.targets.append(key)
        self.expr(value, scope, BIND)
        self.targets = outer

    def target(self, node: ast.expr, scope: Scope) -> None:
        # What is written into is read, and so is a key written under.
        if isinstance(node, ast.Attribute):
            self.expr(node.value, scope, READ)
        elif isinstance(node, ast.Subscript):
            self.expr(node.value, scope, READ)
            self.expr(node.slice, scope, READ)
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

    # -- expressions ----------------------------------------------------------

    def expr(self, node: ast.expr, scope: Scope, context: str | _Flow) -> None:  # noqa: C901
        reader = self.reader
        value_context = (
            context if context in (PASS, SLOT, BIND) or isinstance(context, _Flow) else None
        )
        if isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                self.load(reader.lookup(scope, node.id), scope, context)
        elif isinstance(node, ast.Attribute):
            ref = reader.attribute_ref(node, scope)
            if ref is not None:
                self.load(ref, scope, context)
            else:
                self.expr(node.value, scope, READ)
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                self.literal(node.value, scope, context)
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
            self.bind(node.value, scope, [node.target.id])
        elif isinstance(node, ast.Starred):
            self.expr(node.value, scope, context)
        elif isinstance(node, ast.Call):
            self.call(node, scope, context)
        elif isinstance(node, ast.Set):
            for element in node.elts:
                self.expr(element, scope, READ)
        elif isinstance(node, (ast.Tuple, ast.List)):
            self.sequence(node, scope, value_context)
        elif isinstance(node, ast.Dict):
            self.mapping(node, scope, context, value_context)
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            for generator in node.generators:
                self.loop(generator.iter, generator.target, scope)
                self.target(generator.target, scope)
                for condition in generator.ifs:
                    self.expr(condition, scope, READ)
            produced = PASS if value_context is not None else READ
            if isinstance(node, ast.DictComp):
                self.expr(node.key, scope, READ)
                self.expr(node.value, scope, produced)
            else:
                self.expr(node.elt, scope, READ if isinstance(node, ast.SetComp) else produced)
        elif isinstance(node, ast.Lambda):
            inner = reader.scopes[id(node)]
            self.arguments(node.args, scope, inner)
            self.expr(node.body, inner, PASS)
        elif isinstance(node, (ast.JoinedStr, ast.FormattedValue)):
            for part in ast.iter_child_nodes(node):
                if isinstance(part, ast.expr):
                    self.expr(part, scope, READ)
        elif isinstance(node, ast.Subscript):
            if reader.dict_displays(node.value, scope) is not None and isinstance(
                node.value, (ast.Name, ast.Attribute)
            ):
                # A constant mapping's values are read out where the item goes.
                self.expr(node.value, scope, context)
            else:
                self.expr(node.value, scope, READ)
            self.expr(node.slice, scope, READ)
        elif isinstance(node, ast.Slice):
            for bound in (node.lower, node.upper, node.step):
                if bound is not None:
                    self.expr(bound, scope, READ)
        elif isinstance(node, (ast.Await, ast.Yield, ast.YieldFrom)):
            if node.value is not None:
                self.expr(node.value, scope, PASS)
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self.expr(child, scope, READ)

    def sequence(
        self, node: ast.Tuple | ast.List, scope: Scope, context: str | _Flow | None
    ) -> None:
        reader = self.reader
        if context is None or reader.all_codes(node.elts, scope):
            for element in node.elts:
                self.expr(element, scope, READ)
            return
        shape = reader.shapes.get(len(node.elts)) if isinstance(node, ast.Tuple) else None
        if shape is not None and any(isinstance(e, ast.Starred) for e in node.elts):
            shape = None
        for index, element in enumerate(node.elts):
            if shape is not None and index == shape.code_index:
                text = node.elts[shape.text_index] if shape.text_index is not None else None
                self.known(element, scope, text)
            else:
                self.expr(element, scope, PASS)

    def mapping(
        self, node: ast.Dict, scope: Scope, context: str | _Flow, value_context: str | _Flow | None
    ) -> None:
        text = None
        for key, value in zip(node.keys, node.values, strict=True):
            if isinstance(key, ast.Constant) and key.value in TEXT_KEYWORDS:
                text = value
        for key, value in zip(node.keys, node.values, strict=True):
            if key is None:
                self.expr(value, scope, PASS)
                continue
            self.expr(key, scope, READ)
            if value_context is not None and isinstance(key, ast.Constant) and key.value == "code":
                self.slot(value, scope, '"code": {}', text, ("dict",))
            elif value_context is None:
                self.expr(value, scope, READ)
            elif context == BIND:
                self.expr(value, scope, BIND)
            else:
                self.expr(value, scope, PASS)

    def call(self, node: ast.Call, scope: Scope, context: str | _Flow) -> None:  # noqa: C901
        reader = self.reader
        func = node.func
        if reader.builtin(func, scope, "frozenset", "set"):
            for argument in node.args:
                self.expr(argument, scope, READ)
            return
        if (
            reader.builtin(func, scope, "str", "tuple", "list", "sorted")
            and len(node.args) == 1
            and not node.keywords
        ):
            self.expr(node.args[0], scope, context)
            return
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "get"
            and isinstance(func.value, (ast.Name, ast.Attribute))
            and reader.dict_displays(func.value, scope) is not None
            and 1 <= len(node.args) <= 2
        ):
            # A lookup in a constant mapping: the values and the default go where
            # the result goes; the key is read.
            self.expr(func.value, scope, context)
            self.expr(node.args[0], scope, READ)
            if len(node.args) == 2:
                self.expr(node.args[1], scope, context)
            return
        kind, target, skip = reader.callee(func, scope)
        if not (isinstance(func, ast.Name) or kind == "function"):
            self.expr(func, scope, READ)
        text = next((k.value for k in node.keywords if k.arg in TEXT_KEYWORDS), None)
        if kind == "type":
            finding: FindingType = target
            for index, argument in enumerate(node.args):
                if index == finding.code_index and not isinstance(argument, ast.Starred):
                    positional_text = None
                    if finding.text_index is not None and finding.text_index < len(node.args):
                        positional_text = node.args[finding.text_index]
                    self.slot(
                        argument,
                        scope,
                        f"{ast.unparse(func)}({{}}, …)",
                        text or positional_text,
                        ("type", id(finding.scope)),
                    )
                else:
                    self.expr(argument, scope, PASS)
            for keyword in node.keywords:
                if keyword.arg == "code":
                    text_value = next(
                        (k.value for k in node.keywords if k.arg == finding.text_name), text
                    )
                    self.slot(
                        keyword.value, scope, "code={}", text_value, ("type", id(finding.scope))
                    )
                else:
                    self.expr(keyword.value, scope, PASS)
        elif kind == "callback":
            for argument in [*node.args, *(k.value for k in node.keywords)]:
                self.known(argument, scope, None)
        elif kind == "function":
            function: Scope = target
            keywords = {id(k.value): k.arg for k in node.keywords}
            for argument, param in reader.bind_args(node, function, skip):
                if param is None:
                    self.expr(argument, scope, PASS)
                elif self.flow:
                    self.expr(argument, scope, _Flow(function, param))
                else:
                    level = reader.level(function, param)
                    if level == _SLOT_LEVEL:
                        form = (
                            f"{keywords[id(argument)]}={{}}"
                            if id(argument) in keywords
                            else f"{ast.unparse(func)}({{}}, …)"
                        )
                        self.slot(argument, scope, form, text, ("param", id(function), param))
                    else:
                        self.expr(argument, scope, PASS if level == _PASS_LEVEL else READ)
        else:
            argument_context = PASS if kind == "store" else READ
            for argument in node.args:
                self.expr(argument, scope, argument_context)
            for keyword in node.keywords:
                self.expr(keyword.value, scope, argument_context)


def _placeholder(node: ast.expr) -> str:
    """What an interpolated value is called.

    A call with one argument is named by that argument (``safe_finding_value(tid)``
    is tid), any other call by its callee (``_retired_note(tid, attck)`` is
    retired_note), and an item by its key (``best['score_gate']`` is score_gate).
    """
    if isinstance(node, ast.FormattedValue):
        return _placeholder(node.value)
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value
        return _placeholder(node.value)
    if isinstance(node, ast.Call):
        if len(node.args) == 1 and not node.keywords:
            only = node.args[0]
            if isinstance(only, ast.Constant) and isinstance(only.value, str):
                return only.value
            return _placeholder(only)
        name = _placeholder(node.func)
        return name.lstrip("_") or name
    if isinstance(node, ast.BinOp):
        return _placeholder(node.left)
    if isinstance(node, (ast.GeneratorExp, ast.ListComp, ast.SetComp)):
        return _placeholder(node.elt)
    return "…"


def _placeholders_only(text: str) -> bool:
    """A message whose every word is a value filled in, such as ``<why> <remedy>``."""
    outside: list[str] = []
    depth = 0
    for char in text:
        if char == "<":
            depth += 1
        elif char == ">" and depth:
            depth -= 1
        elif not depth:
            outside.append(char)
    return not any(char.isalpha() for char in outside)


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
    # The register keeps its own count of how deep it follows a name
    # (MAX_CHAIN); Python's limit is raised so that count, not the caller's
    # stack, is what stops it.
    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(limit, 20 * MAX_CHAIN))
    try:
        reader = Reader(root)
        reader.read_platform()
        reader.index_calls()
        reader.discover_types()
        reader.read_positions()
        reader.read_flow()
        reader.read_keywords()
        reader.read_uses()
        reader.read_tests()
        reader.read_console_tests()
        reader.read_docs()
        return reader.register()
    finally:
        sys.setrecursionlimit(limit)
