"""No module outside the static providers decides by a static provider's name or imports one.

Every fact the platform needs from a static provider is asked through the
interface in ``providers.base.StaticProvider``: the open before an analyst's
loop, the call graph the sink pre-pass ranks, the anti-analysis scan the pack
makes, the function hashes. A comparison of a provider id with a literal name
(directly, through a variable holding it, a string method or a ``match``), a
read keyed by a provider's id (``paths.get("ghidra")``, ``cfg.static.ghidra``),
or an import of one provider's own modules (a statement or ``import_module``)
is a behaviour a provider registered tomorrow would not get, so this test
reads every module of the core and the API and refuses one outside
``providers/static/``, except the settings and declaration modules that hold
each provider's block, each named below with its reason.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SOURCES = (ROOT / "src" / "maljan", ROOT / "apps" / "api" / "app")
OWN = "src/maljan/providers/static/"

# The static provider ids the platform ships (``providers.static.BUILT_IN_MODULES``
# registers them), the names a read keyed by a provider id would spell.
from maljan.providers.registry import static_provider_ids  # noqa: E402

PROVIDER_IDS = frozenset(static_provider_ids())

# Modules that hold each provider's own settings block or declaration by its
# key: the settings model and its catalogue, the declarations built from those
# blocks, and the retired-environment migration. The settings shape is ts2 C1's.
BLOCK_HOLDERS: dict[str, str] = {
    "src/maljan/core/config.py": "the settings model holds each provider's block by its key",
    "src/maljan/core/settings_annotations.py": "the settings catalogue describes each block",
    "src/maljan/core/tool_declarations.py": "declarations are built from each provider's block",
    "src/maljan/core/builtin_declarations.py": "the shipped declaration of each provider's block",
}


def _literals(node: ast.AST) -> list[str]:
    """The strings a literal holds: a string, or a tuple, list or set of them."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return [value for element in node.elts for value in _literals(element)]
    return []


def _scope_nodes(scope: ast.AST) -> list[ast.AST]:
    """The nodes of one scope (a module or a function), without the functions inside it."""
    out: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        out.append(node)
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            stack.extend(ast.iter_child_nodes(node))
    return out


class _Reads:
    """What in one scope reads a static provider's id, the scope's own aliases included."""

    def __init__(self, scope: ast.AST, inherited: frozenset[str] = frozenset()) -> None:
        self.aliases: set[str] = set(inherited)
        # Flow-insensitive within the scope: a name ever assigned a provider id holds one.
        changed = True
        while changed:
            changed = False
            for node in _scope_nodes(scope):
                targets: list[ast.AST] = []
                value: ast.AST | None = None
                if isinstance(node, ast.Assign):
                    targets, value = list(node.targets), node.value
                elif isinstance(node, ast.AnnAssign | ast.NamedExpr) and node.value is not None:
                    targets, value = [node.target], node.value
                if value is None or not self.id_of(value):
                    continue
                for target in targets:
                    if isinstance(target, ast.Name) and target.id not in self.aliases:
                        self.aliases.add(target.id)
                        changed = True

    def id_of(self, node: ast.AST) -> bool:
        """Whether ``node`` evaluates to a static provider's id."""
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "str":
                return any(self.id_of(arg) for arg in node.args)
            if isinstance(func, ast.Name) and func.id == "getattr" and len(node.args) >= 2:
                attr = node.args[1]
                if not isinstance(attr, ast.Constant):
                    return False
                if attr.value == "id":
                    return _looks_like_a_provider(node.args[0])
                return str(attr.value).endswith("provider_id")
            if isinstance(func, ast.Attribute) and func.attr in {"lower", "strip", "casefold"}:
                return self.id_of(func.value)
            return self.id_of(func)
        if isinstance(node, ast.BoolOp):
            return any(self.id_of(value) for value in node.values)
        if isinstance(node, ast.Name):
            return node.id.endswith("provider_id") or node.id in self.aliases
        if isinstance(node, ast.Attribute):
            if node.attr.endswith("provider_id") or node.attr == "id":
                return node.attr != "id" or _looks_like_a_provider(node.value)
            if node.attr == "provider":
                owner = node.value
                return (isinstance(owner, ast.Attribute) and owner.attr == "static") or (
                    isinstance(owner, ast.Name) and owner.id == "static"
                )
        return False


def _looks_like_a_provider(node: ast.AST) -> bool:
    """Whether the object an ``.id`` is read from is a provider (by the name it goes by)."""
    if isinstance(node, ast.Call):
        node = node.func
    name = node.id if isinstance(node, ast.Name) else getattr(node, "attr", "")
    return "provider" in str(name).lower()


def _names_a_provider(node: ast.AST) -> bool:
    """Whether a variable or attribute goes by a provider's name (``provider`` and the like)."""
    name = node.id if isinstance(node, ast.Name) else getattr(node, "attr", "")
    return isinstance(node, ast.Name | ast.Attribute) and "provider" in str(name).lower()


def _imports_a_provider(module: str) -> bool:
    """Whether a dotted module path names one of Ghidra's modules, the one provider with its own."""
    return any("ghidra" in part for part in module.split("."))


def offenders(source: str, where: str = "<snippet>") -> list[str]:
    """Each place ``source`` decides by, reads by or imports a static provider's name."""
    tree = ast.parse(source)
    holder = where in BLOCK_HOLDERS
    found: list[str] = []
    module = _Reads(tree)
    scopes: list[tuple[ast.AST, _Reads]] = [(tree, module)]
    scopes += [
        (node, _Reads(node, frozenset(module.aliases)))
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    ]
    for scope, reads in scopes:
        found.extend(_scope_offenders(scope, reads, holder, where))
    return found


def _scope_offenders(scope: ast.AST, reads: _Reads, holder: bool, where: str) -> list[str]:
    found: list[str] = []
    for node in _scope_nodes(scope):
        line = getattr(node, "lineno", 0)
        if isinstance(node, ast.Compare):
            sides = [node.left, *node.comparators]
            named = [value for side in sides for value in _literals(side)]
            if any(reads.id_of(side) for side in sides) and named:
                found.append(f"{where}:{line} compares a provider id with a name")
            elif any(_names_a_provider(side) for side in sides) and PROVIDER_IDS & set(named):
                found.append(f"{where}:{line} compares a provider with a provider's id")
        elif isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in {"startswith", "endswith"}
                and reads.id_of(func.value)
                and any(_literals(arg) for arg in node.args)
            ):
                found.append(f"{where}:{line} tests a provider id against a name")
            named = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if named == "import_module" and any(
                _imports_a_provider(value) for arg in node.args for value in _literals(arg)
            ):
                found.append(f"{where}:{line} imports a provider module by name")
            if (
                named == "get"
                and not holder
                and node.args
                and any(value in PROVIDER_IDS for value in _literals(node.args[0]))
            ):
                found.append(f"{where}:{line} reads by a provider's id")
        elif isinstance(node, ast.Match) and reads.id_of(node.subject):
            found.append(f"{where}:{line} matches on a provider id")
        elif isinstance(node, ast.Subscript) and not holder:
            if any(value in PROVIDER_IDS for value in _literals(node.slice)):
                found.append(f"{where}:{line} reads by a provider's id")
        elif isinstance(node, ast.Attribute) and not holder:
            owner = node.value
            static = (isinstance(owner, ast.Attribute) and owner.attr == "static") or (
                isinstance(owner, ast.Name) and owner.id == "static"
            )
            if static and node.attr in PROVIDER_IDS:
                found.append(f"{where}:{line} reads a provider's own block")
        elif isinstance(node, ast.Import):
            found.extend(
                f"{where}:{line} imports {alias.name}"
                for alias in node.names
                if _imports_a_provider(alias.name)
            )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = [f"{module}.{alias.name}" for alias in node.names]
            if _imports_a_provider(module) or any(_imports_a_provider(name) for name in names):
                found.append(f"{where}:{line} imports from {module}")
    return found


def test_no_module_outside_the_static_providers_names_or_imports_one() -> None:
    found: list[str] = []
    for source in SOURCES:
        for path in sorted(source.rglob("*.py")):
            relative = path.relative_to(ROOT).as_posix()
            if relative.startswith(OWN):
                continue
            found.extend(offenders(path.read_text(encoding="utf-8"), relative))
    assert found == [], "\n".join(found)


GUARDED_FORMS = [
    'if provider_id == "ghidra": pass',
    'if provider_id != "ghidra": pass',
    'if self._provider_id() == "r2": pass',
    'if resolved.static_provider_id in ("ghidra", "r2"): pass',
    'if cfg.static.provider == "ghidra": pass',
    'if str(cfg.static.provider) == "r2": pass',
    'if "ghidra" == settings.static.provider: pass',
    'if provider.id == "ghidra": pass',
    'if self._provider().id == "ghidra": pass',
    'if getattr(provider, "id", "") == "ghidra": pass',
    'provider = _effective_static_provider(overrides)\nif provider != "none": pass',
    'provider = cfg.static.provider\nif provider == "ghidra": pass',
    'chosen = str(cfg.static.provider)\nother = chosen\nif other in {"r2"}: pass',
    'if (cfg.static.provider or "") == "ghidra": pass',
    'if cfg.static.provider.startswith("ghid"): pass',
    'match cfg.static.provider:\n    case "ghidra":\n        pass',
    'path = paths.get("ghidra")',
    'path = state["static_sample_paths"]["ghidra"]',
    "url = cfg.static.ghidra.url",
    "block = settings.static.r2",
    'importlib.import_module("maljan.providers.static.ghidra")',
    'import_module("maljan.providers.static.ghidra.passes")',
    "from maljan.providers.static.ghidra import GhidraStaticProvider",
    "from maljan.providers.static.ghidra.passes import GhidraPasses",
    "from maljan.providers.static import ghidra",
    "import maljan.providers.static.ghidra",
    "from maljan.analysis import ghidra_passes as p",
]


@pytest.mark.parametrize("snippet", GUARDED_FORMS)
def test_the_guard_sees_each_way_a_provider_is_named(snippet: str) -> None:
    assert offenders(snippet), snippet


@pytest.mark.parametrize("snippet", GUARDED_FORMS)
def test_each_form_mutated_into_a_real_module_is_refused(snippet: str) -> None:
    """The triage node's module is clean as it is, and refused with any one form added."""
    where = "src/maljan/pipeline/nodes.py"
    real = (ROOT / where).read_text(encoding="utf-8")
    assert offenders(real, where) == []
    body = "\n".join("    " + line for line in snippet.splitlines())
    mutated = f"{real}\n\ndef _mutation(cfg, paths, provider, self, state, settings, p):\n{body}\n"
    assert offenders(mutated, where), snippet


def test_a_settings_block_holder_may_hold_a_block_by_its_key() -> None:
    assert offenders("url = cfg.static.ghidra.url", "src/maljan/core/config.py") == []
    # A comparison is still refused there.
    assert offenders('if cfg.static.provider == "r2": pass', "src/maljan/core/config.py")


def test_the_guard_lets_a_provider_asked_by_its_interface_be() -> None:
    clean = (
        "if provider_id != str(settings.static.provider): pass\n"
        "provider = container.get_static_provider(provider_id)\n"
        "scan = provider.anti_analysis_scan(job)\n"
        'if kind_of(entry) == "anti_analysis_scan": pass\n'
        'label = provider.display_name() or "static"\n'
        "if provider_id == NO_STATIC_PROVIDER: pass\n"
        'if entry.id == "ev_0001": pass\n'
        'value = row.get("rule")\n'
        "from maljan.providers.static import import_built_ins\n"
        'importlib.import_module("maljan.providers.static.r2")\n'
    )
    assert offenders(clean) == []
