"""No module outside the static providers decides by a static provider's name or imports one.

Every fact the platform needs from a static provider is asked through the
interface in ``providers.base.StaticProvider``: the open before an analyst's
loop, the call graph the sink pre-pass ranks, the anti-analysis scan the pack
makes, the function hashes. A comparison of a provider id or of
``static.provider`` with a literal name, or an import of one provider's own
modules, is a behaviour a provider registered tomorrow would not get, so this
test reads every module of the core and the API and refuses one outside
``providers/static/``.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SOURCES = (ROOT / "src" / "maljan", ROOT / "apps" / "api" / "app")
OWN = "src/maljan/providers/static/"


def _literals(node: ast.AST) -> list[str]:
    """The strings a literal holds: a string, or a tuple, list or set of them."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return [value for element in node.elts for value in _literals(element)]
    return []


def _names_a_provider(node: ast.AST) -> bool:
    """Whether ``node`` reads a static provider's id: ``*provider_id`` or ``*.static.provider``."""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "str":
            return any(_names_a_provider(arg) for arg in node.args)
        return _names_a_provider(node.func)
    if isinstance(node, ast.Name):
        return node.id.endswith("provider_id")
    if isinstance(node, ast.Attribute):
        if node.attr.endswith("provider_id"):
            return True
        if node.attr == "provider":
            owner = node.value
            return (isinstance(owner, ast.Attribute) and owner.attr == "static") or (
                isinstance(owner, ast.Name) and owner.id == "static"
            )
    return False


def _imports_a_provider(module: str) -> bool:
    """Whether a dotted module path names one of Ghidra's modules, the one provider with its own."""
    return any("ghidra" in part for part in module.split("."))


def offenders(source: str, where: str = "<snippet>") -> list[str]:
    """Each comparison of a provider id with a literal, and each import of a provider's module."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Compare):
            sides = [node.left, *node.comparators]
            if any(_names_a_provider(side) for side in sides) and any(
                _literals(side) for side in sides
            ):
                found.append(f"{where}:{node.lineno} compares a provider id with a name")
        elif isinstance(node, ast.Import):
            found.extend(
                f"{where}:{node.lineno} imports {alias.name}"
                for alias in node.names
                if _imports_a_provider(alias.name)
            )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names = [f"{module}.{alias.name}" for alias in node.names]
            if _imports_a_provider(module) or any(_imports_a_provider(name) for name in names):
                found.append(f"{where}:{node.lineno} imports from {module}")
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


def test_the_guard_sees_each_way_a_provider_is_named() -> None:
    snippets = [
        'if provider_id == "ghidra": pass',
        'if provider_id != "ghidra": pass',
        'if self._provider_id() == "r2": pass',
        'if resolved.static_provider_id in ("ghidra", "r2"): pass',
        'if cfg.static.provider == "ghidra": pass',
        'if str(cfg.static.provider) == "r2": pass',
        'if "ghidra" == settings.static.provider: pass',
        "from maljan.providers.static.ghidra import GhidraStaticProvider",
        "from maljan.providers.static.ghidra.passes import GhidraPasses",
        "from maljan.providers.static import ghidra",
        "import maljan.providers.static.ghidra",
        "from maljan.analysis import ghidra_passes as p",
    ]
    for snippet in snippets:
        assert offenders(snippet), snippet


def test_the_guard_lets_a_provider_asked_by_its_interface_be() -> None:
    clean = (
        "if provider_id != str(settings.static.provider): pass\n"
        "provider = container.get_static_provider(provider_id)\n"
        "scan = provider.anti_analysis_scan(job)\n"
        'if kind_of(entry) == "anti_analysis_scan": pass\n'
        'label = provider.display_name() or "static"\n'
        "from maljan.providers.static import import_built_ins\n"
    )
    assert offenders(clean) == []
