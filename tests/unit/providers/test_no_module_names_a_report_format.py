"""No module outside the readers decides by a report format's name or reads a source's own block.

A sandbox report is read by the registered reader its format names
(``providers.sandbox.readers``), and every consumer reads the neutral report's
document by its parts (``schemas.sandbox_document``). So outside the readers:

* no comparison of a report's ``source_format``, a provider's
  ``report_format``, a format's ``reader`` or the REST ``report.format`` (or a
  name assigned one of them) with a literal name;
* no read keyed by a block name a sandbox gives a block the document names
  otherwise (``schemas.sandbox_report.CAPE_RENAMES``);
* no call of one reader's own function, which goes through the registry.

A reader registered tomorrow would get none of what such code gives a built-in.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SOURCES = (ROOT / "src" / "maljan", ROOT / "apps" / "api" / "app")
# The readers' home: the registry and the reader functions it calls.
READERS = frozenset(
    {
        "src/maljan/providers/sandbox/readers.py",
        "src/maljan/schemas/sandbox_report.py",
    }
)
FORMAT_ATTRIBUTES = frozenset({"source_format", "report_format", "reader"})
READER_FUNCTIONS = frozenset({"cape_report_to_sandbox_report", "triage_overview_to_sandbox_report"})

from maljan.schemas.sandbox_report import CAPE_RENAMES  # noqa: E402

SOURCE_BLOCKS = frozenset(CAPE_RENAMES)


def _literals(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return [value for element in node.elts for value in _literals(element)]
    return []


def _names_a_format(node: ast.AST, aliases: set[str]) -> bool:
    """Whether ``node`` names a format: one of the attributes, ``report.format``, an alias."""
    if isinstance(node, ast.Attribute):
        if node.attr in FORMAT_ATTRIBUTES:
            return True
        return (
            node.attr == "format"
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "report"
        )
    return isinstance(node, ast.Name) and node.id in aliases


def _aliases(tree: ast.AST) -> set[str]:
    """The names a module ever assigns a format's name to (flow-insensitive)."""
    found: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and _names_a_format(node.value, found):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id not in found:
                        found.add(target.id)
                        changed = True
    return found


def _is_literal_type(node: ast.AST) -> bool:
    """Whether ``node`` is ``Literal``: a type's choices, not a read."""
    return (isinstance(node, ast.Name) and node.id == "Literal") or (
        isinstance(node, ast.Attribute) and node.attr == "Literal"
    )


def _violations(path: Path, rel: str = "") -> list[str]:
    rel = rel or path.relative_to(ROOT).as_posix()
    if rel in READERS:
        return []
    tree = ast.parse(path.read_text(encoding="utf-8"))
    aliases = _aliases(tree)
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            sides = [node.left, *node.comparators]
            if any(_names_a_format(side, aliases) for side in sides) and any(
                _literals(side) for side in sides
            ):
                out.append(f"{rel}:{node.lineno}: compares a format's name with a literal")
        if (
            isinstance(node, ast.Subscript)
            and not _is_literal_type(node.value)
            and set(_literals(node.slice)) & SOURCE_BLOCKS
        ):
            out.append(f"{rel}:{node.lineno}: reads a source's own block by its name")
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in ("get", "pop", "setdefault")
                and node.args
                and set(_literals(node.args[0])) & SOURCE_BLOCKS
            ):
                out.append(f"{rel}:{node.lineno}: reads a source's own block by its name")
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name in READER_FUNCTIONS:
                out.append(f"{rel}:{node.lineno}: calls a reader's own function")
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in READER_FUNCTIONS:
                    out.append(f"{rel}:{node.lineno}: imports a reader's own function")
    return out


def test_no_module_outside_the_readers_names_a_report_format() -> None:
    found = [
        violation
        for source in SOURCES
        for path in sorted(source.rglob("*.py"))
        for violation in _violations(path)
    ]
    assert found == []


def test_the_guard_sees_each_form_it_refuses(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text(
        "def a(run, cfg, report):\n"
        "    fmt = cfg.report.format\n"
        "    if fmt == 'triage':\n"
        "        pass\n"
        "    if run.report.source_format in ('cape2', 'mock'):\n"
        "        pass\n"
        "    report.get('CAPE')\n"
        "    report['suricata']\n"
        "    cape_report_to_sandbox_report(report, provider='x')\n",
        encoding="utf-8",
    )
    assert len(_violations(sample, "src/maljan/sample.py")) == 5
