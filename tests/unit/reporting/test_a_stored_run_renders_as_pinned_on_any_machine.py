"""Every stored-run render pin renders without this machine's configured model endpoints.

The stored benchmark runs are on the developer's machine only, so CI skips the
tests that render them, and a pin that depends on the machine is never caught
there. A model's recorded endpoint prints kept only where the settings
configure it, and the settings read the checkout's ``.env``: a stored run
rendered where the ``.env`` names the run's own endpoint misses a pin taken
anywhere else. This check runs everywhere, CI included: a test that reads the
stored runs (``_benchmark``) and renders must use
``no_model_endpoint_configured``, itself or through its module's ``pytestmark``.
"""

from __future__ import annotations

import ast
from pathlib import Path

TESTS = Path(__file__).resolve().parents[2]
FIXTURE = "no_model_endpoint_configured"


def _uses_fixture(decorators: list[ast.expr]) -> bool:
    return any(
        isinstance(d, ast.Call)
        and isinstance(d.func, ast.Attribute)
        and d.func.attr == "usefixtures"
        and any(isinstance(a, ast.Constant) and a.value == FIXTURE for a in d.args)
        for d in decorators
    )


def _renders(node: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "render"
        for n in ast.walk(node)
    )


def _calls(node: ast.AST) -> set[str]:
    calls = (n for n in ast.walk(node) if isinstance(n, ast.Call))
    return {n.func.id for n in calls if isinstance(n.func, ast.Name)}


def _unguarded(path: Path) -> list[str]:
    """The tests in ``path`` that read the stored runs and render without the fixture."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    assigns = (n for n in tree.body if isinstance(n, ast.Assign))
    marks = [n.value for n in assigns if "pytestmark" in {getattr(t, "id", "") for t in n.targets}]
    if _uses_fixture(marks):
        return []
    functions = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    # A test reads the stored runs where it, or a helper of its module it calls, calls _benchmark.
    readers = {"_benchmark"}
    while grown := {name for name, f in functions.items() if _calls(f) & readers} - readers:
        readers |= grown
    return [
        f"{path.name}::{name}"
        for name, node in functions.items()
        if name.startswith("test_")
        and name in readers
        and _renders(node)
        and not _uses_fixture(node.decorator_list)
    ]


def test_every_test_that_renders_a_stored_run_reads_no_configured_endpoint() -> None:
    readers = [p for p in sorted(TESTS.rglob("test_*.py")) if "_benchmark(" in p.read_text()]
    assert readers, "no test reads the stored runs; this check checks nothing"
    assert [name for path in readers for name in _unguarded(path)] == []


def test_a_render_without_the_fixture_is_named(tmp_path: Path) -> None:
    body = (
        "def _report():\n    return _benchmark()\n"
        "def test_x():\n    MarkdownRenderer().render(_report())\n"
        "def test_y():\n    MarkdownRenderer().render(None)\n"
    )
    (tmp_path / "test_bare.py").write_text(body, encoding="utf-8")
    marked = body.replace(
        "def test_x", '@pytest.mark.usefixtures("no_model_endpoint_configured")\ndef test_x'
    )
    (tmp_path / "test_marked.py").write_text(marked, encoding="utf-8")
    module = 'pytestmark = pytest.mark.usefixtures("no_model_endpoint_configured")\n' + body
    (tmp_path / "test_module.py").write_text(module, encoding="utf-8")

    assert _unguarded(tmp_path / "test_bare.py") == ["test_bare.py::test_x"]
    assert _unguarded(tmp_path / "test_marked.py") == []
    assert _unguarded(tmp_path / "test_module.py") == []
