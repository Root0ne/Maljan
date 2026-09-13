"""No alembic revision imports the application, and this is why.

Alembic imports *every* revision file on every run, to build the history —
including revisions from releases nobody has run in a year. A revision that
imports `maljan` therefore couples the whole migration history to a name in the
application: rename or delete that name and `alembic upgrade head` stops
working on every database, including the ones the revision has already been
applied to.

It is the same reason a revision keeps its own copy of every constant it needs.
A migration has to keep doing what was correct on the day it ran, and anything
imported from the application follows the application instead.

An AST scan rather than a grep, so a name in a docstring or a comment — the
copy notice a duplicated helper carries, for instance — is not mistaken for a
dependency, and so a deferred import inside a function is caught as readily as
one at the top of the file.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

VERSIONS = Path(__file__).resolve().parents[3] / "apps/api/alembic/versions"

# What a revision may not reach into. `app` is the FastAPI package and `maljan`
# the core one; both move under the revisions' feet.
FORBIDDEN_ROOTS = {"maljan", "app"}


def _revisions() -> list[Path]:
    return sorted(p for p in VERSIONS.glob("*.py") if p.name != "__init__.py")


def _imported_roots(tree: ast.AST) -> set[str]:
    """Every top-level package this module imports, however it imports it."""
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            # A relative import has no module root to speak of, and would be
            # just as wrong; `level` catches it.
            if node.level:
                roots.add(".")
            elif node.module:
                roots.add(node.module.split(".")[0])
    return roots


def test_there_are_revisions_to_check():
    """A glob that matches nothing would make every assertion below vacuous."""
    assert len(_revisions()) > 5


@pytest.mark.parametrize("revision", _revisions(), ids=lambda p: p.name)
def test_a_revision_imports_no_application_code(revision: Path):
    roots = _imported_roots(ast.parse(revision.read_text(encoding="utf-8")))
    offenders = sorted(roots & FORBIDDEN_ROOTS)
    assert not offenders, (
        f"{revision.name} imports {', '.join(offenders)}. Alembic loads every "
        "revision on every run, so the whole history breaks when that name "
        "moves. Keep a copy in the revision instead."
    )


def test_the_rename_revision_carries_its_own_copy_of_the_helper():
    """The revision this rule was written against, named so the next reader
    finds the worked example rather than only the rule."""
    revision = VERSIONS / "20260917000000_rename_colliding_agent_keys.py"
    tree = ast.parse(revision.read_text(encoding="utf-8"))
    assert not _imported_roots(tree) & FORBIDDEN_ROOTS
    functions = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert "set_if_list" in functions
