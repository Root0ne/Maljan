"""Every module the repository tracks under src/maljan must still import by name.

The layout branch moves directories. ``maljan.*`` is the one namespace it may
not move, because ``tests/evaluation/**`` imports it and must stay byte-identical
to ``dev``. A move that renames a module, drops one from the wheel, or breaks an
import chain shows up here as a failing import rather than as a 500 in the API
three tasks later.

The module list comes from ``git ls-files``, not from a hand-written constant, so
a file added on ``dev`` after this test was written is covered the moment it is
merged.
"""

from __future__ import annotations

import importlib
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# The files that say "the default profile is what it was". They live under
# tests/unit/ with the rest of the suite.
GOLDEN_MODULES: tuple[str, ...] = (
    "tests/unit/pipeline/test_graph_snapshot.py",
    "tests/unit/agents/test_prompt_byte_identity.py",
    "tests/unit/agents/test_revision_prompt_golden.py",
    "tests/unit/servers/test_builtin_tool_sets.py",
    "tests/unit/servers/test_agent_parity.py",
    "tests/unit/test_topology_sources.py",
)


def tracked_modules() -> list[str]:
    """Dotted module names for every tracked .py file under src/maljan."""
    out = subprocess.run(
        ["git", "ls-files", "src/maljan"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    names: list[str] = []
    for rel in out:
        if not rel.endswith(".py"):
            continue
        parts = Path(rel).relative_to("src").with_suffix("").parts
        if parts[-1] == "__init__":
            parts = parts[:-1]
        if parts:
            names.append(".".join(parts))
    return sorted(set(names))


def test_the_package_has_modules_to_check() -> None:
    """A guard on the guard: an empty list would make every assertion below vacuous."""
    assert len(tracked_modules()) > 100


@pytest.mark.parametrize("name", tracked_modules())
def test_every_tracked_module_imports_under_its_own_name(name: str) -> None:
    importlib.import_module(name)


def test_the_six_golden_modules_are_where_this_plan_says_they_are() -> None:
    missing = [rel for rel in GOLDEN_MODULES if not (ROOT / rel).is_file()]
    assert missing == [], (
        "a golden module moved without this list following it: the six are the "
        "only proof the default profile is unchanged"
    )
