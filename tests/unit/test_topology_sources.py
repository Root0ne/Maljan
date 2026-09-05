"""Only one thing may decide which analysts exist, and no agent may know its own name.

Risk R1 in the spec: five call sites read ``AgentRegistry.list_agents()``
today, and missing one leaves a node set that disagrees with the active
profile. Risk R2: a built-in class running under a clone's name diverges the
moment anything branches on ``self.name == "static"``.

This test is written against today's code and passes unchanged: the
allow-lists below name every current call site. Task 7 shrinks
``TOPOLOGY_SOURCES`` to the registry and the parity test, and removes the
name branches ``NAME_BRANCHES`` records, editing this file to match. It is a
ratchet, so it only ever gets smaller.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEARCHED = [ROOT / "src" / "maljan", ROOT / "apps" / "api" / "app"]

# Where "which analysts exist" may be answered from. Task 7 reduces this to
# the registry itself plus the parity test that compares it with the seeds.
TOPOLOGY_SOURCES: set[str] = {
    "src/maljan/agents/registry.py",
    "src/maljan/pipeline/builder.py",
    "src/maljan/pipeline/nodes.py",
    "src/maljan/core/container.py",
    "src/maljan/app.py",
    "src/maljan/cli.py",
    "apps/api/app/worker/analysis_worker.py",
}

# Where an agent's *key* may be compared against a literal built-in name.
# Every one of these is a static-role branch that must become a role check
# once a clone of ``static`` can run under another key (Task 7).
NAME_BRANCHES: set[str] = {
    "src/maljan/core/container.py",
    "src/maljan/pipeline/nodes.py",
}

_LIST_AGENTS = re.compile(r"\blist_agents\s*\(")
_NAME_EQ = re.compile(
    r"""(?:self\.name|agent_name|\bname)\s*==\s*["'](?:static|dynamic|network)["']"""
)


def _python_files() -> list[Path]:
    return [p for root in SEARCHED for p in root.rglob("*.py") if "__pycache__" not in p.parts]


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def test_list_agents_is_called_only_where_the_allow_list_says():
    offenders = sorted(
        _rel(p)
        for p in _python_files()
        if _LIST_AGENTS.search(p.read_text(encoding="utf-8")) and _rel(p) not in TOPOLOGY_SOURCES
    )
    assert offenders == [], (
        "a new topology source appeared: read the active profile "
        "(container.analyst_keys()) instead of the class registry"
    )


def test_the_allow_list_names_no_file_that_stopped_calling_it():
    """A ratchet only ratchets if it is trimmed when a call site goes away."""
    calling = {
        _rel(p) for p in _python_files() if _LIST_AGENTS.search(p.read_text(encoding="utf-8"))
    }
    stale = sorted(TOPOLOGY_SOURCES - calling - {"tests/servers/test_agent_parity.py"})
    assert stale == [], f"remove these from TOPOLOGY_SOURCES: {stale}"


def test_no_new_module_branches_on_a_built_in_agent_name():
    offenders = sorted(
        _rel(p)
        for p in _python_files()
        if _NAME_EQ.search(p.read_text(encoding="utf-8")) and _rel(p) not in NAME_BRANCHES
    )
    assert offenders == [], (
        "an agent's key is not its role: a clone of 'static' runs under its own "
        "key, so branch on container.agent_role(key) instead"
    )


def test_the_recorded_name_branches_are_the_ones_that_exist_today():
    """Names the debt explicitly so Task 7 can prove it paid it off."""
    branching = {_rel(p) for p in _python_files() if _NAME_EQ.search(p.read_text(encoding="utf-8"))}
    assert branching == NAME_BRANCHES
