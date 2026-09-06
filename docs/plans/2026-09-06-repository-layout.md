# Repository layout implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the repository's top level into the shape the design fixes — sidecars under `services/`, scripts grouped by kind, one `tests/unit` mirror, shared panels under `apps/web/src/components/analysis/`, images under `docs/assets/`, and one uv workspace instead of two projects stitched together with `PYTHONPATH` — without changing a single byte of behaviour.

**Architecture:** Eight sequential tasks on one branch, one commit each, and every commit carries the references its move breaks so the tree is green at each of them. The order is forced by what each task's verification needs. Task 1 lands the guards before anything moves: a layout test that imports every `maljan` module, a script-path test that reads the `Makefile`, and a Docker manifest test that reads `docker/Dockerfile.backend` — the three files that name paths a move invalidates, so a broken reference fails a test rather than a deploy. Task 2 makes the workspace next, because every later verification wants `maljan` and `app` importable with no environment variable to keep in step with the moves; doing it after the moves would mean fixing `PYTHONPATH` strings twice. Task 3 (sidecars) precedes Task 4 (scripts) so `scripts/capture_builtin_tool_sets.py` is edited exactly once per concern: Task 3 changes its two sidecar directory literals while it still sits at its old path, Task 4 changes its `parents[]` anchor when it moves into `scripts/goldens/`. Task 5 (tests) comes after 3 and 4 so `tests/unit/test_topology_sources.py`'s allow-list and `tests/unit/scripts/`'s script anchors are each rewritten once, at their final paths. Task 6 (web) touches no Python and could run anywhere; it sits here so the Python suite is already at rest when the frontend gates run. Task 7 (docs and root hygiene) is last of the moves because the README's new "Repository layout" section describes the finished tree. Task 8 proves the whole thing from a clean clone, a Docker build and one live job. Behaviour is proven by counts and goldens, never by inspection: the collected test count recorded in Task 1 must equal the count in Tasks 5 and 8, the six golden modules run at the end of every task, and `make facts` plus `git diff dev -- tests/evaluation` stay empty throughout.

**Tech Stack:** Python 3.13, uv 0.11.28 workspaces, hatchling, pytest, mypy, ruff, semgrep; FastAPI + arq (`apps/api`); LangChain / LangGraph, MCP (stdio + streamable-http); Next.js 16 / React 19 / TypeScript, Playwright; Docker Compose; GNU Make; GitHub Actions.

**Spec:** docs/specs/2026-09-06-repository-layout-design.md

## Global Constraints

From the spec (§2 and §5):

- `maljan.*` module paths do not change. No module is renamed, split or merged; `src/maljan/` internals are out of scope (§6).
- One uv workspace: root `maljan` plus member `apps/api` (`maljan-api`), one `uv.lock` at the root. Every `PYTHONPATH` and `sys.path` shortcut that existed to make the two halves import each other goes away.
- Sidecars live at `services/network-mcp/` and `services/threatintel-mcp/`; scripts at `scripts/{dev,goldens,knowledge,paper,settings}/`; tests under `tests/{unit,api,integration,fixtures,evaluation}/` only; shared panels at `apps/web/src/components/analysis/`; images at `docs/assets/`.
- `other/`, `logs/`, `models/`, `external/` and the `data/samples` binaries stay exactly where they are. Only the root `llama.log` is removed.
- No behaviour change anywhere. This is a move.
- Clean install works: `uv sync --all-extras` at the root installs both packages, `uv run pytest tests/ -q` passes, `uv run maljan --help` works, `uv run --directory apps/api uvicorn app.main:app --help` works.
- Docker: `docker compose -f docker/docker-compose.yml config` validates, `docker build -f docker/Dockerfile.backend .` succeeds and the image imports both packages without `PYTHONPATH`, the frontend image builds.
- Web: `tsc --noEmit`, `npm run lint` (pre-existing warnings only), `npm run build`, `analysis-tabs.spec.ts` on chromium.

Project constraints, verbatim:

- `tests/evaluation/**` is never modified. `make facts` stays byte-identical and `git diff dev -- tests/evaluation` stays empty. The pinned test-count artefact is never re-pinned.
- The collected test count does not change. It is recorded in Task 1 Step 1 and compared in Tasks 5 and 8.
- No AI self-attribution in commits, comments, docs or generated files.
- No question sentences in headings, comments or docs.
- Every step's commit leaves the tree green: `uv run pytest tests/ -q` at the end of each task, and the six golden modules at the end of each task.
- Never `git checkout`, `git stash` or `git reset`. `git add` explicit paths only.
- `git mv` for every move, so history follows the file.
- Check `free -g` before any heavy step (the uv resolve, the Docker builds, the full suite, the live smoke). A `llama-server` at ~15 GB plus an arq worker leaves little room on this box; stop what is running before the heavy step, and never stop the separate `cti-life` project to reclaim it.
- Implementers do not spawn subagents.

Working rules: branch `chore/repo-layout` from `dev` (7c2d517), one commit per task, imperative lowercase messages with a `chore:` / `refactor:` / `docs:` / `test:` prefix. Run only the modules a task names mid-task; the full suite at the end of the task.

## The six golden modules

The files that say "the default profile is what it was". They run at the end of every task, at whatever path they currently hold.

| Before Task 5 | From Task 5 on |
| :-- | :-- |
| `tests/pipeline/test_graph_snapshot.py` | `tests/unit/pipeline/test_graph_snapshot.py` |
| `tests/agents/test_prompt_byte_identity.py` | `tests/unit/agents/test_prompt_byte_identity.py` |
| `tests/agents/test_revision_prompt_golden.py` | `tests/unit/agents/test_revision_prompt_golden.py` |
| `tests/servers/test_builtin_tool_sets.py` | `tests/unit/servers/test_builtin_tool_sets.py` |
| `tests/servers/test_agent_parity.py` | `tests/unit/servers/test_agent_parity.py` |
| `tests/unit/test_topology_sources.py` | `tests/unit/test_topology_sources.py` |

Tasks 1-4 end with:

```bash
uv run pytest tests/pipeline/test_graph_snapshot.py tests/agents/test_prompt_byte_identity.py \
  tests/agents/test_revision_prompt_golden.py tests/servers/test_builtin_tool_sets.py \
  tests/servers/test_agent_parity.py tests/unit/test_topology_sources.py -q
```

Tasks 5-8 end with:

```bash
uv run pytest tests/unit/pipeline/test_graph_snapshot.py tests/unit/agents/test_prompt_byte_identity.py \
  tests/unit/agents/test_revision_prompt_golden.py tests/unit/servers/test_builtin_tool_sets.py \
  tests/unit/servers/test_agent_parity.py tests/unit/test_topology_sources.py -q
```

## The ledger

Filled in by the step named in the last column, and read back by the step named in the row. Nothing else in this plan depends on a number that is not in this table.

| Fact | Value | Recorded by |
| :-- | :-- | :-- |
| Collected test count on the branch point | _(written by Task 1 Step 1)_ | Task 1 Step 1 |
| Collected test count after the test move | _(written by Task 5 Step 6)_ | Task 5 Step 6, equal to the row above |
| Collected test count at the final gate | _(written by Task 8 Step 2)_ | Task 8 Step 2, equal to both rows above |
| `npm run lint` warning count on the branch point | _(written by Task 6 Step 1)_ | Task 6 Step 1 |

## File structure

The target tree, one line per directory on what moves in and which references change.

```
maljan/
├── apps/
│   ├── api/                 workspace member "maljan-api"; nothing moves in, but its
│   │                        pyproject switches to hatchling + a workspace source, its
│   │                        uv.lock is deleted, and analysis_worker.py loses its
│   │                        sys.path.insert block (Task 2)
│   └── web/
│       └── src/components/analysis/   six panels move in from the [id]/<tab>/ folders;
│                                      importers are detection/page.tsx and
│                                      process/page.tsx (Task 6)
├── src/maljan/              nothing moves; docstrings that name a script path are
│                            retargeted (Task 4)
├── services/
│   ├── network-mcp/         server.py + a new README.md; referenced by
│   │                        core/config.py::_builtin_servers, capture_builtin_tool_sets.py,
│   │                        Dockerfile.backend, Makefile PY_SOURCES, ci.yml, .dockerignore,
│   │                        tests/unit/core/test_server_settings.py, apps/web/e2e/mocks.ts
│   └── threatintel-mcp/     server.py + a new README.md; the same reference set plus
│                            apps/web/e2e/settings-servers.spec.ts and .env.example (Task 3)
├── scripts/
│   ├── dev/                 llm_server.sh night_guard.sh run_with_restarts.sh
│   │                        ghidra_manager.py cape_mcp_wrapper.py fetch_external.sh;
│   │                        referenced by Makefile (setup, external, ghidra-*), README,
│   │                        tests/unit/scripts/test_llm_server.py, test_night_guard.py
│   ├── goldens/             capture_builtin_tool_sets.py capture_graph_golden.py
│   │                        capture_provider_goldens.py capture_revision_prompt_golden.py
│   │                        probe_r2_tools.py; referenced by src/maljan/providers/static/r2.py
│   ├── knowledge/           build_api_capability_db.py build_attck_case_kb.py
│   │                        build_family_feature_kb.py expand_yara_rules.py
│   │                        prepare_attck_malware_fixtures.py prepare_tram_dataset.py;
│   │                        referenced by Makefile (prepare-*, prepare-api-db),
│   │                        src/maljan/core/config.py and settings_annotations.py,
│   │                        tests/unit/scripts/test_build_attck_case_kb.py,
│   │                        test_expand_yara_rules.py
│   ├── paper/               check_paper.sh complete_cohort.sh; referenced by Makefile
│   │                        (paper-check, cohort-complete)
│   └── settings/            seed_settings_annotations.py; referenced by
│                            src/maljan/core/settings_annotations.py (Task 4)
├── tests/
│   ├── unit/                gains agents/ (9 files merged into the existing folder),
│   │                        pipeline/ (1 file), providers/ (new, with sandbox/ and
│   │                        static/), servers/ (new); every moved file's parents[] anchor
│   │                        gains one level; test_topology_sources.py's allow-list is
│   │                        retargeted (Task 5)
│   ├── api/ integration/ fixtures/   unchanged, except the rest_stub import in
│   │                        integration/test_rest_sandbox_end_to_end.py (Task 5)
│   └── evaluation/          never touched
├── data/                    unchanged
├── docker/                  Dockerfile.backend rewritten (Task 2, COPY lines again in
│                            Task 3); both compose files lose their PYTHONPATH lines and
│                            gain a services bind mount (Task 2, Task 3)
├── docs/
│   ├── README.md            new index (Task 7)
│   ├── assets/              the five images move in from assets/; README links follow
│   ├── specs/ plans/        left as history, including their old path mentions
├── .github/workflows/ci.yml  path lists follow the sidecars (Task 3)
└── Makefile pyproject.toml uv.lock README.md LICENSE .env.example .gitignore
    .dockerignore .pre-commit-config.yaml .semgrepignore
```

`llama.log` at the root is deleted (Task 7). `assets/` ceases to exist (Task 7). `network-mcp/` and `threatintel-mcp/` cease to exist (Task 3).

---

### Task 1: The guards, before a single file moves

**Files:**
- Create: `tests/unit/test_package_layout.py`, `tests/unit/scripts/test_makefile_script_paths.py`, `tests/unit/test_docker_manifest.py`
- Modify: nothing. This task must not touch `src/`, `apps/`, `scripts/`, `docker/` or any configuration file.
- Test: the three new modules.

**Interfaces:**
- Consumes: `git ls-files src/maljan` through `subprocess`, `importlib.import_module`, `Path.read_text` over `Makefile` and `docker/Dockerfile.backend`.
- Produces:
  ```python
  # tests/unit/test_package_layout.py
  ROOT: Path                       # repo root, parents[2] of this file
  GOLDEN_MODULES: tuple[str, ...]  # the six paths from "The six golden modules" above
  def tracked_modules() -> list[str]        # dotted names from git ls-files src/maljan
  # tests/unit/scripts/test_makefile_script_paths.py
  def makefile_script_tokens() -> set[str]  # every scripts/... token in the Makefile
  # tests/unit/test_docker_manifest.py
  def copy_sources(dockerfile: Path) -> list[str]   # the <src> operands of every COPY
  ```

- [ ] **Step 1: Record the branch point**

```bash
free -g
git rev-parse --abbrev-ref HEAD          # chore/repo-layout
git status --short                        # clean
uv run pytest tests/ -q --co -q | tail -1
```

Write the number that last command prints into the ledger table above, in the row "Collected test count on the branch point", replacing the parenthesised placeholder. This number is the contract for Tasks 5 and 8; nothing else pins it.

- [ ] **Step 2: The package layout test**

```python
# tests/unit/test_package_layout.py
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

# The files that say "the default profile is what it was". Their paths change in
# Task 5, when the four stray test folders merge into tests/unit/.
GOLDEN_MODULES: tuple[str, ...] = (
    "tests/pipeline/test_graph_snapshot.py",
    "tests/agents/test_prompt_byte_identity.py",
    "tests/agents/test_revision_prompt_golden.py",
    "tests/servers/test_builtin_tool_sets.py",
    "tests/servers/test_agent_parity.py",
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
```

- [ ] **Step 3: The Makefile script-path test**

```python
# tests/unit/scripts/test_makefile_script_paths.py
"""Every scripts/... path the Makefile names must exist.

Task 4 regroups twenty scripts into five directories. A target that still names
the old path fails only when somebody runs that target, which for ``paper-check``
and ``cohort-complete`` can be weeks later. Reading the Makefile and stat-ing
what it names turns that into a test failure in the same commit as the move.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MAKEFILE = ROOT / "Makefile"

# A path token starting with "scripts/". Stops at whitespace, a quote, a comma or
# a closing paren, so `$(PY_SOURCES)` expansions and shell quoting do not bleed in.
_SCRIPT_TOKEN = re.compile(r"scripts/[A-Za-z0-9_./-]+")


def makefile_script_tokens() -> set[str]:
    """Every distinct scripts/... token in the Makefile, comments included."""
    return {
        token.rstrip("/")
        for token in _SCRIPT_TOKEN.findall(MAKEFILE.read_text(encoding="utf-8"))
        if token != "scripts/"
    }


def test_the_makefile_names_scripts_at_all() -> None:
    assert len(makefile_script_tokens()) >= 8


def test_every_script_the_makefile_names_exists() -> None:
    missing = sorted(t for t in makefile_script_tokens() if not (ROOT / t).exists())
    assert missing == [], f"the Makefile names paths that are not there: {missing}"
```

- [ ] **Step 4: The Docker manifest test**

```python
# tests/unit/test_docker_manifest.py
"""Every COPY source in the backend Dockerfile must exist in the tree.

``docker build`` is the slowest way to learn that a directory was renamed, and on
this box it is also the most expensive. The Dockerfile's COPY operands are a
manifest of what the image needs; checking them against the working tree costs
milliseconds and catches the sidecar move (Task 3) and the manifests-first
rewrite (Task 2) at commit time.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "docker" / "Dockerfile.backend"


def copy_sources(dockerfile: Path) -> list[str]:
    """The <src> operands of every COPY that reads from the build context."""
    sources: list[str] = []
    for raw in dockerfile.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line.upper().startswith("COPY "):
            continue
        parts = line.split()[1:]
        # ``COPY --from=<image> ...`` reads from another stage, not the context.
        if any(p.startswith("--from=") for p in parts):
            continue
        parts = [p for p in parts if not p.startswith("--")]
        # The last operand is the destination inside the image.
        sources.extend(parts[:-1])
    return sources


def test_the_backend_dockerfile_copies_something() -> None:
    assert len(copy_sources(BACKEND)) >= 4


def test_every_backend_copy_source_exists() -> None:
    missing = sorted(s for s in copy_sources(BACKEND) if not (ROOT / s.rstrip("/")).exists())
    assert missing == [], f"Dockerfile.backend copies paths that are not there: {missing}"
```

- [ ] **Step 5: Run the three new modules**

```bash
uv run pytest tests/unit/test_package_layout.py tests/unit/scripts/test_makefile_script_paths.py \
  tests/unit/test_docker_manifest.py -q
```
Expected: PASS. Every assertion is written against today's tree, so a failure here is a pre-existing broken reference and must be reported before any move begins.

- [ ] **Step 6: Lint, type-check and commit**

```bash
uv run ruff check tests/unit/test_package_layout.py tests/unit/scripts/test_makefile_script_paths.py tests/unit/test_docker_manifest.py && \
uv run ruff format --check tests/unit/test_package_layout.py tests/unit/scripts/test_makefile_script_paths.py tests/unit/test_docker_manifest.py && \
uv run mypy src/ apps/api/
git add tests/unit/test_package_layout.py tests/unit/scripts/test_makefile_script_paths.py \
  tests/unit/test_docker_manifest.py docs/plans/2026-09-06-repository-layout.md
git commit -m "test: guard the module namespace, the makefile script paths and the docker manifest"
```

- [ ] **Step 7: Full suite and the goldens**

```bash
free -g
uv run pytest tests/ -q
uv run pytest tests/pipeline/test_graph_snapshot.py tests/agents/test_prompt_byte_identity.py \
  tests/agents/test_revision_prompt_golden.py tests/servers/test_builtin_tool_sets.py \
  tests/servers/test_agent_parity.py tests/unit/test_topology_sources.py -q
```
Expected: PASS, at the ledger's recorded count plus the tests this task adds.

---

### Task 2: One uv workspace

**Files:**
- Modify: `pyproject.toml` (add `[tool.uv.workspace]`, drop `[tool.pytest.ini_options].pythonpath`, drop `[tool.mypy].mypy_path`), `apps/api/pyproject.toml` (hatchling, workspace source, drop `pythonpath`), `apps/api/app/worker/analysis_worker.py:460-468`, `tests/conftest.py:1-15`, `Makefile:68,74,87`, `docker/Dockerfile.backend` (full rewrite), `docker/docker-compose.yml:172,264` (and the two volume lists at `:213-217`, `:328-332`), `uv.lock` (regenerated)
- Delete: `apps/api/uv.lock`
- Test: `tests/unit/test_docker_manifest.py`, `tests/unit/test_package_layout.py`, `tests/unit/test_compose_config.py`, `tests/unit tests/api`

**Interfaces:**
- Produces: a root `uv.lock` that resolves both `maljan` and `maljan-api`; `maljan-api` as a hatchling wheel over the `app` package; both installed editable into the root `.venv`, so `import maljan` and `import app` succeed from any working directory with no environment variable set.
- Consumes: uv 0.11.28's workspace resolution (`[tool.uv.workspace]` at the root, `{ workspace = true }` in the member).

- [ ] **Step 1: Root pyproject**

Add a workspace table immediately after `[tool.hatch.build.targets.wheel]`:

```toml
# One workspace, one lockfile. apps/api used to be a separate uv project with its
# own uv.lock and a path dependency back here, which is why the runtime needed
# PYTHONPATH in the Makefile, CI, the Dockerfile, compose and a sys.path.insert
# inside the worker. As a member it is installed alongside maljan by one
# `uv sync`, and every one of those shortcuts goes away.
[tool.uv.workspace]
members = ["apps/api"]
```

Replace the `[tool.mypy]` header block (the three commented lines plus `mypy_path`) with:

```toml
[tool.mypy]
python_version = "3.13"
# No mypy_path: `mypy src/ apps/api/` derives the search roots from its own
# arguments, and both packages are installed in the environment, so the two
# halves resolve each other without a hand-maintained path list.
warn_return_any = true
```

Replace the `[tool.pytest.ini_options]` block's first line:

```toml
[tool.pytest.ini_options]
markers = [
```

(that is, delete `pythonpath = ["src", "apps/api"]` and keep the `markers` list exactly as it stands).

- [ ] **Step 2: The API pyproject**

Replace the `[build-system]` block, the `[tool.setuptools.packages.find]` block, the `[tool.pytest.ini_options]` block and the `[tool.uv.sources]` block at the end of `apps/api/pyproject.toml` with:

```toml
# hatchling, matching the root project. setuptools' packages.find needed a
# separate include pattern to see `app`; hatchling names the package directly.
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["app"]
```

and, at the end of the file:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"

# The core package comes from the workspace root, not from a relative path. uv
# installs both members editable into one environment, so `import maljan` works
# in the API process, the worker process and the test session alike.
[tool.uv.sources]
maljan = { workspace = true }
```

(`pythonpath = ["."]` goes: `app` is installed. The `[project]` table, its dependency list including `"maljan[yara]"`, `[dependency-groups]` and the whole `[tool.ruff]` section are unchanged.)

- [ ] **Step 3: Delete the second lockfile and relock**

```bash
free -g
git rm apps/api/uv.lock
uv lock
uv sync --all-extras
grep -n 'name = "maljan-api"' uv.lock | head -1
uv run python -c "import maljan, app; print(maljan.__file__); print(app.__file__)"
```
Expected: `uv lock` succeeds, the root lock now carries a `maljan-api` package entry, and both imports resolve from the tree. If the resolve fails because the API pins a dependency the root cannot satisfy, align the pin upward in `apps/api/pyproject.toml`; never loosen the root's.

- [ ] **Step 4: Remove the worker's sys.path block**

In `apps/api/app/worker/analysis_worker.py`, delete lines 460-468 — the comment, the two imports and the four-level `os.path.abspath` climb:

```python
            # Make sure core package is in sys.path
            import os
            import sys

            core_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "src")
            )
            if core_path not in sys.path:
                sys.path.insert(0, core_path)

            from maljan.app import MaljanApp
```

becomes:

```python
            from maljan.app import MaljanApp
```

Then check that nothing else in the module used those two names:

```bash
grep -n "\bos\.\|\bsys\." apps/api/app/worker/analysis_worker.py
```
Expected: any hit is on a line that imports `os` or `sys` for itself elsewhere in the file. If a later line uses `os.` or `sys.` and the deleted block was its only import, add a module-level `import os` / `import sys` at the top of the file rather than restoring the block.

- [ ] **Step 5: Remove the conftest's path insert**

In `tests/conftest.py`, replace lines 1-16:

```python
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maljan.app import MaljanApp

# Import observability to reset counters/throttle
_API_PATH = Path(__file__).resolve().parent.parent / "apps" / "api"
if str(_API_PATH) not in sys.path:
    sys.path.insert(0, str(_API_PATH))

from app import observability  # noqa: E402
from app.auth import throttle  # noqa: E402
```

with:

```python
from unittest.mock import MagicMock

import pytest
from app import observability
from app.auth import throttle

from maljan.app import MaljanApp
```

The per-module `sys.path.insert` guards in `tests/api/`, `tests/unit/api/`, `tests/servers/` and `tests/integration/` stay. They are conditional (`if str(_API) not in sys.path`), inert once `app` is installed, and several of their siblings live under `tests/evaluation/`, which this branch may not touch — rewriting forty files to delete dead lines is churn this move does not need.

- [ ] **Step 6: Makefile**

Drop `PYTHONPATH=src` from the three benchmark targets. Lines 67-68, 73-74 and 86-87 become:

```make
benchmark:
	uv run python -m tests.evaluation.benchmark_suite
```

```make
benchmark-tram:
	uv run python -m tests.evaluation.benchmark_suite --fixtures-dir tests/evaluation/ground_truth/tram
```

```make
benchmark-attck:
	uv run python -m tests.evaluation.benchmark_suite --fixtures-dir tests/evaluation/ground_truth/attck_malware
```

And the `setup` target (lines 53-56) syncs the whole workspace with its extras:

```make
setup:
	uv sync --all-extras
	uv run pre-commit install
	bash scripts/fetch_external.sh
```

(The `scripts/fetch_external.sh` path changes in Task 4, not here.)

- [ ] **Step 7: The backend image**

Replace `docker/Dockerfile.backend` in full:

```dockerfile
# ── Maljan Backend Dockerfile ────────────────────────
FROM python:3.13-slim AS base

WORKDIR /app

# System dependencies.
# The pango/harfbuzz trio and the DejaVu fonts are WeasyPrint's runtime
# requirement for /reports/{id}/pdf (Phase 6). WeasyPrint loads them through
# ctypes at call time, not at import, so without them the PDF endpoint would
# 503 at runtime while everything else kept working — easy to miss. DejaVu is
# the last entry in the report stylesheet's font stack and the only one that
# exists in a slim image; drop it and every glyph falls back to a default.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl gcc libpq-dev \
    libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 fonts-dejavu-core && \
    rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency management
COPY --from=ghcr.io/astral-sh/uv:0.11.28 /uv /usr/local/bin/uv

# Manifests first, sources second: the dependency layer stays cached across
# every source edit. Both workspace members' manifests are needed, because the
# root lockfile resolves them together.
COPY pyproject.toml uv.lock ./
COPY apps/api/pyproject.toml apps/api/pyproject.toml

# Install the workspace.
# 2026-07 round 2: include the ``yara`` extra so yara-python is available in the
# backend image — otherwise detection_signatures._validate_yara reports
# "yara-python not installed; rule body not validated" for every generated rule.
# The manylinux wheel bundles libyara, so no system package is required.
RUN uv sync --frozen --no-dev --extra yara --no-install-workspace

# Sources. Both members are installed editable from here, so `maljan` and `app`
# import with no PYTHONPATH: the ENV that used to set it is gone, and so is the
# sys.path.insert the worker carried.
COPY src/ src/
COPY apps/ apps/
COPY data/ data/
COPY threatintel-mcp/ threatintel-mcp/
COPY network-mcp/ network-mcp/

RUN uv sync --frozen --no-dev --extra yara

# Expose API port
EXPOSE 8000

# Default command (overridden in docker-compose)
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

The two sidecar COPY lines keep their current paths in this task; Task 3 moves them to `services/`.

- [ ] **Step 8: Compose**

In `docker/docker-compose.yml`, delete the `PYTHONPATH` line and the comment above it from `backend-api` (lines 166-172):

```yaml
      # F1 (2026-07-05): make the ``maljan`` core package importable from the
      # API process (the on-demand markdown re-render imports it). The worker
      # inserts ``src`` into sys.path at runtime; the API had no such path, so
      # /reports/{id}/markdown 500'd with ModuleNotFoundError: No module 'maljan'.
      PYTHONPATH: /app/apps/api:/app/src
```

and from `backend-worker` (lines 262-264):

```yaml
      # F1 (2026-07-05): make ``maljan`` importable (parity with API); the
      # worker also inserts src at runtime, this makes it explicit/robust.
      PYTHONPATH: /app/apps/api:/app/src
```

Both blocks go entirely. Every other environment key in both services is untouched. The bind mounts stay as they are in this task; Task 3 adds the `services` mount.

`docker/docker-compose.dev.yml` names no `PYTHONPATH` and is unchanged.

- [ ] **Step 9: Verify the workspace**

```bash
uv run python -c "import maljan, app"
uv run maljan --help | head -3
uv run --directory apps/api uvicorn app.main:app --help | head -3
uv run pytest tests/unit tests/api -q
uv run mypy src/ apps/api/
docker compose -f docker/docker-compose.yml config >/dev/null && echo "compose ok"
```
Expected: every command succeeds. If `mypy` reports `Cannot find implementation or library stub for module named "maljan"`, restore the path list in the root `[tool.mypy]` with the reason recorded:

```toml
# Restored: editable installs land as a .pth file, which mypy does not read, so
# the two package roots are named explicitly here.
mypy_path = ["src", "apps/api"]
```

- [ ] **Step 10: The image, on a machine with room for it**

```bash
free -g
df -h . | tail -1
docker build -f docker/Dockerfile.backend -t maljan-backend:layout .
docker run --rm maljan-backend:layout python -c "import maljan, app; print('ok')"
```
Expected: the build succeeds (several minutes on a cold cache) and the container prints `ok` with no `PYTHONPATH` set anywhere. Stop `llama-server` first if it is running; this build wants the memory and the disk.

- [ ] **Step 11: Lint, format and commit**

```bash
uv run ruff check src/ tests/ apps/api/ network-mcp/ threatintel-mcp/ scripts/ && \
uv run ruff format --check src/ tests/ apps/api/ network-mcp/ threatintel-mcp/ scripts/ && \
uv run mypy src/ apps/api/
git add pyproject.toml uv.lock apps/api/pyproject.toml apps/api/app/worker/analysis_worker.py \
  tests/conftest.py Makefile docker/Dockerfile.backend docker/docker-compose.yml
git commit -m "chore: one uv workspace, no pythonpath anywhere"
```

- [ ] **Step 12: Full suite and the goldens**

```bash
uv run pytest tests/ -q
uv run pytest tests/pipeline/test_graph_snapshot.py tests/agents/test_prompt_byte_identity.py \
  tests/agents/test_revision_prompt_golden.py tests/servers/test_builtin_tool_sets.py \
  tests/servers/test_agent_parity.py tests/unit/test_topology_sources.py -q
```
Expected: PASS at the same count as Task 1.

---
### Task 3: The sidecars become services

**Files:**
- Move: `network-mcp/server.py` → `services/network-mcp/server.py`, `threatintel-mcp/server.py` → `services/threatintel-mcp/server.py`
- Create: `services/network-mcp/README.md`, `services/threatintel-mcp/README.md`
- Modify: `src/maljan/core/config.py:763,764,772,773`; `scripts/capture_builtin_tool_sets.py:28,29`; `services/threatintel-mcp/server.py:4`; `docker/Dockerfile.backend` (the two sidecar COPY lines); `Makefile:22,24,45`; `.github/workflows/ci.yml:62,64,67,86`; `docker/docker-compose.yml` (two volume lists); `README.md:232`; `.env.example:284-285`; `tests/unit/core/test_server_settings.py:27,28,36,37`; `tests/servers/test_builtin_tool_sets.py:3`; `tests/servers/test_teardown_on_the_owning_loop.py:5,6`; `apps/web/e2e/mocks.ts:632,639`; `apps/web/e2e/settings-servers.spec.ts:163`
- Test: `tests/servers/test_builtin_tool_sets.py`, `tests/unit/core/test_server_settings.py`, `tests/unit/test_topology_sources.py`, `tests/unit/test_docker_manifest.py`

**Interfaces:**
- Consumes: `maljan.core.paths.resolve_mcp_args`, which joins any argument containing a separator onto `get_project_root()`. `"services/network-mcp/server.py"` is such an argument, so the launch path stays project-root-relative exactly as `"network-mcp/server.py"` was.
- Produces: no new symbol. `_builtin_servers()` returns the same two `MCPServerConfig` objects with two string fields changed each.

Ordering note: `scripts/capture_builtin_tool_sets.py` is edited here, at its current path, for its sidecar literals, and again in Task 4 for its `parents[]` anchor when it moves into `scripts/goldens/`. Two edits, two different concerns, neither repeated.

- [ ] **Step 1: Move the two directories**

```bash
mkdir -p services
git mv network-mcp services/network-mcp
git mv threatintel-mcp services/threatintel-mcp
git status --short
ls -l services/network-mcp/server.py services/threatintel-mcp/server.py
```
Expected: two renames staged, both files present, modes unchanged.

- [ ] **Step 2: A README in each**

```markdown
<!-- services/network-mcp/README.md -->
# network-mcp

PCAP tooling over stdio MCP: DNS queries, conversation summaries and the
protocol breakdown of a capture the sandbox produced.

Launched by `maljan.core.config._builtin_servers()` as the `network` server —
`sys.executable services/network-mcp/server.py`, cwd `services/network-mcp`, no
environment variables passed through — and its tools are bound to the `network`
analyst.
```

```markdown
<!-- services/threatintel-mcp/README.md -->
# threatintel-mcp

Reputation lookups over stdio MCP: VirusTotal file and URL verdicts, AbuseIPDB
address reports, with a mock fallback when neither key is set.

Launched by `maljan.core.config._builtin_servers()` as the `threatintel` server —
`sys.executable services/threatintel-mcp/server.py`, cwd `services/threatintel-mcp`,
with `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` passed through — and its tools
are bound to the `judge`.
```

- [ ] **Step 3: The launch parameters**

In `src/maljan/core/config.py`, `_builtin_servers()` (lines 763-764 and 772-773):

```python
        "network": MCPServerConfig(
            enabled=True,
            transport="stdio",
            command=sys.executable,
            args=["services/network-mcp/server.py"],
            cwd="services/network-mcp",
            agents=["network"],
            label="Network MCP",
        ),
        "threatintel": MCPServerConfig(
            enabled=True,
            transport="stdio",
            command=sys.executable,
            args=["services/threatintel-mcp/server.py"],
            cwd="services/threatintel-mcp",
            env_allow=["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"],
            agents=["judge"],
            label="Threat intel MCP",
        ),
```

The docstring above it names no path and is unchanged.

- [ ] **Step 4: The capture script's directory map**

In `scripts/capture_builtin_tool_sets.py`, lines 27-30:

```python
SIDECARS: dict[str, tuple[str, tuple[str, ...]]] = {
    "network": ("services/network-mcp", ()),
    "threatintel": ("services/threatintel-mcp", ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY")),
}
```

`ROOT / subdir` at lines 53-54 needs no change: `Path("services/network-mcp")` joins the same way `Path("network-mcp")` did.

- [ ] **Step 5: The sidecar's own usage line**

In `services/threatintel-mcp/server.py`, line 4:

```python
    uv run python services/threatintel-mcp/server.py
```

`services/network-mcp/server.py` opens with `import os` and names no path; it is unchanged.

- [ ] **Step 6: The image**

In `docker/Dockerfile.backend`, the two sidecar COPY lines become:

```dockerfile
COPY services/ services/
```

One line replaces two: `services/` holds exactly the two sidecars and their READMEs, and a third sidecar added later needs no Dockerfile edit.

- [ ] **Step 7: Compose sees the same tree the image does**

In `docker/docker-compose.yml`, both `backend-api` and `backend-worker` gain one bind mount, so an edited sidecar is live in the dev loop the way an edited `src/` file already is. `backend-api`'s volume list becomes:

```yaml
    volumes:
      - ../src:/app/src
      - ../apps:/app/apps
      - ../data:/app/data
      - ../tests:/app/tests
      - ../services:/app/services
```

and `backend-worker`'s, keeping its named cache volume and its comment:

```yaml
    volumes:
      - ../src:/app/src
      - ../apps:/app/apps
      - ../data:/app/data
      - ../tests:/app/tests
      - ../services:/app/services
      # Derived caches, not source data — but expensive enough that losing them
      # is a production problem rather than a warm-up. Two things live here: the
      # 40 MB ATT&CK STIX bundle (re-downloaded from MITRE when absent), and the
      # ATT&CK embedding cache, whose absence costs the judge node +1.3 GB of
      # resident memory and 105 s on the first analysis — measured 2026-07-28.
      # Without this volume both are rebuilt on every container recreation,
      # because /root is in the container's writable layer and a rebuild
      # discards it.
      - attck_cache:/root/.cache/maljan
```

- [ ] **Step 8: The lint and scan path lists**

`Makefile`, lines 18-24 — the comment's example keeps naming the file that motivated the gate, at its new path:

```make
# Everything Python in the repo, not just the library. `src/ tests/` left the
# FastAPI app, the arq worker, the MCP sidecars and scripts/ outside the gate:
# pre-commit still ran ruff over them because it works on staged files, so the
# only way to drift was to go a long time without being staged — which is
# exactly what services/network-mcp/server.py did, unformatted since 8e3370c and
# unnoticed because nothing ever looked at the whole tree.
PY_SOURCES = src/ tests/ apps/api/ services/ scripts/
```

`Makefile`, line 45:

```make
	uv run --with semgrep==1.176.0 semgrep scan --config p/python --config p/security-audit --error --metrics=off src/ apps/api/ services/ scripts/
```

`.github/workflows/ci.yml`, lines 61-67:

```yaml
      # The same set the Makefile's PY_SOURCES names: the FastAPI app, the arq
      # worker, the two MCP sidecars and scripts/ were outside this gate.
      - name: Ruff lint
        run: uv run ruff check src/ tests/ apps/api/ services/ scripts/

      - name: Ruff format check
        run: uv run ruff format --check src/ tests/ apps/api/ services/ scripts/
```

`.github/workflows/ci.yml`, line 86:

```yaml
        run: semgrep scan --config p/python --config p/security-audit --error --metrics=off src/ apps/api/ services/ scripts/
```

`.pre-commit-config.yaml` names no sidecar path — its ruff hooks read staged files and its mypy hook passes `src/ apps/api/` — so it is unchanged. `.semgrepignore` lists `other/ tests/ apps/web/ data/ .venv/ node_modules/` and names no sidecar either; unchanged. `.dockerignore` has no sidecar entry to retarget; its own edit belongs to Task 7.

- [ ] **Step 9: Operator-facing text**

`README.md`, line 232 (inside "Connecting your own tool servers"):

```markdown
so `services/threatintel-mcp` sees `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` and
```

`.env.example`, lines 283-285:

```
# Every MCP server Maljan can attach, keyed by a short name. Two are seeded by
# the application itself and need nothing here: `network` (the PCAP sidecar in
# services/network-mcp/) and `threatintel` (the reputation sidecar in
# services/threatintel-mcp/).
```

Four docstrings name a sidecar as a server rather than as a directory and stay as they are: `src/maljan/agents/subprocess_env.py:6`, `src/maljan/agents/network_analyst.py:89`, `src/maljan/agents/judge_agent.py:204`, `src/maljan/core/memprobe.py:6`.

- [ ] **Step 10: The tests that pin the paths**

`tests/unit/core/test_server_settings.py`, lines 27-28 and 36-37:

```python
    assert network.args == ["services/network-mcp/server.py"]
    assert network.cwd == "services/network-mcp"
```

```python
    assert intel.args == ["services/threatintel-mcp/server.py"]
    assert intel.cwd == "services/threatintel-mcp"
```

`tests/servers/test_builtin_tool_sets.py`, line 3:

```python
Sub-project B moves ``services/network-mcp`` and ``services/threatintel-mcp`` out
```

`tests/servers/test_teardown_on_the_owning_loop.py`, lines 5-6:

```python
word for it: it starts the two in-repo MCP servers — `services/network-mcp/server.py`
and `services/threatintel-mcp/server.py`, both of which come up with no network access
```

`apps/web/e2e/mocks.ts`, lines 632 and 639:

```ts
          args: ["services/network-mcp/server.py"], env: {}, cwd: "services/network-mcp",
```

```ts
          args: ["services/threatintel-mcp/server.py"], env: {}, cwd: "services/threatintel-mcp",
```

`apps/web/e2e/mocks.ts`, line 901, names the file as the source of two tool names:

```ts
  // (`extract_dns`, `read_pcap_summary`, see `services/network-mcp/server.py`) — the
```

`apps/web/e2e/settings-servers.spec.ts`, line 163:

```ts
    expect(sent.args).toEqual(["services/threatintel-mcp/server.py"]);
```

`tests/fixtures/golden/mcp_tools/network.json` and `threatintel.json` pin tool names, not paths, and are not regenerated.

- [ ] **Step 11: Prove the launch path resolves**

```bash
uv run python -c "
from pathlib import Path
from maljan.core.config import _builtin_servers
from maljan.core.paths import resolve_mcp_args
for key in ('network', 'threatintel'):
    cfg = _builtin_servers()[key]
    resolved = resolve_mcp_args(cfg.args)
    assert Path(resolved[0]).is_file(), (key, resolved)
    assert (Path(resolve_mcp_args([cfg.cwd])[0])).is_dir(), (key, cfg.cwd)
    print(key, resolved[0])
"
```
Expected: two absolute paths under `services/`, both existing. This is the assertion the settings test cannot make: it checks the literal, this checks the file.

```bash
uv run pytest tests/servers/test_builtin_tool_sets.py tests/unit/core/test_server_settings.py \
  tests/unit/test_topology_sources.py tests/unit/test_docker_manifest.py \
  tests/unit/scripts/test_makefile_script_paths.py -q
```
Expected: PASS, including `test_the_live_sidecar_still_offers_exactly_the_pinned_tools`, which performs a real stdio handshake from the new directory.

- [ ] **Step 12: Lint, format, type-check and commit**

```bash
uv run ruff check src/ tests/ apps/api/ services/ scripts/ && \
uv run ruff format --check src/ tests/ apps/api/ services/ scripts/ && \
uv run mypy src/ apps/api/ && \
docker compose -f docker/docker-compose.yml config >/dev/null && echo "compose ok"
git add services network-mcp threatintel-mcp src/maljan/core/config.py \
  scripts/capture_builtin_tool_sets.py docker/Dockerfile.backend docker/docker-compose.yml \
  Makefile .github/workflows/ci.yml README.md .env.example \
  tests/unit/core/test_server_settings.py tests/servers/test_builtin_tool_sets.py \
  tests/servers/test_teardown_on_the_owning_loop.py apps/web/e2e/mocks.ts \
  apps/web/e2e/settings-servers.spec.ts
git commit -m "refactor: the two mcp sidecars move under services/"
```

- [ ] **Step 13: Full suite and the goldens**

```bash
uv run pytest tests/ -q
uv run pytest tests/pipeline/test_graph_snapshot.py tests/agents/test_prompt_byte_identity.py \
  tests/agents/test_revision_prompt_golden.py tests/servers/test_builtin_tool_sets.py \
  tests/servers/test_agent_parity.py tests/unit/test_topology_sources.py -q
```
Expected: PASS at the same count as Task 1.

---

### Task 4: Scripts grouped by kind

**Files:**
- Move: twenty files, per the table in Step 1
- Modify: `scripts/goldens/capture_builtin_tool_sets.py:23`, `scripts/goldens/capture_graph_golden.py:19`, `scripts/goldens/capture_provider_goldens.py:25`, `scripts/goldens/capture_revision_prompt_golden.py:21`, `scripts/goldens/probe_r2_tools.py:18`, `scripts/knowledge/build_api_capability_db.py:32`, `scripts/knowledge/build_attck_case_kb.py:39`, `scripts/knowledge/build_family_feature_kb.py:43`, `scripts/knowledge/expand_yara_rules.py:55`, `scripts/knowledge/prepare_attck_malware_fixtures.py:55`, `scripts/knowledge/prepare_tram_dataset.py:47,55`, `scripts/settings/seed_settings_annotations.py:16,19`, `scripts/dev/ghidra_manager.py:27`, `scripts/dev/fetch_external.sh:22`, `scripts/dev/run_with_restarts.sh:53,54,56,57,91`, plus the usage lines listed in Step 4; `Makefile:56,62,71,77,84,131,134,137,140,160,164`; `tests/unit/scripts/test_build_attck_case_kb.py:17`, `test_expand_yara_rules.py:20`, `test_llm_server.py:29,122`, `test_night_guard.py:39`; `src/maljan/core/config.py:502,526,583`, `src/maljan/core/settings_annotations.py:4,540,572,620`, `src/maljan/core/paths.py:73,74`, `src/maljan/providers/static/r2.py:7,29,53`, `src/maljan/analysis/family_feature_rag.py:14`, `src/maljan/memory/family_fingerprint_index.py:4`; `README.md:605`
- Test: `tests/unit/scripts/`, `tests/unit/scripts/test_makefile_script_paths.py`

**Interfaces:**
- Consumes: nothing new. Every script keeps its module name, its CLI and its file mode.
- Produces: five directories. No `__init__.py` anywhere under `scripts/` — the scripts are run, not imported as a package, and `tests/unit/scripts/` reaches them by inserting the holding directory on `sys.path`.

- [ ] **Step 1: The move table**

```bash
mkdir -p scripts/dev scripts/goldens scripts/knowledge scripts/paper scripts/settings

git mv scripts/llm_server.sh scripts/dev/llm_server.sh
git mv scripts/night_guard.sh scripts/dev/night_guard.sh
git mv scripts/run_with_restarts.sh scripts/dev/run_with_restarts.sh
git mv scripts/ghidra_manager.py scripts/dev/ghidra_manager.py
git mv scripts/cape_mcp_wrapper.py scripts/dev/cape_mcp_wrapper.py
git mv scripts/fetch_external.sh scripts/dev/fetch_external.sh

git mv scripts/capture_builtin_tool_sets.py scripts/goldens/capture_builtin_tool_sets.py
git mv scripts/capture_graph_golden.py scripts/goldens/capture_graph_golden.py
git mv scripts/capture_provider_goldens.py scripts/goldens/capture_provider_goldens.py
git mv scripts/capture_revision_prompt_golden.py scripts/goldens/capture_revision_prompt_golden.py
git mv scripts/probe_r2_tools.py scripts/goldens/probe_r2_tools.py

git mv scripts/build_api_capability_db.py scripts/knowledge/build_api_capability_db.py
git mv scripts/build_attck_case_kb.py scripts/knowledge/build_attck_case_kb.py
git mv scripts/build_family_feature_kb.py scripts/knowledge/build_family_feature_kb.py
git mv scripts/expand_yara_rules.py scripts/knowledge/expand_yara_rules.py
git mv scripts/prepare_attck_malware_fixtures.py scripts/knowledge/prepare_attck_malware_fixtures.py
git mv scripts/prepare_tram_dataset.py scripts/knowledge/prepare_tram_dataset.py

git mv scripts/check_paper.sh scripts/paper/check_paper.sh
git mv scripts/complete_cohort.sh scripts/paper/complete_cohort.sh

git mv scripts/seed_settings_annotations.py scripts/settings/seed_settings_annotations.py

ls -l scripts/dev scripts/goldens scripts/knowledge scripts/paper scripts/settings
find scripts -maxdepth 1 -type f
```
Expected: twenty renames staged; the last command prints nothing, because no file is left at the top of `scripts/`; every `.sh` and every previously executable `.py` keeps its `x` bit (`git mv` preserves the mode).

- [ ] **Step 2: The path anchors that gained a level**

Each of these climbs from the script's own file to the repository root. One directory deeper means one more `parents` level. Exhaustively, with the new value:

| File | Line | Was | Becomes |
| :-- | :-- | :-- | :-- |
| `scripts/goldens/capture_builtin_tool_sets.py` | 23 | `Path(__file__).resolve().parents[1]` | `Path(__file__).resolve().parents[2]` |
| `scripts/goldens/capture_graph_golden.py` | 19 | `Path(__file__).resolve().parents[1]` | `Path(__file__).resolve().parents[2]` |
| `scripts/goldens/capture_provider_goldens.py` | 25 | `Path(__file__).resolve().parents[1]` | `Path(__file__).resolve().parents[2]` |
| `scripts/goldens/capture_revision_prompt_golden.py` | 21 | `Path(__file__).resolve().parents[1]` | `Path(__file__).resolve().parents[2]` |
| `scripts/goldens/probe_r2_tools.py` | 18 | `Path(__file__).resolve().parents[1] / "tests" / ...` | `Path(__file__).resolve().parents[2] / "tests" / ...` |
| `scripts/knowledge/build_api_capability_db.py` | 32 | `Path(__file__).resolve().parent.parent` | `Path(__file__).resolve().parents[2]` |
| `scripts/knowledge/build_attck_case_kb.py` | 39 | `Path(__file__).resolve().parents[1]` | `Path(__file__).resolve().parents[2]` |
| `scripts/knowledge/build_family_feature_kb.py` | 43 | `Path(__file__).resolve().parents[1]` | `Path(__file__).resolve().parents[2]` |
| `scripts/knowledge/expand_yara_rules.py` | 55 | `Path(__file__).resolve().parent.parent` | `Path(__file__).resolve().parents[2]` |
| `scripts/knowledge/prepare_attck_malware_fixtures.py` | 55 | `Path(__file__).resolve().parent.parent` | `Path(__file__).resolve().parents[2]` |
| `scripts/knowledge/prepare_tram_dataset.py` | 47 | `Path(__file__).resolve().parent.parent / "tests" / ...` | `Path(__file__).resolve().parents[2] / "tests" / ...` |
| `scripts/knowledge/prepare_tram_dataset.py` | 55 | `Path(__file__).resolve().parent.parent / "data" / ...` | `Path(__file__).resolve().parents[2] / "data" / ...` |
| `scripts/settings/seed_settings_annotations.py` | 16 | `Path(__file__).resolve().parents[1] / "src"` | `Path(__file__).resolve().parents[2] / "src"` |
| `scripts/settings/seed_settings_annotations.py` | 19 | `Path(__file__).resolve().parents[1] / ".env.example"` | `Path(__file__).resolve().parents[2] / ".env.example"` |
| `scripts/dev/ghidra_manager.py` | 27 | `Path(__file__).resolve().parent.parent` | `Path(__file__).resolve().parents[2]` |
| `scripts/dev/fetch_external.sh` | 22 | `"$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"` | `"$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"` |

`parent.parent` is spelled `parents[2]` in its new form so every anchor in `scripts/` reads the same way and a future move is one number to change.

Four shell scripts anchor with `cd "$(dirname "$0")/.." || exit 2` at their own line 13, 23, 18 and 21 — `scripts/paper/check_paper.sh`, `scripts/paper/complete_cohort.sh`, `scripts/dev/llm_server.sh`, `scripts/dev/run_with_restarts.sh`. Each becomes:

```bash
cd "$(dirname "$0")/../.." || exit 2
```

`scripts/dev/night_guard.sh:56` anchors on `${MALJAN_ROOT:-/home/user/Belgeler/kingston/Projects/Maljan}`, an absolute path with an environment override, and is unchanged. `scripts/dev/cape_mcp_wrapper.py` anchors on `--cape-root` / `CAPE_ROOT`, outside this repository, and is unchanged.

- [ ] **Step 3: The one script that calls another**

`scripts/dev/run_with_restarts.sh` invokes the launcher relative to the repository root it has just `cd`-ed into. Lines 53, 54, 56, 57 and 91:

```bash
    if ./scripts/dev/llm_server.sh status >/dev/null 2>&1; then
        ./scripts/dev/llm_server.sh restart || exit 1
    else
        ./scripts/dev/llm_server.sh start
        ./scripts/dev/llm_server.sh wait || { echo "the server never came up" >&2; exit 1; }
```

```bash
    ./scripts/dev/llm_server.sh restart || exit 1
```

- [ ] **Step 4: The usage lines each script prints about itself**

Every one is a docstring or comment line naming the script's own invocation. New value on the right:

| File | Line | New text |
| :-- | :-- | :-- |
| `scripts/goldens/capture_builtin_tool_sets.py` | 5 | `    uv run python scripts/goldens/capture_builtin_tool_sets.py` |
| `scripts/goldens/capture_graph_golden.py` | 10 | ``Run: ``uv run python scripts/goldens/capture_graph_golden.py``` |
| `scripts/goldens/capture_provider_goldens.py` | 5 | `    uv run python scripts/goldens/capture_provider_goldens.py` |
| `scripts/goldens/capture_revision_prompt_golden.py` | 9 | ``Run: ``uv run python scripts/goldens/capture_revision_prompt_golden.py``` |
| `scripts/goldens/probe_r2_tools.py` | 3-4 | `    uv run python scripts/goldens/probe_r2_tools.py` and `    uv run python scripts/goldens/probe_r2_tools.py /path/r2mcp` |
| `scripts/knowledge/build_api_capability_db.py` | 21 | `    uv run python scripts/knowledge/build_api_capability_db.py` |
| `scripts/knowledge/build_attck_case_kb.py` | 23 | `    uv run python scripts/knowledge/build_attck_case_kb.py --qdrant-url http://localhost:6333 \` |
| `scripts/knowledge/build_family_feature_kb.py` | 27 | `    uv run python scripts/knowledge/build_family_feature_kb.py --samples-dir ./rats \` |
| `scripts/knowledge/expand_yara_rules.py` | 36-39 | the four `uv run python scripts/knowledge/expand_yara_rules.py ...` forms |
| `scripts/knowledge/expand_yara_rules.py` | 705 | `            "Run: uv run python scripts/knowledge/prepare_attck_malware_fixtures.py",` |
| `scripts/knowledge/prepare_attck_malware_fixtures.py` | 29-32 | the four `uv run python scripts/knowledge/prepare_attck_malware_fixtures.py ...` forms |
| `scripts/knowledge/prepare_tram_dataset.py` | 19-22 | the four `uv run python scripts/knowledge/prepare_tram_dataset.py ...` forms |
| `scripts/dev/ghidra_manager.py` | 8-11 | the four `python scripts/dev/ghidra_manager.py <cmd>` forms |
| `scripts/dev/cape_mcp_wrapper.py` | 23 | `                   "/path/to/Maljan/scripts/dev/cape_mcp_wrapper.py",` |
| `scripts/dev/fetch_external.sh` | 18 | `#   scripts/dev/fetch_external.sh` |
| `scripts/dev/llm_server.sh` | 16 | `# Run:  scripts/dev/llm_server.sh start \| stop \| restart \| status \| wait` |
| `scripts/dev/run_with_restarts.sh` | 19 | `# Run:  scripts/dev/run_with_restarts.sh <checkpoint> <target-rows> <command...>` |

- [ ] **Step 5: The Makefile targets**

Line 56 (`setup`) and line 62 (`external`):

```make
	bash scripts/dev/fetch_external.sh
```

Line 71 (`prepare-tram`):

```make
	uv run python scripts/knowledge/prepare_tram_dataset.py
```

Line 77 (`prepare-attck`):

```make
	uv run python scripts/knowledge/prepare_attck_malware_fixtures.py
```

Line 84 (`prepare-api-db`):

```make
	uv run python scripts/knowledge/build_api_capability_db.py
```

Lines 131, 134, 137, 140 (`ghidra-status`, `ghidra-sync`, `ghidra-build`, `ghidra-watch`):

```make
	uv run python scripts/dev/ghidra_manager.py status
```
```make
	uv run python scripts/dev/ghidra_manager.py sync
```
```make
	uv run python scripts/dev/ghidra_manager.py build
```
```make
	uv run python scripts/dev/ghidra_manager.py watch
```

Line 160 (`cohort-complete`) and line 164 (`paper-check`):

```make
	./scripts/paper/complete_cohort.sh
```
```make
	./scripts/paper/check_paper.sh
```

`PY_SOURCES` and the semgrep target name `scripts/` as a whole and are unchanged by this task.

- [ ] **Step 6: The tests that reach into `scripts/`**

`tests/unit/scripts/test_build_attck_case_kb.py`, line 17:

```python
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "knowledge"))
```

`tests/unit/scripts/test_expand_yara_rules.py`, line 20:

```python
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts" / "knowledge"))
```

`tests/unit/scripts/test_llm_server.py`, line 29:

```python
_SCRIPT = _ROOT / "scripts" / "dev" / "llm_server.sh"
```

and its `test_the_scripts_parse`, lines 120-125:

```python
def test_the_scripts_parse() -> None:
    for script in ("llm_server.sh", "run_with_restarts.sh"):
        path = _ROOT / "scripts" / "dev" / script
        result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
        assert result.returncode == 0, f"{script} does not parse:\n{result.stderr}"
        assert os.access(path, os.X_OK), f"{script} is not executable"
```

`tests/unit/scripts/test_night_guard.py`, line 39:

```python
_GUARD = _ROOT / "scripts" / "dev" / "night_guard.sh"
```

`_ROOT` in both shell-script tests is `parents[3]`, which is already the repository root and does not change; only the segment after `"scripts"` is new.

- [ ] **Step 7: The docstrings in `src/` that tell an operator which script to run**

These are instructions, not history, so they follow the move:

| File | Line | New path in the text |
| :-- | :-- | :-- |
| `src/maljan/core/config.py` | 502 | `scripts/knowledge/build_family_feature_kb.py` |
| `src/maljan/core/config.py` | 526 | `scripts/knowledge/build_api_capability_db.py` |
| `src/maljan/core/config.py` | 583 | `scripts/knowledge/build_attck_case_kb.py` |
| `src/maljan/core/settings_annotations.py` | 4 | `scripts/settings/seed_settings_annotations.py` |
| `src/maljan/core/settings_annotations.py` | 540 | `scripts/knowledge/build_api_capability_db.py` |
| `src/maljan/core/settings_annotations.py` | 572 | `scripts/knowledge/build_attck_case_kb.py` |
| `src/maljan/core/settings_annotations.py` | 620 | `scripts/knowledge/build_family_feature_kb.py` |
| `src/maljan/core/paths.py` | 73 | `scripts/dev/cape_mcp_wrapper.py` |
| `src/maljan/core/paths.py` | 74 | `/mnt/d/MyCodes/Maljan/scripts/dev/cape_mcp_wrapper.py` |
| `src/maljan/providers/static/r2.py` | 7, 29, 53 | `scripts/goldens/probe_r2_tools.py` |
| `src/maljan/analysis/family_feature_rag.py` | 14 | `scripts/knowledge/build_family_feature_kb.py` |
| `src/maljan/memory/family_fingerprint_index.py` | 4 | `scripts/knowledge/build_family_feature_kb.py` |

`README.md`, line 605:

```markdown
For a fully local LLM backend (no cloud API), set `LLM__PROVIDER=openai` and point `LLM__OPENAI__BASE_URL` at a local OpenAI-compatible server such as `ik_llama.cpp`'s `llama-server`. `make external` fetches the engine at the pinned commit, and `scripts/dev/llm_server.sh` carries the invocation.
```

Test docstrings that name a capture script (`tests/agents/test_prompt_byte_identity.py:3`, `tests/agents/test_revision_prompt_golden.py:7`, `tests/pipeline/test_graph_snapshot.py:7`) name where a fixture came from, at the time it was captured, and are left as the record of that. `docs/specs/*` and `docs/plans/*` are history and are left alone, this plan included, other than the file structure section above.

- [ ] **Step 8: Verify**

```bash
uv run pytest tests/unit/scripts -q
bash -n scripts/dev/llm_server.sh scripts/dev/run_with_restarts.sh scripts/dev/night_guard.sh \
  scripts/dev/fetch_external.sh scripts/paper/check_paper.sh scripts/paper/complete_cohort.sh
uv run python scripts/settings/seed_settings_annotations.py | head -5
uv run python -c "
import subprocess, pathlib
root = pathlib.Path('.').resolve()
for target in ('external', 'prepare-tram', 'prepare-attck', 'prepare-api-db', 'ghidra-status', 'paper-check', 'cohort-complete'):
    out = subprocess.run(['make', '-n', target], capture_output=True, text=True)
    assert out.returncode == 0, (target, out.stderr)
    for token in out.stdout.split():
        if token.startswith('scripts/') or token.startswith('./scripts/'):
            assert (root / token.lstrip('./')).exists(), (target, token)
            print(target, token)
"
```
Expected: the script tests pass, every shell script parses, the annotation seeder prints Python, and `make -n` on each target names only paths that exist. `tests/unit/scripts/test_makefile_script_paths.py` from Task 1 asserts the same thing over the whole file and must pass without being edited.

- [ ] **Step 9: Lint, format, type-check and commit**

```bash
uv run ruff check src/ tests/ apps/api/ services/ scripts/ && \
uv run ruff format --check src/ tests/ apps/api/ services/ scripts/ && \
uv run mypy src/ apps/api/
git add scripts Makefile README.md src/maljan/core/config.py src/maljan/core/paths.py \
  src/maljan/core/settings_annotations.py src/maljan/providers/static/r2.py \
  src/maljan/analysis/family_feature_rag.py src/maljan/memory/family_fingerprint_index.py \
  tests/unit/scripts
git commit -m "refactor: scripts grouped into dev, goldens, knowledge, paper and settings"
```

- [ ] **Step 10: Full suite and the goldens**

```bash
uv run pytest tests/ -q
uv run pytest tests/pipeline/test_graph_snapshot.py tests/agents/test_prompt_byte_identity.py \
  tests/agents/test_revision_prompt_golden.py tests/servers/test_builtin_tool_sets.py \
  tests/servers/test_agent_parity.py tests/unit/test_topology_sources.py -q
```
Expected: PASS at the same count as Task 1.

---
### Task 5: One rule for where a test lives

**Files:**
- Move: `tests/agents/*` → `tests/unit/agents/`, `tests/pipeline/*` → `tests/unit/pipeline/`, `tests/providers/**` → `tests/unit/providers/`, `tests/servers/*` → `tests/unit/servers/`
- Modify: the twenty-two `parents[]` anchors in Step 3, `tests/integration/test_rest_sandbox_end_to_end.py:16`, `tests/unit/test_topology_sources.py:65`, `tests/unit/test_package_layout.py` (`GOLDEN_MODULES`)
- Test: the whole suite, and the collected count against the ledger

**Interfaces:**
- Consumes: pytest's default `prepend` import mode. A test file's module name is derived by walking up while `__init__.py` exists. `tests/`, `tests/unit/`, `tests/providers/` and `tests/servers/` carry one; `tests/agents/`, `tests/pipeline/` and most `tests/unit/<subpackage>` folders do not.
- Produces: `tests/unit/providers/` and `tests/unit/servers/` as packages (their `__init__.py` moves with them); `tests/unit/agents/` and `tests/unit/pipeline/` keep the package status they already have.

- [ ] **Step 1: The duplicate-basename check, before the move**

```bash
find tests -name 'test_*.py' | xargs -n1 basename | sort | uniq -d
find tests -name 'test_registry.py' -o -name 'test_ws_auth.py' | sort
```
Output on the branch point:

```
test_registry.py
test_ws_auth.py
```
```
tests/api/test_ws_auth.py
tests/providers/test_registry.py
tests/unit/test_registry.py
tests/unit/test_ws_auth.py
```

Neither pair collides after the move, and neither is renamed:

- `test_ws_auth.py` is untouched by this task — `tests/api/` does not move.
- `test_registry.py` becomes `tests/unit/providers/test_registry.py` beside `tests/unit/test_registry.py`. Both sides sit in `__init__.py` packages (`tests/`, `tests/unit/`, and `tests/providers/__init__.py` which moves with the folder), so pytest derives `tests.unit.providers.test_registry` and `tests.unit.test_registry` — two distinct module names, which is exactly why the pair already coexists today.

Re-run the first command after Step 2 and confirm the output is the same two lines. A third name appearing means two non-package folders merged and one of the two files must be renamed with a suffix that says what it covers.

- [ ] **Step 2: The moves**

```bash
mkdir -p tests/unit/providers tests/unit/servers

git mv tests/agents/test_bound_servers.py tests/unit/agents/test_bound_servers.py
git mv tests/agents/test_composition.py tests/unit/agents/test_composition.py
git mv tests/agents/test_configurable_analyst.py tests/unit/agents/test_configurable_analyst.py
git mv tests/agents/test_prompt_byte_identity.py tests/unit/agents/test_prompt_byte_identity.py
git mv tests/agents/test_revision_messages.py tests/unit/agents/test_revision_messages.py
git mv tests/agents/test_revision_prompt_golden.py tests/unit/agents/test_revision_prompt_golden.py
git mv tests/agents/test_sidecar_registry_wiring.py tests/unit/agents/test_sidecar_registry_wiring.py
git mv tests/agents/test_static_provider_per_agent.py tests/unit/agents/test_static_provider_per_agent.py
git mv tests/agents/test_tool_call_scaffolding.py tests/unit/agents/test_tool_call_scaffolding.py

git mv tests/pipeline/test_graph_snapshot.py tests/unit/pipeline/test_graph_snapshot.py

git mv tests/providers/__init__.py tests/unit/providers/__init__.py
git mv tests/providers/_cape_fixture.py tests/unit/providers/_cape_fixture.py
git mv tests/providers/test_capability_gates.py tests/unit/providers/test_capability_gates.py
git mv tests/providers/test_cape_normalization_golden.py tests/unit/providers/test_cape_normalization_golden.py
git mv tests/providers/test_container_wiring.py tests/unit/providers/test_container_wiring.py
git mv tests/providers/test_evidence_merge.py tests/unit/providers/test_evidence_merge.py
git mv tests/providers/test_extractor_golden.py tests/unit/providers/test_extractor_golden.py
git mv tests/providers/test_registry.py tests/unit/providers/test_registry.py
git mv tests/providers/test_sandbox_report.py tests/unit/providers/test_sandbox_report.py
git mv tests/providers/test_sniff_format.py tests/unit/providers/test_sniff_format.py
git mv tests/providers/test_unavailable_sections.py tests/unit/providers/test_unavailable_sections.py
git mv tests/providers/sandbox tests/unit/providers/sandbox
git mv tests/providers/static tests/unit/providers/static

git mv tests/servers/__init__.py tests/unit/servers/__init__.py
git mv tests/servers/rest_stub.py tests/unit/servers/rest_stub.py
git mv tests/servers/test_agent_parity.py tests/unit/servers/test_agent_parity.py
git mv tests/servers/test_builtin_tool_sets.py tests/unit/servers/test_builtin_tool_sets.py
git mv tests/servers/test_server_registry.py tests/unit/servers/test_server_registry.py
git mv tests/servers/test_server_security.py tests/unit/servers/test_server_security.py
git mv tests/servers/test_teardown_on_the_owning_loop.py tests/unit/servers/test_teardown_on_the_owning_loop.py

find tests/agents tests/pipeline tests/providers tests/servers -type f -not -path '*__pycache__*' 2>&1 | head
rm -rf tests/agents tests/pipeline tests/providers tests/servers
ls tests/
find tests -name 'test_*.py' | xargs -n1 basename | sort | uniq -d
```
Expected: the `find` prints nothing before the `rm -rf` (only stale `__pycache__` directories remain, which are not tracked), `ls tests/` shows `__init__.py api conftest.py evaluation fixtures integration unit`, and the duplicate check prints the same two names as Step 1.

- [ ] **Step 3: Every anchor gains one level**

Each of these climbs from a test file to `tests/` or to the repository root. One directory deeper means one more level. Exhaustively:

| File | Line | Was | Becomes |
| :-- | :-- | :-- | :-- |
| `tests/unit/agents/test_prompt_byte_identity.py` | 14 | `parents[1] / "fixtures"` | `parents[2] / "fixtures"` |
| `tests/unit/agents/test_revision_prompt_golden.py` | 19 | `parents[1] / "fixtures" / "golden" / ...` | `parents[2] / "fixtures" / "golden" / ...` |
| `tests/unit/pipeline/test_graph_snapshot.py` | 24 | `parents[1] / "fixtures" / "golden" / ...` | `parents[2] / "fixtures" / "golden" / ...` |
| `tests/unit/providers/_cape_fixture.py` | 21 | `parents[2]` | `parents[3]` |
| `tests/unit/providers/test_capability_gates.py` | 8 | `parents[2]` | `parents[3]` |
| `tests/unit/providers/test_container_wiring.py` | 102 | `parents[1] / "fixtures" / "golden" / "mcp_tools" / ...` | `parents[2] / "fixtures" / "golden" / "mcp_tools" / ...` |
| `tests/unit/providers/test_extractor_golden.py` | 30 | `parents[2]` | `parents[3]` |
| `tests/unit/providers/test_sniff_format.py` | 17 | `parents[2]` | `parents[3]` |
| `tests/unit/providers/sandbox/test_cape2_provider.py` | 15 | `parents[3]` | `parents[4]` |
| `tests/unit/providers/sandbox/test_legacy_wrapper.py` | 13 | `parents[3]` | `parents[4]` |
| `tests/unit/providers/sandbox/test_rest_mapping.py` | 22 | `parents[2] / "fixtures" / "golden" / "rest_mapping"` | `parents[3] / "fixtures" / "golden" / "rest_mapping"` |
| `tests/unit/providers/sandbox/test_rest_provider.py` | 16 | `parents[2] / "fixtures" / "sandbox"` | `parents[3] / "fixtures" / "sandbox"` |
| `tests/unit/providers/sandbox/test_rest_provider.py` | 17 | `parents[2] / "fixtures" / "golden" / "rest_mapping"` | `parents[3] / "fixtures" / "golden" / "rest_mapping"` |
| `tests/unit/providers/sandbox/test_triage_provider.py` | 15 | `parents[2] / "fixtures" / "sandbox"` | `parents[3] / "fixtures" / "sandbox"` |
| `tests/unit/providers/sandbox/test_upload_provider.py` | 16 | `parents[3]` | `parents[4]` |
| `tests/unit/providers/static/test_ghidra_provider.py` | 15 | `parents[3]` | `parents[4]` |
| `tests/unit/providers/static/test_r2_provider.py` | 12 | `parents[2] / "fixtures" / "golden" / "r2_tools.json"` | `parents[3] / "fixtures" / "golden" / "r2_tools.json"` |
| `tests/unit/servers/rest_stub.py` | 18 | `parents[1] / "fixtures" / "golden" / "rest_mapping" / ...` | `parents[2] / "fixtures" / "golden" / "rest_mapping" / ...` |
| `tests/unit/servers/test_agent_parity.py` | 15 | `parents[2] / "apps" / "api"` | `parents[3] / "apps" / "api"` |
| `tests/unit/servers/test_builtin_tool_sets.py` | 21 | `parents[2]` | `parents[3]` |
| `tests/unit/servers/test_server_security.py` | 227 | `parents[2] / "apps" / "api"` | `parents[3] / "apps" / "api"` |
| `tests/unit/servers/test_server_security.py` | 273 | `parents[2] / "apps" / "api"` | `parents[3] / "apps" / "api"` |

Sweep for a missed one:

```bash
grep -rn "parents\[" tests/unit/agents tests/unit/pipeline tests/unit/providers tests/unit/servers
uv run python -c "
import pathlib, re
root = pathlib.Path('.').resolve()
bad = []
for sub in ('agents', 'pipeline', 'providers', 'servers'):
    for p in (root / 'tests' / 'unit' / sub).rglob('*.py'):
        text = p.read_text(encoding='utf-8')
        for m in re.finditer(r'parents\[(\d+)\]', text):
            depth = len(p.relative_to(root).parts) - 1
            if int(m.group(1)) > depth:
                bad.append((str(p), m.group(0)))
print(bad)
"
```
Expected: the printed list is empty. An anchor that climbs past the repository root is the one failure mode this catches without running the test.

- [ ] **Step 4: The stub's import path**

`tests/integration/test_rest_sandbox_end_to_end.py`, line 16:

```python
from tests.unit.servers.rest_stub import StubState, build_stub_app
```

This is the only importer of `rest_stub`:

```bash
grep -rn "rest_stub" --include=*.py tests/ | grep -v __pycache__
```
Expected: two lines, the definition and this import.

- [ ] **Step 5: The allow-lists that name a test by path**

`tests/unit/test_topology_sources.py`, line 65:

```python
    stale = sorted(TOPOLOGY_SOURCES - calling - {"tests/unit/servers/test_agent_parity.py"})
```

`TOPOLOGY_SOURCES` itself names only `src/maljan/agents/registry.py` and `NAME_BRANCHES` is empty; both are unchanged. `SEARCHED` covers `src/maljan` and `apps/api/app`, neither of which moves.

`tests/unit/test_package_layout.py`, the `GOLDEN_MODULES` tuple:

```python
GOLDEN_MODULES: tuple[str, ...] = (
    "tests/unit/pipeline/test_graph_snapshot.py",
    "tests/unit/agents/test_prompt_byte_identity.py",
    "tests/unit/agents/test_revision_prompt_golden.py",
    "tests/unit/servers/test_builtin_tool_sets.py",
    "tests/unit/servers/test_agent_parity.py",
    "tests/unit/test_topology_sources.py",
)
```

Its docstring comment above the tuple, which says the paths change in Task 5, becomes:

```python
# The files that say "the default profile is what it was". They live under
# tests/unit/ with the rest of the suite.
```

- [ ] **Step 6: The count, against the ledger**

```bash
free -g
uv run pytest tests/ -q --co -q | tail -1
uv run pytest tests/ -q
git diff dev -- tests/evaluation
git status --short tests/evaluation/
```
Expected: the collected count equals the number recorded in the ledger's first row (nothing was added or removed, only moved); write it into the ledger's second row. The suite passes. Both `tests/evaluation` checks print nothing.

- [ ] **Step 7: Lint, format, type-check and commit**

```bash
uv run ruff check src/ tests/ apps/api/ services/ scripts/ && \
uv run ruff format --check src/ tests/ apps/api/ services/ scripts/ && \
uv run mypy src/ apps/api/
git add tests
git commit -m "refactor: the four stray test folders merge into tests/unit"
```

- [ ] **Step 8: The goldens, at their new paths**

```bash
uv run pytest tests/unit/pipeline/test_graph_snapshot.py tests/unit/agents/test_prompt_byte_identity.py \
  tests/unit/agents/test_revision_prompt_golden.py tests/unit/servers/test_builtin_tool_sets.py \
  tests/unit/servers/test_agent_parity.py tests/unit/test_topology_sources.py -q
```
Expected: PASS.

---

### Task 6: The shared analysis panels

**Files:**
- Move: six `.tsx` files into `apps/web/src/components/analysis/`
- Modify: `apps/web/src/app/(app)/analysis/[id]/detection/page.tsx:3,4,5`, `apps/web/src/app/(app)/analysis/[id]/process/page.tsx:5,6,7`, and the `useReport` import inside each moved panel
- Test: `npx tsc --noEmit`, `npm run lint`, `npm run build`, `e2e/analysis-tabs.spec.ts` on chromium

**Interfaces:**
- Consumes: the `@/*` → `./src/*` path alias in `apps/web/tsconfig.json`. A route segment containing parentheses or brackets is an ordinary directory name in a module specifier, so `@/app/(app)/analysis/[id]/layout` resolves.
- Produces: `apps/web/src/components/analysis/` holding the six panels. Each keeps its default export and its component name; no props change.

- [ ] **Step 1: Record the lint baseline**

```bash
cd apps/web && npm run lint 2>&1 | tail -5
```
Write the warning count into the ledger's fourth row. Step 6 compares against it; the constraint is no new warning, not zero warnings.

- [ ] **Step 2: The moves**

```bash
mkdir -p apps/web/src/components/analysis
git mv "apps/web/src/app/(app)/analysis/[id]/agents/AgentsPanel.tsx" apps/web/src/components/analysis/AgentsPanel.tsx
git mv "apps/web/src/app/(app)/analysis/[id]/pipeline/PipelinePanel.tsx" apps/web/src/components/analysis/PipelinePanel.tsx
git mv "apps/web/src/app/(app)/analysis/[id]/rules/RuleMatchesPanel.tsx" apps/web/src/components/analysis/RuleMatchesPanel.tsx
git mv "apps/web/src/app/(app)/analysis/[id]/signatures/GeneratedRulesPanel.tsx" apps/web/src/components/analysis/GeneratedRulesPanel.tsx
git mv "apps/web/src/app/(app)/analysis/[id]/stix/StixPanel.tsx" apps/web/src/components/analysis/StixPanel.tsx
git mv "apps/web/src/app/(app)/analysis/[id]/timeline/TimelinePanel.tsx" apps/web/src/components/analysis/TimelinePanel.tsx
git status --short
```
Expected: six renames staged. `TranscriptView.tsx` stays in `process/` — it has one importer in its own route folder and is not shared.

- [ ] **Step 3: The panels' own import of the route context**

All six read the report through `useReport`, exported from the analysis layout. `"../layout"` was a sibling-of-parent path from inside a route folder; from `src/components/analysis/` the same module is reached through the alias. In each of the six files, replace:

```ts
import { useReport } from "../layout";
```

with:

```ts
import { useReport } from "@/app/(app)/analysis/[id]/layout";
```

The line numbers, in file order: `AgentsPanel.tsx:3`, `PipelinePanel.tsx:3`, `RuleMatchesPanel.tsx:4`, `GeneratedRulesPanel.tsx:5`, `StixPanel.tsx:8`, `TimelinePanel.tsx:16`. Every other import in the six files already uses the `@/` alias (`@/types`, `@/lib/api`, `@/lib/report-utils`, `@/lib/errors`, `@/lib/verdict`, `@/types/malware-report`) or is a package import, and none of them changes.

- [ ] **Step 4: The two importing routes**

`apps/web/src/app/(app)/analysis/[id]/detection/page.tsx`, lines 3-5:

```ts
import RuleMatchesPanel from "@/components/analysis/RuleMatchesPanel";
import GeneratedRulesPanel from "@/components/analysis/GeneratedRulesPanel";
import StixPanel from "@/components/analysis/StixPanel";
```

`apps/web/src/app/(app)/analysis/[id]/process/page.tsx`, lines 5-7:

```ts
import AgentsPanel from "@/components/analysis/AgentsPanel";
import PipelinePanel from "@/components/analysis/PipelinePanel";
import TimelinePanel from "@/components/analysis/TimelinePanel";
```

These two files are the only importers:

```bash
cd apps/web && grep -rn "RuleMatchesPanel\|TimelinePanel\|AgentsPanel\|StixPanel\|PipelinePanel\|GeneratedRulesPanel" src --include=*.tsx --include=*.ts | grep "^src.*import"
```
Expected: exactly the six lines above.

- [ ] **Step 5: The redirect pages' comments**

Five route pages carry a comment saying where their panel now lives. Each names the panel with a `./` prefix that is no longer true:

| File | Line | New text |
| :-- | :-- | :-- |
| `apps/web/src/app/(app)/analysis/[id]/agents/page.tsx` | 8 | ` * panel itself now lives in @/components/analysis/AgentsPanel and is composed into the PROCESS tab;` |
| `apps/web/src/app/(app)/analysis/[id]/rules/page.tsx` | 8 | ` * panel itself now lives in @/components/analysis/RuleMatchesPanel and is composed into the DETECTION tab;` |
| `apps/web/src/app/(app)/analysis/[id]/timeline/page.tsx` | 8 | ` * panel itself now lives in @/components/analysis/TimelinePanel and is composed into the PROCESS tab;` |
| `apps/web/src/app/(app)/analysis/[id]/stix/page.tsx` | 8 | ` * panel itself now lives in @/components/analysis/StixPanel and is composed into the DETECTION tab;` |
| `apps/web/src/app/(app)/analysis/[id]/signatures/page.tsx` | 8 | ` * panel itself now lives in @/components/analysis/GeneratedRulesPanel and is composed into the DETECTION tab;` |
| `apps/web/src/app/(app)/analysis/[id]/pipeline/page.tsx` | 8 | ` * panel itself now lives in @/components/analysis/PipelinePanel and is composed into the PROCESS tab;` |

`apps/web/e2e/report-fixture.ts:19` and `:481` name `RuleMatchesPanel` as a component, not as a path, and are unchanged.

- [ ] **Step 6: The frontend gates**

```bash
cd apps/web
npx tsc --noEmit
npm run lint 2>&1 | tail -5
NEXT_TELEMETRY_DISABLED=1 npm run build
```
Expected: `tsc` clean; the lint warning count equal to the ledger's fourth row and no new warning; the production build succeeds.

- [ ] **Step 7: The tab spec**

No `next dev` may be running: Playwright starts its own server on its own port and a stray dev server takes the port and serves a different build.

```bash
pgrep -af "next dev" || echo "no dev server"
cd apps/web && ./scripts/e2e-clean-env.sh npx playwright test e2e/analysis-tabs.spec.ts --project=chromium
```
Expected: PASS. If `pgrep` finds a dev server started earlier in this session, stop it by its recorded pid; never `pkill -f next`.

- [ ] **Step 8: Commit**

```bash
git add apps/web/src/components/analysis "apps/web/src/app/(app)/analysis"
git commit -m "refactor: the six shared analysis panels move to components/analysis"
```

- [ ] **Step 9: Full suite and the goldens**

```bash
uv run pytest tests/ -q
uv run pytest tests/unit/pipeline/test_graph_snapshot.py tests/unit/agents/test_prompt_byte_identity.py \
  tests/unit/agents/test_revision_prompt_golden.py tests/unit/servers/test_builtin_tool_sets.py \
  tests/unit/servers/test_agent_parity.py tests/unit/test_topology_sources.py -q
```
Expected: PASS at the ledger's count. No Python changed in this task; the run proves that.

---
### Task 7: Documentation and root hygiene

**Files:**
- Move: `assets/*` → `docs/assets/`
- Create: `docs/README.md`
- Delete: `llama.log` (untracked, ignored by `*.log`; `rm`, not `git rm`)
- Modify: `README.md:2,27,29` (image links), a new "Repository layout" section after "Architecture", `README.md:466-474` and `:515-533` (the Development section's path names), `.gitignore` (full rewrite), `.dockerignore` (two additions)
- Test: `tests/unit/test_package_layout.py`, `tests/unit/test_docker_manifest.py`, `tests/unit/scripts/test_makefile_script_paths.py`, the full suite

**Interfaces:**
- Consumes: `git check-ignore -v`, which reports the rule that ignores a path and stays silent for a path already tracked in the index.
- Produces: `docs/README.md` as the entry point for the documentation tree, `docs/assets/` as the only place README images live.

- [ ] **Step 1: The images**

```bash
mkdir -p docs/assets
git mv assets/logo.svg docs/assets/logo.svg
git mv assets/ui-analysis.png docs/assets/ui-analysis.png
git mv assets/ui-attack.png docs/assets/ui-attack.png
git mv assets/ui-dashboard.png docs/assets/ui-dashboard.png
git mv assets/ui-detection.png docs/assets/ui-detection.png
ls assets 2>&1
```
Expected: five renames staged and `assets` gone.

`README.md`, line 2:

```html
  <img src="docs/assets/logo.svg" alt="Maljan" width="112">
```

`README.md`, lines 27 and 29:

```markdown
| <img src="docs/assets/ui-dashboard.png" alt="Dashboard"> | <img src="docs/assets/ui-analysis.png" alt="Analysis detail"> |
```
```markdown
| <img src="docs/assets/ui-detection.png" alt="Detection tab"> | <img src="docs/assets/ui-attack.png" alt="ATT&CK matrix"> |
```

- [ ] **Step 2: The root log**

```bash
git ls-files llama.log        # prints nothing: it was never tracked
rm llama.log
git check-ignore -v llama.log 2>&1 || echo "no longer present"
```
Expected: the file is gone and nothing is staged for it. `*.log` in `.gitignore` is what kept it out of the index and stays in Step 4, so a llama run that recreates it stays ignored.

- [ ] **Step 3: The README's new section**

Insert a "Repository layout" section immediately after the "Architecture" section's closing `---` (currently line 85), before "## Quick Start":

```markdown
## Repository layout

```
maljan/
├── apps/
│   ├── api/                 FastAPI app + arq worker; workspace member "maljan-api"
│   └── web/                 Next.js UI; shared analysis panels in src/components/analysis/
├── src/maljan/              the core package: agents, pipeline, providers, analysis, memory
├── services/
│   ├── network-mcp/         PCAP tooling over stdio MCP, bound to the network analyst
│   └── threatintel-mcp/     VirusTotal and AbuseIPDB over stdio MCP, bound to the judge
├── scripts/
│   ├── dev/                 the LLM server launcher, the overnight guard, the Ghidra manager
│   ├── goldens/             one-off capture scripts that write tests/fixtures/golden/
│   ├── knowledge/           builders for the data/ assets and the evaluation fixtures
│   ├── paper/               the paper conformance check and the cohort completer
│   └── settings/            the settings-annotation seeder
├── tests/
│   ├── unit/                mirrors src/maljan, one subdirectory per subpackage
│   ├── api/  integration/  fixtures/
│   └── evaluation/          the measured corpus and its analysis scripts
├── data/                    tracked knowledge assets, loaded lazily, each with a fallback
├── docker/                  Dockerfiles and the compose stack
├── docs/                    README.md (this tree explained), assets/, specs/, plans/
├── Makefile                 every gate and every generator
└── pyproject.toml uv.lock   one uv workspace: maljan plus apps/api
```

One `uv sync --all-extras` at the root installs both Python packages. There is no
`PYTHONPATH` anywhere: `maljan` and `app` are installed, in the venv, in the
image and in CI alike.
```

`README.md`, the Security section's "Static analysis" paragraph (lines 471-474):

```markdown
**Static analysis.** `make semgrep` runs the same `p/python` and
`p/security-audit` rulesets, pinned to the same semgrep version, as the
CI "Semgrep" job, across `src/`, `apps/api/`, `services/` and
`scripts/`.
```

`README.md`, the Development section's gate comment (lines 528-533):

```markdown
# The gate covers every Python directory in the repo: src/, tests/, apps/api/,
# services/ and scripts/. It used to be src/ and tests/ only, which
# meant the FastAPI app and the arq worker were never type-checked anywhere,
# and a sidecar could sit unformatted for weeks because pre-commit only ever
# sees staged files.
```

and gains, directly below the `make benchmark-*` block that ends the Development code fence:

```markdown
Tests live under `tests/unit/` (mirroring `src/maljan`), `tests/api/`,
`tests/integration/`, `tests/fixtures/` and `tests/evaluation/`. Generators and
operator tools live under `scripts/{dev,goldens,knowledge,paper,settings}/`;
`make -n <target>` shows which one a target runs.
```

- [ ] **Step 4: `docs/README.md`**

```markdown
# Maljan documentation

The repository's own map: where each concern lives, how to get a working
environment in one command, and where the design record is kept.

## Where things live

| Path | What is there |
| :-- | :-- |
| `src/maljan/` | The core package. Agents, the LangGraph pipeline, the provider layer, the deterministic evidence layers, memory and reporting. Module paths are stable; the evaluation corpus imports them by name. |
| `apps/api/` | The FastAPI application and the arq worker, as the workspace member `maljan-api`. Alembic migrations and the API's own `.env.example` sit beside it. |
| `apps/web/` | The Next.js interface. Route-local components stay in their route folder; a component two routes use lives in `src/components/`. |
| `services/` | Deployable sidecar processes. Each is one `server.py` speaking stdio MCP, launched by `maljan.core.config._builtin_servers()` and bound to one agent. |
| `scripts/dev/` | Running the system locally: the LLM server launcher, the overnight memory guard, the restart wrapper, the Ghidra MCP manager, the CAPE wrapper, the third-party fetcher. |
| `scripts/goldens/` | One-off capture scripts. Each writes a fixture under `tests/fixtures/golden/` and is committed so a reviewer can re-run it and diff the result. |
| `scripts/knowledge/` | Builders for the tracked data assets under `data/` and for the evaluation ground truth. The curated lists live in the builder; the JSON is the artefact. |
| `scripts/paper/` | The paper's machine-checkable rubric and the cohort completer. |
| `scripts/settings/` | The settings-annotation seeder, run when a new settings leaf needs its operator-facing text. |
| `tests/unit/` | Mirrors `src/maljan`, one subdirectory per subpackage. Every new test starts here. |
| `tests/api/`, `tests/integration/` | The FastAPI surface, and the flows that cross the worker, the database and object storage. |
| `tests/fixtures/` | Sample inputs, pinned prompts and the goldens. |
| `tests/evaluation/` | The measured corpus, its per-sample artefacts and the scripts that recompute the paper's numbers. Treated as read-only by feature work. |
| `data/` | Tracked knowledge assets. Loaded lazily, cached per path, each degrading to a built-in fallback when absent. |
| `docker/` | The Dockerfiles and the compose stack, production plus a development overlay. |
| `docs/specs/` | One design document per sub-project: the problem, the decisions and the invariants, approved before implementation. |
| `docs/plans/` | One implementation plan per design: tasks, exact commands, verification. |
| `docs/assets/` | The images the top-level README embeds. |

## One-command setup

```bash
uv sync --all-extras     # installs maljan and maljan-api into one environment
make setup               # the above, plus pre-commit and the third-party trees
```

The repository is one uv workspace with one `uv.lock`. Nothing needs
`PYTHONPATH`: both packages are installed, so `import maljan` and `import app`
work from any directory, in the venv, in the backend image and in CI.

```bash
make test        # the whole suite
make check       # lint, format check, type check, tests
make semgrep     # the security rulesets CI runs
```

## The design record

Read the spec before the plan, and the plan before the code. Specs are approved
designs; plans are the task-by-task execution of one spec; both are kept as
written, including the paths they named at the time.

- `docs/specs/2026-09-02-runtime-settings-design.md` and `docs/plans/2026-09-02-runtime-settings.md`
- `docs/specs/2026-09-03-provider-layer-design.md` and `docs/plans/2026-09-03-provider-layer.md`
- `docs/specs/2026-09-03-security-hardening-design.md` and `docs/plans/2026-09-03-security-hardening.md`
- `docs/specs/2026-09-04-tool-servers-design.md` and `docs/plans/2026-09-04-tool-servers.md`
- `docs/specs/2026-09-05-agent-composition-design.md` and `docs/plans/2026-09-05-agent-composition.md`
- `docs/specs/2026-09-06-repository-layout-design.md` and `docs/plans/2026-09-06-repository-layout.md`

The top-level `README.md` is the product-facing document: what Maljan does, how
to run it and how it is configured. This file is the repository-facing one.
```

- [ ] **Step 5: `.gitignore`, before**

Record what the current file does, so the rewrite can be compared against it rather than against memory:

```bash
for p in data/samples/x.exe data/samples/rat-collection/a data/uploads/x \
         other/x logs/x models/x external/x llama.log apps/web/.next/x \
         data/sigma_rules/x data/capa-rules/x data/cape_reports/x data/external/x \
         .env apps/api/.env node_modules/x .venv/x apps/api/.venv/x; do
  printf '%-40s ' "$p"; git check-ignore -v "$p" || echo "(not ignored)"
done
for p in .env.example apps/api/.env.example "apps/web/src/app/(app)/samples/page.tsx" \
         data/samples/dynamic/sample_1.json data/samples/network/sample_1.json \
         data/samples/static/sample_1.json README.md; do
  printf '%-50s ' "$p"; git check-ignore -v "$p" || echo "(not ignored)"
done
git status --short | head
```
Every path in the first list must report a rule; every path in the second must report `(not ignored)`. The three `data/samples/*/sample_1.json` fixtures are tracked, which is why `check-ignore` stays silent for them — the rule `samples/` would otherwise cover them, and `git ls-files` in Step 7 is what proves they are still in the index.

- [ ] **Step 6: `.gitignore`, after**

Replace the file in full. Sections are by area, one comment each; the removals are the redundant entries a broader rule in the same file already covers, so no path changes status:

```gitignore
# ── Python build and cache output ──────────────────────────────────────
__pycache__/
*.py[oc]
build/
dist/
wheels/
*.egg-info
.mypy_cache/
.pytest_cache/
.ruff_cache/

# ── Virtual environments ───────────────────────────────────────────────
# A pattern without a slash matches at any depth, so this covers apps/api/.venv
# and apps/web/.venv as well as the root one.
.venv

# ── Node and Next.js ───────────────────────────────────────────────────
node_modules/
apps/web/.next/
apps/web/out/
# Playwright run artefacts: screenshots, traces, error contexts from failures.
apps/web/test-results/
apps/web/playwright-report/

# ── Secrets ────────────────────────────────────────────────────────────
# Every real .env and any *.local override, at any depth. The example and
# template files are the tracked ones, at any depth, and win over the rules
# above them.
.env
.env.local
.env.*.local
!**/.env.example
!**/.env.template

# ── Real malware ───────────────────────────────────────────────────────
# Any directory named samples/, which is the worker's mirror of MinIO-downloaded
# binaries and the live-malware dataset copies beneath it. The fixtures under
# data/samples/{dynamic,network,static}/ are already tracked and stay tracked.
samples/
# ...but not the web app's own samples route, which is source, not a payload drop.
!apps/web/src/app/(app)/samples/
# Runtime upload staging: the API streams uploads through data/uploads/.tmp
# (Defender-excluded) before pushing to MinIO. Ephemeral.
data/uploads/

# ── Third-party corpora, fetched rather than vendored ──────────────────
# scripts/dev/fetch_external.sh clones each at a pinned ref, licence file and all.
external/
data/sigma_rules/
data/capa-rules/
data/external/
# CAPE analysis reports for the n=100 dynamic cohort: ~7 MB each, reproducible
# from the committed task ledger (tests/evaluation/cape_task_ledger_n100.json)
# plus the instance. The ledger is the artefact worth versioning.
data/cape_reports/

# ── Local model weights ────────────────────────────────────────────────
/models/
*.gguf
*.safetensors

# ── Machine-local output ───────────────────────────────────────────────
# Logs at any depth, which is what keeps a root llama.log out of the index, and
# the overnight watch directory.
*.log
logs/
# A/B eval transient checkpoints, regenerated per run.
tests/evaluation/ab_off.jsonl
tests/evaluation/ab_on.jsonl
tests/evaluation/ab_off.partial.jsonl

# ── Not part of this repository ────────────────────────────────────────
# Third-party threat reports, the journal's guide and class files, reference
# PDFs, drafts. One directory rather than a scatter of root-level entries, so
# "is this ours" is answered by where a file sits.
/other/

# ── Tooling state ──────────────────────────────────────────────────────
.claude/settings.local.json
# Ephemeral cron lock, written per session by Claude /schedule.
.claude/scheduled_tasks.lock
```

Removed as redundant, each covered by a rule that is still present:

| Removed | Covered by |
| :-- | :-- |
| `**/.venv/` | `.venv` (no slash, so any depth) |
| `**/.env`, `**/.env.local`, `**/.env.*.local` | `.env`, `.env.local`, `.env.*.local` (no leading slash, so any depth) |
| `data/samples/*.apk` and the ten sibling extension rules | `samples/` |
| `data/samples/rat-collection/`, `data/samples/dike/`, `data/samples/extracted/` | `samples/` |

- [ ] **Step 7: `.gitignore`, verify**

Re-run both loops from Step 5 verbatim. Expected: byte-identical status for every path — the same seventeen ignored, the same seven not ignored — with only the rule line numbers moving. Then:

```bash
git ls-files data/samples/dynamic/sample_1.json data/samples/network/sample_1.json \
  data/samples/static/sample_1.json
git status --short
git check-ignore -v other/ logs/ models/ external/ llama.log
```
Expected: the three fixtures are listed (still tracked), `git status` shows only this task's staged changes and no deletion under `data/samples/`, and the last command names a rule for each of the five.

- [ ] **Step 8: `.dockerignore`**

The build context still needs `services/`, so nothing is removed. Two directories that are never `COPY`-ed are added, at the end of the "Build artifacts & logs" section, which becomes:

```
# Build artifacts & logs
*.log
reports/

# Never copied into any image: the documentation tree (including its images) and
# the test suite, which the compose stack bind-mounts from the host instead.
docs/
tests/
```

Every other line in `.dockerignore` is unchanged, including the `data/samples/*` extension list, which mirrors the ignore rules rather than reusing them because Docker has no equivalent of a directory-name pattern.

Confirm the Dockerfile does not need either:

```bash
grep -n "^COPY" docker/Dockerfile.backend
```
Expected: `pyproject.toml uv.lock`, `apps/api/pyproject.toml`, `src/`, `apps/`, `data/`, `services/` and the uv binary stage. Neither `docs/` nor `tests/` appears.

- [ ] **Step 9: Verify and commit**

```bash
uv run pytest tests/unit/test_package_layout.py tests/unit/test_docker_manifest.py \
  tests/unit/scripts/test_makefile_script_paths.py -q
grep -rn "assets/" README.md
docker compose -f docker/docker-compose.yml config >/dev/null && echo "compose ok"
git add README.md docs/README.md docs/assets assets .gitignore .dockerignore
git commit -m "docs: a documentation index, the repository layout in the readme, and a tidied gitignore"
```
Expected: the three tests pass, every `assets/` hit in the README reads `docs/assets/`, compose validates.

- [ ] **Step 10: Full suite and the goldens**

```bash
uv run pytest tests/ -q
uv run pytest tests/unit/pipeline/test_graph_snapshot.py tests/unit/agents/test_prompt_byte_identity.py \
  tests/unit/agents/test_revision_prompt_golden.py tests/unit/servers/test_builtin_tool_sets.py \
  tests/unit/servers/test_agent_parity.py tests/unit/test_topology_sources.py -q
```
Expected: PASS at the ledger's count.

---

### Task 8: The final gate

**Files:**
- Modify: `docs/specs/2026-09-06-repository-layout-design.md` (the status line only)
- Test: everything

**Interfaces:**
- Consumes: `git worktree`, `docker build`, `docker compose`, the live stack.
- Produces: a pull request into `dev`.

- [ ] **Step 1: The static gates**

```bash
free -g
make lint
make format-check
make typecheck
make semgrep
```
Expected: all four clean, over `src/ tests/ apps/api/ services/ scripts/`.

- [ ] **Step 2: The suite, against the ledger**

```bash
uv run pytest tests/ -q --co -q | tail -1
uv run pytest tests/ -q
```
Expected: the collected count equals the ledger's first and second rows; write it into the third. The suite passes.

```bash
uv run pytest tests/unit/pipeline/test_graph_snapshot.py tests/unit/agents/test_prompt_byte_identity.py \
  tests/unit/agents/test_revision_prompt_golden.py tests/unit/servers/test_builtin_tool_sets.py \
  tests/unit/servers/test_agent_parity.py tests/unit/test_topology_sources.py -q
```
Expected: PASS.

- [ ] **Step 3: The measured corpus is untouched**

```bash
make facts
git status --short tests/evaluation/
git diff dev -- tests/evaluation
git diff --stat dev -- tests/evaluation
```
Expected: all four produce no output about a change. `make facts` reads committed per-sample artefacts only — no LLM, no network — so a non-empty diff means a move leaked into the corpus.

- [ ] **Step 4: A clean checkout installs and runs**

```bash
free -g
git worktree add /tmp/maljan-layout-check HEAD
cd /tmp/maljan-layout-check
uv sync --all-extras
uv run pytest tests/unit -q
uv run maljan --help | head -3
uv run --directory apps/api uvicorn app.main:app --help | head -3
cd -
git worktree remove /tmp/maljan-layout-check
```
Expected: the sync installs `maljan` and `maljan-api` from the root lockfile with no second lockfile present; `tests/unit` passes in a tree that has never had a `PYTHONPATH` set; both entry points respond. `tests/integration` and `tests/api` are not run here — they want the infra containers, which Step 6 brings up.

- [ ] **Step 5: The images**

```bash
free -g
df -h . | tail -1
docker build -f docker/Dockerfile.backend -t maljan-backend:layout .
docker run --rm maljan-backend:layout python -c "import maljan, app; print('both import')"
docker run --rm maljan-backend:layout ls services/network-mcp/server.py services/threatintel-mcp/server.py
docker build -f docker/Dockerfile.frontend -t maljan-frontend:layout .
docker compose -f docker/docker-compose.yml config >/dev/null && echo "compose ok"
docker compose -f docker/docker-compose.yml -f docker/docker-compose.dev.yml config >/dev/null && echo "dev overlay ok"
```
Expected: both images build, the backend imports both packages with no `PYTHONPATH`, both sidecars are present inside the image at their new path, and both compose renderings validate.

- [ ] **Step 6: One live job**

Stop anything holding memory first; do not stop the separate `cti-life` project.

```bash
free -g
cd docker && POSTGRES_PORT=5433 docker compose up -d postgres redis qdrant minio ghidra-mcp && cd -
docker compose -f docker/docker-compose.yml ps
```

Then start the API and the worker from the tree, each in its own terminal, with no `PYTHONPATH` exported anywhere:

```bash
env | grep -i pythonpath || echo "no PYTHONPATH set"
uv run --directory apps/api uvicorn app.main:app --host 127.0.0.1 --port 8000
```
```bash
uv run arq app.worker.analysis_worker.WorkerSettings
```

Submit one sample through the UI with every select left on "Inherit from settings", so the job runs the `default` profile. Confirm:

- the job reaches `completed` and the report renders every tab;
- the worker log shows both sidecars attaching, with the launch path under `services/` (`grep -i "services/network-mcp\|services/threatintel-mcp"` over the worker output);
- `run_summary.profile` names `default` with the three built-in analysts;
- the API's `/reports/{id}/markdown` responds, which is the endpoint that used to need `src` on the path.

Then bring the infra down:

```bash
cd docker && docker compose down && cd -
```

- [ ] **Step 7: The web gates**

```bash
pgrep -af "next dev" || echo "no dev server"
cd apps/web
npx tsc --noEmit
npm run lint 2>&1 | tail -5
NEXT_TELEMETRY_DISABLED=1 npm run build
./scripts/e2e-clean-env.sh npx playwright test e2e/analysis-tabs.spec.ts --project=chromium
cd -
```
Expected: `tsc` clean, the ledger's warning count with no new warning, the build succeeds, the tab spec passes.

- [ ] **Step 8: The spec's status line**

`docs/specs/2026-09-06-repository-layout-design.md`, line 3:

```markdown
Status: implemented on branch `chore/repo-layout` from `dev` (7c2d517). Companion plan: `docs/plans/2026-09-06-repository-layout.md`.
```

- [ ] **Step 9: The pull request**

```bash
git add docs/specs/2026-09-06-repository-layout-design.md docs/plans/2026-09-06-repository-layout.md
git commit -m "docs: mark the repository layout design implemented"
git log --oneline dev..HEAD
git diff --stat dev..HEAD -- . ':!tests/evaluation'
git push -u origin chore/repo-layout
gh pr create --base dev --title "chore: repository layout" --body "$(cat <<'BODY'
Moves the top level into the shape `docs/specs/2026-09-06-repository-layout-design.md` fixes, with no behaviour change.

- The two MCP sidecars move to `services/`; `_builtin_servers()`, the capture script, the Dockerfile, compose, the Makefile, CI and the e2e mocks follow them.
- `scripts/` becomes five directories by kind; every path anchor, Makefile target and operator-facing docstring follows.
- The four stray top-level test folders merge into `tests/unit/`, which now mirrors `src/maljan` throughout.
- `apps/api` becomes a uv workspace member. One `uv.lock`, one `uv sync`, and no `PYTHONPATH` in the Makefile, CI, the Dockerfile, compose or the worker.
- The six shared analysis panels move to `apps/web/src/components/analysis/`.
- README images move to `docs/assets/`, `docs/README.md` indexes the tree, `.gitignore` is grouped by area with the redundant rules removed, and the root `llama.log` is gone.

Verification: the collected test count is unchanged, the six golden modules pass, `make facts` and `git diff dev -- tests/evaluation` are empty, a clean `git worktree` installs and runs `tests/unit` plus `maljan --help`, both images build and the backend imports `maljan` and `app` with no `PYTHONPATH`, and one default-profile job completes end to end with both sidecars attaching from `services/`.
BODY
)"
```
Expected: CI green on the PR. `main` follows only on the user's word.

---

## Final check on this plan

```bash
grep -n "TBD\|TODO\|similar to Task\|update references\|fill in" docs/plans/2026-09-06-repository-layout.md
```
Expected: no output.
