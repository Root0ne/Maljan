# Repository layout design

Status: implemented on branch `chore/repo-layout` from `dev` (7c2d517). Companion plan: `docs/plans/2026-09-06-repository-layout.md`.

## 1. Problem

The repository grew sub-project by sub-project and its top level shows it: two single-file MCP sidecars sit beside `src/` as `network-mcp/` and `threatintel-mcp/`; `scripts/` holds twenty tools of five unrelated kinds in one flat directory; tests live in six top-level folders where four of them (`agents/`, `pipeline/`, `providers/`, `servers/`) duplicate the `tests/unit/<subpackage>` mirroring the rest of the suite follows; six analysis panels are imported across routes from the route folder that happened to create them; `apps/api` is a separate uv project with its own lockfile and a path dependency back to the root, so the runtime is stitched together with `PYTHONPATH` in the Makefile, CI, the Dockerfile, docker-compose and a `sys.path.insert` inside the worker; a `llama.log` sits at the root and README images live in a top-level `assets/`.

## 2. Decisions

| Question | Decision | Reason |
| :-- | :-- | :-- |
| Python package internals | `maljan.*` module paths do not change | `tests/evaluation/**` imports them and must stay byte-identical; the goldens pin the default profile; a stage-based regrouping would need permanent shims |
| Packaging | One uv workspace: root `maljan` plus member `apps/api` (`maljan-api`), one `uv.lock` | Removes every `PYTHONPATH` and `sys.path` shortcut; one `uv sync` installs both |
| Sidecars | `services/network-mcp/`, `services/threatintel-mcp/` | Deployable processes are not library code and not scripts |
| Scripts | `scripts/{dev,goldens,knowledge,paper,settings}/` | Five kinds of tool, five directories |
| Tests | `tests/unit/` mirrors `src/maljan`; `tests/api/`, `tests/integration/`, `tests/fixtures/`, `tests/evaluation/` stay; the four stray top-level folders move under `tests/unit/` | One rule for where a test lives |
| Web | Shared analysis panels in `apps/web/src/components/analysis/` | A component imported by two routes is not route-local |
| Images | `assets/` becomes `docs/assets/` | Documentation assets belong with documentation |
| Git-ignored local trees | `other/`, `logs/`, `models/`, `external/`, `data/samples` binaries stay where they are | They are outside the repository; only the root `llama.log` is removed and `.gitignore` sections are tidied |
| Behaviour | No behaviour change anywhere | This is a move; every test, golden and artefact proves it |

## 3. Target layout

```
maljan/
├── apps/
│   ├── api/                 FastAPI app + arq worker; workspace member "maljan-api"
│   │   ├── app/             (unchanged inside)
│   │   ├── alembic/ alembic.ini .env.example pyproject.toml
│   └── web/                 Next.js app (unchanged except components/analysis)
├── src/maljan/              core package, module paths unchanged
├── services/
│   ├── network-mcp/         server.py, README.md
│   └── threatintel-mcp/     server.py, README.md
├── scripts/
│   ├── dev/                 llm_server.sh night_guard.sh run_with_restarts.sh ghidra_manager.py cape_mcp_wrapper.py fetch_external.sh
│   ├── goldens/             capture_builtin_tool_sets.py capture_graph_golden.py capture_provider_goldens.py capture_revision_prompt_golden.py probe_r2_tools.py
│   ├── knowledge/           build_api_capability_db.py build_attck_case_kb.py build_family_feature_kb.py expand_yara_rules.py prepare_attck_malware_fixtures.py prepare_tram_dataset.py
│   ├── paper/               check_paper.sh complete_cohort.sh
│   └── settings/            seed_settings_annotations.py
├── tests/
│   ├── unit/                existing tree + agents/ pipeline/ providers/ servers/ (moved in)
│   ├── api/  integration/  fixtures/
│   └── evaluation/          untouched
├── data/                    tracked knowledge assets (unchanged)
├── docker/                  compose files and Dockerfiles (paths updated)
├── docs/
│   ├── README.md            index: layout, where things live, how to run
│   ├── assets/              README images (moved from assets/)
│   ├── specs/  plans/
├── .github/workflows/ci.yml
├── Makefile  pyproject.toml  uv.lock  README.md  LICENSE  .env.example  .gitignore  .dockerignore  .pre-commit-config.yaml
```

## 4. Moves and the references each one carries

Every move is one commit that also updates every reference, so the tree is green at each commit.

### 4.1 Sidecars → `services/`
- `git mv network-mcp services/network-mcp`, `git mv threatintel-mcp services/threatintel-mcp`; a three-line README in each (what it serves, how it is launched, which agent receives it).
- `src/maljan/core/config.py::_builtin_servers()` args and cwd literals (`services/network-mcp/server.py`, cwd `services/network-mcp`, same for threatintel); `resolve_mcp_args` keeps resolving relative to the project root.
- `scripts/goldens/capture_builtin_tool_sets.py` literals; `docker/Dockerfile.backend` COPY lines; `.dockerignore`; `Makefile` `PY_SOURCES`; `.github/workflows/ci.yml` lint/semgrep path lists; `.pre-commit-config.yaml` if it names them; README sections that name the paths; `tests/fixtures/golden/mcp_tools/*` stay valid (they pin tool names, not paths) and `tests/servers/test_builtin_tool_sets.py` (moved in 4.4) keeps passing against the live handshake.

### 4.2 Scripts → grouped
- `git mv` per the table in §3; every shebang script keeps its mode.
- References: `Makefile` targets (`external`, `prepare-*`, `paper-check`, `cohort-complete`, `ghidra-*`), README (Quick Start, Development, ATT&CK cache, external), `docs/specs/*` and `docs/plans/*` mention historical paths and are left as history; `tests/unit/scripts/` tests import scripts by path or module: update their paths; `scripts/goldens/*` write to `tests/fixtures/golden/` with paths resolved from the project root, not from the script's location (verify each uses `get_project_root()` or an absolute anchor; fix the ones that used `Path(__file__).parents[1]`).
- The controller's own memory notes name `scripts/llm_server.sh`; updated at the end.

### 4.3 uv workspace
- Root `pyproject.toml`: `[tool.uv.workspace] members = ["apps/api"]`; `[tool.uv.sources] maljan-api = { workspace = true }` is not needed at the root; remove `[tool.pytest.ini_options].pythonpath` and `[tool.mypy].mypy_path` entries for `src`/`apps/api` (the packages are installed); keep `testpaths`.
- `apps/api/pyproject.toml`: `name = "maljan-api"`, `packages = ["app"]` (hatchling), dependency `maljan` with `[tool.uv.sources] maljan = { workspace = true }`; delete `apps/api/uv.lock`; `uv lock` at the root regenerates one lockfile including the API's dependencies.
- Delete the `sys.path.insert` block in `apps/api/app/worker/analysis_worker.py`.
- `docker/Dockerfile.backend`: copy `pyproject.toml uv.lock apps/api/pyproject.toml` first, `uv sync --frozen --no-dev` for the workspace, then the sources; remove `ENV PYTHONPATH`; `docker/docker-compose.yml` and `docker-compose.dev.yml`: remove `PYTHONPATH` environment lines, keep the bind mounts (paths updated for `services/`); the uvicorn and arq commands are unchanged (`app.main:app`, `app.worker.analysis_worker.WorkerSettings` resolve through the installed `maljan-api` package).
- `Makefile`: drop `PYTHONPATH=src` from the benchmark targets (`python -m tests.evaluation.benchmark_suite` runs from the root, `maljan` is installed); `setup` runs one `uv sync --all-extras`.
- CI: `uv sync` once at the root (already the case) and no `PYTHONPATH`.
- `apps/api/.env.example` stays with the app.

### 4.4 Tests consolidated
- `git mv tests/agents/* tests/unit/agents/` (name collisions are renamed with a suffix that says what the test covers, never merged), `tests/pipeline/* → tests/unit/pipeline/`, `tests/providers/* → tests/unit/providers/`, `tests/servers/* → tests/unit/servers/` (including `rest_stub.py`); `tests/fixtures/` unchanged.
- References: the controller sweep list in memory and `other/audit` ledgers (history, left alone), `docs/plans` (history), README Development section, CI (`uv run pytest tests/` — unchanged), `tests/unit/test_topology_sources.py` allow-lists that name test files by path (`tests/servers/test_agent_parity.py` if present), any test that opens a sibling file by relative path (`rest_stub.py`, golden fixtures resolved from `tests/fixtures/`).
- Test count before and after is identical (moves only); `tests/evaluation/**` untouched; `make facts` byte-identical.

### 4.5 Web shared components
- `git mv` the six panels (`RuleMatchesPanel`, `TimelinePanel`, `AgentsPanel`, `StixPanel`, `PipelinePanel`, `GeneratedRulesPanel`) from their route folders to `apps/web/src/components/analysis/`; update every import (route pages and the panels' mutual imports); `tsc`, lint, build; Playwright `analysis-tabs.spec.ts` on chromium.

### 4.6 Docs and root hygiene
- `git mv assets docs/assets`; README image links updated; `docs/README.md` index written (layout table, where each concern lives, the one-command setup, links to specs/plans).
- README gains a "Repository layout" section (the tree in §3) and its Development section names the new script and test paths; `.gitignore` sections reordered by area with one comment each, stale entries removed (verify each removal with `git check-ignore` before and after on a sample path); root `llama.log` deleted and `*.log` at the root ignored; `.dockerignore` mirrors the new tree.

## 5. Invariants and verification

- `maljan.*` import paths unchanged: a test imports every module listed in `git ls-files src/maljan` by name (`tests/unit/test_package_layout.py`) and the six golden modules stay green.
- `tests/evaluation/**` byte-identical to `dev`; `make facts && git status --short tests/evaluation/` empty.
- Test count unchanged: the full-suite count at the end equals the count on `dev` (4041 passed at the same skip count); the pinned artefact is not re-pinned.
- Clean install works: in a fresh clone (or `git worktree`) `uv sync --all-extras` at the root installs `maljan` and `maljan-api`, `uv run pytest tests/ -q` passes, `uv run maljan --help` works, `uv run --directory apps/api uvicorn app.main:app --help` works.
- Docker: `docker compose -f docker/docker-compose.yml config` validates; `docker build -f docker/Dockerfile.backend .` succeeds and the image imports both packages (`python -c "import maljan, app"`) without `PYTHONPATH`; the frontend image builds.
- Live smoke on the branch: infra containers, API and worker started from the tree with no `PYTHONPATH`, one default-profile job completes, the sidecars launch from `services/` (the worker log shows the network and threat-intel servers attaching).
- Web: `tsc --noEmit`, lint (pre-existing warnings only), build; `analysis-tabs.spec.ts` chromium.
- CI green on the PR into `dev`; `main` follows only on the user's word.

## 6. Out of scope

- Regrouping `src/maljan` internals (ingest/evidence/platform), splitting the files over 1500 lines, merging `apps/api/app/config.py` with `maljan.core.config`, moving `other/docs/academic-article` into the repository, converting `external/` to submodules. Each is a behaviour or licensing decision, not a layout move.

## 7. Risks

- **Hidden path literals.** The inventory lists every known one; the layout test plus a clean-clone install and the Docker build catch the rest.
- **Test collisions on merge into `tests/unit/`.** Renamed with descriptive suffixes; pytest's `--import-mode=importlib` is not assumed, so duplicate basenames across packages are avoided by checking `find tests -name` before each move.
- **uv workspace resolution.** If the API's pinned dependencies conflict with the root's, the lock step fails loudly; the fix is to align the pin in the API's `pyproject.toml`, never to loosen the root's.
- **Docker layer cache.** The Dockerfile copies manifests before sources so the dependency layer stays cached.
