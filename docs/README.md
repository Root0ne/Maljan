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
uv sync --all-extras --all-packages     # installs maljan and maljan-api into one environment
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
