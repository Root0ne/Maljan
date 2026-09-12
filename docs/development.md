# Development

What is where, which command runs which gate, and the conventions a change is
expected to follow.

## Repository layout

```
Maljan/
├── apps/
│   ├── api/           FastAPI app, arq worker, Alembic migrations ("maljan-api")
│   └── web/           Next.js console, Playwright specs under e2e/
├── src/maljan/        the core package: agents, pipeline, analysis layers,
│                      providers, memory, reporting, core (config, container)
├── services/          stdio MCP sidecars, one server.py each
├── scripts/
│   ├── dev/           fetch_external.sh and the Ghidra image manager
│   ├── goldens/       one-off capture scripts that write tests/fixtures/golden/
│   ├── knowledge/     builders for the data/ assets and the evaluation fixtures
│   └── paper/         the paper conformance check and the cohort completer
├── tests/             unit/ api/ integration/ fixtures/ evaluation/
├── data/              tracked knowledge assets, loaded lazily, each with a fallback
├── docker/            Dockerfiles, the compose stack and its dev overlay
├── docs/              this documentation set and assets/
├── Makefile           every gate and every generator
└── pyproject.toml uv.lock   one uv workspace: maljan plus apps/api
```

The repository is one uv workspace with one lockfile. `uv sync --all-extras
--all-packages` installs both Python packages, so `import maljan` and
`import app` work from any directory without `PYTHONPATH`, in the venv, in the
backend image and in CI alike.

Route-local React components stay in their route folder; a component two routes
use moves to `apps/web/src/components/`. `tests/unit/` mirrors `src/maljan`,
one subdirectory per subpackage, and is where a new test starts.

Host-specific helpers (a launcher for a local llama-server, a memory guard, a
restart wrapper for long evaluations) live outside the repository. For the
record, the local model server the measurements in this repository were taken
with ran `ik_llama.cpp` as
`llama-server -m Qwen3.6-35B-A3B-IQ3_K_R4.gguf -c 131072 -t 16 -fa on -ctk q8_0 -ctv q8_0 -ngl 999 -ot 'blk\.([1-3][0-9])\.ffn_(up|gate|down)_exps=CPU' --context-shift on --jinja`
on loopback port 8080.

## Make targets

| Target | What it does |
| :-- | :-- |
| `make setup` | `uv sync --all-extras --all-packages`, pre-commit hooks, `external/`. |
| `make test` | `pytest tests/ -q`. `test-unit`, `test-integration` and `test-qdrant` narrow it. |
| `make lint` / `make format` / `make format-check` | ruff over `src/ tests/ apps/api/ services/ scripts/`. |
| `make typecheck` | mypy over `src/` and `apps/api/`. |
| `make check` | lint, format check, typecheck, tests — the local mirror of CI. |
| `make semgrep` | the two rulesets CI runs, at the pinned version. |
| `make migrate` | `alembic upgrade head` against `DATABASE_URL`. |
| `make dev-up` / `dev-down` / `dev-logs` | the compose stack with the development overlay. |
| `make fe-rebuild` / `worker-restart` | make a source edit real on the production stack. |
| `make external` | refetch the third-party trees at their pinned refs. |
| `make ghidra-status` / `-sync` / `-build` / `-watch` | the Ghidra MCP manager. |

## Tests

- **Python** — `uv run pytest tests/ -q`. `tests/unit/` is the default home;
  `tests/api/` covers the FastAPI surface and `tests/integration/` the flows
  that cross the worker, the database and object storage. The suite needs no
  secret in the environment: a pytest-only JWT secret is substituted, and the
  auth bypass is forced off so real 401 and 403 assertions still mean
  something.
- **Frontend unit** — `cd apps/web && npm run test:unit` (vitest), alongside
  `npx tsc --noEmit` and `npm run lint`.
- **Playwright** — `cd apps/web && npm run test:e2e`. The suite starts its own
  `next dev` on port 3100, forces `NEXT_PUBLIC_AUTH_DISABLED=false` and points
  the client at the Next server's own origin, so it is hermetic and contacts no
  backend; every API call is mocked in `e2e/mocks.ts`. Run a named spec while
  developing (`npx playwright test e2e/settings-configuration.spec.ts
  --project=chromium`) rather than the whole suite, and stop any dev server you
  started yourself first — the browsers are memory-hungry, which is why the
  local worker count and the timeouts are raised deliberately.
- **`tests/evaluation/`** — the measured corpus behind the paper. Feature work
  treats it as read-only; CI enforces that with
  `scripts/paper/check_evaluation_diff.py`, which compares syntax trees with
  every string blanked and admits only string-literal and docstring edits
  inside existing `.py` files.

## Continuous integration

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on pushes to
`main` and `dev` and on pull requests into `main`, `dev` or `feat/**`:

| Job | Contents |
| :-- | :-- |
| `quality` | The evaluation-artefact gate (off `main`), ruff lint, ruff format check, mypy. Every other job needs it. |
| `semgrep` | `p/python` and `p/security-audit` at the pinned version, over `src/ apps/api/ services/ scripts/`. |
| `test` | `pytest tests/ -q --tb=short` on Python 3.13. |
| `test-qdrant` | `tests/unit/test_qdrant_store.py` against a live Qdrant service container. |
| `frontend` | `tsc --noEmit`, eslint, vitest and a production `next build`. |
| `e2e` | Playwright, through the same `npm run test:e2e` entry point developers use. |

## Conventions

- Conventional commits, one logical slice per commit.
- Feature branches start from `dev` and are merged into `dev`; `main` is
  branch-protected and only ever advanced by an explicit promotion pull
  request from `dev`.
- No question sentences in headings, comments or documentation.
- A comment explains why the code is the way it is. Process tags — dated audit
  identifiers, ticket numbers, "new in phase B" — do not belong in the tree;
  the reasoning stays, the bookkeeping goes.
- New settings need an entry in `src/maljan/core/settings_annotations.py`, or
  they appear in the console under their dotted path with no description.
- A removal is not done until `grep` shows zero remaining references across
  `src apps tests scripts docs` and the affected tests are updated.
