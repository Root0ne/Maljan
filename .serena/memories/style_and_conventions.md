# Style and Conventions

> Refreshed 2026-05-30.

## Language & Formatting
- All code, comments, identifiers, docs, and commit messages in **English**.
- Line length 100 (Ruff). No emojis in code. Python 3.13+ with strict type hints (mypy strict).

## Linting & Formatting
- Ruff rules `E`, `F`, `I`, `W`, `UP`, `B`. Import sorting via Ruff.
- Per-file ignore: `src/maljan/agents/*.py` ignores `E501` (long LLM prompt strings).
- MyPy: `disallow_untyped_defs`, `disallow_incomplete_defs`, `warn_return_any`, `ignore_missing_imports`
  (overrides for the LangChain/LangGraph/tiktoken/qdrant ecosystem).

## Async & IO
- Async-first for all DB/Redis/HTTP/MinIO. SQLAlchemy 2.0 async via asyncpg.
- ARQ workers run the pipeline natively async (`MaljanApp.arun()`) to avoid "Event loop is closed".

## Architecture Rules
- **DI**: use `ServiceContainer` (`core/container.py`). No global state / module-level singletons
  (exception: `ATTCKValidator` double-checked-locking singleton). Config via lazy `get_settings()` —
  never instantiate `Settings()` at import time (breaks test monkeypatching).
- **Models**: Pydantic v2 for validation, SQLAlchemy 2.0 for ORM.
- **Agents**: new analysts extend `BaseAnalyst` + `@register_agent("name")`. JudgeAgent is the
  exception (not registered, not a BaseAnalyst).
- **Config duality**: core nested Pydantic (`src/maljan/core/config.py`, `__` delimiter) vs API flat
  env (`apps/api/app/config.py`). Update `.env.example` + the relevant model when changing config.
- **Analyst topology**: respect `LLMConfig.parallel_analysts` (hosted parallel vs local sequential).
- **Graceful Degradation** (mandatory): YARA, Sigma, ATT&CK validator, LTM, MCP, sandbox, narrative,
  detection signatures, extractors, and enrichment must all fail silently with a logged warning —
  the pipeline always continues.
- **Platform consistency (Wave 4)**: when touching the cascade / detection rules / fp_linter, keep
  `state["platform"]` threaded consistently (judge and report nodes must use the same value).
- **Confidence integrity (CONF-INFL-01)**: do not surface inflated cascade-only confidence; honour
  `degraded_mode` and the 0.60 cap in consumers.

## Testing
- pytest in `tests/`; fixtures in `tests/conftest.py`.
- Unit `tests/unit/` (~58 modules), integration `tests/integration/` (6), benchmarks `tests/evaluation/` (4).
- **Frontend E2E**: Playwright in `apps/web/e2e/` (`playwright.config.ts`); run with `npx playwright test`.

## Development Workflow
- `make setup` — deps + pre-commit
- `make check` — lint + format-check + typecheck + test (full gate)
- `make ci-check` — lint + format-check + test (fast gate)
- `make format` — auto-fix + format
