# Style and Conventions

> Refreshed 2026-07-05.

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
  Platform values are now ONLY windows/linux/unknown; foreign samples rejected at entry.
- **Confidence integrity (CONF-INFL-01)**: do not surface inflated cascade-only confidence; honour
  `degraded_mode` and the 0.60 cap in consumers.
- **New feature pattern (June 2026)**: retrieval/heuristic additions must be config-gated on
  `PreprocessingConfig`, fail-safe (None/empty on any error), verdict-neutral (advisory hints,
  LLM decides), and measured by an `eval_*` harness before being enabled by default. Vendor only
  derived text catalogs in `data/`; never commit binaries (`data/samples/` gitignored).
- **Agent event loop**: all agent coroutines run on the shared persistent loop
  (`base_agent._get_agent_loop()`); never create/close per-call event loops (BUG-04/06 regression).
- **Research findings** go to `docs/academic-article/findings-log.md` (append-only,
  IMPLEMENTED/EXPERIMENTAL/OBSERVED/HYPOTHESIS/NEGATIVE tags).

## Testing
- pytest in `tests/`; fixtures in `tests/conftest.py`.
- Unit `tests/unit/` (79 modules recursive), integration `tests/integration/` (6),
  `tests/evaluation/` = 8 `test_*` scoring tests + 10 `eval_*` measurement harnesses
  (deliberately not `test_*` so pytest skips them).
- **Frontend E2E**: Playwright in `apps/web/e2e/` (`playwright.config.ts`); run with `npx playwright test`.

## Development Workflow
- `make setup` — deps + pre-commit
- `make check` — lint + format-check + typecheck + test (full gate)
- `make ci-check` — lint + format-check + test (fast gate)
- `make format` — auto-fix + format
