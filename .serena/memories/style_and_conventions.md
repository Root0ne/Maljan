# Style and Conventions

## Language & Formatting
- **Language**: All code, comments, variable names, and commit messages in **English**.
- **Line Length**: 100 characters (Ruff).
- **No emojis** in code.
- **Python**: 3.13+ with strict type hints (mypy strict mode).

## Linting & Formatting
- **Ruff** rules: `E`, `F`, `I`, `W`, `UP`, `B`
- **isort**: Absolute imports preferred; Ruff handles import sorting.
- **Per-file ignores**: `src/maljan/agents/*.py` ignores `E501` for long LLM prompt strings.
- **Type checking**: MyPy with `disallow_untyped_defs=true`, `disallow_incomplete_defs=true`, `warn_return_any=true`, `ignore_missing_imports=true`.

## Async & IO
- **Async-first**: All DB/Redis/HTTP/MinIO operations use `async`/`await`.
- SQLAlchemy 2.0 async via `asyncpg`.
- ARQ worker runs pipeline natively async (`MaljanApp.arun()`) to avoid "Event loop is closed" errors.

## Architecture Rules
- **Dependency Injection**: Use `ServiceContainer` (`src/maljan/core/container.py`). Never global state or module-level singletons (except `ATTCKValidator` which uses double-checked locking for thread-safe lazy init).
- **Models**: Pydantic v2 for validation, SQLAlchemy 2.0 for ORM.
- **Agents**: New agents must extend `BaseAnalyst` and register via `@register_agent("name")` in `AgentRegistry`.
- **Config**: Two separate systems:
  1. Core: `src/maljan/core/config.py` – nested Pydantic models with `__` delimiter (e.g., `LLM__PROVIDER`, `LLM__AGENTS__STATIC__PROVIDER`).
  2. API: `apps/api/app/config.py` – flat env vars (e.g., `DATABASE_URL`).
- **Environment**: If changing config, update both `.env.example` and the relevant config model.
- **Graceful Degradation**: All optional components (YARA, Sigma, ATT&CK validator, LTM, MCP) fail silently with logged warnings. Pipeline always continues.

## Testing
- **pytest** in `tests/` directory.
- **Fixtures** in `tests/conftest.py`.
- Unit tests: `tests/unit/` (35 modules)
- Integration tests: `tests/integration/` (4 modules)
- Benchmarks: `tests/evaluation/`

## Development Workflow
- `make setup` – install deps + pre-commit
- `make check` – lint + format-check + typecheck + test (full gate)
- `make ci-check` – lint + format-check + test (fast gate, no typecheck)
- `make format` – auto-fix and format with Ruff
