# Suggested Commands
- `uv sync`: Install dependencies.
- `make check`: Run all quality gates (lint, typecheck, tests).
- `make test`: Run all pytest tests.
- `make lint`: Run Ruff linting.
- `make typecheck`: Run MyPy type checking.
- `cd docker && docker compose up --build -d`: Start all services (API, Worker, Frontend, Postgres, Redis, Minio, Qdrant).
- `uv run maljan analyze <hash> --provider openai`: Run CLI analysis standalone.
- `uv run python -c "from maljan.memory.attck_validator import ATTCKValidator; ATTCKValidator.get_instance()"`: Pre-build ATT&CK index cache.
