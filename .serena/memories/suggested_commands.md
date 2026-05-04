# Suggested Commands

## Setup
- `uv sync` – Install all dependencies
- `uv run pre-commit install` – Install git hooks
- `make setup` – Runs both above

## Testing
- `make test` – Run all tests
- `make test-unit` – Unit tests only (35 modules)
- `make test-integration` – Integration tests only (4 modules)
- `make test-verbose` – Verbose pytest output
- `make test-qdrant` – Qdrant store test against local Qdrant

## Quality Gates
- `make lint` – Ruff linting
- `make format` – Ruff auto-fix + format
- `make format-check` – Check formatting without modifying
- `make typecheck` – MyPy strict type checking
- `make check` – Full gate: lint + format-check + typecheck + test
- `make ci-check` – Fast gate: lint + format-check + test (no typecheck)
- `make pre-commit-run` – Run pre-commit on all files

## CLI Analysis (standalone, no Docker)
- `uv run maljan analyze <file_hash> --provider openai`
- `uv run maljan analyze <hash> --mock` – No LLM calls (fixture responses)

## Docker
- `cd docker && docker compose up --build -d` – Start all 7 services
- `docker logs maljan-api --tail 50` – API logs
- `docker logs maljan-worker --tail 50` – Worker logs

## Benchmarks
- `make benchmark` – Run evaluation benchmark suite
- `make prepare-tram` + `make benchmark-tram` – TRAM dataset
- `make prepare-attck` + `make benchmark-attck` – ATT&CK malware dataset

## Database (Docker)
- `docker exec maljan-postgres psql -U maljan -d maljan -c "\\dt"` – List tables
- `docker exec maljan-api uv run python -c "import asyncio; from app.database import Base, async_engine; from app.models import *; asyncio.run(init_db())"` – Create tables

## Cache & Index
- `uv run python -c "from maljan.memory.attck_validator import ATTCKValidator; ATTCKValidator.get_instance()"` – Pre-build ATT&CK index cache
- `uv run python -c "from maljan.memory.qdrant_store import QdrantStore; store = QdrantStore(); print(store.count())"` – Verify Qdrant connectivity

## MCP Servers
- `python network-mcp/server.py` – Start Network MCP server (standalone)
- `python threatintel-mcp/server.py` – Start ThreatIntel MCP server
- `python scripts/cape_mcp_wrapper.py` – Start CAPEv2 MCP wrapper

## Worker (local dev)
- `arq app.worker.analysis_worker.WorkerSettings` – Start ARQ worker (from apps/api/)
