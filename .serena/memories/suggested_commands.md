# Suggested Commands

> Refreshed 2026-05-30. Windows host; commands assume project root `d:\Projects\Maljan`.

## Setup
- `uv sync` — install all dependencies
- `uv run pre-commit install` — install git hooks
- `make setup` — runs both above

## Testing
- `make test` — all tests
- `make test-unit` — unit tests (~58 modules)
- `make test-integration` — integration tests (6 modules)
- `make test-verbose` — verbose pytest
- `make test-qdrant` — Qdrant store test against local Qdrant

## Quality Gates
- `make lint` — Ruff lint
- `make format` / `make format-check` — Ruff auto-fix / check-only
- `make typecheck` — MyPy strict
- `make check` — full gate (lint + format-check + typecheck + test)
- `make ci-check` — fast gate (no typecheck)
- `make pre-commit-run` — pre-commit on all files

## CLI Analysis (standalone, no Docker)
- `uv run maljan analyze <file_hash> --provider openai`
- `uv run maljan analyze <hash> --mock` — no LLM calls (fixtures)
- For a local single-slot llama-server, set `LLM__PARALLEL_ANALYSTS=false` so analysts run
  sequentially (each gets the full LLM slot for its timeout budget).

## Docker (8 services)
- `cd docker && docker compose up --build -d` — start all 8 services
  (postgres, redis, qdrant, minio, ghidra-mcp, backend-api, backend-worker, frontend)
- `docker logs maljan-api --tail 50` / `docker logs maljan-worker --tail 50`
- Backend default LLM = local llama-server at `host.docker.internal:8080/v1` (Ollama fallback).

## Database / Migrations
- `cd apps/api && uv run alembic upgrade head` — apply migrations (preferred over auto-create)
- `cd apps/api && uv run alembic revision --autogenerate -m "<msg>"` — new migration
- `docker exec maljan-postgres psql -U maljan -d maljan -c "\dt"` — list tables
- Auto-upgrade on API startup is OFF by default (`RUN_MIGRATIONS_ON_STARTUP`); run as a deploy step.

## Reporting / Enrichment (API)
- `GET /api/v1/reports/{id}/full` — comprehensive MalwareReport JSON
- `GET /api/v1/reports/{id}/markdown` — markdown render
- `GET /api/v1/reports/{id}/signatures/{yara|sigma|suricata|snort}` — generated rule bodies
- `POST /api/v1/reports/{id}/enrich` — queue threat-intel enrichment (idempotent)

## Frontend (apps/web)
- `npm install` then `npm run dev` (Next.js); `npm run build` / `npm run lint`
- `npx playwright test` — E2E suite (apps/web/e2e: auth, dashboard, ws_reconnect)

## Benchmarks (tests/evaluation)
- `make benchmark`; `make prepare-tram` + `make benchmark-tram`; `make prepare-attck` + `make benchmark-attck`

## Cache & Index
- `uv run python -c "from maljan.memory.attck_validator import ATTCKValidator; ATTCKValidator.get_instance()"`
  — pre-build ATT&CK index cache
- `uv run python -c "from maljan.memory.qdrant_store import QdrantStore; print(QdrantStore().count())"`
  — verify Qdrant (collection `maljan_cases_v2`, 384-dim BGE)

## MCP Servers
- `python network-mcp/server.py`; `python threatintel-mcp/server.py`; `python scripts/cape_mcp_wrapper.py`
- Ghidra MCP runs as a Docker service (HTTP :8089).

## Worker (local dev, from apps/api/)
- `uv run arq app.worker.analysis_worker.WorkerSettings` — analysis worker
- `uv run arq app.worker.enrich_worker.WorkerSettings` — enrichment worker (if separate settings)
