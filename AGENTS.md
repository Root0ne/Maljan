# Maljan — Agent Instructions

> Multi-Agent Malware Analysis Framework powered by LangGraph.

## Project Overview

Maljan is a production-grade malware analysis platform that uses adversarial multi-agent debate (LangGraph) to classify samples as **Malware**, **Benign**, or **Suspicious**. It combines LLM-powered reasoning with deterministic detection layers (YARA, Sigma) and outputs STIX 2.1 intelligence bundles.

**Key differentiator:** Instead of a single-model analysis, multiple specialized LLM agents (Static, Dynamic, Network) independently analyze samples, then enter a structured negotiation loop with sycophancy detection and adaptive termination before a Judge agent renders the final verdict.

---

## Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Python | 3.13 |
| Package Manager | uv | latest |
| Orchestration | LangGraph | >=1.1.6 |
| LLM Framework | LangChain | >=1.2.15 |
| LLM Providers | OpenAI, Anthropic, Ollama, Gemini | Multi-provider |
| Web API | FastAPI + Uvicorn | >=0.115 |
| Frontend | Next.js 16 + React 19 + TailwindCSS 4 | See package.json |
| Database | PostgreSQL 16 (async via SQLAlchemy + asyncpg) | Alpine |
| Cache/Queue | Redis 7 (ARQ worker) | Alpine |
| Object Storage | MinIO (S3-compatible) | latest |
| Vector DB | Qdrant (LTM/RAG) | latest |
| Detection | YARA rules, Sigma rules, TIEF classifier | Built-in |
| Schemas | Pydantic v2, STIX 2.1, ISR models | >=2.12 |
| Containerization | Docker Compose | Multi-service |
| Linting | Ruff, MyPy | See pyproject.toml |
| Testing | Pytest | >=9.0 |

---

## Repository Structure

```
maljan/
├── src/maljan/                 # Core analysis engine (importable library)
│   ├── agents/                 # LLM analyst agents
│   │   ├── base_agent.py       # Abstract BaseAnalyst class
│   │   ├── static_analyst.py   # PE/ELF static analysis agent
│   │   ├── dynamic_analyst.py  # Behavioral/sandbox analysis agent
│   │   ├── network_analyst.py  # Network traffic analysis agent
│   │   ├── judge_agent.py      # Final verdict + STIX output agent
│   │   ├── mcp_client.py       # Model Context Protocol client
│   │   └── registry.py         # Dynamic agent registration
│   ├── pipeline/               # LangGraph workflow engine
│   │   ├── builder.py          # Dynamic graph construction (fan-out/fan-in)
│   │   ├── nodes.py            # LangGraph node functions
│   │   ├── routing.py          # ConsensusRouter + adaptive termination
│   │   ├── state.py            # AnalysisState TypedDict
│   │   └── sycophancy_detector.py
│   ├── analysis/               # Deterministic analysis layers
│   │   ├── yara_layer.py       # YARA rule matching
│   │   ├── sigma_layer.py      # Sigma rule detection
│   │   ├── ttp_cascade.py      # MITRE ATT&CK TTP validation
│   │   ├── tief_classifier.py  # Threat intelligence enrichment
│   │   ├── run_summary.py      # RunSummary builder
│   │   ├── schema_pruner.py    # Schema optimization
│   │   ├── chunk_merger.py     # Multi-chunk result merging
│   │   └── function_summarizer.py
│   ├── core/                   # Framework internals
│   │   ├── config.py           # Hierarchical Settings (pydantic-settings)
│   │   ├── container.py        # ServiceContainer (DI / composition root)
│   │   ├── protocols.py        # Abstract protocols/interfaces
│   │   └── exceptions.py       # Custom exception types
│   ├── llm/                    # LLM provider implementations
│   │   ├── registry.py         # LLMProviderRegistry
│   │   ├── openai_provider.py
│   │   ├── anthropic_provider.py
│   │   ├── ollama_provider.py
│   │   └── gemini_provider.py
│   ├── loaders/                # Data ingestion
│   │   ├── file_loader.py      # FileDataLoader (local/sandbox)
│   │   ├── binary_chunker.py   # Token-aware binary splitting
│   │   ├── sandbox_client.py   # SandboxClient protocol
│   │   ├── cape2_client.py     # CAPEv2 sandbox integration
│   │   ├── triage_client.py    # Hatching Triage integration
│   │   └── mock_sandbox_client.py
│   ├── memory/                 # Long-term memory / RAG
│   │   ├── long_term_memory.py # MemoryStore protocol
│   │   ├── qdrant_store.py     # Qdrant vector backend
│   │   ├── in_memory_store.py  # In-process fallback
│   │   ├── attck_index.py      # ATT&CK knowledge index
│   │   ├── attck_loader.py     # ATT&CK STIX bundle loader
│   │   ├── attck_validator.py  # Technique ID validation
│   │   └── ttp_validation.py   # TTP cross-validation
│   ├── parsers/                # Sandbox output parsers
│   │   ├── static_parser.py
│   │   ├── dynamic_parser.py
│   │   └── network_parser.py
│   ├── preprocessors/          # Pre-analysis optimization
│   │   └── cfg_orderer.py      # Control flow graph ordering
│   ├── schemas/                # Pydantic domain models
│   │   ├── isr_models.py       # ISR (Intermediate Structural Representation)
│   │   ├── stix_models.py      # STIX 2.1 bundle models
│   │   └── mediation_models.py
│   ├── app.py                  # MaljanApp orchestrator
│   └── cli.py                  # Typer CLI entrypoint
│
├── apps/api/                   # FastAPI backend application
│   ├── app/
│   │   ├── main.py             # Application factory + lifespan
│   │   ├── config.py           # APISettings (pydantic-settings)
│   │   ├── database.py         # AsyncEngine + session factory
│   │   ├── deps.py             # FastAPI dependencies
│   │   ├── logging_config.py   # Structured JSON logging
│   │   ├── api/v1/             # Versioned REST endpoints
│   │   │   ├── auth.py         # JWT auth (login/register)
│   │   │   ├── samples.py      # Sample CRUD + upload
│   │   │   ├── jobs.py         # Analysis job management
│   │   │   ├── reports.py      # Report retrieval
│   │   │   └── dashboard.py    # Dashboard statistics
│   │   ├── api/ws.py           # WebSocket real-time events
│   │   ├── models/             # SQLAlchemy ORM models
│   │   │   ├── user.py         # User account
│   │   │   ├── sample.py       # Malware sample metadata
│   │   │   ├── job.py          # AnalysisJob
│   │   │   ├── report.py       # AnalysisReport + AgentFinding
│   │   │   └── audit.py        # AuditLog + APIKey
│   │   ├── schemas/            # Pydantic request/response schemas
│   │   ├── services/           # Business logic layer
│   │   │   ├── analysis_service.py
│   │   │   └── report_service.py
│   │   ├── worker/             # ARQ background worker
│   │   │   └── analysis_worker.py
│   │   ├── auth/               # JWT + password utilities
│   │   │   ├── jwt.py
│   │   │   └── password.py
│   │   └── middleware/
│   │       └── logging_middleware.py  # RequestLoggingMiddleware
│   ├── alembic/                # Database migrations
│   └── init_db.py              # Manual table creation script
│
├── apps/web/                   # Next.js frontend
│   ├── src/app/(app)/          # Authenticated pages
│   │   ├── dashboard/
│   │   ├── samples/
│   │   ├── jobs/
│   │   ├── analysis/
│   │   ├── reports/
│   │   └── settings/
│   ├── src/app/(auth)/         # Auth pages (login/register)
│   ├── src/components/         # Reusable UI components
│   ├── src/lib/                # API client, utilities
│   └── src/types/              # TypeScript type definitions
│
├── docker/
│   ├── docker-compose.yml      # 7-service orchestration
│   ├── Dockerfile.backend      # Python 3.12-slim + uv
│   └── Dockerfile.frontend     # Node 20-alpine multi-stage
│
├── data/
│   ├── samples/                # Test malware samples (fixtures)
│   ├── sigma_rules/            # Sigma detection rules
│   ├── yara_ttp_rules.yaml     # YARA TTP rule definitions
│   └── attck_*.json            # MITRE ATT&CK data
│
├── external/                   # Third-party integrations
│   ├── CAPEv2/                 # CAPEv2 sandbox
│   └── ghidra-mcp/             # Ghidra MCP server
│
├── tests/
│   ├── unit/                   # 29 unit test modules
│   ├── integration/
│   └── evaluation/             # Benchmark suites
│
├── scripts/                    # Utility scripts
├── pyproject.toml              # Project config + dependencies
├── uv.lock                     # Locked dependencies
├── Makefile                    # Dev commands
└── .env.example                # Environment template
```

---

## Architecture

### Analysis Pipeline Flow (LangGraph)

```
START
  ├── static_analyst   ──┐
  ├── dynamic_analyst  ──┤  (parallel fan-out)
  └── network_analyst  ──┘
           │
     [fan-in: wait all]
           │
      negotiation ◄──────── revision (loop)
           │                    │
     [consensus? or max_iter]   │
           │                    │
      [no consensus] ───────────┘
           │
      [consensus or max_iter]
           │
        judge
           │
          END
```

### Key Design Patterns

1. **ServiceContainer (DI):** `src/maljan/core/container.py` — composition root. All agents, LLMs, loaders, and stores are created/cached here. Never use global state.

2. **AgentRegistry:** Dynamic agent registration. Adding a new agent type requires: (a) create agent class extending `BaseAnalyst`, (b) register in `AgentRegistry`. The pipeline builder auto-discovers and wires it.

3. **ISR (Intermediate Structural Representation):** Agents exchange `AgentISR` objects (not raw text) during negotiation. Each claim requires an `evidence_ref` and `confidence` score.

4. **Heterogeneous Model Ensemble:** Different agents can use different LLM providers/models via `LLM__AGENTS__<NAME>__PROVIDER` env vars. Reduces echo-chamber risk.

5. **Adaptive Termination:** The negotiation loop exits on rolling confidence convergence (not just iteration count). `ConsensusRouter` in `pipeline/routing.py`.

6. **Sycophancy Detection:** `pipeline/sycophancy_detector.py` flags when agents blindly agree without evidence changes.

---

## Configuration

### Environment Variables (`.env`)

The project uses **two separate config systems**:

1. **Core Engine** (`src/maljan/core/config.py` → `Settings`):
   - Nested Pydantic models with `__` delimiter: `LLM__PROVIDER=openai`
   - Controls: LLM providers, negotiation params, chunking, memory, sandbox

2. **API Server** (`apps/api/app/config.py` → `APISettings`):
   - Flat env vars: `DATABASE_URL`, `REDIS_URL`, `JWT_SECRET_KEY`
   - Controls: DB connection, Redis, MinIO, JWT auth, CORS

### Critical Environment Variables

```bash
# LLM (required for analysis)
LLM__PROVIDER=openai|anthropic|ollama|gemini
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_API_KEY=...

# Infrastructure (Docker overrides these automatically)
DATABASE_URL=postgresql+asyncpg://maljan:maljan_dev@localhost:5432/maljan
REDIS_URL=redis://localhost:6379/0
MINIO_ENDPOINT=localhost:9000
QDRANT_URL=http://localhost:6333

# Security
JWT_SECRET_KEY=<generate with openssl rand -hex 32>
```

---

## Development Commands

```bash
# Setup
uv sync                          # Install all dependencies
uv run pre-commit install        # Git hooks

# Testing
make test                        # Run all tests
make test-unit                   # Unit tests only
make lint                        # Ruff linting
make typecheck                   # MyPy type checking
make check                       # Full quality gate

# CLI Analysis (standalone, no Docker needed)
uv run maljan analyze <file_hash> --provider openai
uv run maljan analyze <hash> --mock   # No LLM calls

# Docker
cd docker && docker compose up --build -d   # Start all services
docker logs maljan-api --tail 50            # API logs (JSON)
docker logs maljan-worker --tail 50         # Worker logs
docker exec maljan-postgres psql -U maljan -d maljan -c "\dt"  # List tables

# Database
docker exec maljan-api uv run python -c "
import asyncio; from app.database import Base, async_engine; from app.models import *
async def init():
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await async_engine.dispose()
asyncio.run(init())
"
```

---

## Docker Services

| Service | Container | Port | Image |
|---------|-----------|------|-------|
| API | maljan-api | 8000 | python:3.12-slim + uv |
| Worker | maljan-worker | — | Same as API |
| Frontend | maljan-frontend | 3000 | node:20-alpine |
| PostgreSQL | maljan-postgres | 5432 | postgres:16-alpine |
| Redis | maljan-redis | 6379 | redis:7-alpine |
| MinIO | maljan-minio | 9000/9001 | minio/minio |
| Qdrant | maljan-qdrant | 6333/6334 | qdrant/qdrant |

**Note:** Qdrant has no healthcheck (minimal image lacks curl/wget). API verifies connectivity in its own lifespan event.

---

## Database Schema (PostgreSQL)

| Table | Description |
|-------|-------------|
| `users` | User accounts (email, hashed password, role, active status) |
| `api_keys` | API key management per user |
| `samples` | Uploaded malware samples (hash, filename, size, MinIO path) |
| `analysis_jobs` | Job queue (status, sample_id, config, timestamps) |
| `analysis_reports` | Final analysis reports (verdict, STIX output, summary) |
| `agent_findings` | Individual agent findings linked to reports |
| `audit_log` | Action audit trail |
| `alembic_version` | Migration tracking |

ORM models: `apps/api/app/models/`
Base class: `apps/api/app/database.py → Base`

---

## API Endpoints

Base path: `/api/v1`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | User registration |
| POST | `/auth/login` | JWT token login |
| POST | `/auth/refresh` | Refresh access token |
| GET | `/samples` | List samples |
| POST | `/samples/upload` | Upload malware sample |
| GET | `/samples/{id}` | Get sample details |
| POST | `/jobs` | Create analysis job |
| GET | `/jobs` | List jobs |
| GET | `/jobs/{id}` | Get job status |
| GET | `/reports` | List reports |
| GET | `/reports/{id}` | Get full report |
| GET | `/dashboard/stats` | Dashboard statistics |
| WS | `/ws/analysis/{job_id}` | Real-time analysis events |
| GET | `/health` | Health check (root, not /api/v1) |
| GET | `/docs` | Swagger UI |

---

## Logging

Production logging outputs **structured JSON** to stdout:

```json
{
  "timestamp": "2026-05-03T14:27:44Z",
  "level": "INFO",
  "logger": "maljan.main",
  "message": "Database connection verified",
  "correlation_id": "5022d600-488c-...",
  "component": "database"
}
```

- **correlation_id**: UUID assigned per HTTP request for tracing
- **duration_ms**: Request-response timing
- Development mode (`DEBUG=true`): colored human-readable output
- Logger factory: `from app.logging_config import get_logger`

---

## Coding Conventions

1. **Language:** All code, comments, variable names, and commit messages in **English**
2. **Python:** 3.13+, type hints required (mypy strict mode)
3. **Line length:** 100 chars (Ruff)
4. **Linting:** Ruff rules: E, F, I, W, UP, B
5. **Imports:** isort via Ruff, absolute imports preferred
6. **Agent files:** E501 (line length) is ignored for LLM prompt strings in `src/maljan/agents/*.py`
7. **No emojis** in code
8. **Async-first:** All DB/Redis/HTTP operations use async/await
9. **Dependency injection:** Use `ServiceContainer`, avoid global state
10. **Models:** Pydantic v2 for validation, SQLAlchemy 2.0 for ORM
11. **Tests:** pytest, all tests in `tests/` directory, fixtures in `conftest.py`
12. **PYTHONPATH:** `src/` for core engine; Docker sets `/app/apps/api` for API imports

---

## Testing

```bash
make test              # All tests
make test-unit         # Unit tests (29 modules)
make test-integration  # Integration tests
make benchmark         # Evaluation benchmark suite
make benchmark-tram    # TRAM dataset benchmark
make benchmark-attck   # ATT&CK malware benchmark
```

Test structure follows the source layout. Fixtures use `conftest.py` at `tests/` root.

---

## Key Files Quick Reference

| Purpose | File |
|---------|------|
| CLI entrypoint | `src/maljan/cli.py` |
| App orchestrator | `src/maljan/app.py` |
| DI container | `src/maljan/core/container.py` |
| Core config | `src/maljan/core/config.py` |
| Pipeline graph | `src/maljan/pipeline/builder.py` |
| Pipeline state | `src/maljan/pipeline/state.py` |
| API factory | `apps/api/app/main.py` |
| API config | `apps/api/app/config.py` |
| DB engine | `apps/api/app/database.py` |
| Worker | `apps/api/app/worker/analysis_worker.py` |
| Logging | `apps/api/app/logging_config.py` |
| Docker compose | `docker/docker-compose.yml` |
| Env template | `.env.example` |

---

## Known Constraints

1. **Qdrant healthcheck:** Disabled in Docker (no curl/wget in image). Connection verified at API startup.
2. **Alembic migrations:** Not yet populated. Tables created via `Base.metadata.create_all()`. Run `alembic revision --autogenerate` to initialize.
3. **Frontend API URL:** Baked at build time via `NEXT_PUBLIC_API_URL`. For Docker-internal communication, the frontend container uses `http://backend-api:8000`.
4. **Torch dependency:** Large (~2GB). Docker builds may be slow on first run due to PyTorch download.
5. **JWT secret:** Default is insecure. Must be changed for production via `JWT_SECRET_KEY` env var.
