# Maljan Project Analysis Report

> Comprehensive architectural and code-quality analysis of the Maljan multi-agent malware analysis framework. Updated after memory refresh.

---

## 1. Project Overview

**Maljan** is a production-grade malware analysis platform using adversarial multi-agent debate (LangGraph) to classify samples as Malware, Benign, or Suspicious. Combines LLM reasoning with deterministic detection (YARA, Sigma) and outputs STIX 2.1 bundles with per-claim confidence annotations.

- **Language**: Python 3.13 (pinned `>=3.13, <3.14`)
- **Orchestration**: LangGraph >= 1.1.6
- **API**: FastAPI + Uvicorn
- **Frontend**: Next.js 16 + React 19 + TailwindCSS 4
- **DB**: PostgreSQL 16 (async via SQLAlchemy + asyncpg)
- **Queue**: Redis 7 + ARQ
- **Storage**: MinIO (S3)
- **Vectors**: Qdrant
- **Tests**: 800+ passed

---

## 2. Architecture Assessment

### 2.1 Pipeline Flow (LangGraph)

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
     [consensus? sycophancy? convergence? max_iter?]
           │
        judge
           │
      YARA + Sigma scan
           │
     TTP cascade + ATT&CK validation + schema pruning + LTM retrieval
           │
        STIX 2.1 Bundle + RunSummary
           │
          END
```

**Strengths:**
- Dynamic graph from `AgentRegistry` — adding agents requires no pipeline changes.
- Parallel fan-out for analyst nodes — O(1) wall-clock in agent count.
- Generic agent-keyed dicts in `AnalysisState` — no schema migrations.
- `MaljanApp` facade (`src/maljan/app.py`) is a clean entry point used by CLI + ARQ worker.
- Sandbox submission decoupled from graph (`MaljanApp._submit_to_sandbox`) → result feeds in via `state["sandbox_report"]`.

### 2.2 Key Design Patterns

1. **MaljanApp Facade** — Composition root that wires `ServiceContainer` + `build_graph()`; provides sync `run()` and async `arun()`.
2. **ServiceContainer (DI)** — All agents, LLMs, loaders, stores cached here. No global state (exception: `ATTCKValidator` singleton with double-checked locking for lazy init).
3. **AgentRegistry** — `@register_agent` decorator, auto-discovery.
4. **ISR** — `AgentISR` objects exchanged during negotiation; every claim has `evidence_ref` and `confidence`.
5. **Heterogeneous Ensemble** — Per-agent LLM via `LLM__AGENTS__<NAME>__PROVIDER`.
6. **Adaptive Termination** — Rolling std<0.04 over last 3 rounds with mean≥0.70.
7. **Sycophancy Detection** — Cosine similarity → forced devil's-advocate.
8. **Protocol-based extensibility** — `MemoryStore`, `SandboxClient`, `DataLoaderProtocol` are runtime-checkable.

### 2.3 Configuration System
- **Core Engine** (`src/maljan/core/config.py`): nested Pydantic, `__` delimiter (e.g., `LLM__PROVIDER=openai`).
- **API Server** (`apps/api/app/config.py`): flat env vars (`DATABASE_URL`, `JWT_SECRET_KEY`).
- Two-config duality preserved (functional but adds cognitive overhead).

### 2.4 Path Robustness — Fixed
- Previously: brittle `os.path.dirname(__file__)` chains.
- Now: `src/maljan/core/paths.py` provides `get_project_root()` (walks up for `pyproject.toml`/`.git`) and `resolve_mcp_args()` (resolves relative MCP arg paths against project root). This makes `.env` portable.

---

## 3. Code Quality & Standards

### 3.1 Positive
- Strict mypy (`disallow_untyped_defs`, `disallow_incomplete_defs`).
- Near-universal docstrings.
- Graceful degradation (YARA, Sigma, ATT&CK, LTM, cascade, sandbox).
- Async-first (DB, Redis, HTTP).
- `BaseAnalyst._truncate_input()` tiktoken w/ char fallback.
- `execute_tool_loop()` thread-isolated event loop for ReAct (avoids nest_asyncio/anyio cancel scope conflicts).
- `utils/json_cleaner.py` recovers malformed LLM JSON output.

### 3.2 Linting & Formatting
- Ruff 100 col, rules `E/F/I/W/UP/B`, per-file ignores for agent prompt strings.
- MyPy 3.13 target, ignores missing imports for LangChain ecosystem.
- Pre-commit configured.

### 3.3 Identified Issues
- **TIEF orphan weight**: `tief_classifier.py` was removed but `ttp_cascade.py` still has `tief=0.80` in `LAYER_WEIGHTS`. Dead weight unless TIEF ISRs come from another path.
- **mediation_models location**: `MediatorVerdict` lives in `pipeline/mediation_models.py` (not the more idiomatic `schemas/`).
- **Mock mode type leakage**: Mock ISRs use `domain=agent_name` with `# type: ignore[arg-type]` because the Literal type narrows to `static|dynamic|network`.
- **TODO comments in production**: `nodes.py` still has `TODO-1`/`TODO-B` markers around now-implemented YARA/Sigma blocks.

---

## 4. Test Coverage

- `tests/unit/` — 35+ modules (agents, container, DI cache, ISR models, judge, routing, sycophancy, workflow, LTM, ReAct routing, etc.).
- `tests/integration/` — 4 modules.
- `tests/evaluation/` — TRAM + ATT&CK malware benchmarks.
- **Gaps**: No `MaljanApp.run()`/`arun()` facade-level tests; no frontend E2E (Playwright/Cypress).

---

## 5. Security
- JWT auth + bcrypt password hashing.
- `api_keys` table for per-user keys.
- `audit_log` table.
- MockSandboxClient for CI/test isolation.
- Token-aware truncation prevents oversized prompt injection.
- **Concerns**: Default secrets in `.env.example` and Docker Compose (`minioadmin`, JWT placeholder); no visible rate-limiting middleware; CORS depends on `settings.cors_origins` (risk if misconfigured).

---

## 6. Production Readiness

### 6.1 Infrastructure
- Docker Compose: **8 services** (API, Worker, Frontend, PostgreSQL, Redis, MinIO, Qdrant, Ghidra MCP HTTP `:8089`).
- Alembic dir exists at `apps/api/alembic/` — migrations in progress.
- ARQ worker with WebSocket `/ws/analysis/{job_id}` for real-time events.

### 6.2 Observability
- Structured JSON logging with `correlation_id`, `duration_ms`, `component`.
- Optional LangSmith tracing.
- `RunSummary` aggregate observability (negotiation metrics, agent stats, cascade, validation).

### 6.3 Scalability
- Stateless FastAPI (state in Postgres + Redis).
- ARQ allows horizontal worker scaling (`max_jobs=2` per container).
- ReAct uses `ThreadPoolExecutor(max_workers=1)` → serialized per agent (safe but bottleneck under heavy parallel tool use).

---

## 7. Strengths
1. Multi-agent ISR architecture with sycophancy detection + adaptive termination — research-grade.
2. Registry + DI + generic state dicts = trivial extension.
3. Graceful degradation everywhere — pipeline never crashes on optional dependency failures.
4. STIX 2.1 with per-claim confidence intervals (`x_maljan_*` extensions).
5. Comprehensive CLI + Docker + benchmarks + structured logging.

---

## 8. Improvement Areas & Technical Debt

| Priority | Area | Description |
|----------|------|-------------|
| **High** | Alembic migration workflow | `apps/api/alembic/` exists; ensure migrations are actually run rather than relying on `Base.metadata.create_all()`. |
| **High** | Rate limiting | No middleware visible in `apps/api/app/main.py`. |
| **Medium** | TIEF weight cleanup | Either remove `tief=0.80` from `LAYER_WEIGHTS` or restore the classifier. |
| **Medium** | Frontend E2E tests | Add Playwright/Cypress for Next.js. |
| **Medium** | Facade tests | Unit tests for `MaljanApp.run()`/`arun()`. |
| **Low** | TODO cleanup | Remove `TODO-1`/`TODO-B` markers in `nodes.py`. |
| **Low** | Config unification | Merge core+API config systems. |
| **Low** | Mock type safety | Remove `# type: ignore[arg-type]` in mock ISR construction. |
| **Low** | Schema location | Consider moving `mediation_models.py` from `pipeline/` to `schemas/` for consistency. |

---

## 9. Conclusion

Maljan is a **well-architected, research-informed malware analysis framework** approaching production maturity. Strong typing, DI, async I/O, graceful degradation, and the multi-agent ISR design with sycophancy detection + adaptive termination are highlights.

Recent improvements since last analysis:
- New `MaljanApp` facade replaces ad-hoc entry points.
- `core/paths.py` resolves the previously flagged "hardcoded paths" issue.
- Sandbox submission (Triage client) added as a pre-pipeline step.
- `apps/api/alembic/` directory exists.
- 8th Docker service (Ghidra MCP) added.
- Test count ~800+ passing.

Remaining gaps: rate limiting, frontend tests, facade tests, dead TIEF weight, TODO markers.

**Overall grade: A** (excellent architecture; minor production-hardening gaps).
