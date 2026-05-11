# Maljan: Multi-Agent Malware Analysis Framework

[![CI](https://github.com/Root0ne/Maljan/actions/workflows/ci.yml/badge.svg)](https://github.com/Root0ne/Maljan/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.13-blue)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-800%2B%20passed-brightgreen)](tests/)

Maljan is a production-grade malware analysis platform that uses adversarial multi-agent debate (LangGraph) to classify samples as **Malicious**, **Benign**, or **Suspicious**. It combines LLM-powered reasoning with deterministic detection layers (YARA, Sigma) and outputs STIX 2.1 intelligence bundles with per-claim confidence annotations.

**Key differentiator:** Instead of a single-model analysis, multiple specialized LLM agents (Static, Dynamic, Network) independently analyze samples, then enter a structured negotiation loop with sycophancy detection and adaptive termination before a Judge agent renders the final verdict.

---

## Key Capabilities

| Feature | Description |
|---|---|
| Multi-agent negotiation | Static, Dynamic, and Network analysts run in parallel, then debate findings through structured ISR exchange until consensus or max iterations |
| Deterministic grounding | YARA (40+ rules) and Sigma (2,946 rules) Layer-0 detection runs before LLM agents; maps known patterns directly to MITRE ATT&CK IDs |
| Anti-echo-chamber | Sycophancy detection via cosine similarity; forced devil's-advocate dissent when agents converge without evidence changes |
| Adaptive termination | Rolling confidence convergence detection exits the negotiation loop early when positions stabilize |
| ATT&CK validation | In-memory TF-IDF index of the full ATT&CK Enterprise dataset validates every TTP claim before STIX generation |
| Multi-layer TTP cascade | Cross-domain weighted scoring (YARA > Sigma > Dynamic > Static > Network) with corroboration multipliers up to 1.75x |
| Long-term memory (RAG) | Past analyses are vectorized and retrieved by similarity; injected as few-shot context into verdict calls |
| Heterogeneous ensemble | Each agent can use a different LLM provider/model via config, reducing echo-chamber risk across model families |

> For deep-dive technical documentation see [`AGENTS.md`](AGENTS.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Architecture

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
      YARA + Sigma scan
           │
     TTP cascade + ATT&CK validation
           │
        STIX 2.1 Bundle
           │
          END
```

- **ISR (Intermediate Structural Representation):** Agents exchange structured `AgentISR` objects (claims + `evidence_ref` + confidence) instead of raw text.
- **ServiceContainer (DI):** All agents, LLMs, loaders, and stores are created/cached in a single composition root. No global state.
- **AgentRegistry:** New agents are auto-discovered via `@register_agent` decorator; the pipeline builder wires them dynamically.

---

## Quick Start

### Requirements

- Python 3.13+
- [uv](https://astral.sh/uv/)
- Docker + Docker Compose (for full-stack mode)

### Standalone CLI (no Docker)

```bash
# 1. Clone
git clone https://github.com/Root0ne/Maljan.git
cd Maljan

# 2. Install dependencies
uv sync

# 3. Configure environment
cp .env.example .env
# Edit .env — set LLM__PROVIDER and add your API key

# 4. Run a mock analysis (no API key required)
uv run maljan analyze sample_1 --mock --name test.exe

# 5. Run a real analysis
uv run maljan analyze <sha256> --provider openai
```

### Full-Stack Docker (recommended)

```bash
cp .env.example .env
# Edit .env with your API keys and LLM provider settings

# Windows: avoid PostgreSQL port conflict
$env:POSTGRES_PORT="5433"

# Start all 8 services
cd docker
docker compose up -d --build

# Access points
# Frontend:      http://localhost:3000
# Backend API:   http://localhost:8000/docs
# Ghidra MCP:    http://localhost:8089/check_connection
# MinIO Console: http://localhost:9001
```

> **Note:** Containers reach the Windows host's Ollama via `host.docker.internal:11434` (configured automatically in `docker-compose.yml`).

### Pre-build the ATT&CK cache (optional)

```bash
uv run python -c "from maljan.memory.attck_validator import ATTCKValidator; ATTCKValidator.get_instance()"
```

---

## Project Structure

```
maljan/
├── src/maljan/            # Core analysis engine (importable library)
│   ├── agents/            # LLM analyst agents + Judge + MCP client
│   ├── pipeline/          # LangGraph workflow (builder, nodes, routing, state)
│   ├── analysis/          # Deterministic layers (YARA, Sigma, TTP cascade, TIEF)
│   ├── core/              # DI container, config, protocols
│   ├── llm/               # Provider implementations (OpenAI, Anthropic, Ollama, Gemini)
│   ├── loaders/           # Data ingestion + sandbox clients
│   ├── memory/            # LTM/RAG (Qdrant, ATT&CK index/validator)
│   ├── parsers/           # Sandbox output parsers
│   └── schemas/           # Pydantic models (ISR, STIX 2.1)
│
├── apps/api/              # FastAPI backend + ARQ worker
│   ├── app/api/v1/        # REST endpoints (auth, samples, jobs, reports)
│   ├── app/worker/        # Background analysis worker
│   └── alembic/           # Database migrations
│
├── apps/web/              # Next.js 16 + React 19 + TailwindCSS 4 frontend
├── docker/                # Docker Compose + Dockerfiles
├── data/                  # YARA rules, Sigma rules, ATT&CK fixtures
├── tests/                 # Unit, integration, and evaluation benchmarks
└── external/              # CAPEv2 + Ghidra-MCP integrations
```

---

## Web UI

A professional dark-mode dashboard inspired by Google Threat Intelligence.

| Page | Description |
|---|---|
| Dashboard | Overview metrics, recent analyses, verdict distribution |
| Samples | Upload and manage malware samples |
| Jobs | Monitor analysis jobs with real-time status |
| Analysis Detail | 7-tab view: Summary, Agents, **Pipeline**, Rules, TTPs, Timeline, STIX |
| Live Analysis | WebSocket-powered real-time event stream |
| Reports | Filterable report list with JSON/STIX export |

---

## API Endpoints

Base path: `/api/v1`

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | User registration |
| POST | `/auth/login` | JWT token login |
| POST | `/samples/upload` | Upload malware sample |
| POST | `/jobs` | Create analysis job |
| GET | `/jobs/{id}` | Get job status |
| GET | `/reports/{id}` | Get full report |
| GET | `/dashboard/stats` | Dashboard statistics |
| WS | `/ws/analysis/{job_id}` | Real-time analysis events |
| GET | `/health` | Health check |
| GET | `/docs` | Swagger UI |

---

## Development

```bash
# Run all tests
make test

# Lint + type check
make lint
make typecheck

# Full quality gate
make check

# Benchmarks
make benchmark-attck
make benchmark-tram
```

---

## Configuration

All settings live in `.env`. The project uses two config systems:

1. **Core Engine** — nested Pydantic models with `__` delimiter (e.g., `LLM__PROVIDER=openai`)
2. **API Server** — flat env vars (e.g., `DATABASE_URL`, `JWT_SECRET_KEY`)

Critical variables:

```bash
LLM__PROVIDER=openai|anthropic|ollama|gemini
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
DATABASE_URL=postgresql+asyncpg://maljan:maljan_dev@localhost:5432/maljan
REDIS_URL=redis://localhost:6379/0
JWT_SECRET_KEY=<generate with openssl rand -hex 32>
```

See `.env.example` for the full reference.

---

## Design Principles

- **No hallucinated TTPs:** Every ATT&CK technique ID is validated against the authoritative dataset before STIX generation.
- **No sycophancy:** Agents cannot passively agree. Cosine-similarity monitoring triggers forced re-evaluation when convergence is cosmetic.
- **Graceful degradation:** YARA, Sigma, ATT&CK validation, memory retrieval, and sandbox integration are all optional. The pipeline always produces a verdict, even offline.
- **Protocol-based extensibility:** `MemoryStore`, `SandboxClient`, and `DataLoaderProtocol` are runtime-checkable Protocols. Swap backends without touching pipeline code.
