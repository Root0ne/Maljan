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
| Comprehensive reports | Every run emits a structured `MalwareReport` (verdict, severity, identity, static + dynamic + network IOCs, persistence, ATT&CK heatmap, attribution + Qdrant nearest-neighbours, LLM narrative, auto-generated YARA/Sigma/Suricata, P0/P1/P2 defense playbook); rendered as Markdown / JSON / extended STIX 2.1 / MISP; surfaced through a 16-tab analysis UI. See [`docs/REPORTING.md`](docs/REPORTING.md). |
| Post-hoc threat-intel enrichment | Async ARQ worker fills VirusTotal / AbuseIPDB / WHOIS / GeoIP reputation and Qdrant LTM nearest-neighbours after the verdict ships — verdict latency stays unaffected |

> For deep-dive technical documentation see [`AGENTS.md`](AGENTS.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and [`docs/REPORTING.md`](docs/REPORTING.md).

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

> **Local LLM:** Containers reach the Windows host's LLM via `host.docker.internal:8080/v1` (OpenAI-compatible — typically `ik_llama.cpp`'s `llama-server`). The legacy Ollama path on `:11434` is also wired up as a fallback. See [`docs/LOCAL_LLM_LLAMACPP.md`](docs/LOCAL_LLM_LLAMACPP.md) for the recommended `Qwen3.6-35B-A3B-IQ3_K_R4` setup that fits on an 8 GB GPU.

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

## Static-analysis data assets

Deterministic detection is data-driven. These live under `data/`, are loaded
lazily, are cached per path, and **every one of them degrades to a built-in
fallback when absent** — a missing file costs depth, never a run.

| Asset | What it drives |
|---|---|
| `api_behaviour_map_v1.json` | Windows API → behaviour category, ~780 names / 13 categories. Each category carries a `tier`; only `high`/`medium` mark an import *suspicious*, so categorising `RegOpenKeyExA` does not mean accusing it. |
| `api_attck_map_v1.json` | Windows API → ATT&CK, 47 techniques. This is what gives a **sandbox-less run real technique coverage**: with CAPE unreachable the Sigma corpus (2651 rules) is telemetry-gated and contributes nothing. |
| `tool_artifacts_v1.json` | Offensive-tool / RAT byte markers. The only source of a **malware family name without a sandbox**. |
| `packer_signatures_v1.json` | Packer / protector identification, ranked: section name > entry point > string. |
| `language_signatures_v1.json` | Source-language and runtime fingerprints, scored rather than substring-matched. |

The first two are generated — the curated lists live in the builder, not the
JSON, so a reader can see *why* an API is classified the way it is:

```bash
make prepare-api-db   # validates every ATT&CK ID before writing
```

**Restart the worker after regenerating.** `data/` is bind-mounted, so the
container sees the new file immediately — but each asset is cached per path in
the loading process, and the arq worker is long-lived. It keeps serving the
catalog it read on first use, and the run looks successful while classifying
against stale data. Editing a data asset without

```bash
docker compose restart worker
```

is indistinguishable, in the report, from not having edited it at all.

## Development

```bash
# Run all tests
make test

# Lint + type check
make lint
make typecheck

# Full quality gate
make check

# The gate covers every Python directory in the repo — src/, tests/, apps/api/,
# the two MCP sidecars and scripts/. It used to be src/ and tests/ only, which
# meant the FastAPI app and the arq worker were never type-checked anywhere,
# and a sidecar could sit unformatted for weeks because pre-commit only ever
# sees staged files.

# If `git commit` prints "`pre-commit` not found. Did you forget to activate
# your virtualenv?", the installed hook has a stale absolute interpreter path
# baked into it (it happens whenever the venv is recreated, or when the
# snap-installed toolchain the venv points at is upgraded). Reinstall it —
# do NOT reach for --no-verify:
uv run pre-commit install

# Benchmarks
make benchmark-attck
make benchmark-tram
```

### Making a code change actually take effect

**Read this before debugging anything that "should have worked".** On the
production stack neither the frontend nor the worker picks up a source edit,
and neither of them tells you:

| Service | Source | Picks up an edit? |
|---|---|---|
| `backend-api` | bind-mounted | **yes** — uvicorn `--reload` |
| `backend-worker` | bind-mounted | **no** — `arq` never re-imports a changed module |
| `frontend` | **baked into the image** | **no** — it serves a Next.js standalone build |

So on the production stack:

```bash
make worker-restart   # after ANY Python edit under src/ or apps/api
make fe-rebuild       # after ANY frontend edit — a plain restart is not enough
```

Both traps cost a full debugging session on 2026-07-26: a live analysis ran the
*previous* worker build and silently wrote nothing, and the deployed UI served a
pre-change bundle while every local check passed.

The alternative is the development overlay, where both are live:

```bash
make dev-up      # next dev + watchfiles-supervised arq, source mounted
make dev-logs
make dev-down
```

### Memory

An analysis can take the worker process from ~3.4 GB to ~8.5 GB. On a host that
also runs a local LLM this is the difference between a working machine and a
frozen one, so the worker is capped (`mem_limit: 8g`) and restarts itself
between jobs above `WORKER_RSS_RESTART_MB`. Set `MALJAN_MEMPROBE=objects` (or
`tracemalloc`) to see where the growth happens — `src/maljan/core/memprobe.py`
explains what the numbers mean.

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

For a fully local LLM backend (no cloud API), set `LLM__PROVIDER=openai` and point `LLM__OPENAI__BASE_URL` at a local OpenAI-compatible server such as `ik_llama.cpp`'s `llama-server`. End-to-end recipe with the Qwen3.6-35B-A3B MoE model: [`docs/LOCAL_LLM_LLAMACPP.md`](docs/LOCAL_LLM_LLAMACPP.md).

See `.env.example` for the full reference.

---

## Design Principles

- **No hallucinated TTPs:** Every ATT&CK technique ID is validated against the authoritative dataset before STIX generation.
- **No sycophancy:** Agents cannot passively agree. Cosine-similarity monitoring triggers forced re-evaluation when convergence is cosmetic.
- **Graceful degradation:** YARA, Sigma, ATT&CK validation, memory retrieval, and sandbox integration are all optional. The pipeline always produces a verdict, even offline.
- **Protocol-based extensibility:** `MemoryStore`, `SandboxClient`, and `DataLoaderProtocol` are runtime-checkable Protocols. Swap backends without touching pipeline code.
