<p align="center">
  <img src="assets/logo.svg" alt="Maljan" width="112">
</p>

<h1 align="center">Maljan</h1>
<p align="center"><em>Multi-Agent Malware Analysis Framework</em></p>


[![CI](https://github.com/Root0ne/Maljan/actions/workflows/ci.yml/badge.svg)](https://github.com/Root0ne/Maljan/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.13-blue)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-2%2C707%20passed-brightgreen)](tests/)
[![Licence](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

Maljan maps evidence about a Windows PE sample to MITRE ATT&CK technique
identifiers and emits a STIX 2.1 bundle. It is mostly not a language model: six
deterministic evidence layers assert techniques from signatures and rules, three
LLM analysts describe behaviour over three channels of evidence, a judge
synthesises a verdict, and a deterministic reconciliation and gating stage
decides what the analyst actually receives. The organising rule is that the
model proposes and code disposes: **the model never emits a technique identifier
or a final set.**

## Web UI

| | |
|---|---|
| <img src="assets/ui-dashboard.png" alt="Dashboard"> | <img src="assets/ui-analysis.png" alt="Analysis detail"> |
| **Dashboard.** Totals, failure rate, recent analyses and verdict distribution. | **Analysis detail.** Eleven tabs over one run, with Markdown, PDF, HTML, STIX 2.1 and MISP export. |
| <img src="assets/ui-detection.png" alt="Detection tab"> | <img src="assets/ui-attack.png" alt="ATT&CK matrix"> |
| **Detection.** The deterministic YARA and Sigma rules that fired, each with the technique it maps to and the pattern that matched. | **ATT&CK.** Each technique carries where it came from: `SINGLE SOURCE` or `CORROBORATED`, and which layers agreed. |

The last image is the corroboration cascade made visible. A technique asserted by
one layer and a technique three independent layers agree on are different claims,
and the interface says which is which rather than presenting a flat list.

---

## Key Capabilities

| Feature | Description |
|---|---|
| Deterministic grounding | Six Layer-0 sources assert techniques before any model runs: YARA, tool-artifact byte markers, Sigma, PE import capability, LOLBin signed-proxy execution and network DGA entropy. The rule sets behind two of them are covered below. |
| Deterministic technique assignment | The model describes behaviour; a hybrid retrieval index over the official ATT&CK corpus assigns every identifier. This removes identifier recall from a model that does not have the taxonomy memorised. Measured against two external corpora. |
| Multi-agent decomposition | Static, Dynamic and Network analysts each read one evidence channel through one tool server. Sequential by default, because a single local llama-server slot turns fan-out into queue thrash; set `parallel_analysts=True` for hosted APIs where each request gets its own slot. |
| Structured negotiation | A negotiation node tests for consensus and routes disputes to a revision pass, with sycophancy detection and adaptive termination. At matched call budget this contributes +0.0005 F1; the calls it costs are what pay. |
| Multi-layer TTP cascade | Cross-domain weighted scoring (YARA 0.90 down to network 0.20) with corroboration multipliers rising to 1.90 at five independent layers. |
| Reconciliation and gating | After the model: unresolvable identifiers dropped, the cascade's set restored, a confidence cap, and a STIX integrity pass. This stage is why the deterministic layer dominates the output. |
| STIX 2.1 output | Conformance measured with the OASIS `cti-stix-validator` rather than with the integrity pass this project wrote itself, which is how two specification violations were found and fixed. |
| Long-term memory (RAG) | Past analyses and family fingerprints are vectorised in Qdrant and retrieved by similarity. Measured end to end, the three retrieval components contribute nothing; they are kept and reported rather than removed. |
| Comprehensive reports | Every run emits a structured `MalwareReport` rendered as Markdown, JSON, STIX 2.1 and MISP, surfaced through the analysis UI. |
| Post-hoc threat-intel enrichment | An async ARQ worker fills VirusTotal, AbuseIPDB, WHOIS and GeoIP reputation after the verdict ships, so verdict latency is unaffected. |

---

## Architecture

A LangGraph `StateGraph` over one shared state. The analyst stage has two
shapes and the topology is chosen by `parallel_analysts`:

```
START
  │
  ├─ parallel_analysts = False  (the default)
  │     static_analyst -> dynamic_analyst -> network_analyst
  │     one local server slot means fan-out is queue thrash, not speed
  │
  └─ parallel_analysts = True   (hosted APIs, one slot per request)
        START fans out to all three, then fans in
  │
negotiation  <-------- revision
  │  (consensus, or the iteration cap)   ^
  └─ no consensus -----------------------┘
  │
judge
  │   inside this node: the YARA and Sigma scanners, the per-technique
  │   TTP cascade, ATT&CK validation, then the STIX 2.1 bundle
  │
report  ->  END
```

- **ISR (Intermediate Structural Representation).** Agents exchange structured `AgentISR` objects (claims, `evidence_ref`, confidence) rather than raw text.
- **ServiceContainer (DI).** Agents, LLMs, loaders and stores are created and cached in one composition root. No global state.
- **AgentRegistry.** New agents are discovered through the `@register_agent` decorator and the builder wires them dynamically.

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

# 2. Install dependencies and fetch the third-party trees
make setup

# 3. Configure environment
cp .env.example .env
# Edit .env: set LLM__PROVIDER and add your API key

# 4. Run a mock analysis (no API key required)
uv run maljan analyze sample_1 --mock --name test.exe

# 5. Run a real analysis
uv run maljan analyze <sha256> --provider openai
```

### Full-Stack Docker (recommended)

```bash
cp .env.example .env
# Edit .env with your API keys and LLM provider settings

# The ghidra-mcp image is built from external/, which git does not carry
make external

# If host port 5432 is already taken, publish Postgres elsewhere and point
# DATABASE_URL at the same port
export POSTGRES_PORT=5433

# Start all 8 services
cd docker
docker compose up -d --build

# Access points
# Frontend:      http://localhost:3000
# Backend API:   http://localhost:8000/docs
# Ghidra MCP:    http://localhost:8089/check_connection
# MinIO Console: http://localhost:9001
```

> **Local LLM:** Containers reach the host's LLM via `host.docker.internal:8080/v1` (OpenAI-compatible: typically `ik_llama.cpp`'s `llama-server`). The legacy Ollama path on `:11434` is also wired up as a fallback. `make external` fetches `ik_llama.cpp` at the commit this project was measured against; the model is `Qwen3.6-35B-A3B` quantised to `IQ3_K_R4`, which fits on an 8 GB GPU with a hybrid MoE offload.

### Pre-build the ATT&CK cache (optional)

```bash
uv run python -c "from maljan.memory.attck_validator import ATTCKValidator; ATTCKValidator.get_instance()"
```

---

## `external/` is not in this repository

Two third-party projects are built against and neither is ours to redistribute.
Git ignores the directory; the repository records the ref each was used at, and a
script reconstructs the tree from the upstream repositories:

```bash
make external     # or: make setup, which runs it for you
```

| Project | Ref | Why |
|---|---|---|
| [ghidra-mcp](https://github.com/bethington/ghidra-mcp) | `v5.6.0` | `docker compose` builds the headless disassembly image from this checkout, so the tree has to be on disk before the stack comes up. |
| [ik_llama.cpp](https://github.com/ikawrakow/ik_llama.cpp) | `eb570eb9` | The inference engine. This is the commit the evaluation pins, so fetching it here is what makes that pin reproducible rather than merely recorded. |

### The sandbox is not ours to install

CAPE is somebody else's platform and nothing here installs, builds or packages
it. It wants a Linux host of its own with KVM and its own Windows guest images
registered as analysis machines, which is a deployment rather than a dependency.

What this project does is talk to one over its REST API. Point it at yours:

```bash
SANDBOX__CAPE2_BASE_URL=http://<your-cape-host>:8000
SANDBOX__CAPE2_API_TOKEN=<token from that instance>
```

With no sandbox reachable the pipeline degrades rather than fails: the dynamic
path is skipped and the run completes on static evidence, a behaviour pinned by a
test.

---

## Whose rules these are

Two rule sets drive the deterministic layer and only one of them is ours.

**Sigma is SigmaHQ's.** The corpus is not in this repository and never should
have been: it was committed here as 2,651 files by Florian Roth, Nasreddine
Bencherchali, frack113 and the rest of [SigmaHQ](https://github.com/SigmaHQ/sigma),
carrying neither their licence nor their names. Their rules are published under
the Detection Rule License. `make external` clones the corpus at a pinned release
into `data/sigma_rules`, licence file included, and git ignores the directory. No
rule in it was written here.

**The YARA-TTP set is ours.** `data/yara_ttp_rules.yaml` holds 30 hand-written
patterns that map byte and API-name markers straight to ATT&CK identifiers. It is
a small grounding set for this pipeline rather than a detection corpus, and it is
not a substitute for one.

The Sigma layer degrades to zero rules when the corpus is absent: it logs the
missing directory and the run continues on the other five Layer-0 sources.

There is a third thing that is easy to confuse with these. `MalwareReport` can
pivot the indicators one run produced into **draft** YARA, Sigma and Suricata
rules, offered through `/api/v1/reports/{report_id}/signatures/{kind}`. Those are
generated from that sample's own evidence for an analyst to review. This project
does not author detection rules.

---

## API Endpoints

REST lives under `/api/v1`. The health probes and the WebSocket sit on the
application root, not under that prefix.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/auth/register` | User registration |
| POST | `/api/v1/auth/login` | JWT token login |
| POST | `/api/v1/auth/refresh` | Exchange a refresh token |
| GET, PATCH | `/api/v1/auth/me` | Read or update the current user |
| POST | `/api/v1/samples/upload` | Upload a sample |
| GET | `/api/v1/samples` | List samples |
| POST | `/api/v1/jobs` | Create an analysis job |
| GET | `/api/v1/jobs/{job_id}` | Job status |
| GET | `/api/v1/jobs/{job_id}/events` | Server-sent event stream for one job |
| GET | `/api/v1/reports/{report_id}` | Report summary |
| GET | `/api/v1/reports/{report_id}/full` | The whole `MalwareReport` |
| GET | `/api/v1/reports/{report_id}/markdown` | Markdown render |
| GET | `/api/v1/reports/{report_id}/pdf` | Print-ready PDF |
| GET | `/api/v1/reports/{report_id}/html` | Self-contained HTML |
| GET | `/api/v1/reports/{report_id}/stix` | STIX 2.1 bundle |
| GET | `/api/v1/reports/{report_id}/mitre` | ATT&CK technique set |
| GET | `/api/v1/reports/{report_id}/iocs` | Extracted indicators |
| GET | `/api/v1/reports/{report_id}/signatures/{kind}` | Generated YARA, Sigma or Suricata |
| POST | `/api/v1/reports/{report_id}/enrich` | Queue post-hoc threat-intel enrichment |
| GET | `/api/v1/dashboard/stats` | Dashboard metrics |
| GET | `/api/v1/system/status` | Component health |
| GET | `/api/v1/audit/logs` | Audit trail |
| WS | `/ws/analysis/{job_id}` | Real-time analysis events |
| GET | `/health`, `/healthz` | Liveness probes |
| GET | `/docs` | Swagger UI |

---

## Static-analysis data assets

Deterministic detection is data-driven. These live under `data/`, are loaded
lazily, are cached per path, and **every one of them degrades to a built-in
fallback when absent**: a missing file costs depth, never a run.

| Asset | What it drives |
|---|---|
| `api_behaviour_map_v1.json` | Windows API → behaviour category, ~780 names / 13 categories. Each category carries a `tier`; only `high`/`medium` mark an import *suspicious*, so categorising `RegOpenKeyExA` does not mean accusing it. |
| `api_attck_map_v1.json` | Windows API → ATT&CK, 47 techniques. This is what gives a **sandbox-less run real technique coverage**: with CAPE unreachable the Sigma corpus is telemetry-gated and contributes nothing. |
| `tool_artifacts_v1.json` | Offensive-tool / RAT byte markers. The only source of a **malware family name without a sandbox**. |
| `packer_signatures_v1.json` | Packer / protector identification, ranked: section name > entry point > string. |
| `language_signatures_v1.json` | Source-language and runtime fingerprints, scored rather than substring-matched. |

The first two are generated: the curated lists live in the builder, not the
JSON, so a reader can see *why* an API is classified the way it is:

```bash
make prepare-api-db   # validates every ATT&CK ID before writing
```

**Restart the worker after regenerating.** `data/` is bind-mounted, so the
container sees the new file immediately, but each asset is cached per path in
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

# The gate covers every Python directory in the repo: src/, tests/, apps/api/,
# the two MCP sidecars and scripts/. It used to be src/ and tests/ only, which
# meant the FastAPI app and the arq worker were never type-checked anywhere,
# and a sidecar could sit unformatted for weeks because pre-commit only ever
# sees staged files.

# If `git commit` prints "`pre-commit` not found. Did you forget to activate
# your virtualenv?", the installed hook has a stale absolute interpreter path
# baked into it (it happens whenever the venv is recreated, or when the
# snap-installed toolchain the venv points at is upgraded). Reinstall it: # do NOT reach for --no-verify:
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
| `backend-api` | bind-mounted | **yes**: uvicorn `--reload` |
| `backend-worker` | bind-mounted | **no**: `arq` never re-imports a changed module |
| `frontend` | **baked into the image** | **no**: it serves a Next.js standalone build |

So on the production stack:

```bash
make worker-restart   # after ANY Python edit under src/ or apps/api
make fe-rebuild       # after ANY frontend edit; a plain restart is not enough
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
`tracemalloc`) to see where the growth happens: `src/maljan/core/memprobe.py`
explains what the numbers mean.

---

## Configuration

All settings live in `.env`. The project uses two config systems:

1. **Core Engine**: nested Pydantic models with `__` delimiter (e.g., `LLM__PROVIDER=openai`)
2. **API Server**: flat env vars (e.g., `DATABASE_URL`, `JWT_SECRET_KEY`)

Critical variables:

```bash
LLM__PROVIDER=openai|anthropic|ollama|gemini
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
DATABASE_URL=postgresql+asyncpg://maljan:maljan_dev@localhost:5432/maljan
REDIS_URL=redis://localhost:6379/0
JWT_SECRET_KEY=<generate with openssl rand -hex 32>
```

For a fully local LLM backend (no cloud API), set `LLM__PROVIDER=openai` and point `LLM__OPENAI__BASE_URL` at a local OpenAI-compatible server such as `ik_llama.cpp`'s `llama-server`. `make external` fetches the engine at the pinned commit, and `scripts/llm_server.sh` carries the invocation.

See `.env.example` for the full reference.

---

## Design Principles

- **No hallucinated TTPs:** Every ATT&CK technique ID is validated against the authoritative dataset before STIX generation.
- **No sycophancy:** Agents cannot passively agree. Cosine-similarity monitoring triggers forced re-evaluation when convergence is cosmetic.
- **Graceful degradation:** YARA, Sigma, ATT&CK validation, memory retrieval, and sandbox integration are all optional. The pipeline always produces a verdict, even offline.
- **Protocol-based extensibility:** `MemoryStore`, `SandboxClient`, and `DataLoaderProtocol` are runtime-checkable Protocols. Swap backends without touching pipeline code.
