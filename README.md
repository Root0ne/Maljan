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

cp docker/.env.example docker/.env
# docker/.env holds three variables compose refuses to start without —
# there is no baked-in default for any of them:
#   GHIDRA_MCP_AUTH_TOKEN  bearer token the ghidra-mcp container requires
#   REDIS_PASSWORD         --requirepass on the redis container
#   QDRANT_API_KEY         QDRANT__SERVICE__API_KEY on the qdrant container
# Generate all three:
python -c "import secrets; [print(f'{k}={secrets.token_urlsafe(32)}') for k in ('GHIDRA_MCP_AUTH_TOKEN','REDIS_PASSWORD','QDRANT_API_KEY')]"
# and paste the output into docker/.env.
#
# Every published port binds to BIND_ADDRESS, which docker/.env.example
# defaults to 127.0.0.1 — the stack is unreachable from the network unless
# you deliberately set BIND_ADDRESS=0.0.0.0 behind a firewall or reverse
# proxy you control.

# The ghidra-mcp image is built from external/, which git does not carry
make external

# If host port 5432 is already taken, publish Postgres elsewhere and point
# DATABASE_URL at the same port
export POSTGRES_PORT=5433

# Start all 8 services
cd docker
docker compose up -d --build

# Access points (loopback only, per BIND_ADDRESS above)
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

### Static and sandbox providers are a choice, not a requirement

The static analyst attaches to one of `ghidra`, `r2`, `capa_yara`, `generic_mcp`
or `none`; the dynamic path pulls its evidence from one of `mock`, `cape2`,
`upload`, `triage` or `rest`. Pick either pair from Settings → Static analysis
provider / Sandbox provider in the web UI, per job at submit time, or with
`STATIC__PROVIDER` / `SANDBOX__PROVIDER` in `.env`. Ghidra plus CAPEv2 is the
profile this project's evaluation was measured on and stays the default for
both, but neither is required to run Maljan: `STATIC__PROVIDER=capa_yara`
with `SANDBOX__PROVIDER=upload` needs no external service at all, and
`SANDBOX__PROVIDER=mock` needs none either.

What each optional tool costs to turn on:

- **radare2 (`r2`)** — install radare2 itself, then its MCP plugin:
  `r2pm -ci r2mcp`.
- **capa + YARA (`capa_yara`)** — no external service. Pull in the optional
  dependency (`uv sync --extra capa`) and a rule checkout:
  `git clone https://github.com/mandiant/capa-rules data/capa-rules`.
- **Hatching Triage (`triage`)** — a Triage API key; no host of your own.
- **Uploaded report (`upload`)** — nothing to install: an operator attaches
  a report from any supported sandbox when submitting a sample.
- **generic_mcp** — any MCP server you already run. A custom server exposes
  nothing until you tick tools from its probe's manifest in Settings → Tool
  servers, and even so the model can call whatever is ticked, so connect only
  a server you control.

### Connecting your own tool servers

Every MCP server Maljan can attach lives in one place, `mcp.servers`, keyed by
a short name you choose. Two entries are there by default — `network` and
`threatintel`, the two sidecars that ship with the project — and you add your
own from Settings → Tool servers: a name, how to reach the server (a command
for stdio, a URL for HTTP), which analysts it serves, and which of its tools
the model may call.

**A server you add exposes nothing until you say what it may run.** That is
the trust boundary, and it is worth being exact about where it sits. Pressing
"Test" performs one MCP handshake and lists the tools the server advertises;
nothing is called. Ticking a tool adds its name to that entry's allow-list, and
only allow-listed tools are ever handed to the model. An entry with an empty
allow-list is connected and inert. The two built-in sidecars carry no
allow-list at all, which means "every tool they offer" — they are in this
repository, their tool sets are pinned by a test, and narrowing them would
change the profile the evaluation was measured on. Both built-ins can be
disabled from the same screen but not deleted; a run resumes seeing their
full manifest the moment they are re-enabled.

What a tool server's process can see is equally explicit. It is started with an
argument list, never through a shell. Its environment is a fixed base set
(`PATH`, `HOME`, locale, `TMPDIR`, `JAVA_HOME`, and a handful more) plus
exactly the variable names you list under "Environment names passed through" —
so `threatintel-mcp` sees `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` and
nothing else, and no server sees the database URL, the settings encryption key
or any LLM credential. Listing a name under `env_allow` is the only way a
credential from the process's own environment reaches a tool server; a value
you type into the server's own `env` field is an ordinary, UI-readable
setting, not a secret. A working directory, if you set one, has to resolve
inside the repository or to an absolute directory that already exists — it is
never created for you. A bearer token for an HTTP server is typed once and
stored the way every other secret in Maljan is stored: encrypted with
`SETTINGS_ENCRYPTION_KEY`, in a row of its own (`core.mcp.servers.<key>.auth_token`)
rather than in the server list's JSON, never returned by the API and never
written into a run summary. Without that key set, the UI refuses a token the
same way it refuses every other secret, and `MCP__SERVERS__<KEY>__AUTH_TOKEN`
in `.env` stays the way to supply one from the environment instead. A server
bound to the static or dynamic analyst degrades rather than failing a job: if
it cannot be reached, the run says so in its degradation reasons and
continues on the evidence it has.

### A sandbox Maljan has never heard of

`SANDBOX__PROVIDER=rest` drives an HTTP sandbox you describe rather than one
this project has an adapter for. You give it a base URL, the path a sample is
POSTed to, where the task id is in the reply, where to poll and which state
values are terminal, and where the finished report is. If that report is
CAPE-, Cuckoo- or Triage-shaped, say so and it goes through the same reader the
matching adapter uses; a dedicated Triage sandbox provider still exists
separately for the Triage cloud service itself; the REST provider's own
`triage` report format only maps a single report body shaped like one, and
does not replace it as the path for Triage. If the report is in its own
shape, describe where each channel lives with an
[RFC 9535](https://www.rfc-editor.org/rfc/rfc9535.html) JSONPath. Paste one
real response into the settings editor and press "Preview mapping" to see, in
one pass over that response, per channel how many rows each path selected and
how many survived — before a sample is ever detonated. A channel you leave
empty is reported as unavailable in the finished report, so a sandbox that
publishes no DNS log never reads as a sample that made no DNS requests. A
`verify_tls=false` setting is flagged as a warning, not refused, since some
operator-run sandboxes sit behind a self-signed certificate on a network you
already trust.

**Known limits.** Every job still uses whichever server `mcp.servers` says
serves its analyst — there is no per-job server selection yet. And
`resolve_mcp_args` roots any argument containing a `/` under the repository,
which is convenient for a relative script path but means an absolute path
outside the repo has to be passed a different way; both are open follow-ups
for a later sub-project.

CAPE itself is somebody else's platform and nothing here installs, builds or
packages it. It wants a Linux host of its own with KVM and its own Windows
guest images registered as analysis machines, which is a deployment rather
than a dependency. What this project does is talk to one over its REST API.
Point it at yours:

```bash
SANDBOX__CAPE2__BASE_URL=http://<your-cape-host>:8000
SANDBOX__CAPE2__API_TOKEN=<token from that instance>
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
| GET | `/docs` | Swagger UI (served only when `DEBUG=true`) |

---

## Security

**Sessions.** Login and refresh return the access token in the response
body only; the API never puts it in a cookie. The refresh token instead
rides an HttpOnly, `SameSite=Lax` cookie named `maljan_refresh`, scoped to
the path `/api/v1/auth`, so it is invisible to page JavaScript and is only
ever sent back to the auth endpoints. `Secure` is on by default outside
`DEBUG=true` (`COOKIE_SECURE` overrides either way). `POST /auth/logout`
clears that cookie and consumes the refresh token server-side; the web
client keeps only the short-lived access token, in memory and
`localStorage`, and refreshes it silently before it expires.

**WebSocket auth.** `/ws/analysis/{job_id}` takes the JWT access token as a
WebSocket subprotocol — `maljan.v1.<jwt>` — never as a query string, so it
does not land in access logs or browser history. The server accepts and
echoes back only the bare `maljan.v1` subprotocol. A connection lacking that
token subprotocol is rejected with close code 4401; every other auth
failure (invalid token, unknown job, a job that belongs to someone else)
closes with the generic policy code 1008. The frontend's WebSocket client
treats both codes as terminal and does not attempt to reconnect on them.

**API docs.** `/docs`, `/redoc` and `/openapi.json` are served only when
`DEBUG=true`; in a production deployment those paths do not exist.

**Report HTML.** `GET /reports/{report_id}/html` is self-contained (inline
CSS, inline SVG, no external requests) and is served with a
`Content-Security-Policy` that allows inline `<style>` only via a
per-response nonce (`style-src 'nonce-<random>'`); everything else
(`script-src`, `default-src`) is denied.

**Throttle degradation.** The per-account login/refresh throttle is backed
by Redis. When Redis is unreachable, refresh-token consumption fails
closed — no refresh succeeds until Redis is back — while the login lock
fails open rather than locking every account for the outage. This state is
visible without authentication in `GET /health?deep=true` as
`throttle_degraded`, and to an authenticated admin in `GET /system/status`
as `throttle.available` / `throttle.degraded_since` / `throttle.last_error`
and `audit_write_failures`.

**Sample copies on disk.** The worker's private working copies of a sample
live under `data/uploads/.tmp` (download staging) and `<SAMPLES_DIR>/.work`
(the Ghidra bind-mount mirror), both created `0o700` with files `0o600`.
Every worker startup sweeps both directories for copies left behind by a
process that was killed mid-job.

**Uploaded sandbox reports outlive the submit dialog.** A report attached
under the `upload` sandbox provider is kept until the sample itself is
deleted, listed under that sample regardless of whether the analysis it was
attached for ever ran. Attach a report in the submit dialog and abandon the
submission, and the report stays listed under the sample anyway; nothing
today cleans that up automatically (follow-up in sub-project B).

**Trusted proxies.** `TRUSTED_PROXY_IPS` takes CIDR networks (e.g.
`10.0.0.0/8`), not just bare IPs — only requests arriving through one of
these networks may set `X-Forwarded-For` for rate-limit identity. Left
empty, only the direct TCP peer address is trusted.

**MCP sidecar environment.** Each MCP sidecar subprocess (Ghidra, CAPE,
network capture, judge) starts from a fixed, minimal base environment
(`PATH`, `HOME`, locale/timezone vars, `JAVA_HOME`, no LLM keys, no database
URL, no encryption key) plus only the credentials that server is documented
to read — the judge sidecar is the one that additionally sees
`VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY`.

**Enrichment domain filter.** Threat-intel enrichment skips IP literals,
single-label names and special-use/private DNS suffixes before ever calling
a public reputation service, so internal hostnames are not leaked to
VirusTotal or spent against its quota for an answer that is always
"unknown".

**Static analysis.** `make semgrep` runs the same `p/python` and
`p/security-audit` rulesets, pinned to the same semgrep version, as the
CI "Semgrep" job, across `src/`, `apps/api/`, the two MCP sidecars and
`scripts/`.

**Compose secrets and network binding** are documented in the Full-Stack
Docker section above (`GHIDRA_MCP_AUTH_TOKEN`, `REDIS_PASSWORD`,
`QDRANT_API_KEY`, `BIND_ADDRESS`).

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

**From the UI.** Administrators (Settings → Configuration; the tab is shown
but disabled for everyone else) can change every core pipeline setting and the API's
runtime-safe knobs without editing `.env`. Precedence is
`UI (Postgres) > environment / .env > code default`; nothing writes `.env`.
Each field shows where its current value is coming from. A saved change
either takes effect immediately (`live`, read through a 5-second cache),
at the start of the next analysis (`next job`, the worker reads overrides
when a job starts), or requires a process restart (`restart` — shown
read-only: database, Redis, MinIO, JWT and other bootstrap settings stay in
`.env`). Secret fields (API keys, tokens) are stored Fernet-encrypted under
`SETTINGS_ENCRYPTION_KEY` and are only ever set or cleared from the UI — a
saved secret is never read back, the API returns whether it is set and a
short hint. "Test connection" checks the LLM endpoint (OpenAI, Anthropic,
Ollama or Gemini, whichever is selected), Ghidra MCP, the CAPEv2 sandbox,
Qdrant, Redis, VirusTotal and AbuseIPDB against the values you are about to
save, before you save them. The `capa_yara` probe is neither of those
services: it counts rule files locally. The indicator reports ok when capa
itself imports and its rules directory holds rules; the YARA half is checked
too, but only ever named in the detail text — a missing or empty YARA rules
directory does not flip the indicator, since capa evidence alone is enough
for the provider to run. "Test MCP server" launches one configured tool
server and lists what it offers; "Test sandbox API" asks a REST sandbox's
status endpoint about a task that does not exist, so any answer other than a
refused credential means the endpoint and the token are right. Exporting the
current UI overrides produces a
`.env`-formatted file with secret values masked as `***`. Every analysis
records the settings that were actually in effect, and which of them came
from a UI override, in its run summary.

---

## Design Principles

- **No hallucinated TTPs:** Every ATT&CK technique ID is validated against the authoritative dataset before STIX generation.
- **No sycophancy:** Agents cannot passively agree. Cosine-similarity monitoring triggers forced re-evaluation when convergence is cosmetic.
- **Graceful degradation:** YARA, Sigma, ATT&CK validation, memory retrieval, and sandbox integration are all optional. The pipeline always produces a verdict, even offline.
- **Protocol-based extensibility:** `MemoryStore`, `SandboxClient`, and `DataLoaderProtocol` are runtime-checkable Protocols. Swap backends without touching pipeline code.
