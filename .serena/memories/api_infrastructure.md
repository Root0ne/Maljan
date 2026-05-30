# API & Infrastructure

> Refreshed 2026-05-30 against `apps/api/`. Cross-refs: `mem:reporting_layer`,
> `mem:extractors_enrichment_qa`, `mem:suggested_commands`.

## FastAPI Application (`apps/api/app/main.py`)

### Factory + Lifespan
- `create_app()` factory; module-level `app = create_app()` for uvicorn.
- Startup: ensure `upload_temp_dir` exists (resolved absolute — Wave 9 HOTFIX-08; Defender-excluded);
  verify DB (`SELECT 1`); verify Redis (non-critical); optional **Alembic auto-upgrade**
  (`run_migrations_on_startup`, OFF by default to avoid multi-worker races); optional `AUTH_DISABLED`
  dev-admin seeding (must NOT run outside local dev). Shutdown: dispose async engine.

### Middleware (registration order)
1. `RequestLoggingMiddleware` (added first) — injects `correlation_id`, logs duration_ms (structured JSON).
2. `RateLimitMiddleware` — **Redis-backed rate limiting** (configurable `enabled`/`max_requests`/
   `window_seconds`/`whitelist`). [NEW since last memory.]
3. `CORSMiddleware` — from `settings.cors_origins` / methods / headers.
4. `SecurityHeadersMiddleware` — OWASP headers (CSP, X-Frame-Options, X-Content-Type-Options,
   Referrer-Policy, Permissions-Policy; HSTS on when not debug). SEC-CORS-HEADERS-01. [NEW.]

### Routes (all `/api/v1` unless noted)
- `auth`, `audit`, `jobs`, `samples`, `reports`, `dashboard`, `system` routers + `ws` (no prefix).
- `/health` and `/healthz` (System); `/docs`, `/redoc`.

## Report Endpoints (`api/v1/reports.py`) — comprehensive report surface (Faz 5)
- `GET /reports` (paginated), `GET /reports/{id}`, `GET /reports/job/{job_id}`.
- `GET /reports/{id}/stix` (minimal judge bundle), `GET /reports/{id}/mitre` (empty list != 404).
- `GET /reports/{id}/full` — comprehensive `MalwareReport` JSON.
- `GET /reports/{id}/markdown` — text/markdown render.
- `GET /reports/{id}/iocs` — flat IOC list, filterable by kind (hash/domain/ip/url/user_agent/ja3).
- `GET /reports/{id}/signatures/{kind}` — rule bodies (yara/sigma/suricata/snort).
- `POST /reports/{id}/enrich` — 202; idempotent ARQ job keyed `enrich:{report_id}`; returns
  `queued` / `already_queued` / `skipped_no_network_iocs`.
- `GET /reports/{id}/timeline` — negotiation timeline for visualization.

## Services
- `services/analysis_service.py` — job lifecycle: `create_job` (verify sample -> AnalysisJob pending ->
  ARQ enqueue `run_analysis`; Redis down -> mark failed), `get_job`, `list_jobs`, `cancel_job`
  (publish cancel to `analysis:{job_id}`), `get_user_stats` (dashboard metrics).
- `services/report_service.py` [NEW] — report retrieval + MalwareReport accessors (full/markdown/iocs/
  signature) + `enqueue_enrichment` (raises `EnrichmentEnqueueError` when queue unavailable).

## ARQ Workers (`app/worker/`)
- `analysis_worker.run_analysis(ctx, job_id)`: load job -> load sample -> status running ->
  `MaljanApp.arun(file_hash, file_name)` -> persist `AnalysisReport` (+ `malware_report`) and
  `AgentFinding` per agent -> status completed -> publish events. `WorkerSettings`: `max_jobs=2`,
  `job_timeout=1800`, `max_tries=1`, `health_check_interval=30`.
- `enrich_worker.py` [NEW]: `enrich_threat_intel(ctx, report_id)` — load report -> `enrich_malware_report()`
  (VirusTotal/AbuseIPDB/WHOIS + Qdrant attribution) -> persist mutated report. Idempotent, fail-safe.

## Database (PostgreSQL 16, async SQLAlchemy 2.0 + asyncpg)
Tables: users, api_keys, samples, analysis_jobs, analysis_reports (+ `malware_report` JSON column),
agent_findings (+ status), audit_log.

### Alembic (`apps/api/alembic/versions/`) — 5 migrations [was "in progress"]
1. `20250505000000_initial_schema`
2. `20250516000000_add_malware_report`
3. `20250517000000_fix_audit_resource_id_type`
4. `20250517010000_multiuser_sample_dedup_and_numeric_duration`
5. `20250524000000_add_agent_finding_status`

## Redis / WebSocket
- ARQ queue + PubSub channel `analysis:{job_id}`. Events: status_change, pipeline_started,
  agent_progress, phase_change, completed, error, cancelled.
- `app/api/ws.py` `/ws/analysis/{job_id}` subscribes and forwards events to the live UI.

## MinIO
- S3-compatible sample storage; worker mirrors download into `data/samples/` so the Ghidra MCP
  container (bind mount `/data/samples/`) can read the binary (`static_sample_path`, GHIDRA-DELIVERY-01).

## Config (`apps/api/app/config.py`) — flat env vars
DATABASE_URL, REDIS_URL, QDRANT_URL, MINIO_*, JWT secret, rate-limit settings, cors settings,
VirusTotal/AbuseIPDB enrichment keys, `run_migrations_on_startup`, `auth_disabled*`, `upload_temp_dir`,
`app_name`/`app_version`/`debug`.

## Docker (8 services, `docker/docker-compose.yml`)
postgres:16, redis:7, qdrant, minio, ghidra-mcp (HTTP :8089), backend-api, backend-worker, frontend.
Backend points `LLM__OPENAI__BASE_URL` at `host.docker.internal:8080/v1` (local llama-server);
Ollama fallback at `:11434`. Dockerfiles: `docker/Dockerfile.backend`, `docker/Dockerfile.frontend`.
