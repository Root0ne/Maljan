# API & Infrastructure

## FastAPI Application (`apps/api/app/main.py`)

### Lifespan Events
1. **Startup**:
   - Verify DB connectivity (`SELECT 1` via async SQLAlchemy engine).
   - Verify Redis connectivity (ping).
   - Log structured JSON with component tags.
2. **Shutdown**:
   - Dispose async engine.

### Middleware Stack
1. `RequestLoggingMiddleware` — MUST be added first. Injects `correlation_id` per request, logs duration_ms, request/response details in structured JSON.
2. `CORSMiddleware` — configured from `settings.cors_origins`.

### Routes
- `/api/v1/auth` — JWT login/register/refresh
- `/api/v1/samples` — CRUD + upload (MinIO storage)
- `/api/v1/jobs` — Analysis job creation and management
- `/api/v1/reports` — Report retrieval
- `/api/v1/dashboard` — Statistics endpoint
- `/ws/analysis/{job_id}` — WebSocket real-time events (no API prefix)
- `/health` — Service health check

## Analysis Service (`apps/api/app/services/analysis_service.py`)

### `AnalysisService`
- **create_job(sample_id, user, config)**:
  - Verifies sample exists in DB.
  - Creates `AnalysisJob` record (status="pending").
  - Enqueues to ARQ via `arq.enqueue_job("run_analysis", str(job.id))`.
  - If Redis unavailable: marks job as failed with error message.
- **get_job(job_id, user)**: User-scoped job lookup.
- **list_jobs(user, page, page_size, status_filter)**: Paginated with count.
- **cancel_job(job_id, user)**:
  - Validates job exists and is cancellable (pending/running).
  - Sets status="cancelled".
  - Publishes cancellation event to Redis PubSub channel `analysis:{job_id}`.
- **get_user_stats(user)**: Dashboard metrics:
  - total_jobs, total_samples, jobs_by_status, verdict_distribution, avg_duration_seconds.

## ARQ Worker (`apps/api/app/worker/analysis_worker.py`)

### `run_analysis(ctx, job_id)`
1. **Load job**: Query DB, validate not cancelled.
2. **Load sample**: Get SHA256 and original filename.
3. **Transition**: status="running", publish `status_change` event.
4. **Setup pipeline**:
   - Injects `src/` into `sys.path` for core engine imports.
   - Builds `Settings()` with optional job config overrides (`max_iterations`, `llm_provider`).
   - `MaljanApp(config=settings, mock=env MALJAN_MOCK_MODE)`.
5. **Publish pipeline_started event**: Lists registered agents, sample info.
6. **Execute**: `await app.arun(file_hash=sample.sha256, file_name=sample.original_filename)`.
7. **Publish agent_progress + phase_change events**.
8. **Save report**:
   - `AnalysisReport`: verdict, confidence, malware_category, STIX bundle, MITRE techniques, negotiation log, run_summary.
   - `AgentFinding` per agent: domain, claims, dissent_items, revision_rounds, final_confidence.
9. **Mark complete**: status="completed", duration_seconds.
10. **Publish completed event** with verdict and confidence.

### Error Handling
- Catches all exceptions, logs full traceback.
- Updates job status="failed" with error_message (truncated to 2000 chars).
- Publishes error event to Redis.
- DB rollback on commit failure.

### WorkerSettings
- `max_jobs = 2` (concurrent analyses)
- `job_timeout = 1800` (30 minutes)
- `max_tries = 1` (no auto-retry)
- `health_check_interval = 30`

## Database Schema (PostgreSQL)

| Table | Key Fields |
|-------|-----------|
| `users` | id, email, hashed_password, role, active |
| `api_keys` | id, user_id, key_hash, name, created_at |
| `samples` | id, sha256, original_filename, size_bytes, minio_path, uploaded_by, uploaded_at |
| `analysis_jobs` | id, sample_id, created_by, status, config, started_at, completed_at, duration_seconds, error_message |
| `analysis_reports` | id, job_id, verdict, overall_confidence, malware_category, stix_bundle, mitre_techniques, agent_reports, negotiation_log, run_summary |
| `agent_findings` | id, report_id, agent_name, domain, claims, dissent_items, revision_rounds, final_confidence |
| `audit_log` | id, user_id, action, resource_type, resource_id, timestamp |

## Redis Usage
1. **ARQ Queue**: Job enqueueing and worker task distribution.
2. **PubSub**: Real-time pipeline events channel `analysis:{job_id}`.
   - Event types: `status_change`, `pipeline_started`, `agent_progress`, `phase_change`, `completed`, `error`, `cancelled`.
3. **Cancellation**: `PUBLISH analysis:{job_id} {"type":"cancelled"}`.

## WebSocket (`apps/api/app/api/ws.py`)
- Subscribes to Redis PubSub channel for job events.
- Forwards events to connected WebSocket clients in real-time.
- Frontend uses this to show live agent progress, phase changes, and final verdict.

## Structured Logging
- Logger factory: `app.logging_config.get_logger(name)`.
- JSON format in production: `{timestamp, level, logger, message, correlation_id, component, ...}`.
- Development mode (`DEBUG=true`): colored human-readable output.
- All services use consistent component tags: `database`, `redis`, `pipeline`, `worker.lifecycle`, `report`, etc.
