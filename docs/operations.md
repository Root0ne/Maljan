# Operations

Day-to-day running of a deployed instance: what the logs say, what is recorded,
what is throttled, where samples live, what to back up, and what the common
failures look like.

## Logs

The API and the worker log through `apps/api/app/logging_config.py`. Production
output is one JSON object per line — timestamp, level, logger, message,
correlation id, module, function and line, plus the extra fields the request
middleware attaches (`method`, `url`, `status_code`, `duration_ms`,
`client_ip`, `user_id`) and a structured `exception` block when one is
attached. A human-readable coloured format is used in debug mode.

Every request carries a correlation id: the middleware reuses an inbound
`X-Request-ID` or generates one, puts it in every log line for that request and
echoes it back in the `X-Request-ID` response header.

`SQL_ECHO` adds every SQL statement; it is deliberately
independent of `DEBUG`, because turning it on drowns pipeline stages in
duplicated queries.

```bash
make dev-logs                                   # the whole dev stack
cd docker && docker compose logs -f backend-worker
```

## Audit trail

Security-relevant actions are written to the `audit_log` table by
`apps/api/app/services/audit.py`: registrations and logins, sample uploads and
deletions, job creation and cancellation, sandbox-report uploads and deletions,
and every settings write, including imports. Each row carries the action, the
resource, the acting user, the client address and a details object.

Two properties are deliberate. An audit row is written on a session of its own,
so a row recording a refused action is not rolled back with the request that
was refused. And writing one is best effort: a failure is logged at ERROR and
counted rather than turning a handled 4xx into a 500. The count is visible to
admin callers on `GET /api/v1/system/status`.

Admins read the trail through `GET /api/v1/audit/logs` and one row at
`/audit/logs/{log_id}`.

## Rate limits and login protection

`RateLimitMiddleware` applies a Redis-backed sliding window per client address
and path. It is configured from the settings store, under the API group, and
every change takes effect immediately: `rate_limit_enabled`,
`rate_limit_requests`, `rate_limit_window_seconds`, `rate_limit_whitelist` and
`trusted_proxy_ips`, which decides whether `X-Forwarded-For` is honoured.
Login attempts are bounded separately by `login_max_attempts` and
`login_lockout_seconds`.

The limiter needs Redis. When the counter store is unavailable the deep health
check reports `throttle_degraded`, and `GET /api/v1/system/status` shows the
same state.

## Sample storage

Sample bytes live in MinIO, in the bucket named by `MINIO_BUCKET`
(`maljan-samples` by default); metadata, jobs and reports live in Postgres.
Uploads are streamed through `UPLOAD_TEMP_DIR` rather than the system temp
directory, and the worker mirrors each downloaded sample into `SAMPLES_DIR`
so the Ghidra container can read it through its read-only bind mount. Both
directories hold live malware: exclude them from any on-access scanner and
keep them off shared storage.

`upload_max_bytes` and `upload_allowed_mime_types` bound what the API accepts.

## Backups

Two things carry state that cannot be rebuilt: the Postgres volume (`pgdata`)
and the MinIO volume (`minio_data`). The Qdrant volume holds long-term memory,
which is derived from past analyses; the ATT&CK cache volume is purely derived.

```bash
cd docker
docker compose exec -T postgres pg_dump -U maljan maljan > maljan-$(date +%F).sql
```

Back up MinIO by copying the bucket out with any S3 client, or by snapshotting
the `minio_data` volume while the stack is down.

A database dump is not enough on its own: every secret in the settings store is
encrypted with `SETTINGS_ENCRYPTION_KEY`, which is not in the dump. Store the
key with the backup, or the restored instance comes up with every credential
unreadable. A JSON export (see [configuration.md](configuration.md)) is a
useful complement — it is safe to keep next to the dump precisely because it
carries no credentials.

## Troubleshooting

| Symptom | Cause and fix |
| :-- | :-- |
| The process exits with `bootstrap: ...` | The environment failed validation. The line names every problem at once: set the variables it lists. `MINIO_SECRET_KEY` left at `minioadmin` and a short or placeholder `JWT_SECRET_KEY` are refusals outside debug. |
| Compose refuses with "set X in docker/.env" | A `:?` variable is missing from `docker/.env`. |
| Every API request fails on a fresh stack, tables missing | The `migrate` service did not run or did not succeed. `docker compose up migrate`, then check its logs. |
| The worker takes no jobs | It waits on the API's healthcheck, on `migrate` and on Postgres, Redis and Ghidra MCP being healthy. Check `docker compose ps` for the one that is not healthy, and that `REDIS_URL` matches the password Redis was started with. |
| Jobs run but the console shows no progress | Events are published on Redis and relayed over `/ws/analysis/{job_id}`. The job row is still written; check Redis and the WebSocket connection rather than the job. |
| A probe fails with a connection error | Catalog defaults are `localhost`-shaped and wrong inside the Docker network. Use `http://ghidra-mcp:8089`, `http://qdrant:6333`, and `host.docker.internal` for a service on the host. |
| A probe fails with 401 or 403 | The credential in the settings store does not match the one the container was started with — most often `GHIDRA_MCP_AUTH_TOKEN` or `QDRANT_API_KEY`. |
| Secrets show as set but the provider behaves as unconfigured | `SETTINGS_ENCRYPTION_KEY` changed. The service logs one warning per row it cannot open and falls back to the default. Restore the old key or re-enter the secrets. |
| `Storage service unavailable` on upload | MinIO is unreachable, or `UPLOAD_TEMP_DIR` is not writable. `GET /health?deep=true` distinguishes the two. |
| The worker container is killed and restarts mid-analysis | It hit its 8 GB ceiling. The startup sweep repairs the job row it was holding. Lower concurrency, or raise `mem_limit` and `WORKER_RSS_RESTART_MB` together. |
| The first analysis after a rebuild is very slow | The ATT&CK embedding cache was discarded. It lives in the `attck_cache` volume; keep it across recreations, or prebuild it. |
| A source edit has no effect | The production stack bakes the frontend and runs the worker under plain `arq`. `make fe-rebuild` and `make worker-restart`, or use `make dev-up`. |
