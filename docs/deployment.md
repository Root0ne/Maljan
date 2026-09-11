# Deployment

How the stack is assembled, what it refuses to start without, how to check that
it is healthy, and how to upgrade it. For the meaning of individual settings
see [configuration.md](configuration.md).

## The compose stack

[`docker/docker-compose.yml`](../docker/docker-compose.yml) is the production
shape. `docker/docker-compose.dev.yml` is an overlay that swaps the frontend to
`next dev` and supervises the worker so source edits take effect; `make dev-up`
applies both.

| Service | Image | Purpose |
| :-- | :-- | :-- |
| `postgres` | `postgres:16-alpine` | Relational store. Healthchecked with `pg_isready`. |
| `redis` | `redis:7-alpine` | Queue, events, rate-limit counters. Password-protected; the healthcheck asserts an actual `PONG`. |
| `qdrant` | `qdrant/qdrant:v1.18.2` | Vector store, pinned to match the client version. |
| `minio` | `minio/minio:latest` | Sample storage, with its own console. |
| `ghidra-mcp` | built from `external/ghidra-mcp` | Static analysis engine. Capped at 6 GB memory and swap, because the JVM's own limit does not bound the container. |
| `migrate` | `maljan-backend` | One-shot `alembic upgrade head`. Runs to completion before the API and the worker start. |
| `backend-api` | `maljan-backend` | The FastAPI service. |
| `backend-worker` | `maljan-backend` | The arq worker. Capped at 8 GB memory and swap; `WORKER_RSS_RESTART_MB` makes it exit between jobs before it gets there, and `restart: unless-stopped` brings it back. |
| `frontend` | built from `docker/Dockerfile.frontend` | The console. |

The three backend services share one build and one image tag, so Compose
builds `maljan-backend` once rather than once per service.

Ordering is explicit: `migrate` waits for a healthy Postgres, the API waits for
`migrate` to exit successfully and for Postgres, Redis and Ghidra MCP to be
healthy, and the worker waits for the API's own healthcheck on top of that.

## Required secrets

Every secret Compose substitutes is declared with `:?`, so the stack refuses to
start — with the variable named — while any is missing. There is no baked-in
default for any of them.

| Variable | Used by |
| :-- | :-- |
| `POSTGRES_PASSWORD` | The database, and the `DATABASE_URL` Compose assembles. |
| `REDIS_PASSWORD` | `--requirepass` on Redis, and the API and worker URLs. |
| `QDRANT_API_KEY` | `QDRANT__SERVICE__API_KEY` on Qdrant. |
| `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` | MinIO, and the API's MinIO credentials. |
| `GHIDRA_MCP_AUTH_TOKEN` | The bearer token the Ghidra MCP container requires. |
| `JWT_SECRET_KEY` | Signs API session tokens. |
| `SETTINGS_ENCRYPTION_KEY` | Encrypts secrets in the settings store. |

Optional knobs with defaults: `BIND_ADDRESS` (`127.0.0.1`), the published
ports, `RUN_MIGRATIONS_ON_STARTUP`, `CORS_ORIGINS`, `COOKIE_SECURE`,
`WORKER_RSS_RESTART_MB`, `MALJAN_EMBED_THREADS` and `MALJAN_EMBED_BATCH`.

Every published port binds to `BIND_ADDRESS`, which the example file sets to
`127.0.0.1`. The stack is unreachable from the network until that is changed
deliberately, behind a firewall or a reverse proxy you control.

## Health

`GET /health` and `GET /healthz` are the same endpoint under two paths, so both
a bare and a Kubernetes-style liveness probe work without extra configuration.

- Without parameters it performs no I/O: it returns `status`, the service name
  and version, and a `config` block reporting `bootstrap` and `encryption`,
  both of which the process already satisfied before it could serve anything.
  A liveness probe must not restart the API because Postgres blinked.
- `GET /health?deep=true` probes Postgres, Redis, MinIO and Qdrant
  concurrently, each with a three-second budget, and reports every result as
  data. `status` becomes `degraded` when Postgres or Redis is unreachable and
  `degraded_optional` when only MinIO or Qdrant is, so use the deep form for
  readiness and the bare form for liveness.

Operational detail — throttle state and dropped audit rows — lives on
`GET /api/v1/system/status`, where those fields are returned to admin callers
only; the health endpoint publishes only the public readiness bit.

## Outside Compose

The API and the worker need nothing but the bootstrap contract in their process
environment, so any orchestrator that can inject environment variables can run
them.

- **API**: `uv run uvicorn app.main:app --host 0.0.0.0 --port 8000` from the
  repository root, without `--reload`.
- **Worker**: `uv run arq app.worker.analysis_worker.WorkerSettings`.
- **Kubernetes**: put the contract in a Secret and a ConfigMap and inject it as
  environment variables. `SETTINGS_ENCRYPTION_KEY` must be identical for the
  API and the worker deployments, or the worker cannot open the credentials the
  console stored. Point the liveness probe at `/healthz` and the readiness
  probe at `/health?deep=true`. Run migrations as a Job before the rollout and
  leave `RUN_MIGRATIONS_ON_STARTUP` false, so replicas do not race the same
  upgrade.
- **systemd**: an `EnvironmentFile=` pointing at a root-owned copy of
  `bootstrap.env` is enough for both units; nothing else is read from disk.

Behind a reverse proxy, set `CORS_ORIGINS` to the console's real origin, keep
`COOKIE_SECURE` true, and populate the `trusted_proxy_ips` setting so the rate
limiter honours `X-Forwarded-For` only from your proxy.

## Upgrades and migrations

The API does not migrate on startup unless `RUN_MIGRATIONS_ON_STARTUP` is set,
which it should not be in production.

- On the compose stack the `migrate` service reruns on the next `up` and exits
  immediately when there is nothing to apply: `docker compose up migrate`.
- Elsewhere, `make migrate` from the repository root. It sources
  `bootstrap.env` when present and runs `alembic upgrade head` from
  `apps/api`; `DATABASE_URL` must be reachable from where you run it, so the
  compose-internal `postgres:5432` will not do.

After a pull that adds a revision, migrate before restarting the services. The
production stack bakes the frontend into an image and runs the worker under
plain `arq`, so neither picks up a source edit on its own: `make fe-rebuild`
rebuilds and replaces the frontend container, and `make worker-restart`
restarts the worker.

There is no automatic import of a previous `.env` deployment. An instance
upgrading from one enters its settings once in Settings → Configuration, or
imports a JSON export from another instance.
