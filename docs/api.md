# HTTP API

Every route is mounted under `/api/v1`, except the health endpoints and the
WebSocket. This document describes the router groups and the conventions that
hold across them; the exact request and response models are in the generated
schema rather than repeated here.

## Schema

FastAPI serves `/docs`, `/redoc` and `/openapi.json` only when `DEBUG` is true.
A production deployment publishes no schema, so read it from a development
instance, or from the routers under `apps/api/app/api/v1/`.

## Authentication

Send either an access token or an API key:

```
Authorization: Bearer <access token>
X-API-Key: <key>
```

A request carrying `X-API-Key` is judged on that key. The refresh token is an
HttpOnly cookie scoped to `/api/v1/auth` and is never sent by hand. See
[security.md](security.md).

## Router groups

| Prefix | Purpose |
| :-- | :-- |
| `/auth` | Register, log in, refresh, log out, and read or update the current user. |
| `/samples` | Upload a sample, list and read sample metadata, delete a sample. |
| `/samples/{sample_id}/sandbox-reports` | Attach, list and delete sandbox reports produced elsewhere, for the `upload` sandbox provider. |
| `/jobs` | Create an analysis job, list and read jobs, read a job's event history, cancel a job. |
| `/reports` | Everything a finished analysis produces: the report itself, its renderings, its indicators, its signatures, its timeline, and post-hoc enrichment. |
| `/dashboard` | Aggregate counts for the console's landing page. |
| `/audit` | The audit trail and API-key management. Admin only. |
| `/settings` | The settings catalog, values, patches, resets, export, import and the connection probes. Admin only. |
| `/system` | Non-secret pipeline-mode flags for dashboards, and long-term-memory maintenance. |

Outside the prefix: `GET /health` and `GET /healthz` (see
[deployment.md](deployment.md)), and the WebSocket at
`/ws/analysis/{job_id}`, which streams one analysis run's events and
negotiates the `maljan.v1` subprotocol when the client asks for it.

### Reports

One report is reachable by its own id or by the job that produced it, and the
same content is offered in several renderings under
`/reports/{report_id}/...`: `markdown`, `html`, `pdf`, `stix`, `mitre`,
`full`, `iocs`, `signatures/{kind}` and `timeline`. `POST
/reports/{report_id}/enrich` queues threat-intelligence enrichment and answers
202 — the lookups run as their own job so they never delay a verdict.

### Settings

`GET /settings/schema` returns the catalog: every entry with its type, bounds,
choices, group, title, description and when it takes effect. `GET /settings`
returns the current values with their source. `PATCH /settings` applies a set
of changes in one write; `DELETE /settings/{key}` and `DELETE /settings` remove
one override or a group's. `GET /settings/export` and `POST /settings/import`
carry configuration between instances, and `POST /settings/test/{probe}` (plus
`/test/mcp` and `/test/agent`, which take a body) run the connection probes.
See [configuration.md](configuration.md).

## Conventions

- **Pagination** — list endpoints take `page` (from 1) and `page_size` (1 to
  100, default 20) and answer with `{"items": [...], "total": n, "page": p,
  "page_size": s}`. `GET /jobs` additionally accepts `status`.
- **Identifiers** — samples, jobs and reports are UUIDs.
- **Validation** — a value that does not fit its field comes back as 422 with
  the offending key named, which is also how a settings patch or import
  reports a bad value. Nothing in a rejected patch is applied.
- **Probes** — a connection test answers 200 whether the connection worked or
  not; the outcome is in the body. A failed test is an answer, not an error.
- **Errors** — refusals are JSON with a `detail` string. 401 means the
  credential is missing, invalid or expired; 403 means the account is
  deactivated or lacks the role, and names the role the caller actually has.
- **Correlation** — send `X-Request-ID` to tie your call to the server's log
  lines; the API echoes it back and generates one when it is absent.
- **Rate limits** — requests are throttled per client address and path from the
  settings store; see [operations.md](operations.md).
