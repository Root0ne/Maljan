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
| `/jobs` | Create an analysis job, list and read jobs, read a job's event history and its evidence ledger, cancel a job. |
| `/reports` | Everything a finished analysis produces: the report itself, its renderings, its indicators, its signatures, its timeline, and post-hoc enrichment. |
| `/dashboard` | Aggregate counts for the console's landing page, and `GET /dashboard/tools?limit=` — the per-tool call counts of the caller's last `limit` completed runs (default 20, at most 100), read from each run's `run_summary.evidence.by_tool`. |
| `/audit` | The audit trail and API-key management. Admin only. |
| `/settings` | The settings catalog, values, patches, resets, export, import and the connection probes. Admin only. |
| `/system` | Non-secret pipeline-mode flags for dashboards, and long-term-memory maintenance. |

Outside the prefix: `GET /health` and `GET /healthz` (see
[deployment.md](deployment.md)), and the WebSocket at
`/ws/analysis/{job_id}`, which streams one analysis run's events and
negotiates the `maljan.v1` subprotocol when the client asks for it.

### Jobs

`GET /jobs/{job_id}/evidence` is the analysis's evidence ledger: one entry per
tool call, in the order the calls were made. An entry carries the citation id
the report quotes (`entry_id`, e.g. `ev_0007`), the stage, the agent, the tool
server (null for an in-process tool), the tool, the arguments, whether the call
succeeded, its duration, the result text and the parsed result when the tool
answered JSON. `stage`, `agent` and `tool` narrow it — the three grains the
console groups by — and `page` and `page_size` (up to 200) page it. Ordering is
by the sequence the ids were issued in across the whole run, so paging walks
the analysis rather than one agent at a time, and the page an id is on is
therefore arithmetic: `ev_0051` is the first entry of page two at the default
page size.

Ownership is the job's own — the same rule the job's report endpoint applies —
and an entry whose output was dropped to the per-agent byte budget comes back
with an empty `output` and the rest of its record intact.

### The run summary

A finished report carries `run_summary`, and five of its keys describe the run
rather than the sample:

| Key | What it says |
| :-- | :-- |
| `evidence` | `entries`, `ok`, `failed`, `trimmed` and `by_tool` — how many calls the run made, how many worked, and how many lost their output to the per-agent byte budget. |
| `sections_without_evidence` | Report sections that can name neither a ledger entry nor the finding they came from. Not zero is a defect. |
| `validation` | `retries`, `by_code` and `unresolved` — what the feedback loops cost and what stayed wrong, with the agent that owns each. |
| `corroboration` | Per technique id, the sources that named it. A count of distinct sources, not a combined confidence; the judge is listed as a source but does not corroborate, because it read the analysts. |
| `stages` | Every stage of the active team in declaration order: `key`, `kind`, `ran`, `reason`, `agents`, `duration_ms`. A stage that declined is a row saying so, not an absent row. |

### The analysis WebSocket

`/ws/analysis/{job_id}` streams one run. Alongside `status_change`,
`phase_change`, `agent_progress`, `agent_message`, `completed`, `error` and
`cancelled`, the team announces each of its stages exactly once:

| Event | Payload | When |
| :-- | :-- | :-- |
| `stage_started` | `stage`, `kind`, `agents` | The stage's first node runs. |
| `stage_skipped` | `stage`, `kind`, `reason` | That node instead, when the stage's `when` condition is false. |
| `stage_finished` | `stage`, `kind`, `ran`, `reason`, `agents`, `duration_ms` | The one node that runs after everything in the stage is done. |

A stage that was skipped is never finished — the skip was its terminator — and
no stage is announced twice, whatever shape it has. Events are also mirrored
into a bounded Redis stream and served by `GET /jobs/{job_id}/events` for a tab
that opens mid-run; the stream expires after 24 hours, after which
`run_summary.stages` is the record.

The socket is held to the same account checks an HTTP route is. The handshake
reads the account the token names and closes with 1008 when it is missing or
deactivated, before it says anything about the job; while the socket streams,
it reads that account again every minute and closes with 1008 the moment it is
deactivated, rather than letting the feed run until the access token expires.
Every string on the feed is scrubbed by the publisher — credential shapes
replaced, URLs cut to scheme and host, host paths cut to file names — and a
published failure names the kind of exception it was, never its message.

### Reports

One report is reachable by its own id or by the job that produced it, and the
same content is offered in several renderings under
`/reports/{report_id}/...`: `markdown`, `html`, `pdf`, `stix`, `mitre`,
`full`, `iocs`, `signatures/{kind}` and `timeline`. Every rendering is made on
request from the stored report, so there is one source of truth and no second
copy to fall behind it. `POST /reports/{report_id}/enrich` queues
threat-intelligence enrichment and answers 202 — the lookups run as their own
job so they never delay a verdict.

`iocs` is a feed another system acts on, and it answers accordingly. `kind`
narrows to one of `hash`, `domain`, `ip`, `url`, `user_agent`, `ja3`, `ja3s`.
`include` decides what is returned:

| `include` | what comes back |
| :-- | :-- |
| `published` (default) | only what the platform's publish rule would publish — the same rule the exported STIX bundle is built with |
| `unpublished` | only the rows it withholds, for a reader who is triaging rather than acting |
| `all` | both |

Every row carries `kind`, `value`, `is_suspicious`, `notes`, **`source`** —
`sandbox` for something the sample resolved, reached or requested, `analyst`
for something an agent put in an artefact, `strings` for a run of bytes in the
file that has the shape of one, `identity` for the sample's own hashes — and
**`published`**. A name only the sample's own byte image knows is not an
observation of infrastructure, so it is withheld from the default feed and
labelled in the wider ones rather than shipped looking like one the sandbox
watched.

### Settings

`GET /settings/schema` returns the catalog: every entry with its type, bounds,
choices, group, title, description and when it takes effect. `GET /settings`
returns the current values with their source. `PATCH /settings` applies a set
of changes in one write; `DELETE /settings/{key}` and `DELETE /settings` remove
one override or a group's. `GET /settings/export` and `POST /settings/import`
carry configuration between instances, and `POST /settings/test/{probe}` (plus
`/test/mcp` and `/test/agent`, which take a body) run the connection probes.
`POST /settings/validate-condition` checks one stage's `when` expression
against the parser that will run it and answers `{"valid": …, "problems":
[…]}`; it stores nothing, and the console calls it as each condition box loses
focus so a typo is answered next to the box rather than at apply time. See
[configuration.md](configuration.md).

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
