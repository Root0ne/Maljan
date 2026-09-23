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

`stix` serves the exported bundle. `stix?source=judge` serves the judge's own
bundle beside it, as `{"bundle": …, "labels": {…}}`: the bundle as the pipeline
read it and the map from each id the judge wrote to the id it was published
under. It is the bundle every export decline row says an object "is unchanged
in". A report stored before it was kept answers `{"kept": false, "reason": …}`
— the report exists and has none — and only a report that does not exist, or
is not the caller's, answers 404. A kept record carries `"kept": true`, and a
label the judge gave two objects maps to the list of ids it named.

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

#### What changed between two runs

`GET /reports/diff?a=<id>&b=<id>` compares two stored runs; `by=job` names
them by job id instead of report id. Both must be runs the caller may read,
and one that is not answers 404 exactly as a single report read does. The
two runs may be of different samples: the answer's `same_sample` is `true`,
`false`, or `null` when either SHA-256 is not recorded, and
`sample_statement` says which in a sentence. `GET /jobs?sample_id=<id>`
lists one sample's runs, which is how a run finds the others to compare with.

The diff is made on request from the two stored records — the report
columns, the `MalwareReport` document, the run summary, the exported STIX
bundle and the per-agent findings — and nothing else. It states what each
record says; it does not say which run is right, does not merge them and
writes into neither. The same function, `maljan.reporting.run_diff.diff_runs`,
can be called on any two records; it is linear in their sizes, and the route
runs it and encodes its answer off the event loop.

The answer carries `a` and `b` (report id, job id, time, SHA-256, file name),
`totals`, and `sections` in a fixed order. Each section has a `match_key`
saying what its rows are paired by, `counts` per status, `recorded` saying
whether each run's record holds the source the section reads, `notes`, and
`rows`, plus `section_evidence`: the ledger ids a record cites for the
section as a whole (the rule-match sections and the capability profile cite
their entries that way, not per row). A row has its `status`, both sides'
fields as recorded (`a`, `b`, null where the run has no such row), `changes`
naming each differing field with both values, and the evidence-ledger ids
each run's record cites for that row. Ids are read only from fields that hold
ids — `family_evidence_ids`, a key finding's `evidence_ids`, a configuration
item's, a command's and a C2 channel's `evidence_refs`, a persistence
mechanism's and a claim's `evidence_ref`, a STIX object's
`x_maljan_evidence_refs` — and never out of a quote, a note, a title or a
sample's own strings. A row whose record holds no such field cites none; that
is every ATT&CK mapping and every indicator.

A `stated_by` names who stated a value only where the record shows it. A
confidence is the judge's when the verdict reading is `stated`. A family's is
its `family_source`. A severity is the judge's only on a report that carries
`verdict_reading`: a report stored before that carries a rating the builder
computed, and its severity row has no `stated_by` at all.

| Section | Paired by |
| :-- | :-- |
| `verdict` | the field: verdict (with `verdict_reading`), confidence, severity, family (with `family_source` and its evidence ids), category |
| `attack` | `ttp_mappings.technique_id`; the confidence source comes from the capability matrix |
| `indicators` | `consolidated_iocs` kind and value. A row stored without a kind (a report stored before the column existed, whose network values may be defanged) is keyed by its type and value as stored and pairs only with rows of that shape; against the other shape both runs' rows are listed by run, with a note. A report without the table is read from its network block, which records no publish decision, and says so |
| `key_findings` | exact text only |
| `analysts` | `agent_findings.agent_name` |
| `persistence` | kind and target |
| `configuration` | the configuration key |
| `commands` | the command id, or the name when it has none |
| `c2_channels` | the channel name |
| `capability_profile` | the behaviour category of `static.api_capabilities` |
| `detection` | engine and rule name from the `yara_matches`, `sigma_matches` and `capa_capabilities` sections |
| `stix` | STIX type and an identifying property: the ATT&CK id, an indicator's pattern, a name (as written, and compared), a value, a file's SHA-256 or name, a registry key, a directory path; a relationship by its type and both ends' keys, a sighting by what it sights. Any other object pairs only with an identical object, id included |
| `run` | the fact: profile, analysts, models per agent, token figures, wall time, job duration, degraded |
| `tools` | the tool name of `run_summary.evidence.by_tool` |
| `degradation` | exact text only |

A status is `added` or `removed` (present in B only or A only by key),
`changed`, `unchanged`, or `only_in_a` / `only_in_b`. The last two are rows
the record does not key stably — a key finding's prose, a degradation
sentence, a STIX object with no identifying property such as a report, a
note or a process, a relationship to one — and indicators of two storage
shapes. They are listed by run and never paired by resemblance. Object ids
are not a key: the platform mints some ids per run, so two runs of one sample
carry different ids for the same content.

Rows under one key pair as a multiset. When both runs hold a key n times the
rows pair, identical rows first; the rows one run holds beyond the other's
count are `added` or `removed` with a note that they are a repeat. A record
compared with itself is unchanged in every row.

One case rule applies to indicator values and STIX keys alike: a value is
compared without regard to case only where it is case-insensitive by
definition — a domain name, an IP address, a hash, a MAC address and a
Windows registry key; an e-mail address in its domain part only. A URL, a
path, a mutex name and a malware or tool name are compared as written.

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
