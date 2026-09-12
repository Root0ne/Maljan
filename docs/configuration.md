# Configuration

Maljan is configured in two places and no others. A small bootstrap contract
comes from the process environment and is validated once at startup; every
other application setting lives in the settings store in Postgres and is edited
from the web console. This document describes both, the export and import
format, and how secrets are stored.

## The bootstrap contract

`apps/api/app/config.py` builds `APISettings` from the process environment
only — no `.env` file is discovered or read. Construction never refuses;
`apps/api/app/bootstrap.py` performs every refusal at startup and raises one
`bootstrap: ...` line naming every problem at once, so a misconfigured
deployment does not have to be restarted once per missing variable.

The full surface is documented in
[`bootstrap.env.example`](../bootstrap.env.example). The table below is the
same contract in short form.

| Variable | Required | Default | Notes |
| :-- | :-- | :-- | :-- |
| `DATABASE_URL` | yes | `postgresql+asyncpg://maljan:maljan_dev@127.0.0.1:5433/maljan` | Async driver. |
| `REDIS_URL` | yes | `redis://127.0.0.1:6379/0` | Job queue, events, rate-limit counters. |
| `MINIO_ENDPOINT` | yes | `127.0.0.1:9000` | Host and port, no scheme. |
| `MINIO_ACCESS_KEY` | yes | `minioadmin` | |
| `MINIO_SECRET_KEY` | yes | — | Refused outside debug while unset or left at `minioadmin`. |
| `SETTINGS_ENCRYPTION_KEY` | yes | — | Fernet key; an invalid or missing key aborts startup. |
| `JWT_SECRET_KEY` | outside debug | — | Refused when unset, under 32 characters, or a known placeholder. |
| `DB_POOL_SIZE` | no | `5` | |
| `DB_MAX_OVERFLOW` | no | `10` | |
| `DB_POOL_RECYCLE_SECONDS` | no | `1800` | |
| `RUN_MIGRATIONS_ON_STARTUP` | no | `false` | Leave off in production; migrate as a deploy step. |
| `MINIO_BUCKET` | no | `maljan-samples` | |
| `MINIO_SECURE` | no | `false` | |
| `JWT_ALGORITHM` | no | `HS256` | |
| `JWT_ISSUER` | no | `maljan-api` | |
| `JWT_AUDIENCE` | no | `maljan-clients` | |
| `JWT_KEY_ID` | no | `v1` | `kid` stamped on new tokens. |
| `JWT_PREVIOUS_SECRET_KEY` | no | — | Accepted alongside the current secret during a rotation window. |
| `JWT_PREVIOUS_KEY_ID` | no | `v0` | |
| `APP_NAME` | no | `Maljan` | |
| `APP_VERSION` | no | `0.1.0` | |
| `DEBUG` | no | `false` | Also enables `/docs`, `/redoc` and `/openapi.json`. |
| `SQL_ECHO` | no | `false` | Independent of `DEBUG`. |
| `CORS_ORIGINS` | no | `["http://localhost:3000","http://127.0.0.1:3000"]` | JSON list. |
| `CORS_ALLOW_METHODS` | no | `GET, POST, PUT, PATCH, DELETE, OPTIONS` | JSON list. |
| `CORS_ALLOW_HEADERS` | no | `Authorization, Content-Type, X-Correlation-Id, X-API-Key` | JSON list. |
| `COOKIE_SECURE` | no | inverse of `DEBUG` | `Secure` flag on the refresh cookie. |
| `AUTH_DISABLED` | no | `false` | Local development only; refused when `DEBUG` is false. |
| `AUTH_DISABLED_USER_ID` / `_EMAIL` / `_FULL_NAME` | no | seeded dev admin | Only read when the bypass is on. |
| `SAMPLES_DIR` | no | `data/samples` | Host directory bind-mounted into the Ghidra container. |
| `UPLOAD_TEMP_DIR` | no | `data/uploads/.tmp` | Scratch directory for uploads and worker tempfiles. |
| `GHIDRA_CONTAINER_SAMPLES_PATH` | no | `/data/samples` | Must match the samples bind mount in `docker/docker-compose.yml`. |

One warning does not block startup: `COOKIE_SECURE` false outside debug, which
means the refresh cookie crosses the wire unencrypted unless a trusted proxy
terminates TLS.

Outside Compose, keep these in the gitignored `bootstrap.env` at the repository
root. `make dev-up`, `make dev-down`, `make dev-logs` and `make migrate` source
it; for a bare process, `set -a; . ./bootstrap.env; set +a` first.

## Settings → Configuration

Everything else is a catalog entry. The catalog is derived from the core
`Settings` model (`src/maljan/core/config.py`) plus the editable and read-only
API fields (`apps/api/app/services/settings_catalog_api.py`), and each entry
carries its own title, description, type, bounds, choices and the group it
belongs to (`src/maljan/core/settings_annotations.py`).

The backend exposes sixteen groups, in this order:

| Group | Covers |
| :-- | :-- |
| LLM & model | Which backend the analysts and the judge call, and the per-call limits. |
| Providers | Credentials, endpoints and model names per LLM vendor. |
| Frontier arms | Evaluation-only comparison endpoints and their cost accounting. |
| Static analysis provider | The static analyst's provider and its connection details. |
| Sandbox provider | Where samples are detonated, or which uploaded report stands in. |
| Tool servers (MCP) | The servers agents may call and the tools each may expose. |
| Memory / LTM (Qdrant) | Backend, collections and how many neighbours are recalled. |
| Analysis layers | Deterministic pre-analysis layers, reference data and thresholds. |
| Negotiation | Rounds and the consensus condition. |
| Chunking | How large inputs are split before they reach a model. |
| Reporting | Report contents and the metadata stamped on it. |
| Agents | The analysts, the active profile and the ReAct limits. |
| Tracing | LangSmith tracing of model calls. |
| Enrichment / threat intelligence | Lookups for the indicators a report names. |
| API | Request limits and login protection; applied immediately. |
| Deployment (read-only) | Bootstrap values, shown for reference. |

The console maps them onto five sections — Models, Analysis tools, Agents and
pipeline, Layers and reporting, Platform — and adds one synthesised group,
Profiles, carved out of Agents
(`apps/web/src/app/(app)/settings/configuration/sections.ts`). A backend group
the console does not list explicitly falls through to Platform, so a new group
appears without a frontend change.

### Editing, review and apply

Edits are staged in the browser, not written per keystroke. The toolbar shows
what is staged, the review step lists each change as a before/after pair, and
applying sends one `PATCH /api/v1/settings` with the whole set. Each entry
declares when it takes effect: `live`, `next_job`, or `restart` for read-only
deployment values.

An entry that has an override can be reset: `DELETE /api/v1/settings/{key}`
removes one override, `DELETE /api/v1/settings` removes a whole group's. The
value then falls back to the catalog default and the console shows it as such.

### Per-agent model overrides

`llm.agents` holds one optional override per agent key — provider, model,
temperature and base URL — so the analysts and the judge need not share a
single model. It is a JSON leaf of its own and is ordinarily edited from the
Agents page, one agent at a time.

The base URL is per agent, and applies to the `openai` and `ollama` providers
only: Anthropic and Gemini are vendor APIs with no endpoint to override, and an
override set against them is rejected on save. Two agents can therefore sit on
two different local OpenAI-compatible servers (llama.cpp / ik_llama.cpp) or two
different Ollama hosts, while the global `llm.openai.base_url` and
`llm.ollama.base_url` stay the fallback for everything that sets none. The
credential is not per agent: an `openai` entry with its own endpoint still
authenticates with `llm.openai.api_key`. A per-agent endpoint gets the same
treatment a global one does — the llama.cpp sampler keys and the structured
output the local servers handle badly are decided from the endpoint the agent
will actually call.

### Setup guides

**Settings → Setup** offers seven guided flows
(`apps/web/src/app/(app)/settings/setup/guides.ts`): `llm`, `static`,
`sandbox`, `tool-server`, `agent`, `memory`, `enrichment`. A guide walks
provider choice, credentials, a connection test and a review step, and applies
the result as one write, so a half-configured provider is never left behind.

### Connection probes

Thirteen probes back the "Test" buttons
(`apps/api/app/services/settings_probes.py`): `llm`, `ghidra`, `r2`, `capa`,
`mcp`, `agent`, `cape2`, `triage`, `rest`, `qdrant`, `redis`, `virustotal`,
`abuseipdb`. They are reached at `POST /api/v1/settings/test/{probe}`, with
`/test/mcp` and `/test/agent` taking a body naming the server or agent. A probe
that fails answers 200 with the failure as data — a connection test that fails
is an answer, not an error.

### Format routing and the sandbox

No sample is refused for its format. Routing detects the file type from magic
bytes (`pe`, `elf`, `mach-o`, `apk`, `dex`, `ipa`, `jar`, `ole2`, `ooxml`,
`pdf`, `lnk`, the script types, the archive types) and maps it to a platform.

The platform vocabulary is `windows`, `linux`, `macos`, `android`, `ios`,
`multi` and `unknown`. It is a plain string rather than a closed set: an
unlisted value degrades the rule filtering that reads it and nothing else.
`multi` is a sample that does not bind to one OS — a JAR, a macro document, a
PDF — and `unknown` is the honest answer when the bytes did not say.

Each sandbox is asked for the options its format needs:

- **CAPEv2.** `sandbox.cape2.package_by_format` maps a file type to a CAPE
  analysis package, e.g. `{"apk": "apk", "elf": "generic", "pdf": "pdf",
  "ooxml": "doc"}`. `*` is the fallback key; a format with no entry is
  submitted without a package, so CAPE picks one. The guest platform is sent
  when CAPE has a name for it (`windows`, `linux`, `android`) and left unset
  otherwise. `sandbox.cape2.submit_options` is sent verbatim as further form
  fields (`machine`, `tags`, `options`, `timeout`, anything else
  `tasks/create/file` accepts).
- **Hatching Triage.** `sandbox.triage.profile_by_format` maps a file type to a
  VM profile, with `*` as its fallback and `sandbox.triage.profile` behind
  that, so an operator who never touches the map keeps the profile they had.
- **The REST DSL.** `sandbox.rest.submit.submit_fields` is passed through
  verbatim as extra multipart fields, beside the existing `extra_fields`.
  `sandbox.rest.mapping.channels` maps an operator-chosen channel name to a
  JSONPath for anything the report schema has no field for; namespace the name
  by platform, e.g. `{"android.permissions": "$.apk.permissions[*]"}`. Those
  rows land in `SandboxReport.channels` and are capped and counted like every
  other channel.

### ATT&CK domains

The technique universe spans all three ATT&CK domains. `data/attck_valid_ids.json`
carries one sorted id list per domain (`enterprise`, `mobile`, `ics`), and
`src/maljan/memory/attck_loader.py` downloads and caches each domain's STIX
bundle under `~/.cache/maljan/attck/` (or `MALJAN_ATTCK_CACHE`). Enterprise is
required; Mobile and ICS are additive, and a box that can reach neither keeps
working with a narrower catalog. Regenerate the id lists with
`uv run python scripts/knowledge/prepare_attck_malware_fixtures.py`.

### Read-only deployment group

The Deployment group shows the bootstrap values the process is running with —
debug, the auth bypass, CORS origins, the database, Redis and MinIO endpoints,
the cookie flag and the two sample paths. They are not editable from the
console (`editable=false`, reason "set in the deployment environment; restart
required"), and DSNs are redacted before they are shown. Change them by
redeploying with a different environment.

## Tools, and the measurement baseline

Four tool servers are enabled out of the box and bound to the agents that read
them: `analysis` and `knowledge` to the static analyst, `knowledge` also to the
dynamic and network analysts and to the judge, `network` to the network
analyst, `threatintel` to the judge. What each offers is in
[architecture.md](architecture.md); what an operator changes here is the
binding (`agents`), the exposure (`tools`) and whether the server runs at all
(`enabled`).

The per-format tools of `analysis` rest on optional libraries. Install them
with `uv sync --extra tools` (the backend image already does); without them
`apk_info` falls back to the zip-level facts and `macho_info`, the OLE2 half of
`document_info` and the 7z half of `archive_list` answer
`{"error": "<module> is not installed"}`. Nothing else changes, and the server
starts either way.

Two profiles ship built in. `default` is the three analysts with their tools.
`measurement` is the same three analysts with `exclude_servers` covering every
tool server, `exclude_sandbox_tools` on and `static_provider` forced to `none`
— the baseline for measuring what the ensemble contributes without any tool.
Select it from Settings → Agents and pipeline like any other profile; a run
under it resolves each analyst to a prompt, a model and no tools at all.

A profile's three fields are honoured in `agents/composition.resolve_agent`, so
they apply to a custom profile too: `exclude_servers` withholds servers by key,
`exclude_sandbox_tools` withholds the in-process sandbox tool set, and
`static_provider` overrides every member's provider at once.

## Tool servers on another host

Every path-taking tool assumes the server can open the path the worker hands
it. That holds for a local stdio sidecar and for nothing else. There are two
ways to make it hold elsewhere.

**A shared volume.** Mount the same directory into both, and point the
provider's mirror at it — `static.r2.mirror_dir` is the worked example: the
worker copies the sample there (0o700 directory, 0o600 file, removed when the
job ends) and the server reads it from its own mount. Nothing is uploaded, and
the path both sides use has to agree.

**The `put_sample` convention.** A server that cannot share a filesystem
advertises `put_sample` on its manifest, and Maljan uploads the sample to it
before the agent's first tool call:

| tool | arguments | returns |
| :-- | :-- | :-- |
| `put_sample` | `filename`, `content_b64`, `sha256` | `{"path": ...}` |
| `put_sample_begin` | `filename`, `sha256`, `size` | `{"upload_id": ...}` |
| `put_sample_chunk` | `upload_id`, `seq`, `content_b64` | `{"seq": ...}` |
| `put_sample_finish` | `upload_id` | `{"path": ...}` |

Samples over 8 MiB go through the three chunked calls when the manifest carries
all of them, and through the single call otherwise. Chunks are keyed by `seq`
rather than streamed, so a transport that retries one cannot corrupt the file.
The returned path is what that server's tools are then called with —
`agents.tool_pinning.pin_paths` substitutes per server, so one agent can hold a
local sidecar's tools and a remote server's at the same time and each gets the
path it can open. Uploads are cached per `(server, sha256)` for half an hour.

Staging is triggered for any bound server whose transport is not stdio, and for
any server — stdio included — whose manifest advertises `put_sample`. It never
fails a run: an upload that goes wrong is recorded as
`sample staging failed for '<server>': <reason>` on the run's degradation
reasons, and the server is called with the local path exactly as before. The
paths that were used are recorded on the run under `remote_sample_paths`.

The built-in `analysis` sidecar implements the convention itself, so it is
exercised end to end by a default install. Its uploads land under
`$MALJAN_STAGING_DIR` — a private temp directory when that is unset — with the
directory 0o700 and each file 0o600.

## Export and import

`GET /api/v1/settings/export` (admin) returns the configuration as JSON and
sets `Content-Disposition: attachment; filename=maljan-settings.json`:

```json
{
  "format": "maljan-settings/1",
  "exported_at": "2026-09-12T00:00:00Z",
  "values": { "core.llm.provider": "openai" },
  "secrets_omitted": ["core.llm.openai.api_key"]
}
```

- Only keys the store actually holds are exported — values still on their
  catalog default are left out, as are read-only entries.
- No credential is ever written to the document. Secret entries are skipped,
  masked values nested inside a composite (an MCP server's `auth_token`, a
  frontier arm's `api_key`) are stripped at any depth, and every value in a
  server's `env` map is masked while its variable names stay.
- `secrets_omitted` names each credential the document does not carry, so an
  operator can see what has to be re-entered on the other side. Those paths are
  informational, not catalog keys.

`POST /api/v1/settings/import` (admin) accepts the same document. A `format`
other than `maljan-settings/1` is rejected with 422; unknown or read-only keys
are rejected with 422 and a per-key error, and nothing is applied when any key
fails. A successful import writes one audit row (`settings.import`) naming the
applied keys. The console previews the document against the current
configuration before sending it.

## Secrets

Secret settings are encrypted with Fernet under `SETTINGS_ENCRYPTION_KEY` and
stored as `enc:v1:<token>` (`src/maljan/core/settings_secrets.py`). The API and
the worker both read the key from their own environment, so both can open the
same rows.

Credentials nested inside composite settings are never kept inside the
composite row. An MCP server's `auth_token` and a frontier arm's `api_key` are
split into their own encrypted rows and merged back when the value is read, and
a startup repair moves any that a previous version left inline
(`apps/api/app/services/composite_secrets.py`). The console never echoes a
stored credential: it shows a mask and a short hint.

**Rotation caveat.** There is no re-encryption step and no multi-key reader. If
`SETTINGS_ENCRYPTION_KEY` changes, existing secret rows can no longer be
opened: the service logs a warning per row and the setting falls back to its
default, while the console still reports the secret as set. Re-enter each
secret after a key change, or restore the previous key.
