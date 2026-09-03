# Runtime settings managed from the web UI

Date: 2026-09-02. Status: implemented — tasks 1-14 of
`docs/plans/2026-09-02-runtime-settings.md` landed on `feat/runtime-settings`;
final whole-branch review clean after three fix rounds (2026-09-03), verified
live against the running stack (apply, secrets, probes, per-job override).

## Problem

Every knob the pipeline has lives in `.env`: 136 leaf fields on the core `Settings`
model (`src/maljan/core/config.py`) and the API's own `APISettings`
(`apps/api/app/config.py`). Changing the LLM endpoint, the model, a sandbox
address, a retrieval layer or a timeout means editing a file on the host and
restarting processes, and inside Docker the file is baked into the image. The
web UI's Settings page holds only the account and API keys. The owner wants the
project's configuration to be editable from that page, usefully and completely.

## Decisions taken

1. **Persistence:** overrides live in Postgres and layer over the environment.
   Precedence is `UI (database) > environment / .env > code default`. The
   environment stays the bootstrap and default layer; nothing writes `.env`.
2. **Scope:** every core `Settings` field is editable (all 136, `applies:
   next_job`). Of `APISettings`, the operational knobs that are safe to change
   at runtime are editable (`applies: live`): `mock_mode_allowed`,
   `enrichment_enabled`, `enrichment_max_lookups`, `virustotal_api_key`,
   `abuseipdb_api_key`, `upload_max_bytes`, `rate_limit_enabled`,
   `rate_limit_requests`, `rate_limit_window_seconds`, `login_max_attempts`,
   `login_lockout_seconds`, `trusted_proxy_ips`. Infrastructure and bootstrap
   settings are shown read-only (`applies: restart`): `debug`, `auth_disabled`,
   `cors_origins`, database/Redis/MinIO/Qdrant addresses with credentials
   masked, JWT lifetimes.
3. **Secrets:** stored encrypted (Fernet) under a key read from the
   environment, `SETTINGS_ENCRYPTION_KEY`. The API never returns a secret's
   value; the UI can set a new value or clear it. Without the key, secret fields
   are read-only and the rest of the page works.
4. **Approach:** schema-driven. The catalog of fields is derived from the
   pydantic models; a small hand-maintained annotation map supplies titles,
   descriptions, groups and `applies`; the UI renders one generic form from the
   schema. A test fails when a field lacks an annotation or an annotation names
   a field that no longer exists, so coverage is enforced rather than hoped for.
5. **The paper's test count is pinned.** `paper_facts.py` currently takes
   "2,716 passing tests" from a live pytest run, so any test added to the tree
   moves a number in a manuscript under submission. The count becomes an
   artefact, `tests/evaluation/test_suite_count.json`, holding the value and the
   commit it was measured at; the suite still runs, the number no longer moves.

## Architecture

```
                 ┌──────────────┐   PATCH /settings    ┌──────────────────────┐
  admin browser  │ Next.js UI   │ ───────────────────▶ │ FastAPI              │
  /settings/     │ SettingsForm │ ◀─────────────────── │ api/v1/settings.py   │
  configuration  │ (schema-     │   schema, values,    │  · catalog           │
                 │  driven)     │   probe results      │  · RuntimeSettings   │
                 └──────────────┘                      │    Service           │
                                                       │  · probes            │
                                                       └─────┬──────┬─────────┘
                                                             │      │ RuntimeConfig
                                             runtime_settings│      │ (5 s TTL) → api.* knobs
                                                  (Postgres) │      ▼
                                                             │   enrichment, upload,
                                                             │   rate limit, login
                                                             ▼
                                                       ┌──────────────────────┐
                                                       │ arq worker           │
                                                       │ per job:             │
                                                       │ overrides = load()   │
                                                       │ settings =           │
                                                       │  build_settings(ov.) │
                                                       │ + job.config on top  │
                                                       └──────────────────────┘
```

### Components

| Unit | Location | Responsibility |
| :-- | :-- | :-- |
| Catalog | `src/maljan/core/settings_catalog.py` | Walk `Settings` and `APISettings`; emit one entry per leaf: key, type, default, choices, numeric bounds, secret flag, plus the annotation. Pure function of the models; no I/O. |
| Annotations | `src/maljan/core/settings_annotations.py` | Dict `key -> {group, title, description, applies, editable?, probe?}`. Seeded from the `.env.example` comments. Checked by a test for completeness in both directions. |
| Layering | `src/maljan/core/settings_overrides.py` | `nest(flat: dict[str, Any]) -> dict` (dotted keys to nested), `build_settings(overrides) -> Settings` (`Settings(**nested)`, verified to deep-merge with the environment), `effective_source(key)` (default / env / ui), `apply_api_overrides(APISettings, overrides)`. No database access here; it takes a plain dict so the worker and the API share it and tests need no DB. |
| Secret box | `src/maljan/core/settings_secrets.py` | `encrypt(str) -> "enc:v1:<token>"`, `decrypt`, `hint(value) -> last 4`, `is_available()`. Fernet from `cryptography`, key from `SETTINGS_ENCRYPTION_KEY`. |
| Store | `apps/api/app/models/settings.py`, `apps/api/app/services/settings_service.py` | `RuntimeSetting` ORM row; `load_overrides(db) -> dict[key, value]` (decrypting secrets); `save(db, changes, user, ip)` validating the merged models first and writing all-or-nothing; `reset(db, key or group)`; audit entries. |
| RuntimeConfig | `apps/api/app/runtime_config.py` | `get(key)` for `api.*` knobs with a 5-second TTL cache over `load_overrides`; used by the enrichment worker, upload route, rate-limit middleware and login throttle in place of the static `settings.x` reads for those keys. |
| Routes | `apps/api/app/api/v1/settings.py` | The endpoints below, all behind `require_admin`. |
| Probes | `apps/api/app/services/settings_probes.py` | `llm`, `ghidra`, `cape`, `qdrant`, `redis`, `virustotal`, `abuseipdb`. Each takes the candidate field values (unsaved form state; `null` for a secret means "use the stored one"), returns `{ok, latency_ms, detail}`; `llm` also returns the model list. Every probe has a hard timeout of 10 s. |
| Worker hook | `apps/api/app/worker/analysis_worker.py` (around the `Settings()` at line 263) | `core_settings = build_settings(await load_overrides(db))`, then the existing per-job `job.config` overrides on top. A non-secret snapshot of the effective settings goes into `run_summary.settings_snapshot`. |
| UI | `apps/web/src/app/(app)/settings/` | Tabs `account`, `api-keys`, `configuration`; the generic form engine under `configuration/`. |

### Data model

```sql
create table runtime_settings (
  key         text primary key,          -- "core.llm.openai.base_url", "api.enrichment_enabled"
  value       jsonb not null,            -- JSON value; secrets as the string "enc:v1:<fernet token>"
  is_secret   boolean not null default false,
  updated_by  uuid references users(id) on delete set null,
  updated_at  timestamptz not null default now()
);
```

Absence of a row means "no override". Reset deletes the row. There is no
version column: writers are admins, writes are rare, and the response carries
`updated_at` so a stale form can be noticed.

### Precedence and validation

`build_settings(overrides)` nests the dotted keys and calls
`Settings(**nested)`. pydantic-settings deep-merges init kwargs with the
environment and dotenv sources, so overriding `llm.openai.base_url` keeps an
`LLM__OPENAI__API_KEY` from `.env` (verified on 2026-09-02 against the real
model). Saving performs the same construction on the merged set of existing
overrides plus the requested changes; if either model fails validation the
request is rejected with 422 and per-field messages, and nothing is written.

Source attribution per key: `ui` if a row exists; else `env` if the value of
`Settings()` differs from the field's declared default; else `default`. A value
set in the environment to its own default reads as `default`; that is accepted.

### API

All under `/api/v1/settings`, admin only.

| Method | Path | Body / query | Returns |
| :-- | :-- | :-- | :-- |
| GET | `/schema` | | groups in display order, each with its catalog entries |
| GET | `/` | | `{key: {value, source, updated_at, updated_by}}`; for secrets `{is_set, hint, source, …}` and no value |
| PATCH | `/` | `{changes: {key: value}}` (`null` clears a secret) | `{applied: [key], applies: {next_job: n, live: n}}` or 422 `{errors: {key: message}}` |
| DELETE | `/{key}` | | resets one override |
| DELETE | `/?group=<group>` | | resets every override in a group |
| POST | `/test/{probe}` | `{values: {key: value}}` | `{ok, latency_ms, detail, models?}` |
| GET | `/export` | | `text/plain` in `.env` syntax of current overrides; secrets as `***` |

Audit: `settings.update` with `{changed: [key], before: {…}, after: {…}}`
(secrets logged only as `is_set` transitions), `settings.reset` with the keys.

### Apply semantics

- `core.*`: read by the worker at the start of every job. Changes take effect
  on the next analysis; running jobs are untouched.
  The worker also installs the merged object as the process-wide
  `get_settings()` singleton (`install_settings`, `max_jobs = 1`), because
  agents, pipeline nodes and extractors read that singleton rather than the
  config handed to `MaljanApp`; without it an override would stop at the
  container.
- `api.*`: read through `RuntimeConfig` with a 5-second TTL, so a change is
  live within five seconds on every API process.
- `applies: restart` fields are display-only.
- The two-switch rule for mock mode is kept: `api.mock_mode_allowed` can be
  turned on from the UI, and a job still needs `config.mock_mode`.

### Probes

| Probe | Fields it uses | What it does |
| :-- | :-- | :-- |
| `llm` | provider, base URL, API key, expert and judge model | `GET /v1/models` (list returned to the UI), then a completion of at most 8 tokens against the expert model |
| `ghidra` | MCP URL, auth token | `GET /check_connection` |
| `cape` | CAPE base URL, token | `GET /apiv2/tasks/view/1/` |
| `qdrant` | Qdrant URL, collection | `GET /readyz`, then whether the collection exists |
| `redis` | Redis URL | `PING` |
| `virustotal` | key | a request that validates the key without spending quota beyond one call |
| `abuseipdb` | key | same |

Probes never persist anything and run with a 10-second timeout.

## UI

`/settings` gains a tab bar: Account, API keys (both unchanged), Configuration.
Non-admins see the Configuration tab disabled with "admin role required".

Configuration layout:

- Left rail of groups: LLM & model; Providers (OpenAI-compatible, Anthropic,
  Gemini, Ollama); Frontier arms; Sandbox (CAPE); MCP (Ghidra, CAPE); Memory /
  LTM (Qdrant); Analysis layers; Negotiation; Chunking; Reporting; Agent
  timeouts; Enrichment / threat intelligence; API; System (read-only).
- A search box above the rail filters every group by key, title and description.
- A field row shows: title; key in monospace with copy; the widget for its type
  (toggle, number, text, select, tag list, key-value rows, validated JSON,
  secret); a source badge (default / env / ui); an applies chip (next analysis /
  immediately / restart); a "reset to env" action when overridden; the
  description underneath.
- Group headers carry "Test connection" where a probe exists. The LLM group also
  has "Fetch models", which turns the expert and judge model fields into
  selects populated from the endpoint while still allowing a typed value.
- A sticky bar at the bottom shows the count of pending changes with Apply and
  Discard. Apply opens a confirmation listing each change and when it takes
  effect, then sends one PATCH. Leaving the page with pending changes prompts.
- 422 errors land under the field they name.
- Secret fields render masked with "Set new value" and "Clear", and show
  `set · …ab12 · env`.
- "Export overrides (.env)" in the header.

Implementation: one generic `SettingsForm` engine, one `FieldWidget` per type,
hooks `useSettingsSchema` and `useSettingsValues`, six methods on the existing
`api` client, in the existing Tailwind design language.

## Testing

Backend (pytest, `tests/unit/api/` and `tests/unit/core/`):

- catalog: every leaf has an annotation and every annotation names a leaf;
  secret detection; choices from `Literal`.
- layering: dotted keys nest correctly; an override wins over env; an
  untouched sibling keeps its env value; `effective_source` for the three cases.
- secrets: round trip; hint; masked output; behaviour without the key.
- service: PATCH is atomic on validation failure; 422 names the field; reset
  deletes; audit rows written with secrets masked.
- routes: non-admin gets 403; schema and values shapes.
- worker: `build_settings` applied before `job.config`, and `job.config` still
  wins.
- RuntimeConfig: TTL expiry and refresh.
- probes: httpx mocked; timeout path.

Frontend: the repository has no unit-test runner; one Playwright spec with
route mocks (schema, values, PATCH body assertion) in `apps/web/e2e/`, matching
how the rest of the UI is tested. `tsc`, `eslint` and `next build` run in CI.

Paper: `tests/evaluation/test_suite_count.json` with `{"count": 2716,
"measured_at_commit": "afbb797", "measured_on": "2026-09-02"}`; `paper_facts.py`
reads it and still runs the suite for the green-run check. `make facts` must
stay byte-identical.

## Out of scope

Editing `.env` from the UI; per-user settings; settings history/rollback beyond
the audit log; multi-tenant isolation; changing infrastructure addresses at
runtime; a frontend unit-test framework.

## Migration and rollout

1. Alembic revision adds `runtime_settings` (down: drop table).
2. `.env.example` gains `SETTINGS_ENCRYPTION_KEY` with the generation command
   (`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`).
3. README "Configuration" gains a paragraph on UI-managed settings, precedence
   and the encryption key.
4. No behaviour changes until a row exists; an empty table is today's system.
