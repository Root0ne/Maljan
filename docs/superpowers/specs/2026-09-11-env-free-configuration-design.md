# Environment-free configuration — design

Date: 2026-09-11. Follows the settings redesign (`2026-09-08-settings-redesign-design.md`).
Decision taken with the user: the application reads no `.env` file and no application
setting from the environment. Everything an operator configures lives in the settings
store and is edited from the UI. The only values that still come from the process
environment are the ones the process needs before it can reach that store: the
bootstrap contract below.

## Goals

1. One source of truth for application configuration: the `runtime_settings` table,
   edited through `/settings`, audited, encrypted where secret. The catalog's source is
   `ui` or `default`; the `env` source no longer exists.
2. A small, explicit, validated bootstrap contract for deployment values, read from the
   process environment only (Twelve-Factor), so Kubernetes, systemd, compose and secret
   managers all work the same way and no process writes its own secrets to disk.
3. Nothing configured today is lost: the first start on this design imports the legacy
   environment values into the store once, with an audit entry.
4. An operator can move a configuration between environments without a `.env` file:
   JSON export and import from the UI, audited.
5. A misconfigured deployment fails at startup with a message that names what is
   missing, and `/health` reports configuration readiness afterwards.

Non-goals: a first-run wizard for database credentials (a process must not persist its
own deployment secrets); moving compose-level infrastructure secrets (`docker/.env`:
Postgres, Redis, MinIO root, Qdrant, Ghidra tokens) into the application, they stay
container configuration; a secret-manager integration beyond environment injection.

## Bootstrap contract

`BootstrapSettings` (new, `apps/api/app/bootstrap.py`, shared by the API and the
worker) reads these variables from the process environment, never from a file
(`env_file=None`, no `.env` discovery):

| Variable | Required | Notes |
|---|---|---|
| `DATABASE_URL` | yes | asyncpg URL |
| `REDIS_URL` | yes | |
| `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_BUCKET`, `MINIO_SECURE` | endpoint/keys yes | bucket default `maljan-samples` |
| `JWT_SECRET_KEY` (+ `JWT_KEY_ID`, `JWT_PREVIOUS_SECRET_KEY`, `JWT_PREVIOUS_KEY_ID`, `JWT_ALGORITHM`, `JWT_ISSUER`, `JWT_AUDIENCE`) | secret yes | rotation pair optional |
| `SETTINGS_ENCRYPTION_KEY` | **yes** | Fernet key; secrets in the store are always encrypted, "secrets stay in .env" no longer exists |
| `DEBUG`, `SQL_ECHO` | no | |
| `AUTH_DISABLED` (+ the dev-user triple) | no | development bypass |
| `CORS_ORIGINS`, `CORS_ALLOW_METHODS`, `CORS_ALLOW_HEADERS`, `COOKIE_SECURE` | no | |
| `SAMPLES_DIR`, `UPLOAD_TEMP_DIR`, `GHIDRA_CONTAINER_SAMPLES_PATH` | no | mount-shaped paths |
| `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_RECYCLE_SECONDS`, `RUN_MIGRATIONS_ON_STARTUP` | no | |
| `APP_NAME`, `APP_VERSION` | no | |

Validation runs before anything else in `main.py`'s lifespan and in the worker's
startup: a missing required variable, an empty or default JWT secret outside debug, or
an invalid Fernet key aborts the process with one message listing every problem, for
example `bootstrap: DATABASE_URL is not set; SETTINGS_ENCRYPTION_KEY is not a valid
Fernet key`. `/health` gains `config: {bootstrap: "ok", encryption: "ok",
legacy_import: "done" | "not-needed"}`.

The `system` read-only catalog group is renamed "Deployment (read-only)" and shows the
bootstrap values as today (URLs with userinfo redacted, secrets as set/unset), with the
description "Set in the process environment when the service starts; changed by
redeploying." Its entries carry `applies: restart` and `editable: false` as now.

## Application settings

Everything else is an application setting in the store. Concretely:

- Every `core.*` catalog key: the core `Settings` model is built from the store's
  overrides on top of the model defaults; the environment is no longer a layer.
  `build_settings(core_overrides)` constructs `Settings(_env_file=None, **overrides)`
  with environment reading disabled for the settings source (a pydantic-settings
  `settings_customise_sources` returning only init kwargs and defaults). The
  `effective_source` function loses its `env` branch: `"ui"` when a row exists,
  otherwise `"default"`.
- The `api.*` editable keys already read through `runtime_config` (rate limits, login
  lockout, upload limit, enrichment switch/budget/keys, mock-mode gate, trusted proxies)
  keep working; their fallback becomes the catalog default instead of `APISettings`.
- Moved from the environment into the store as new editable `api.*` keys (all `live`):
  `api.qdrant_url`, `api.qdrant_collection`, `api.qdrant_api_key` (secret) — the API's
  own Qdrant access for enrichment and health; `api.jwt_access_token_expire_minutes`,
  `api.jwt_refresh_token_expire_days` — read at token issue time. They leave the
  read-only group.
- The worker keeps reading core overrides from the store at job start
  (`load_core_overrides`) and now also reads the `api.*` values it needs (`mock_mode_allowed`)
  through `runtime_config`.

`APISettings` shrinks to the bootstrap contract and is renamed `BootstrapSettings`
with a compatibility alias `settings` for the modules that import it; every former
application field is removed from it, so nothing can read an application value from the
environment by accident. `src/maljan/core/config.py` keeps its model classes and
defaults; `_find_env_file` is deleted.

## Legacy import

The first API start after this change imports the previous configuration once:

1. `alembic` migration adds `settings_meta(key text primary key, value jsonb,
   created_at)`; the row `legacy_env_import` marks completion.
2. On startup, after bootstrap validation and migrations, if the marker is absent, the
   API builds the legacy view exactly as the old code did — `Settings()` with `.env`
   discovery and environment reading enabled, plus the old `APISettings` field set — in a
   dedicated module `apps/api/app/services/legacy_env_import.py` that is the only place
   still allowed to read a `.env` file. For every catalog key whose legacy value differs
   from the catalog default and that has no row yet, it writes a `runtime_settings` row
   (secrets encrypted with the Fernet key), records one audit entry
   (`settings.legacy_import`, with the list of keys, never values), and writes the marker.
   Keys that already have a row are left alone (the UI value wins, as it always did).
3. The worker never imports; it only reads the store.
4. After the marker exists the legacy module is never invoked again; a later removal of
   the module is a follow-up.

## Export and import

- `GET /api/v1/settings/export` returns JSON `{ "format": "maljan-settings/1",
  "exported_at", "values": { key: value } }` for every `ui`-sourced key; secrets are
  omitted and listed under `"secrets_omitted": [keys]`. Replaces the `.env` export; the
  UI button reads "Export configuration" and downloads `maljan-settings.json`.
- `POST /api/v1/settings/import` (admin) accepts the same document, validates every key
  against the catalog (unknown keys and read-only keys are rejected with a 422 listing
  them), stages nothing: it applies through the same `SettingsService.save` path, so
  validation, encryption and the audit entry (`settings.import`, key list) are the ones
  every UI change gets. Secrets may be included by the operator in the file; they are
  stored encrypted and never echoed. The UI adds "Import configuration" next to Export
  with a file picker, a preview of the keys that will change (`describeChange` lines) and
  a confirmation.

## Deployment and documentation

- `docker/docker-compose.yml`: the `api` and `worker` services drop `env_file: ../.env`
  and receive the bootstrap variables in `environment:` (`DATABASE_URL`, `REDIS_URL`,
  MinIO, `JWT_SECRET_KEY`, `SETTINGS_ENCRYPTION_KEY`, paths). Infrastructure secrets stay
  in `docker/.env` as today.
- `.env.example` is replaced by `bootstrap.env.example` (the contract table), with a
  header explaining that application settings live in the UI. `README.md`, `docs/README.md`
  and the Makefile targets that mention `.env` are updated; `make dev-up` sources
  `bootstrap.env` if present.
- The local helpers under `other/audit/2026-09-07-live-e2e/helpers/` are updated to
  export the bootstrap variables instead of `live.env` (local files, not shipped).

## UI

- The source badge shows `default` or `ui`; the `env` colour and the copy "Remove
  override" keep their meaning (delete the stored row).
- The "SETTINGS_ENCRYPTION_KEY is not set: secrets are read-only" banner and the
  `secrets_available` flag are removed (the API cannot start without the key). The schema
  endpoint stops sending `secrets_available`; the web type drops it.
- Toolbar: "Export configuration" (JSON) and "Import configuration" (file picker →
  preview → confirm); the `.env` wording disappears everywhere (descriptions that say
  "in .env" are rewritten).
- The "Deployment (read-only)" group carries its new description; the guides are
  unchanged.

## Testing

- Backend unit: bootstrap validation (each required variable, invalid Fernet key, debug
  exemption for the JWT secret); `effective_source` without `env`; `build_settings`
  ignores `LLM__PROVIDER`-style variables and a `.env` file in the CWD; legacy import
  (writes rows for non-default legacy values, skips existing rows, encrypts secrets,
  writes the marker, is a no-op on the second start); export/import round trip and
  rejection of unknown/read-only keys; `runtime_config` fallback to catalog defaults;
  the new `api.qdrant_*`/`api.jwt_*` keys are read live.
- API tests: `/health` config block; import endpoint auth (admin only) and 422 shape.
- Web: vitest for the import preview mapping; Playwright updates in
  `settings-configuration.spec.ts` (badge values, export JSON, import flow with a mocked
  endpoint, no secrets banner).
- Existing tests that set `LLM__*` variables to steer the core `Settings` are rewritten to
  pass overrides explicitly (53 files reference `monkeypatch.setenv`/`_env_file`; only
  the ones steering application settings change; `tests/evaluation/**` is untouched —
  if any evaluation test depends on environment steering, the compatibility path stays
  behind an explicit `MALJAN_ALLOW_ENV_SETTINGS=1` flag used only by that suite, and the
  spec records it).
- Live: start the stack with only the bootstrap variables, confirm the legacy import
  populated the store, walk the console and one guide, export and re-import.

## Delivery

Branch `feat/env-free-config` from `dev`; PRs into `dev` in three slices — (1) bootstrap
contract, env-free core settings, legacy import, health; (2) new `api.*` keys, export/
import endpoints and UI; (3) deployment files, docs, helpers, walkthrough — then the
`dev → main` promotion (approved in advance on 2026-09-11).
