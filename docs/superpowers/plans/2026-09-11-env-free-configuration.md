# Environment-free Configuration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The API and worker read only a validated bootstrap contract from the process environment; every application setting lives in the settings store and is edited from the UI; the legacy `.env` values are imported once; configuration moves between environments as JSON.

**Architecture:** A new `BootstrapSettings` (process environment only, validated at startup) replaces the application half of `APISettings`; `build_settings(overrides)` builds the core `Settings` with environment and dotenv sources disabled; `runtime_config` falls back to catalog defaults; a one-time `legacy_env_import` populates the store; export/import endpoints replace the `.env` export; compose passes bootstrap variables only.

**Tech Stack:** FastAPI, pydantic-settings 2, SQLAlchemy async + Alembic, arq, Next.js 16 web console (existing settings UI), vitest + Playwright, pytest.

**Spec:** `docs/superpowers/specs/2026-09-11-env-free-configuration-design.md` (read it first).

## Global Constraints

- No file under `tests/evaluation/` changes; the bare core `Settings()` stays environment-capable (those scripts depend on it). The application never constructs `Settings` bare — enforced by an architecture test.
- No catalog key is renamed or removed; the API contract only grows (new `api.*` keys, new `settings_meta` table, new `/settings/import`, `/settings/export` now JSON, `/health.config`), except that `SchemaResponse.secrets_available` is removed (the web client is updated in the same PR).
- Secrets are never logged, never echoed by export, and always stored Fernet-encrypted; `SETTINGS_ENCRYPTION_KEY` is mandatory.
- Commands: backend `make lint format-check typecheck` and `uv run pytest tests/unit tests/api tests/integration -q -p no:cacheprovider`; web `cd apps/web && npx tsc --noEmit && npm run lint && npm run test:unit`; Playwright only by named spec from the checkout with the dev server stopped by pidfile first (see the previous plan's rule); never `pkill -f`.
- Machine rule: one heavy workload at a time (no `next build`, full pytest, Playwright or Docker in parallel), `free -g` available ≥ 10 GB before any of them.
- Commits: conventional prefix, no AI attribution trailer, no question sentences in headings, comments or docs.
- Branch `feat/env-free-config` (from `dev`); PRs into `dev` from snapshot branches (`feat/env-free-config-pN`); promotion to `main` at the end (approved 2026-09-11).

## File structure

Backend:
- Create `apps/api/app/bootstrap.py` — `BootstrapSettings`, `validate_bootstrap() -> list[str]`, `require_bootstrap()`.
- Modify `apps/api/app/config.py` — `APISettings` becomes the bootstrap contract (application fields removed; class keeps the name `APISettings` for import compatibility and gains `BootstrapSettings = APISettings`).
- Modify `apps/api/app/runtime_config.py` — fallback to catalog defaults.
- Modify `apps/api/app/services/settings_catalog_api.py` — new editable keys (`qdrant_url`, `qdrant_collection`, `qdrant_api_key`, `jwt_access_token_expire_minutes`, `jwt_refresh_token_expire_days`), read-only list reduced to the contract, group title/description "Deployment (read-only)".
- Modify `src/maljan/core/settings_annotations.py` (group title/description), `src/maljan/core/settings_overrides.py` (`build_settings`, `effective_source`, `Source`), `src/maljan/core/config.py` (`Settings.settings_customise_sources` honouring an init flag).
- Modify `apps/api/app/services/settings_service.py` (`values()` uses defaults, no env), `apps/api/app/main.py` (bootstrap validation first, legacy import after migrations, health `config`), `apps/api/app/worker/analysis_worker.py` (bootstrap validation at startup), `apps/api/app/auth/jwt.py`, `apps/api/app/worker/enrich_worker.py` and Qdrant users (runtime_config).
- Create `apps/api/app/services/legacy_env_import.py`, `apps/api/app/models/settings_meta.py`, migration `apps/api/alembic/versions/20260911000000_add_settings_meta.py`.
- Modify `apps/api/app/api/v1/settings.py` (export JSON, import endpoint), `apps/api/app/schemas/settings.py` (drop `secrets_available`, add export/import DTOs).
- Tests: `tests/unit/api/test_bootstrap.py`, `tests/unit/test_no_bare_settings_in_app.py`, `tests/unit/core/test_settings_overrides_env_free.py`, `tests/unit/api/test_legacy_env_import.py`, `tests/api/test_settings_export_import.py`, updates to the 11 env-steering tests.

Web (`apps/web/src/app/(app)/settings/configuration/`):
- Modify `Toolbar.tsx` (Export configuration JSON, Import configuration with preview), `FieldRow.tsx`/`vocabulary.ts` (badge set `default|ui`), `SettingsContext.tsx` (no `secrets_available`), `apps/web/src/types/settings.ts`, `apps/web/src/lib/api.ts` (`exportSettings` JSON, `importSettings`), `apps/web/e2e/settings-configuration.spec.ts`, `e2e/mocks.ts`.
- Create `configuration/ImportDialog.tsx`, `configuration/__tests__/importPreview.test.ts`.

Deployment/docs: `docker/docker-compose.yml`, `bootstrap.env.example` (new; `.env.example` removed), `README.md`, `docs/README.md`, `Makefile`, `other/audit/2026-09-07-live-e2e/helpers/*.sh` (local).

---

## Phase 1 — bootstrap contract, env-free core, legacy import (PR 1)

### Task 1: `BootstrapSettings` and startup validation

**Files:** Create `apps/api/app/bootstrap.py`; Modify `apps/api/app/config.py`, `apps/api/app/main.py` (lifespan head), `apps/api/app/worker/analysis_worker.py` (startup); Test `tests/unit/api/test_bootstrap.py`.

**Interfaces (produces):**
```python
# apps/api/app/bootstrap.py
class BootstrapProblem(ValueError): ...
def validate_bootstrap(s: APISettings) -> list[str]   # human sentences, e.g. "DATABASE_URL is not set"
def require_bootstrap(s: APISettings) -> None          # raises BootstrapProblem("bootstrap: " + "; ".join(problems))
```
Rules: required non-empty `database_url`, `redis_url`, `minio_endpoint`, `minio_access_key`, `minio_secret_key`; `jwt_secret_key` non-empty and not a known placeholder unless `debug`; `settings_encryption_key` present and a valid Fernet key (`Fernet(key)` constructs); `cookie_secure` must be true when `debug` is false unless `auth_disabled` (warning only, not a problem). `APISettings.model_config` becomes `SettingsConfigDict(env_file=None, extra="ignore")` — no dotenv discovery. `main.py` lifespan calls `require_bootstrap(settings)` as its first statement; on `BootstrapProblem` it logs the message at CRITICAL and re-raises (uvicorn exits non-zero). The worker's `startup` does the same.

- [ ] Step 1: tests — `test_missing_required_lists_every_variable`, `test_invalid_fernet_key_is_a_problem`, `test_placeholder_jwt_secret_allowed_only_in_debug`, `test_clean_bootstrap_has_no_problems` (build `APISettings(**kwargs, _env_file=None)`).
- [ ] Step 2: run → fail; Step 3: implement; Step 4: `uv run pytest tests/unit/api/test_bootstrap.py -q`, `make lint format-check typecheck`; Step 5: commit `feat(api): validated bootstrap contract read from the process environment only`.

### Task 2: application fields leave `APISettings`; `runtime_config` falls back to catalog defaults; new `api.*` keys

**Files:** Modify `apps/api/app/config.py`, `apps/api/app/runtime_config.py`, `apps/api/app/services/settings_catalog_api.py`, `apps/api/app/services/settings_service.py:100-120` (api namespace values), `apps/api/app/auth/jwt.py`, `apps/api/app/main.py` (qdrant health), `apps/api/app/worker/enrich_worker.py`, `apps/api/app/api/v1/system.py`; Tests `tests/unit/api/test_runtime_config.py` (extend or create), `tests/unit/api/test_settings_catalog_api_types.py`.

Rules: remove from `APISettings`: `mock_mode_allowed`, `enrichment_*`, `virustotal_api_key`, `abuseipdb_api_key`, `rate_limit_*` (keep `rate_limit_whitelist`? — it is deployment-shaped; move it too as `api.rate_limit_whitelist` list, live), `login_*`, `upload_max_bytes`, `upload_allowed_mime_types` (move as `api.upload_allowed_mime_types`, live), `trusted_proxy_ips`, `qdrant_url`, `qdrant_collection`, `qdrant_api_key`, `jwt_access_token_expire_minutes`, `jwt_refresh_token_expire_days`. Each becomes an `API_EDITABLE` entry with the same default in a `API_DEFAULTS: dict[str, Any]` table next to it (type inferred as today). `runtime_config.get(name)` → override if present else `API_DEFAULTS[name]`; `get_secret` likewise (`""` default). `API_READONLY` keeps only the bootstrap contract fields (`debug`, `auth_disabled`, `cors_origins`, `database_url`, `redis_url`, `minio_endpoint`, `cookie_secure`, `samples_dir`, `upload_temp_dir`) with group `system` retitled "Deployment (read-only)" and the spec's description in `GROUP_DESCRIPTIONS`. Consumers: `jwt.py` reads expiry through `await runtime_config.get(...)` at issue time (make the two token builders async-aware; if they are sync, read via a small cached accessor refreshed on `invalidate()`); `main.py` Qdrant health and `enrich_worker.py` read `api.qdrant_*` through `runtime_config`; `system.py` unchanged.

- [ ] Step 1: tests — runtime_config default fallback per new key; catalog contains the new keys with `applies: live`, read-only list equals the contract set; `APISettings` has no application field (assert on `model_fields`).
- [ ] Steps 2–4: fail → implement → `uv run pytest tests/unit/api tests/api -q`, lint/typecheck; Step 5: commit `feat(settings): application settings leave the environment; runtime defaults come from the catalog`.

### Task 3: env-free core settings for the application

**Files:** Modify `src/maljan/core/config.py` (`Settings`), `src/maljan/core/settings_overrides.py`, `apps/api/app/services/settings_service.py` (`values()`), `apps/api/app/worker/analysis_worker.py:80-90`, `src/maljan/core/container.py` (if it builds `Settings()` for the app path); Tests `tests/unit/core/test_settings_overrides_env_free.py`, `tests/unit/test_no_bare_settings_in_app.py`, plus the env-steering tests listed by `grep -rlE 'setenv\("(LLM|SANDBOX|STATIC|MEMORY|AGENTS|MCP|NEGOTIATION|CHUNKING|REPORTING|ANALYSIS|PREPROCESSING)__' tests/ | grep -v evaluation`.

Design:
```python
# src/maljan/core/config.py
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=_find_env_file(), env_file_encoding="utf-8", env_nested_delimiter="__", extra="ignore")
    @classmethod
    def settings_customise_sources(cls, settings_cls, init_settings, env_settings, dotenv_settings, file_secret_settings):
        # ``_env_file=None`` at construction means "store-only": init kwargs and defaults, no environment.
        if getattr(init_settings, "init_kwargs", {}).get("_store_only"):  # see build_settings
            return (init_settings,)
        return (init_settings, env_settings, dotenv_settings, file_secret_settings)
```
Implement with a private `ClassVar`/context flag rather than a fake kwarg if pydantic-settings rejects unknown init keys: `build_settings` sets a module-level `contextvars.ContextVar("store_only")` to `True` around `Settings(**overrides)` and `settings_customise_sources` reads it. `effective_source(overridden)` → `"ui" | "default"`; `Source = Literal["ui", "default"]`. `settings_service.values()` computes `core_env` from `build_settings({})` (defaults) and drops the env branch; the `api` namespace value comes from `runtime_config` defaults/overrides. Architecture test: read `apps/api/app/**/*.py`, assert the regex `\bSettings\(\)|\bAPISettings\(\)|Settings\(_env_file` matches only in `services/legacy_env_import.py` and `config.py` (the lazy singleton); assert `analysis_worker.py` calls `build_settings`. Rewrite the env-steering application tests to pass overrides (or `build_settings({...})`) — keep their assertions.

- [ ] Step 1: tests — `build_settings({})` ignores `LLM__PROVIDER=anthropic` in the environment and a `.env` in CWD; `Settings()` bare still honours the environment (documented library behaviour); `effective_source(overridden=False) == "default"`; architecture test.
- [ ] Steps 2–4: implement; run `uv run pytest tests/unit tests/api tests/integration -q` (some previously env-driven tests will fail: fix them by passing overrides); lint/typecheck; Step 5: commit `feat(settings): the application builds its core settings from the store and defaults only`.

### Task 4: legacy import, `settings_meta`, health `config`

**Files:** Create `apps/api/app/models/settings_meta.py`, `apps/api/alembic/versions/20260911000000_add_settings_meta.py`, `apps/api/app/services/legacy_env_import.py`; Modify `apps/api/app/models/__init__.py`, `apps/api/app/main.py` (after migrations), `apps/api/app/main.py` health; Tests `tests/unit/api/test_legacy_env_import.py`, `tests/api/test_health_config.py`.

Algorithm (`run_legacy_import(db, fernet) -> list[str]`):
1. If `settings_meta['legacy_env_import']` exists → return `[]`.
2. Build `legacy_core = Settings()` (bare, environment + discovered `.env`) and `legacy_api = LegacyAPIView()` — a pydantic-settings model declared inside the module with the removed application fields and their old defaults, `env_file` discovery as the old `APISettings` had.
3. For each catalog entry: legacy value = `flatten_leaves(legacy_core)[path]` for core, `getattr(legacy_api, path)` for api-editable; skip read-only; skip if equal to the catalog default; skip if a `runtime_settings` row exists; else write the row via `SettingsService.save`-equivalent internals (encrypt secrets with the Fernet box; `updated_by=None`).
4. Audit `settings.legacy_import` with `{"keys": [...], "count": n}`; write the marker `{"imported": n, "at": iso}`; return keys.
`main.py`: after `run_migrations_on_startup` block, `await run_legacy_import(...)` inside a session; log the count. Health: `config: {"bootstrap": "ok", "encryption": "ok", "legacy_import": "done"|"not-needed"}` (`done` when the marker exists with `imported > 0`, `not-needed` when it exists with 0 or nothing to import).

- [ ] Step 1: tests — marker absent + env `LLM__PROVIDER=anthropic` + `LLM__OPENAI__API_KEY=x` → rows written, secret encrypted, audit recorded, marker set; second call no-op; existing row untouched; default-equal values skipped; health block shape.
- [ ] Steps 2–4: implement (`make migrate` locally against the dev DB is allowed), run `uv run pytest tests/unit/api tests/api -q`; Step 5: commit `feat(settings): import the legacy environment configuration once into the store`.

### Task 5: Phase 1 close — full backend suite, PR into dev from `feat/env-free-config-p1`, CI, merge, merge dev back.

---

## Phase 2 — export/import, web updates (PR 2)

### Task 6: JSON export and import endpoints

**Files:** Modify `apps/api/app/api/v1/settings.py`, `apps/api/app/schemas/settings.py`; Tests `tests/api/test_settings_export_import.py`, update `tests/api/test_settings_routes.py` (export shape).

`GET /settings/export` → `{"format": "maljan-settings/1", "exported_at": iso, "values": {key: value for ui-sourced non-secret keys}, "secrets_omitted": [keys]}` (`application/json`, `Content-Disposition: attachment; filename=maljan-settings.json`). `POST /settings/import` body `{"format": "maljan-settings/1", "values": {...}}` → admin; unknown keys / read-only keys → 422 `{"errors": {key: "unknown key" | "read-only"}}`; otherwise `SettingsService.save(changes=values, user_id=...)` (same validation/encryption/audit) plus audit `settings.import` `{"keys": [...]}`; response = `PatchResponse`. `SchemaResponse` drops `secrets_available`; `api/v1/settings.py:76-79` (the "secrets stay in .env" reason) is removed.

- [ ] Step 1: tests — export omits secrets and lists them; import round trip; unknown/read-only rejected with 422; non-admin 403; audit entry present.
- [ ] Steps 2–4: implement, run `uv run pytest tests/api tests/unit/api -q`; Step 5: commit `feat(settings): JSON export and import replace the .env export`.

### Task 7: Web — JSON export, import dialog, source badge, no secrets banner

**Files:** Modify `apps/web/src/lib/api.ts`, `apps/web/src/types/settings.ts`, `configuration/Toolbar.tsx`, `configuration/FieldRow.tsx`, `configuration/vocabulary.ts` (`SOURCE_LABEL: {default, ui}`), `configuration/SettingsContext.tsx`, `configuration/GroupHeader.tsx`/descriptions mentioning `.env`; Create `configuration/ImportDialog.tsx`, `configuration/importPreview.ts` (+ `__tests__/importPreview.test.ts`); Modify `apps/web/e2e/settings-configuration.spec.ts`, `apps/web/e2e/mocks.ts`.

Behaviour: "Export configuration" downloads `maljan-settings.json` (toast "Configuration downloaded as maljan-settings.json"); "Import configuration" opens a dialog (`role="dialog"`, file input accepting `.json`), parses, validates the `format`, builds preview lines with `describeChange(entry, currentValue, importedValue)` for known keys and lists unknown/read-only keys as errors; "Import N settings" → `api.importSettings(doc)` → on success reload and show the applies summary; on 422 show per-key errors. Badge set `default | ui`; remove the secrets banner and any `.env` wording. `buildImportPreview(doc, entriesByKey, values) -> { lines: ChangeLine[], errors: Record<string,string> }` unit-tested.

- [ ] Steps: tests first (`importPreview.test.ts`: known key line, unknown key error, read-only error, format mismatch); implement; `tsc/lint/test:unit`; Playwright `settings-configuration.spec.ts` updated (export JSON request, import dialog with mocked endpoint, badge values, no banner) and run by name; commit `feat(settings-web): configuration export and import as JSON`.

### Task 8: Phase 2 close — build, PR into dev from `feat/env-free-config-p2`, CI, merge, merge dev back.

---

## Phase 3 — deployment, docs, live walkthrough, promotion (PR 3)

### Task 9: compose, `bootstrap.env.example`, README, Makefile, helpers

**Files:** Modify `docker/docker-compose.yml` (api/worker: drop `env_file: ../.env`, pass `SETTINGS_ENCRYPTION_KEY: ${SETTINGS_ENCRYPTION_KEY:?…}`, `JWT_SECRET_KEY: ${JWT_SECRET_KEY:?…}`, MinIO, `UPLOAD_TEMP_DIR`, `SAMPLES_DIR`, `GHIDRA_CONTAINER_SAMPLES_PATH`), `docker/.env.example` (add the two app bootstrap secrets with generation commands), `README.md` (§ configuration rewritten: bootstrap table, "all application settings live in the UI", export/import, legacy import note), `docs/README.md`, `Makefile` (`dev-up` sources `bootstrap.env` if present; remove `.env` mentions); Delete `.env.example`; Create `bootstrap.env.example`; update `other/audit/2026-09-07-live-e2e/helpers/start_services.sh` to export the bootstrap set from a local `bootstrap.env` (not committed).

- [ ] Implement; `docker compose -f docker/docker-compose.yml config` must render (no Docker start); commit `chore(deploy): bootstrap-only environment for the API and worker`.

### Task 10: live walkthrough and close-out

- [ ] Start the API and worker with only the bootstrap variables exported (no `.env` in the tree — move the local `.env` aside), confirm the log line for the legacy import count and `/health.config`, open the console: sources show `ui`/`default`, no banner; export JSON; import it back (no changes); walk one guide; restore the local `.env` aside file only as a backup (not read any more). Screenshots under `other/audit/2026-09-11-env-free-config/`.
- [ ] Final whole-branch review (most capable model) against the spec; one fix wave; PR into dev from `feat/env-free-config-p3`; CI; merge; promotion PR `dev → main`; delete branches; stop the stack; ledger + memory.
