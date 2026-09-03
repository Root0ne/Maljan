# Security hardening after the 2026-09-02 audit

Date: 2026-09-03. Status: approved design, implementation pending.

The audit of 2026-09-02 left a set of findings that change behaviour and were
therefore not applied with the clean-up. This document is the binding design
for applying them: the audit's section 4 in full, plus three cheap low
findings (L4, L9, L12). Every item names the code it changes, the behaviour
before and after, and how it is tested. Items are independent unless a
dependency is stated; they land on one branch, `feat/security-hardening`, as
one pull request, each item as its own commit.

## Ground rules

- Precedence, secrets and the settings catalog follow
  `docs/specs/2026-09-02-runtime-settings-design.md`. A new setting is a new
  catalog leaf with a description, or the catalog test fails.
- Nothing in this work re-runs an evaluation or changes a number the paper
  prints. `make facts` must stay byte-identical; the pinned test count is a
  recorded artefact and is not affected by tests added here.
- No behaviour change is silent: where a request is now refused, the reason
  is in the response; where a background action now fails closed, the state
  is visible in `/health?deep=true` and `/system/status`.
- Local development without Docker Compose keeps working with an unchanged
  `.env`. Compose users get a clear error naming the variable they must set.

## 1. H1 — auth throttle fails closed where it must, and says when it is degraded

Files: `apps/api/app/auth/throttle.py`, `apps/api/app/api/v1/auth.py`,
`apps/api/app/api/v1/system.py`, `apps/api/app/main.py` (health).

Before: the first Redis error writes `_pool = False` and the process never
retries; refresh-token reuse detection returns "valid", the login lock returns
"not locked", failures are recorded nowhere, and only the first error is a
warning.

After:

- `_redis()` keeps no sentinel. A failed connection records
  `_state = {"available": False, "since": <monotonic>, "error": <type name>}`
  and the next call retries once `RETRY_AFTER_S = 30` has passed. Success
  resets the state. A transition in either direction logs one `warning`.
- `refresh_token_consume()` returns `False` when Redis is unavailable or the
  command fails. The refresh route then answers 401 with detail
  `"session store unavailable; sign in again"`. A user loses at most the
  access-token lifetime (30 minutes) during an outage; nobody can replay a
  refresh token while reuse detection is blind.
- `is_login_locked()` still returns `False` without Redis (failing closed
  would lock every account for the length of an outage), and
  `record_login_failure()` is still a no-op. Both mark the state degraded.
- `throttle_state()` returns `{"available": bool, "degraded_since": float | None,
  "last_error": str | None}`. `/health?deep=true` gains `throttle_degraded`
  (bool) and `/system/status` gains the full object. The module docstring is
  rewritten to describe this behaviour.

Tests: fake Redis that raises on demand; assert refresh → 401, login lock →
open, state object transitions, retry after the interval (clock injected),
one warning per transition.

## 2. H3 — every sample copy the worker makes is removed, and lives in its own directory

Files: `apps/api/app/worker/analysis_worker.py`, `apps/api/app/api/v1/samples.py`,
`apps/api/app/config.py` (+ catalog annotation), `docker/docker-compose.yml`
comment.

Before: each job writes `data/uploads/.tmp/<sha><ext>` and mirrors it to
`data/samples/<sha><ext>` (CWD-relative), mode 0644 in 0755 directories, and
never deletes either. `delete_sample` removes only the MinIO object.

After:

- New API setting `samples_dir: str = "data/samples"` (read-only in the UI,
  group system, applies restart) next to the existing `upload_temp_dir`.
  The worker's Ghidra mirror goes to `<samples_dir>/.work/<sha><ext>`; the
  compose mount `../data/samples:/data/samples` is unchanged, so the container
  path becomes `/data/samples/.work/<sha><ext>`. The `.work` subdirectory is
  the boundary: the operator's own corpus in `data/samples/` is never listed,
  never deleted.
- Both directories are created with mode `0o700`; both files are written with
  `0o600` (`os.open` with explicit mode, not `chmod` after the fact).
- The job's `finally` removes the temp copy and the mirror, logging at
  `debug` on success and `warning` (path, error type) on failure. A failed
  job cleans up the same way.
- `delete_sample` also unlinks `<upload_temp_dir>/<sha>*` and
  `<samples_dir>/.work/<sha>*` for the deleted sample's hash.
- Worker startup sweeps `<upload_temp_dir>` and `<samples_dir>/.work` only:
  files older than 24 hours are removed and counted in one `info` line.

Tests: worker lifecycle test asserts both paths are gone after success and
after a pipeline exception; permission bits asserted with `stat`; sweep test
with an aged file and a fresh one; `delete_sample` test asserts unlink calls.

## 3. M1 — trusted proxies are networks, validated up front

Files: `apps/api/app/middleware/rate_limit_middleware.py`, `apps/api/app/config.py`,
`apps/api/app/services/settings_service.py` (validation already runs the model).

Before: `TRUSTED_PROXY_IPS` entries are compared as strings, so the documented
CIDR `10.0.0.0/8` never matches and `X-Forwarded-For` is silently ignored.

After: `APISettings.trusted_proxy_ips` has a validator that parses every entry
with `ipaddress.ip_network(entry, strict=False)` (a bare address is a /32 or
/128) and raises on anything else, so a bad value fails startup and is a 422
in the Configuration tab. The middleware caches the parsed networks per
`runtime_config` value and matches `ip_address(peer) in network`.

Tests: `10.0.0.0/8` matches `10.1.2.3`; `192.168.1.5` (bare) matches itself
only; `"proxy"` and `"10.0.0.0/33"` are rejected; XFF honoured only from a
trusted peer.

## 4. M2 — compose has no baked-in secret and publishes nothing to the network

Files: `docker/docker-compose.yml`, `docker/.env.example` (new if absent),
`README.md`, `src/maljan/core/config.py` (`memory.qdrant_api_key`, secret),
`src/maljan/core/settings_annotations.py`, `apps/api/app/config.py`
(`qdrant_api_key`, secret, read-only), `src/maljan/memory/qdrant_store.py`,
`src/maljan/memory/function_hash_store.py`, `apps/api/app/api/v1/system.py`,
`apps/api/app/services/settings_probes.py` (qdrant probe sends the key).

After:

- `GHIDRA_MCP_AUTH_TOKEN`, `REDIS_PASSWORD` and `QDRANT_API_KEY` are required
  in compose: `${VAR:?set VAR in docker/.env — see README}`. No default.
- Every `ports:` entry binds to the loopback: `127.0.0.1:${PORT:-…}:…`,
  including Qdrant's 6334 and MinIO's console. The API and web services keep
  their published ports but also on `127.0.0.1` by default; an operator who
  fronts them with a reverse proxy changes the bind in `docker/.env`
  (`BIND_ADDRESS`, default `127.0.0.1`).
- Redis runs with `--requirepass ${REDIS_PASSWORD}`; the API and worker
  services receive `REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0`.
- Qdrant runs with `QDRANT__SERVICE__API_KEY=${QDRANT_API_KEY}`; the stores
  accept `api_key: str | None` and pass it to `QdrantClient`; the worker and
  the LTM purge route read it from the merged settings; the probe sends it.
  Outside compose the key is empty and nothing changes.
- README's compose section lists the three variables and one command that
  generates them.

Tests: unit tests for the stores' constructor (key forwarded, absent when
None); a compose config test that renders `docker compose config` with a
fixture env and asserts no `0.0.0.0` publish and no literal token remains.

## 5. M5 — evaluation harnesses count what they drop

Files: new `tests/evaluation/_tally.py`; producers
`eval_attck_case_rag.py`, `eval_family_rag_retrieval.py`,
`eval_fallback_bundle_content.py`, `eval_confidence_cap.py`,
`eval_dynamic_vs_static.py`; `tests/evaluation/paper_facts.py`.

`Tally` has `attempted`, `parsed`, `scored` and `dropped: Counter[str]`, a
`drop(reason)` method that also logs one stderr line, and `as_dict()`.
Each producer replaces its bare `continue` / `return None` with a tally call
and writes `"population": tally.as_dict()` into its result JSON next to the
existing counts. Existing artefacts in the repository are not regenerated.

`paper_facts.py` gains one check: for every artefact it loads that carries
`population`, `scored == attempted` or every dropped sample has a reason
(`sum(dropped.values()) == attempted - scored`); otherwise `FactError` names
the artefact. Artefacts without `population` pass unchanged, so the current
facts are byte-identical.

Tests: `Tally` unit tests; a `paper_facts` test with a synthetic artefact in
each of the three states (no population, consistent, inconsistent).

## 6. M6 — an audit write that fails is an error, and is counted

Files: `apps/api/app/api/v1/auth.py`, `apps/api/app/services/settings_service.py`,
new `apps/api/app/observability.py` (process counters), `apps/api/app/api/v1/system.py`,
`apps/api/app/main.py` (health).

Both `_audit` helpers log at `error` with the action name and exception type
(never the details payload) and increment `counters.audit_write_failures`.
`/system/status` and `/health?deep=true` expose the counter; the throttle
state from item 1 lives in the same module.

Tests: patch the session factory to raise; assert the log level, the counter
and that the calling route still succeeds.

## 7. L5 — the WebSocket token travels only in the subprotocol

Files: `apps/api/app/api/ws.py`, `apps/web/src/lib/useWebSocket.ts`,
`apps/web/e2e/*` where the WS URL is asserted.

The client opens the socket with protocols `["maljan.v1", "maljan.v1.<jwt>"]`
and no query string. The server drops the `?token=` branch: a connection
without the subprotocol form is closed with 4401 before accept. The route
docstring is updated.

Tests: API test with a subprotocol token (accepted) and a query token
(closed 4401); frontend hook test that the URL has no `token` and the
protocols carry it.

## 8. L6 — the refresh token is an HttpOnly cookie

Files: `apps/api/app/api/v1/auth.py`, `apps/api/app/schemas/auth.py`,
`apps/api/app/main.py` (CORS), `apps/api/app/config.py` (`cookie_secure`,
default `not debug`), `apps/web/src/lib/{auth.tsx,api.ts}`,
`apps/web/e2e/{fixtures.ts,mocks.ts}` and specs that read `refresh_token`.

- `/login` and `/refresh` set cookie `maljan_refresh` = refresh JWT with
  `HttpOnly; SameSite=Lax; Path=/api/v1/auth; Max-Age=<refresh lifetime>` and
  `Secure` unless `debug`. The response body carries `access_token` and
  `token_type` only. `TokenResponse` loses `refresh_token`.
- `/refresh` reads the cookie; a missing cookie is 401. The request body is
  gone (`RefreshRequest` removed).
- New `POST /logout`: consumes the cookie's jti (so it cannot be replayed),
  clears the cookie, 204. Works without a valid access token.
- CORS: `allow_credentials=True`; origins stay the explicit list (no `*`).
- Web client: `login`, `refresh`, `logout` send `credentials: "include"`;
  `localStorage` keeps only `access_token`; the existing refresh lock and
  timer stay, keyed on the access token's expiry instead of the refresh
  token's; `logout()` calls the endpoint before clearing local state.
- e2e: `seedSession` sets only the access token; mocks for `/refresh` and
  `/logout` return the new shapes; `auth.spec.ts` asserts no
  `refresh_token` in `localStorage` after login.

Tests: API tests for cookie attributes, 401 without cookie, logout consuming
the jti; the e2e changes above.

## 9. L7 — no inline scripts in the CSP; the report page uses a nonce

Files: `apps/api/app/middleware/security_headers_middleware.py`,
`apps/api/app/api/v1/reports.py`, `src/maljan/reporting/renderers/html.py`.

The global CSP drops `'unsafe-inline'` from `script-src`. The HTML renderer
accepts `nonce: str | None`; when given, its `<style>` carries it and the
route sets `Content-Security-Policy` for that response with
`style-src 'nonce-<value>'` and `script-src 'none'` (the report has no
script). The nonce is 16 random bytes, base64, per response. `/docs`,
`/redoc` and `/openapi.json`, when enabled (item 10), receive the Swagger
CSP (`script-src 'self' cdn.jsdelivr.net 'unsafe-inline'`) on those paths
only.

Tests: header assertions for a report response (nonce present in both
header and body, no `unsafe-inline`), for a JSON route, and for `/docs` in
debug.

## 10. L4, L9, L12 — small production defaults

- L4: `docs_url`, `redoc_url`, `openapi_url` are `None` unless
  `settings.debug`. The rate-limit whitelist entries for them go with it.
- L9: `docker/Dockerfile.backend` copies `ghcr.io/astral-sh/uv:0.11.28`
  (the version in use), not `latest`.
- L12: auth logs print `email_hash=<first 12 hex of sha256(lowercased
  email)>` instead of the address. Audit rows are unchanged.

Tests: app factory test for docs routes in both modes; log capture asserts
no `@` in auth log lines.

## 11. L13, L14, L15 — enrichment scope, Ghidra switch failure, report failure

- L13 (`src/maljan/enrichment/orchestrator.py`): `_is_public_fqdn(name)`
  rejects IP literals, single-label names, and the special-use suffixes
  `.local .localhost .internal .lan .home .corp .intranet .test .example
  .invalid .onion .arpa`. `_enrich_domains` skips those the way
  `_enrich_ips` skips private addresses, counting them in the completion log.
- L14 (`src/maljan/analysis/function_hash_attribution.py`): a failure of the
  program switch or `run_analysis` logs a `warning` with the exception type
  and returns `[]`; hashing a binary that may not be the current one is the
  outcome the file's own comment warns against.
- L15 (`src/maljan/pipeline/nodes.py`, `apps/api/app/worker/analysis_worker.py`):
  the report node returns `{"report_error": "<type>: <message>"}` when the
  deterministic build fails. The worker marks the job `failed` with that
  message when `malware_report` is missing or `report_error` is set, instead
  of completing with an empty report.

Tests: FQDN classifier table; attribution test with a raising switch; worker
lifecycle test with a report-less pipeline result → `failed`.

## 12. MCP sidecars receive a filtered environment

Files: new `src/maljan/agents/subprocess_env.py`; `static_analyst.py`,
`dynamic_analyst.py`, `network_analyst.py`, `judge_agent.py`.

`child_env(extra: Mapping[str, str] | None = None, *, allow: Iterable[str] = ())`
returns a dict with the base set `PATH HOME LANG LC_ALL LC_CTYPE TMPDIR TZ
JAVA_HOME PYTHONIOENCODING VIRTUAL_ENV` (when present), the explicit
`mcp.<server>.env` mapping, and only the named `allow` keys. The judge
agent, which spawns `threatintel-mcp`, passes
`allow=("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY")` because
`threatintel-mcp/server.py` reads exactly those; the static, dynamic and
network analysts pass none (`network-mcp/server.py` reads no environment).
Frontier, OpenAI, Anthropic, Gemini and database credentials never reach a
child process.

Tests: `child_env` unit tests with a populated fake environment; one test per
agent asserting the `env=` passed to the subprocess contains no `*_API_KEY`
except the allowed ones.

## 13. Analyst-parallelism tests run again

File: `tests/unit/pipeline/test_analyst_parallelism.py`.

The four tests read edges through LangGraph's public
`compiled.get_graph().edges` instead of a private attribute, so they stop
skipping. The fixture sets `llm.parallel_analysts = True` where a fan-out is
expected, and a fifth test asserts the default topology (`False`) chains the
analysts sequentially. A skip in this file is a failure from now on.

## 14. Semgrep in CI

Files: `.github/workflows/ci.yml`, new `.semgrepignore`.

Job `semgrep` (Python 3.13, `pip install semgrep==1.176.0`) runs
`semgrep scan --config p/python --config p/security-audit --error --metrics=off`
over `src/ apps/api/ network-mcp/ threatintel-mcp/ scripts/`.
`.semgrepignore` excludes `other/`, `tests/`, `apps/web/`, `data/`.
Existing `# nosemgrep` markers stay with their justifications; a new finding
is fixed or justified in the same line, never silenced globally. The job is
added to the required checks of `main` after the first green run.

## Out of scope

Rotating the two API keys the audit found in history (the operator's task),
the Postgres/MinIO development defaults beyond loopback binding, semgrep for
the frontend, and any change to evaluation results or the manuscript.

## Verification before merge

`make lint format-check typecheck`; `uv run pytest tests/`; `make facts`
byte-identical; `cd apps/web && npx tsc --noEmit && npm run lint && npm run
build`; the Playwright specs touched here on chromium and firefox; a live run
of the stack with the browser: login sets the cookie and no refresh token is
in storage, refresh works, logout clears, a job's WebSocket connects through
the subprotocol, a report HTML response carries the nonce CSP, `/system/status`
shows `throttle_degraded: false`, and stopping Redis flips it to `true` with
refresh answering 401.
