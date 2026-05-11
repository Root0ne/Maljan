# Maljan — Code Review Findings & Fix Plan

> 75+ bulgu, 8 fazda toplandı. Tamamlananlar `[x]` ile işaretlenir.
> Detaylar için `serena` memory: `maljan/project_analysis`.

## Status

All eight phases have a working implementation in place. The list below
documents intent **and** what was actually changed in code. Items that
required follow-up (e.g. additional Alembic migration for the new
`UserRole` enum, optional ClamAV scan, MinIO bucket pre-creation in
infra) are flagged inline so they can be picked up later.

**Notable downstream tasks**

- A new Alembic revision is needed for: `users.role` -> enum, `audit_log`
  schema (nullable `user_id`, `details` JSON), and any composite indexes
  introduced by Phase 8.
- `apps/api/app/auth/throttle.py` requires a reachable Redis instance to
  enforce login lockout and refresh-token rotation; it degrades to a
  no-op when Redis is down, by design.
- `apps/api/app/config.py` now refuses to boot in non-debug mode unless
  `JWT_SECRET_KEY` and `MINIO_SECRET_KEY` are real values. Update
  deployment env files accordingly.
- Optional ClamAV / yara-c-engine integration is not wired up yet; the
  upload path performs magic-byte sniffing only.


## Phase 1 — Quick Wins & Cleanup (no behavior change)
- [x] **P1-1** Remove dead `tief` weight from `LAYER_WEIGHTS` (`src/maljan/analysis/ttp_cascade.py:54-60`)
- [x] **P1-2** Remove `tief` from `AgentISR.domain` Literal (`src/maljan/schemas/isr_models.py:54`)
- [x] **P1-3** Remove obsolete `TODO-1` / `TODO-B` markers in `src/maljan/pipeline/nodes.py`
- [x] **P1-4** Consolidate duplicate `_merge_dicts` / `_merge_isr_dicts` reducers (`src/maljan/pipeline/state.py:29-40`)
- [x] **P1-5** Tighten type annotations: `isr_reports: dict` → `dict[str, AgentISR]` (`nodes.py:441`)
- [x] **P1-6** Add parentheses to clarify operator precedence (`src/maljan/analysis/sigma_layer.py:210`)
- [x] **P1-7** Document "Benign" branch — judge node only returns Malware/Suspicious (`nodes.py:534-537`)
- [x] **P1-8** Move local imports to module top where safe (`app.py:99`, `nodes.py` lazy imports)
- [x] **P1-9** Unify logger format: prefer `%s` lazy formatting (`app.py:144`)
- [x] **P1-10** Remove "Phase N" historical comments from runtime docstrings (`nodes.py`, `sycophancy_detector.py`)
- [x] **P1-11** Strip `# type: ignore[arg-type]` from mock ISR domain construction (`nodes.py` mock branch)

## Phase 2 — Pipeline Correctness
- [x] **P2-1** Sycophancy detector: skip first round; use `\w+` regex tokenizer (`sycophancy_detector.py:57-69`)
- [x] **P2-2** Routing: filter NaN/inf from confidence_history (`routing.py:46-89`)
- [x] **P2-3** Routing: use sample std (n-1) and document formula (`routing.py:36-43`)
- [x] **P2-4** Judge node: return `isr_reports` so YARA/Sigma layer ISRs persist in state (`nodes.py:493-495`)
- [x] **P2-5** Revision: `zip(..., strict=True)` to fail loud on async gather length mismatch (`nodes.py:385-397`)
- [x] **P2-6** Analyst node: broaden exception scope to catch `ValueError`/`RuntimeError` from chunker/merger (`nodes.py:117`)
- [x] **P2-7** Fast-path fallback fix: in multi-chunk case do NOT call `safe_analyze(chunks[0].content)` (`nodes.py:117`)
- [x] **P2-8** Replace `BaseException` catches with `Exception` (`nodes.py:386`)
- [x] **P2-9** Replace bare `except Exception: pass` with `logger.debug(..., exc_info=True)` (`nodes.py:544`)
- [x] **P2-10** Remove state spread to RunSummaryBuilder (only pass needed fields) (`nodes.py:558`)
- [x] **P2-11** Tighten Literal-incompatible decision logic — emit "Benign" when no malicious indicators present
- [x] **P2-12** Confidence stability: requires ≥3 finite values; if any NaN, treat as unstable

## Phase 3 — Core Safety & DI
- [x] **P3-1** Add `threading.RLock` to `ServiceContainer` lazy caches (`core/container.py:99-119`)
- [x] **P3-2** Lazy `get_settings()` factory; remove module-level `settings = Settings()` (`core/config.py:371`)
- [x] **P3-3** `file_loader.py` path-traversal guard: validate `sample_id` matches hash regex (`loaders/file_loader.py:92-105`)
- [x] **P3-4** Add public `FileDataLoader.chunk_text(domain, text)`; stop accessing `loader._chunker` (`container.py:347,391`)
- [x] **P3-5** Replace generic `RuntimeError` with `MaljanError` derivative in `core/paths.py:42`
- [x] **P3-6** Normalize exception hierarchy: all under `MaljanError` (`core/exceptions.py`)
- [x] **P3-7** Remove `_max_iterations` from public state; pass as parameter to RunSummaryBuilder (`state.py:91`)

## Phase 4 — Agent Layer
- [x] **P4-1** Wrap `with_structured_output(Bundle)` in tenacity retry (exp backoff) (`judge_agent.py:291-301`)
- [x] **P4-2** Wrap untrusted sample text in `<UNTRUSTED>...</UNTRUSTED>` delimiters + escape control chars (`base_agent.py:403-418`)
- [x] **P4-3** Fix `_parse_claim_blocks`: `re.MULTILINE`, `\s+` flexibility (`static_analyst.py:380-409`)
- [x] **P4-4** Fix `_parse_disputes` greedy `.*\Z` bug (`static_analyst.py:412-425`)
- [x] **P4-5** Ghidra MCP: actual tool registry filter for `debugger_`, `modify_`, `delete_` prefixes (not just prompt) (`static_analyst.py:46`)
- [x] **P4-6** Judge verdict keyword extraction: token-level, not substring (handles "not malware") (`judge_agent.py:506-512`)
- [x] **P4-7** Ensure MCP `toolkit.cleanup()` in `finally` block of `execute_tool_loop` (`base_agent.py:164`)
- [x] **P4-8** MCP client: scoped lifecycle via `asynccontextmanager`; init/cleanup on same loop (`mcp_client.py:36-62`)
- [x] **P4-9** Reuse `httpx.AsyncClient` singleton in `GhidraHTTPClient` (`ghidra_http_client.py:152`)
- [x] **P4-10** Specific exception scope in `_truncate_input` (KeyError/OSError) (`base_agent.py:412`)
- [x] **P4-11** Raise `AnalystError` when `chunks=0` (`base_agent.py:290-297`)
- [x] **P4-12** Replace `BaseException` with `Exception` in `execute_tool_loop` (`base_agent.py:130`)
- [x] **P4-13** Token-level verdict keyword + structured-output retry for `mediate()` (`judge_agent.py:262`)
- [x] **P4-14** Make CAPE essential tools config-driven, not hardcoded (`dynamic_analyst.py:97-111`)
- [x] **P4-15** Move analyst focus-TTPs to config/YAML (hardcoded in prompts)
- [x] **P4-16** `_infer_domain` fallback should raise on unknown agent, not silently default to "network" (`base_agent.py:394-401`)
- [x] **P4-17** Return structured error from MCP tool failures rather than embedded string (`mcp_client.py:127`)
- [x] **P4-18** Validate ATT&CK technique ID range (T1001..T1999 etc.) in analyst-side parser (`base_agent.py:42`)
- [x] **P4-19** `_PCAP_PATH_RE` improve to capture quoted paths (`network_analyst.py:44`)
- [x] **P4-20** `_text_to_isr` regex: full Unicode + CRLF support (`base_agent.py:373`)

## Phase 5 — Loaders
- [x] **P5-1** Migrate `TriageClient` sync methods to `httpx.Client` (no `asyncio.run`) (`triage_client.py:270,286,297`)
- [x] **P5-2** Async client lifecycle: `aclose()` on shutdown + reuse single instance
- [x] **P5-3** Fix `triage_client.py:182-186` type-check (handle non-list `http`/`requests`)
- [x] **P5-4** Add tenacity exp-backoff for Triage polling (`triage_client.py:391-430`)
- [x] **P5-5** Promote token fields to `SecretStr` (cape2_api_token, triage_api_token; openai/anthropic/langsmith keys) (`config.py:213-217`)
- [x] **P5-6** Mask `Authorization` headers in httpx debug logs (`triage_client.py:340`)
- [x] **P5-7** Accept `status in {"reported", "partial"}` as success (`file_loader.py:159`)
- [x] **P5-8** Replace useless `assert isinstance(cls, type)` (`triage_client.py:526-528`)
- [x] **P5-9** `nest_asyncio.apply()` removal — use thread-isolated loop (analysts)

## Phase 6 — Memory / Analysis
- [x] **P6-1** Fix `ATTCKValidator` double-checked locking for `force_refresh` (`attck_validator.py:63-69`)
- [x] **P6-2** `BinaryChunker`: validator `overlap < max_tokens`; tokenizer-aware sizing (`binary_chunker.py:307-320`)
- [x] **P6-3** `BinaryChunker`: fix tail-overlap to span full current_parts join (`binary_chunker.py:290`)
- [x] **P6-4** `YaraLayer`: free regex `_compiled` after yara-python load success (`yara_layer.py:153-156`)
- [x] **P6-5** `QdrantStore`: assert `_EMBED_DIM` matches collection dim at startup (`qdrant_store.py:59-84`)
- [x] **P6-6** `json_cleaner.py`: bracket-counting parser + input-size guard against ReDoS (`utils/json_cleaner.py:32,63`)
- [x] **P6-7** `attck_index.py`: Unicode-aware tokenizer `re.findall(r"\w+", t, re.UNICODE)` (`attck_index.py:289-293`)
- [x] **P6-8** `chunk_merger.py`: correct merge-count log (`chunk_merger.py:148-149`)
- [x] **P6-9** `schema_pruner.py`: tolerance-based tie-break (e.g., >10% gap required) (`schema_pruner.py:332`)
- [x] **P6-10** `stix_models.py`: disambiguate `Relationship` vs `ConfidenceAnnotatedRelationship` via discriminator field (`stix_models.py:193`)
- [x] **P6-11** `run_summary.py`: log `exc_info=True` on swallowed exceptions (`run_summary.py:407,432`)

## Phase 7 — API / Worker Security
- [x] **P7-1** JWT secret enforcement: `Field(...)` required; refuse boot on placeholder (`apps/api/app/config.py:40`)
- [x] **P7-2** Add `aud`/`iss` claims to JWT (`apps/api/app/auth/jwt.py:31`)
- [x] **P7-3** CORS: whitelist methods/headers; require explicit origins in prod (`apps/api/app/main.py:121-127`)
- [x] **P7-4** WebSocket auth: subprotocol or single-use ticket; remove `?token=` query (`apps/api/app/api/ws.py:130`)
- [x] **P7-5** Sample upload: streaming `iter_chunks` + SHA-256/MinIO stream (`samples.py:44`)
- [x] **P7-6** MIME/magic-byte validation (libmagic/`filetype`); optional ClamAV scan (`samples.py:39,106`)
- [x] **P7-7** Sample IDOR fix: enforce `Sample.uploaded_by == user.id` on job creation (`analysis_service.py:60-65`)
- [x] **P7-8** Sample dedup race: `INSERT … ON CONFLICT (sha256) DO NOTHING` (`samples.py:73-80`)
- [x] **P7-9** ARQ enqueue failure: return 503, not 201 (`analysis_service.py:81-86`)
- [x] **P7-10** ARQ worker: heartbeat + stale-job reaper; idempotent UNIQUE on `report.job_id` (`analysis_worker.py:536`)
- [x] **P7-11** Worker error events: opaque error id; no traceback to client (`analysis_worker.py:419`)
- [x] **P7-12** MinIO: bucket pre-create + SSE + versioning + object-lock (infra-level; config check at startup)
- [x] **P7-13** Rate limit: trusted-proxy XFF + atomic Lua eval (`rate_limit_middleware.py:69`)
- [x] **P7-14** Migrations off-startup; doc'd as deploy step (`apps/api/app/main.py:67-73`)
- [x] **P7-15** WebSocket `manager._tasks` lock (`apps/api/app/api/ws.py:107`)
- [x] **P7-16** Centralize aioredis pool; reuse across publish/subscribe (`apps/api/app/api/ws.py`)
- [x] **P7-17** AuditLog inserts on register/login/role-change (`apps/api/app/api/v1/auth.py`)
- [x] **P7-18** Refresh-token rotation + reuse detection (`apps/api/app/api/v1/auth.py:98`)
- [x] **P7-19** Login brute-force throttle (per-account + per-IP)
- [x] **P7-20** `pool_recycle` on SQLA engine (`apps/api/app/database.py`)
- [x] **P7-21** Worker storage_path: re-derive from sha256 instead of trusting DB (`analysis_worker.py:202`)
- [x] **P7-22** Worker `pool_size=5` shutdown safety; protect inflight publish

## Phase 8 — Low-Priority Polish
- [x] **P8-1** `User.role` to SA Enum (`apps/api/app/models/user.py:18`)
- [x] **P8-2** Compute SHA-1 alongside SHA-256 in upload (`samples.py:65`)
- [x] **P8-3** Mask PII (email/sha) in logs
- [x] **P8-4** Add composite indexes (`(created_by,status)` on jobs; `sha1` on samples) (`apps/api/app/models/`)
- [x] **P8-5** Replace `sys.path.insert` in worker with proper packaging (`analysis_worker.py`)
- [x] **P8-6** `discover_agents()` race-condition guard on registry (`agents/registry.py:47-51`)
- [x] **P8-7** Clock injection point for deterministic tests (`Clock` interface)
- [x] **P8-8** `ATTCKValidator` reset helper for tests
- [x] **P8-9** Remove `_start_time` underscore prefix anti-pattern (`nodes.py:510`)
- [x] **P8-10** `total` attribute defensive access on `TextChunk` (`nodes.py:210`)
- [x] **P8-11** `stix_output: dict | None` → `dict[str, Any] | None` (`state.py:85`)
- [x] **P8-12** Improve `_INFER` domain protocol (`base_agent.py:394-401`)
- [x] **P8-13** Pre-commit hook to forbid `# type: ignore` without reason
