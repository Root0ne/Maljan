# Maljan Project Analysis Report

> Comprehensive architectural and code-quality analysis. Refreshed against code on 2026-05-30
> (active "Wave 10"). Cross-refs: `mem:architecture_key_points`, `mem:reporting_layer`,
> `mem:extractors_enrichment_qa`, `mem:wave_history`.

---

## 1. Project Overview
**Maljan** classifies samples (Malware/Benign/Suspicious) via adversarial multi-agent debate
(LangGraph), grounds verdicts with deterministic detection (YARA, Sigma) + ATT&CK validation,
and emits both a comprehensive `MalwareReport` and a STIX 2.1 bundle with per-claim confidence.

- Python 3.13 (`>=3.13, <3.14`); LangGraph >= 1.1.6; FastAPI; Next.js 16 / React 19 / Tailwind 4.
- PostgreSQL 16 (asyncpg) + Redis 7 (ARQ + PubSub) + MinIO (S3) + Qdrant (vectors).
- Default LLM = local OpenAI-compatible llama-server (Ollama fallback).

---

## 2. Architecture (current)

```
START
  ├─ static / dynamic / network analyst   (parallel fan-out OR sequential chain)
  └──────────────► negotiation ◄──── revision (loop)
                       │ [router: hard-limit / sycophancy / consensus / adaptive-std]
                     judge   (YARA+Sigma scan, platform-aware TTP cascade, ATT&CK validation,
                       │       schema pruning, LTM, STIX verdict + judge_postprocess, degraded flag)
                     report  (MalwareReport: extractors -> narrative LLM -> detection sigs ->
                       │       markdown + extended STIX -> fp_linter)  [if reporting.enabled]
                      END
post-verdict, out-of-band: enrich_worker (VirusTotal/AbuseIPDB/WHOIS/attribution) via ARQ
```

**Strengths**
- Dynamic graph from `AgentRegistry`; generic agent-keyed state dicts (zero schema migration to add agents).
- Builder runtime toggle `parallel_analysts` (hosted parallel vs local sequential).
- `MaljanApp` facade is the single composition root (CLI + ARQ worker).
- Reporting decoupled behind `config.reporting.enabled`; node short-circuits when disabled.
- Pervasive graceful degradation (YARA/Sigma/ATT&CK/LTM/cascade/sandbox/narrative/enrichment/extractors).

**Key patterns**: MaljanApp facade, ServiceContainer DI (lazy caches; `ATTCKValidator` singleton
with double-checked locking), AgentRegistry decorator, ISR exchange, heterogeneous ensemble,
adaptive termination, sycophancy detection, protocol-based extensibility, lazy `get_settings()` factory.

**Two config systems**: core engine `src/maljan/core/config.py` (nested Pydantic, `__` delimiter,
9 sections incl. new `reporting`) and API server `apps/api/app/config.py` (flat env vars).

---

## 3. Code Quality
- Strict mypy (`disallow_untyped_defs/incomplete_defs`, `warn_return_any`), Ruff 100col `E/F/I/W/UP/B`.
- Near-universal docstrings; rich audit-ID comments documenting fixes (see `mem:wave_history`).
- Async-first; tiktoken truncation; thread-isolated ReAct loop; `utils/json_cleaner` for LLM JSON recovery.
- New defensive layers: `judge_postprocess` (hallucinated-IOC dropout), `_indicator_denylists`,
  `qa/fp_linter` (C1-C6 structural FP checks), CONF-INFL-01 degraded-confidence cap.

---

## 4. Test Coverage
- `tests/unit/` ~58 modules, `tests/integration/` 6, `tests/evaluation/` 4 (TRAM + ATT&CK benchmarks).
- **Frontend E2E now exists**: `apps/web/e2e/` (Playwright: auth, dashboard, ws_reconnect) + `playwright.config.ts`.
- Remaining gap: facade-level `MaljanApp.run()/arun()` tests still light.

---

## 5. Security
- JWT auth + bcrypt; `api_keys` + `audit_log` tables; per-user scoping.
- **Rate limiting implemented**: `middleware/rate_limit_middleware.py` (Redis-backed, configurable + whitelist).
- **Security headers**: `middleware/security_headers_middleware.py` (CSP/X-Frame-Options/X-Content-Type-Options/
  Referrer-Policy/Permissions-Policy; HSTS on when not debug) — SEC-CORS-HEADERS-01.
- Auth throttle: `app/auth/throttle.py`. Enrichment clients enforce host-allowlist SSRF guards.
- `AUTH_DISABLED` dev bypass exists (seeds a dev admin) — must never run outside local dev.
- Concerns: default dev secrets in compose/.env.example (minioadmin, ghidra token, dev DB password).

---

## 6. Production Readiness
- Docker Compose 8 services; Alembic with **5 real migrations** (initial_schema -> add_malware_report ->
  fix_audit_resource_id_type -> multiuser_sample_dedup -> add_agent_finding_status). Auto-upgrade on
  startup is OFF by default (`run_migrations_on_startup`) to avoid multi-worker races.
- Two ARQ workers: `analysis_worker` (pipeline) + `enrich_worker` (threat-intel). WebSocket
  `/ws/analysis/{job_id}` live events via Redis PubSub.
- Observability: structured JSON logging (correlation_id/component/duration_ms), optional LangSmith,
  `RunSummary` aggregate (now includes `cascade.platform_filter_summary` + `fp_warnings`).

---

## 7. Resolved Since Last Analysis (were flagged as open issues)
- TIEF orphan weight: REMOVED from `LAYER_WEIGHTS` and from the ISR domain Literal.
- Rate limiting: IMPLEMENTED (middleware).
- Alembic: real migrations exist (no longer "in progress").
- TODO-1/TODO-B markers in nodes.py: GONE.
- Frontend E2E tests: ADDED (Playwright).
- Hardcoded paths: already addressed earlier via `core/paths.py`.

## 8. Remaining Improvement Areas
| Priority | Area | Note |
|----------|------|------|
| Medium | Facade tests | `MaljanApp.run()/arun()` still under-tested. |
| Low | Default dev secrets | Compose/.env.example ship placeholder creds. |
| Low | Config unification | Core (nested) + API (flat) duality remains. |
| Low | `mediation_models` location | Still in `pipeline/`, not `schemas/`. |
| Low | Mock ISR type leakage | `domain=agent_name` with `# type: ignore[arg-type]`. |

---

## 9. Conclusion
A well-architected, research-informed framework that has matured substantially: a new comprehensive
reporting layer (MalwareReport + narrative + detection signatures), platform-aware deterministic
filtering, defensive judge postprocessing, FP linting, rate limiting, security headers, and real DB
migrations. Most previously-flagged gaps are resolved. **Overall grade: A** (strong architecture;
minor production-hardening + facade-test gaps remain).
