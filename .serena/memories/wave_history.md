# Wave / Faz History & Audit-ID Convention

> Written 2026-05-30. Explains the dated comments and audit IDs scattered throughout the code, so
> future readers can decode references like "Wave 4 (2026-05-28)" or "CONF-INFL-01".

## Two parallel naming schemes
- **Faz N** ("Phase" in Turkish) — feature build-out phases of the comprehensive reporting effort:
  - Faz 2 = report_node + deterministic `MalwareReport` build.
  - Faz 3 = NarrativeAgent LLM round.
  - Faz 4 = auto-generated detection signatures (YARA/Sigma/Suricata).
  - Faz 5 = comprehensive report API endpoints (`/reports/{id}/full|markdown|iocs|signatures`).
  - Faz 6 = post-verdict threat-intel enrichment (ARQ).
  - (Phase 5 also refers to the long-term-memory/RAG subsystem; Phase 8 = heterogeneous ensemble.)
- **Wave N** — audit/fix/hardening cycles (each Wave is a dated batch of fixes), currently up to
  **Wave 10 (2026-05-30, the latest commits)**.

## Wave timeline (high-level)
- **Wave 4 (2026-05-28)** — platform-aware everything: `state["file_type"]`/`platform`,
  `ClaimEvidence.rule_platforms`, cascade `sample_platform` drop + `MOBILE_ENTERPRISE_OVERLAP`,
  indicator denylists (J-02), Sigma/YARA family+platform gates. Trigger: 2026-05-23 zararli.apk
  mapped Windows TTPs onto an APK.
- **Wave 5 (2026-05-28)** — HANG-01: single-slot llama-server analyst queue contention -> per-agent
  timeout bumps.
- **Wave 6 (2026-05-28)** — GHIDRA-DELIVERY-01: `state["static_sample_path"]` container path for Ghidra MCP.
- **Wave 7 / 7.5 (2026-05-28)** — THROUGHPUT-01/02: `LLMConfig.parallel_analysts` toggle (parallel vs
  sequential analyst topology); static analyst timeout to 1200s.
- **Wave 9 (2026-05-29)** — Linux ELF support (ELF persistence, ELF audit), REP-02 cascade-orphan
  attack-pattern dropout, `MAX_TOTAL_INDICATORS=15`, markdown `_safe_section`, fp_linter into
  run_summary, HOTFIX-08 (absolute upload_temp_dir), HOTFIX-09 (fp_warnings into state.run_summary),
  YARA gate mirror, SHIP-07 SUMMARY tab FP banner.
- **Wave 10 (2026-05-30, latest)** — W10-NET-01 (fold Triage SandboxCTI into MalwareReport.network),
  W10-TTP-02 (Mobile ATT&CK tactic resolver on TTPS tab), W10-OBS-03 (surface platform_filter_summary
  on ATT&CK tab), W10-LLM-05 (bump llama-server context to 32k), W10-ENV-04 (operator runbook),
  W10-LINT-07 (ESLint v9 flat config) + W10-LINT-DEBT-01/02.

## Audit-ID convention
Fixes carry stable IDs in code comments + commit messages so a regression can be traced to its audit.
Examples seen in code:
- `CONF-INFL-01` (2026-05-19) — degraded-mode confidence cap (0.60) when TTPs lack LLM corroboration.
- `CAT-PERSIST-01` (2026-05-19) — malware_category must coerce to str so the DB column lands.
- `SIG-T0000-01` (2026-05-19) — placeholder TTP (T0000) leak guard in the cascade.
- `PERF-STATIC-ANALYST-LATENCY-01` (2026-05-19) — ReAct tool-call budget warning.
- `SEC-CORS-HEADERS-01` (2026-05-19) — security-headers middleware.
- `PIPE-ANA-01` — static-analyst zero-claim short-circuit guard.

## Where to look
- `docs/operator-runbook.md` is updated each Wave with operator gotchas (the canonical changelog-ish doc).
- `git log --oneline` shows the `feat/fix/chore(scope): Wave N <ID>` commit pattern.
