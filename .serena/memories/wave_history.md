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

## June 2026 — research/eval era (post-Wave-10)
After Wave 10 the Wave numbering stopped; work shifted to a research/evaluation cycle logged in
`docs/academic-article/findings-log.md` (§-numbered sections, entries tagged IMPLEMENTED/
EXPERIMENTAL/OBSERVED/HYPOTHESIS/NEGATIVE). See `mem:evaluation_research` for datasets, harnesses
and A/B results. Highlights (chronological):
- 2026-05-31..06-03: static-analyst verification discipline + advanced-tools prompt (0c56975),
  sink-reachability triage (90114d8), function-hash attribution (28b8514 — same commit DELETED
  `docs/operator-runbook.md`), semantic + hybrid ATT&CK index (81949bd/f2653e9), ATT&CK
  autocorrect zero-regression (6bb1c76), STIX `enforce_bundle_integrity` + degraded-run
  signaling (2a65842), signal-quality hardening (2ad2346), DGA/IDN + COM-hijack + deterministic
  technique surfacing (ff88307/09a3af3).
- 2026-06-02: **OS scope narrowed to Windows+Linux only** (dad0dc8/a5df055) — entry rejection
  `UnsupportedSampleError`, macOS/mobile Sigma rules removed, web mitre-mobile.ts deleted.
- 2026-06-04..06-08: view decomposition + equal-budget A/B (2f4bfbe/7fe581f), token ledger
  (8555f11), concept-drift eval (210 samples / 7 cohorts), judge_max_tokens cap (305018e),
  hint-ablation harness, static-vs-dynamic category backend (30da002).
- 2026-06-07: static-feature family classifier added (12e3277) and REMOVED same day (b92f228) —
  replaced by LLM-centric family-feature RAG (436a16c) + ATT&CK case-prior RAG (07b777f).
- 2026-06-08: MABEL + Ultimate-RAT-Collection dataset integration (30f2766/09ac1ae),
  leakage-free retrieval eval.
- 2026-06-21..23: family-RAG A/B (no measurable TTP gain -> RAGs stay OFF), llama-server
  stability (c7c0999: back to 131k ctx, f16 V-cache), live-UI audit -> DISABLE_THINKING pinned
  (577b954), **BUG-01..07 fix batch** (persistent agent loop e3a3685, per-agent max-steps
  0ffdfd9, forced final synthesis f261ef9, mediation-error routing 5419409, job API
  sha256/filename d9ba6ba).
- 2026-06-24 (HEAD): CAPE MCP over HTTP + remote Ubuntu-VM deployment (e2647a8; d9068fb is an
  identical duplicate commit merged in 4893280).

## New audit-ID pattern: BUG-NN (June 2026)
- BUG-02 job API sample fields; BUG-04 httpx pool / connection-error retry; BUG-05 mediation-error
  routing; BUG-06 per-call event-loop churn; BUG-07 static placeholder parroting.

## Where to look
- `docs/operator-runbook.md` was DELETED (2026-06-01). Operator content now:
  `docs/CAPE2_REMOTE_VM_SETUP.md` (deployment) + `.env.example` (heavily annotated) +
  `docs/academic-article/findings-log.md` (canonical research changelog).
- `git log --oneline` shows the `feat/fix(scope): ...` pattern; audit IDs still appear in code.
