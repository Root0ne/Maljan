# Data Flow: How a Sample Traverses the Pipeline

> Refreshed 2026-07-05. Adds entry OS rejection, judge Layer-0 heuristics (DGA/LOLBin), ATT&CK
> autocorrect, function-hash attribution and RAG hints. See `mem:reporting_layer`,
> `mem:extractors_enrichment_qa`.

## Phase 0: Initialization (`MaljanApp.arun`)
1. **OS-scope rejection (2026-06-02)**: `unsupported_os_reason(sample_path)` — magic bytes
   (Mach-O/APK/IPA) then foreign extensions (.apk/.dex/.ipa/.dmg/.pkg/.app/.scpt) -> raise
   `UnsupportedSampleError` BEFORE sandbox submission. Only definitely-foreign samples rejected.
2. **Sandbox submit (pre-pipeline)**: `_submit_to_sandbox()` (Mock default / CAPE2 remote-VM REST /
   Triage) -> `state["sandbox_report"]` (+ `state["sandbox_cti"]` for Triage). Graceful None.
3. **Platform inference**: `file_type` + canonical `platform` (windows/linux/unknown only) ->
   `state["platform"]`.
4. `build_graph(container)` compiles LangGraph (parallel or sequential analyst topology).

## Phase 1: Analyst fan-out/chain
For each agent, `make_analyst_node(name, container)`:
1. `container.load_chunked(...)` -> `TextChunk` list (6000 tok/chunk, 200 overlap).
2. **Static multi-chunk + TraceRAG** (OFF by default): when `static_function_rag_top_k>0` and
   chunks > min(6), `memory/function_index.select_relevant_chunks()` keeps top-k
   behavior-relevant function chunks (nodes.py:233-248).
3. Single chunk -> `safe_analyze_isr`; **view decomposition** when
   `LLM__VIEW_DECOMPOSITION_VIEWS>=2` (facet=concurrent views / tier=sequential tiers,
   equal token budget); multi-chunk -> `safe_analyze_isr_chunked` + `merge_chunk_isrs()`.
4. StaticAnalyst pre-passes inject prompt hints: PRIORITY FUNCTIONS (sink-reachability, ON),
   ATTRIBUTION PRIOR (function-hash, ON), CANDIDATE FAMILIES (family RAG, OFF),
   CANDIDATE ATT&CK TECHNIQUES (case RAG, OFF).

## Phase 2: Fan-in + Negotiation (`make_negotiation_node`)
1. `detect_sycophancy`; `JudgeAgent.mediate()` -> `MediatorVerdict`.
2. **Fault isolation (bcfde63)**: any Exception -> degrade to no-consensus with
   `finding="[ERROR] Mediation timed out/failed: ..."` in discussion_history.
3. mean_conf -> `confidence_history`; consensus at >= 0.85.

## Phase 3: Routing (`ConsensusRouter.should_continue`)
1. `iteration >= max_iterations` -> judge.
2. **BUG-05**: last finding starts with "[ERROR] Mediation" -> judge (skip wasted revision).
3. sycophancy AND consensus -> revision. 4. consensus -> judge.
5. stable (last 3: std<0.04, mean>=0.70) -> judge. 6. else revision.

## Phase 4: Revision (`make_revision_node`)
- Mediator feedback + Devil's Advocate directive when sycophancy; per-agent
  `_build_revision_context()`; loops to negotiation.

## Phase 5: Judge (`make_judge_node`) — final verdict + STIX
1. Read `sample_platform`.
2. **YARA scan** -> `isr_reports["yara_layer"]`; **Sigma scan** -> `isr_reports["sigma_layer"]`.
3. **Layer-0 heuristics (2026-06-03)**: `build_dga_isr` -> `isr_reports["network_dga"]`
   (T1568.002, domain="network"); `build_lolbin_isr` -> `isr_reports["lolbin"]`
   (T1218.x, domain="dynamic", conf 0.78, windows-only). Fail-safe wrapped.
4. **ATT&CK autocorrect (§1.5)**: `correct_isr_reports()` re-grounds LLM claim technique IDs
   (zero-regression default: fix invalid only). Layer-0 yara/sigma skipped.
5. **TTP cascade**: platform-aware compute; pre-filter counters; ATT&CK validation.
6. LTM retrieve; evidence corpus; sandbox CTI block.
7. **Function-hash attribution**: read side -> `function_hash_matches` (undeclared state key);
   write side upserts current sample's function hashes under inferred family (family != UNKNOWN;
   gated on http Ghidra + qdrant + static_sample_path).
8. Family/case RAG mirrors (gated OFF) contribute report attribution rows.
9. `give_verdict()` -> Bundle; postprocess J-01/J-02/REP-01/REP-02 + `enforce_bundle_integrity`
   (dedup APs by technique, dedup indicators, drop empty patterns, sweep dangling refs).
10. **Fault isolation**: any judge Exception -> `final_decision="Suspicious"`,
    `judge_report="[ERROR] Judge failed (...)"`.
11. Degradation signals (CONF-INFL-01); `RunSummaryBuilder` (+ **token ledger snapshot** ->
    `run_summary.tokens`); LTM persist when quality gate passes.

## Phase 6: Report (`make_report_node`) — when `config.reporting.enabled`
1. Recompute cascade with same platform; `overall_confidence` (cap 0.60 when degraded).
2. Category via `PREPROCESSING__CATEGORY_INFERENCE_BACKEND` (keyword default).
3. `build_deterministic()` extractors (network extractor now emits dga_score/is_punycode/
   homograph_target per domain + ja3s_fingerprints; persistence adds com_hijacking/
   systemd_timer/xdg_autostart kinds).
4. `MalwareReport.degraded_mode` + `degradation_reasons` populated; markdown shows DEGRADED RUN
   banner; `family_grounded` honest "not determined" when no candidate.
5. Narrative (LLM/fallback) -> detection signatures -> markdown + extended STIX
   (integrity-enforced) -> fp_linter -> run_summary.

## Post-verdict (out-of-band): Threat-Intel Enrichment
- ARQ `enrich_worker.py` (auto or `POST /reports/{id}/enrich`): VirusTotal/AbuseIPDB/WHOIS +
  Qdrant `populate_similar_samples`. Idempotent; fail-safe.
