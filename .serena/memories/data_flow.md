# Data Flow: How a Sample Traverses the Pipeline

> Refreshed 2026-05-30. Adds platform inference (Phase 0), the report node (Phase 6), and the
> out-of-band enrichment task. See `mem:reporting_layer`, `mem:extractors_enrichment_qa`.

## Phase 0: Initialization (`MaljanApp`)
1. `MaljanApp.__init__` creates `ServiceContainer` (AgentRegistry + ParserRegistry auto-discovery).
2. **Platform inference**: from sample magic bytes (-> sandbox hints -> MIME) compute `file_type`
   + canonical `platform`; seed `state["file_type"]`, `state["platform"]` (Wave 4).
3. **Sandbox submit (pre-pipeline)**: `_submit_to_sandbox()` (Triage/CAPE/Mock) ->
   `state["sandbox_report"]` (+ `state["sandbox_cti"]` for Triage). Graceful: None on failure.
4. `build_graph(container)` compiles the LangGraph (parallel or sequential analyst topology).

## Phase 1: Analyst fan-out (parallel) or chain (sequential)
For each registered agent, `make_analyst_node(name, container)`:
1. `container.load_chunked(file_hash, name)` -> parse sample -> `BinaryChunker` `TextChunk` list
   (`max_tokens_per_chunk=6000`, `overlap_tokens=200`, `skip_if_fits=True`).
2. Single chunk -> `agent.safe_analyze_isr(chunk.content)`. Multi-chunk ->
   `agent.safe_analyze_isr_chunked(chunks)` + `merge_chunk_isrs()`.
3. Returns `{"reports": {name: text}, "isr_reports": {name: AgentISR}}`.

## Phase 2: Fan-in + Negotiation (`make_negotiation_node`)
1. Collect ISRs; `detect_sycophancy(current_isrs)` (cosine vs previous round).
2. `JudgeAgent.mediate(reports, history, isr_reports)` -> `MediatorVerdict` (contradictions,
   resolution_summary, confidence); fallback `_fallback_mediate()` regex.
3. `mean_conf` across ISRs -> `confidence_history`. Returns `iteration_count+1`, `is_consensus`
   (confidence >= 0.85), `sycophancy_detected`, histories.

## Phase 3: Routing (`ConsensusRouter.should_continue`)
1. `iteration >= max_iterations` -> judge (hard limit).
2. `sycophancy_detected AND consensus` -> revision (override premature consensus).
3. `consensus AND no sycophancy` -> judge.
4. `is_confidence_stable` (last 3: std<0.04 AND mean>=0.70) -> judge.
5. else -> revision.

## Phase 4: Revision (`make_revision_node`)
- Latest mediator feedback + `build_revision_directive(syco, feedback)` (Devil's Advocate when sycophancy).
- Per agent: `_build_revision_context()` (single->raw text; multi->consolidated ISR summary, zero extra I/O)
  then `safe_revise_isr(...)`. Loops back to negotiation.

## Phase 5: Judge (`make_judge_node`) — final verdict + STIX
1. Read `sample_platform = state["platform"] or "unknown"`.
2. **YARA scan** -> inject `isr_reports["yara_layer"]` (domain="yara").
3. **Sigma scan** -> inject `isr_reports["sigma_layer"]` (domain="sigma"). Both can platform-filter rules.
4. **TTP cascade**: `TTPCascadeEngine().compute(isr_reports, sample_platform=...)` (drops platform-mismatched).
5. Pre-cascade filter counters; ATT&CK validation (graceful skip).
6. **LTM retrieve** (graceful skip); build evidence corpus (`judge_postprocess.build_evidence_corpus`).
7. Extract sandbox CTI block.
8. `JudgeAgent.give_verdict(...)` -> structured Bundle; internally runs `postprocess_judge_bundle`
   (J-01 UUID rewrite, J-02 hallucinated-IOC dropout, REP-01 MITRE ref backfill, REP-02 cascade-orphan
   attack-pattern dropout) BEFORE Bundle validation.
9. Decision from bundle (`type=malware` -> "Malware", else "Suspicious").
10. **Degradation signals (CONF-INFL-01)**: set `degraded_mode` + `degradation_reasons` when TTPs exist
    but no LLM analyst corroboration (or `[ERROR]` reports).
11. `RunSummaryBuilder` -> `run_summary` (incl. cascade `platform_filter_summary`).
12. Persist `StoredCase` to LTM if quality gate passes.
13. Returns `final_decision`, `judge_report`, `stix_output`, `run_summary`, `degraded_mode`, `degradation_reasons`.

## Phase 6: Report (`make_report_node`) — only when `config.reporting.enabled`
1. Feature-flag gate (returns `{}` when disabled -> consumers fall back to judge_report/stix_output).
2. Re-run cascade with the same `sample_platform` (keeps report consistent with verdict).
3. Derive `overall_confidence` (confidence_history[-1] or run_summary); **cap at 0.60 when degraded** (CONF-INFL-01).
4. Infer `malware_category` (CAT-PERSIST-01: WARNING + coerce to str so DB field lands).
5. `MalwareReportBuilder.build_deterministic()` runs all extractors (identity/static/dynamic/network/
   persistence/capability_matrix/severity/attribution); `sandbox_cti` folds in Triage network IOCs (W10-NET-01).
6. `NarrativeAgent.generate(report)` (LLM; structured-output then manual-parse fallback) -> `apply_narrative`,
   else `apply_fallback_narrative` (deterministic template).
7. `attach_detection_signatures()` (YARA/Sigma/Suricata, gated by family_grounded + platform).
8. `MarkdownRenderer().render()` -> `malware_report_markdown`; `ExtendedSTIXRenderer().render(report, base_bundle)`
   -> `stix_bundle_extended` (+ `x_maljan_cti`).
9. `qa/fp_linter.lint_report(report, platform)` -> `fp_warnings` merged into `run_summary`.
10. Returns `malware_report`, `malware_report_markdown`, `stix_bundle_extended`, updated `run_summary`.

## Post-verdict (out-of-band): Threat-Intel Enrichment
- ARQ task `apps/api/app/worker/enrich_worker.py` (auto after report persist when
  `reporting.enrichment_async`, or manual `POST /reports/{id}/enrich`):
  `enrich_malware_report()` fills `network.domains[].reputation` + `network.ips[].{reputation,asn,geo}`
  via VirusTotal/AbuseIPDB/WHOIS, plus Qdrant `populate_similar_samples`. Idempotent; fail-safe.
