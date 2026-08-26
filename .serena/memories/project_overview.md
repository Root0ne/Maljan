# Project Overview

Maljan is a production-grade, multi-agent malware analysis framework powered by LangGraph.
It uses adversarial multi-agent debate (Static, Dynamic, Network LLM analysts) to classify
samples as Malware, Benign, or Suspicious, grounds the verdict in deterministic layers
(YARA, Sigma, LOLBin, DGA) + ATT&CK validation/autocorrect, and then assembles a comprehensive
`MalwareReport` (CTI-analyst-grade) plus a STIX 2.1 intelligence bundle with per-claim confidence.

> Memory last refreshed against code on 2026-07-05 (HEAD 4893280). Research/eval era is active —
> see `mem:evaluation_research` (NEW) and `mem:wave_history` for the June-2026 timeline.

## Key Facts
- **Version**: 1.0.0 (pyproject.toml). **Python**: >=3.13, <3.14. **Package Manager**: uv.
- **OS-support scope (2026-06-02): Windows + Linux ONLY.** Foreign samples (Mach-O/APK/IPA/
  DMG/PKG/.app/.scpt/.dex) are rejected at pipeline entry (`app.arun` raises
  `UnsupportedSampleError` before any sandbox submission). `Platform` Literal is now
  `"windows" | "linux" | "unknown"` (`reporting/models.py:91`). macOS/mobile Sigma rules and the
  web Mobile-ATT&CK resolver were removed.
- **Tests**: tests/unit = 79 modules (recursive, 11 subpackages), tests/integration = 6,
  tests/evaluation = 8 `test_*` scoring tests + **10 `eval_*` measurement harnesses** (not pytest).
- **Entry Points**: CLI (`maljan analyze` via `src/maljan/cli.py`), `MaljanApp` facade
  (`src/maljan/app.py`), FastAPI backend (`apps/api/`), Next.js frontend (`apps/web/`).
- **Containerization**: Docker Compose, 8 services (postgres, redis, qdrant, minio,
  ghidra-mcp, backend-api, backend-worker, frontend) at `docker/docker-compose.yml`.
- **Default LLM**: local OpenAI-compatible **llama-server** (ik_llama.cpp, Qwen3.6-35B-A3B,
  `-c 131072 -ctk q8_0`, f16 V-cache — see run_llama.ps1) at `host.docker.internal:8080/v1`.
  `LLM__OPENAI__DISABLE_THINKING=true` is REQUIRED for this local Qwen setup (suppresses `<think>`
  via `chat_template_kwargs.enable_thinking=false`; ~10x speedup). Ollama fallback; hosted
  OpenAI/Anthropic/Gemini supported.
- **Sandbox**: default `SANDBOX__BACKEND=mock`; live option = CAPEv2 in a remote Ubuntu VM via
  REST (`docs/CAPE2_REMOTE_VM_SETUP.md`), optional CAPE MCP over HTTP (streamable-http).

## Core Capabilities
1. **Multi-Agent Negotiation**: Static, Dynamic, Network analysts; parallel fan-out or sequential
   chain via `LLMConfig.parallel_analysts`. Mediator/Judge fan-in. Agents run on a single
   **persistent process-wide event loop** in a daemon thread (BUG-04/06/07 fix, 2026-06-23).
2. **Deterministic Layers**: YARA (0.90), Sigma (0.55), Dynamic (0.45), Static (0.35),
   Network (0.20); cross-layer multipliers 1.00->1.90. Plus **Layer-0 heuristic ISRs** injected in
   the judge node: DGA/IDN scoring (`network_dga`, T1568.002) and LOLBin signed-proxy-execution
   (`lolbin`, T1218.x, conf 0.78) — see `mem:extractors_enrichment_qa`.
3. **Platform-Aware Filtering (Wave 4)** + entry rejection (§1.8): cascade drops
   platform-incompatible techniques; Sigma/YARA filter rules by platform.
4. **ATT&CK autocorrect (§1.5)**: `ATTCKValidator.correct_isr_reports()` re-grounds LLM claim
   technique IDs pre-cascade; default **zero-regression mode** (fix invalid IDs only,
   `attck_autocorrect_swap_valid=False`). Index backend `attck_index_backend="hybrid"` (default):
   semantic (BGE-384) ranking + TF-IDF alignment gate; `"tfidf"`/`"semantic"` also available.
5. **Sycophancy Detection** + Devil's Advocate; **Adaptive Termination** (`ConsensusRouter`,
   window=3, std<0.04, mean>=0.70); mediation-error fast-path to judge (BUG-05).
6. **Long-Term Memory**: Qdrant default (`maljan_cases_v2`, fastembed BGE-small 384-dim) +
   **FunctionHashStore** (`maljan_function_hashes_v1`, exact-match function-hash attribution).
7. **Retrieval layers (config-gated, most OFF by default)**: family-feature RAG (U3),
   ATT&CK case-prior RAG (U2), TraceRAG function retrieval (`static_function_rag_top_k=0`),
   sink-reachability priority hint (ON), function-hash attribution (ON). A/B showed no measurable
   TTP gain for U2+U3 → kept gated OFF (see `mem:evaluation_research`).
8. **MCP Integration**: Ghidra MCP (HTTP :8089, pinned v5.6.0 + 2 local patches), CAPE MCP
   (stdio or HTTP/SSE via `MCP__CAPE__TRANSPORT`), Network MCP, ThreatIntel MCP.
9. **ISR**: `AgentISR` (claims + evidence_ref + confidence + technique_id + rule_platforms +
   dissent_items). See `mem:isr_lifecycle`.
10. **Judge Postprocess**: J-01/J-02/REP-01/REP-02 + **`enforce_bundle_integrity`** (2026-06-01:
    dedup/dangling-ref/empty-pattern sweeps) on the judge STIX bundle.
11. **Comprehensive Reporting**: `report_node` builds `MalwareReport` (now with
    `degraded_mode`/`degradation_reasons` fields + honest "DEGRADED RUN" banner) — see
    `mem:reporting_layer`. **Token ledger**: per-run `TokenLedger` on the container; snapshot
    into `RunSummary.tokens` (input/output/total, llm_calls).
12. **Threat-Intel Enrichment** (out-of-band ARQ): VirusTotal, AbuseIPDB, WHOIS, Qdrant attribution.
13. **Degraded-mode confidence cap (CONF-INFL-01)**: `overall_confidence` capped 0.60.

## Project Layout
- `src/maljan/`
  - `app.py`: MaljanApp facade (entry rejection -> sandbox submit -> platform inference -> graph).
  - `agents/`: BaseAnalyst (persistent loop, ReAct, view decomposition), Static/Dynamic/Network,
    Judge, registry, mcp_client (stdio+http+sse), judge_postprocess, _indicator_denylists.
  - `pipeline/`: builder, nodes (~1400 lines), routing, state, sycophancy_detector, mediation_models.
  - `analysis/`: yara_layer, sigma_layer, ttp_cascade, schema_pruner, chunk_merger, run_summary,
    function_summarizer, **attck_case_rag, family_feature_rag, function_hash_attribution,
    lolbin_layer, semantic_category, sink_reachability** (all NEW June 2026).
  - `core/`: container, config, exceptions (+`UnsupportedSampleError`), logger, paths, **token_ledger**.
  - `llm/`: registry + providers (openai provider: disable_thinking, repetition_penalty forwarding).
  - `loaders/`: file_loader, binary_chunker, pe_loader, sandbox_client, mock_sandbox_client,
    cape2_client, triage_client.
  - `memory/`: long_term_memory, qdrant_store, in_memory_store, embeddings, attck_index (TF-IDF),
    **semantic_attck_index, hybrid_attck_index (default), attck_case_index, family_fingerprint_index,
    function_index, function_hash_store** (NEW), attck_loader, attck_validator, ttp_validation.
  - `extractors/`: sample_identity (+`unsupported_os_reason`), pe_extractor, dynamic_extractor,
    network_extractor (+DGA/IDN scoring, `build_dga_isr`), persistence_extractor (+COM-hijack),
    capability_matrix, attribution.
  - `enrichment/`, `reporting/`, `qa/` (fp_linter), `parsers/`, `preprocessors/`, `schemas/`, `utils/`.
- `apps/api/`: FastAPI + async SQLAlchemy + ARQ workers + alembic (still 5 migrations).
- `apps/web/`: Next.js 16 + React 19 + Tailwind 4; **16 nav tabs** (TTPS merged into ATT&CK at
  `/capabilities`, Enterprise-only matrix). See `mem:frontend_web_app`.
- `tests/`, `docs/` (CAPE2_REMOTE_VM_SETUP.md, academic-article/findings-log.md — the canonical
  research log; operator-runbook.md DELETED 2026-06-01), `scripts/` (+build_attck_case_kb.py,
  build_family_feature_kb.py), `external/` (CAPEv2 pinned 976b3690, ghidra-mcp pinned v5.6.0),
  `data/` (vendored RAG catalogs; `data/samples/` gitignored live binaries).
