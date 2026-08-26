# Architecture Key Points

> Refreshed against code 2026-07-05. See also `mem:data_flow`, `mem:pipeline_deep_dive`,
> `mem:reporting_layer`, `mem:extractors_enrichment_qa`, `mem:api_infrastructure`,
> `mem:evaluation_research`.

## 0. Entry Point — MaljanApp Facade (`src/maljan/app.py`)
- `MaljanApp(config, mock, samples_dir)` builds `ServiceContainer`, compiles LangGraph.
- `arun(...)` order: **(1) OS-scope rejection** — `unsupported_os_reason(sample_path)`
  (`extractors/sample_identity.py:214`, magic-bytes-first + foreign-extension fallback) raises
  `UnsupportedSampleError` (app.py:209-217) BEFORE sandbox submit; only definitely-foreign
  samples rejected. (2) sandbox submit (Triage/CAPE/Mock). (3) platform inference ->
  `state["platform"]` in {windows, linux, unknown}.

## 1. LangGraph Pipeline (`pipeline/builder.py`)
- Unchanged topology: START -> analysts (parallel fan-out when `LLMConfig.parallel_analysts=True`,
  else sequential chain) -> negotiation -> [revision loop] -> judge -> report -> END.
- Routing (`pipeline/routing.py`) priority: hard-limit -> **mediation-error fast-path (BUG-05:
  last discussion finding starts with "[ERROR] Mediation" -> judge)** -> sycophancy+consensus
  override -> genuine consensus -> adaptive termination (window=3, std<0.04, mean>=0.70) -> revision.

## 2. Agent Runtime (`agents/base_agent.py`) — reworked 2026-06-23
- **Persistent agent event loop** (BUG-04/06/07): module-level `_AGENT_LOOP` daemon thread
  (`maljan-agent-loop`); all agent coroutines via `run_coroutine_threadsafe` +
  `future.result(timeout+30)`. Replaces per-call loop create/close (which orphaned httpx pools).
- BUG-04: 3-attempt `APIConnectionError` retry (2^n backoff) inside ReAct `_invoke()`; provider
  `max_retries=0`; genuine `asyncio.TimeoutError` NOT retried.
- BUG-07: static placeholder handling — meta-claim regex widened; meta-claims dropped from ISR.
- **Forced final synthesis** (f261ef9): when ReAct exhausts steps with empty/`need more steps`
  content and tool_call_count>0, one extra no-tools invoke to synthesize (`_force_final_synthesis`).
- ReAct budgets (root `Settings`): `react_agent_timeout=180`, overrides
  `{static:1200, judge:600, dynamic:600, network:300}`; `react_agent_max_steps=10`, overrides
  `{static:40}` (`react_agent_max_steps_overrides`); tool_call_budget=20 (soft warn).
- **View decomposition** (config-gated, default OFF): `analyze_isr_views` (facet mode — N
  concurrent sub-prompts, AppPoet-style, equal budget `total_max_tokens // n_views`) and
  `analyze_isr_tiered` (tier mode — LAMD-style sequential facts->behaviour->semantics). Config:
  `LLM__VIEW_DECOMPOSITION_VIEWS=0`, `view_decomposition_mode="facet"|"tier"`, `expert_max_tokens`.
  Optional grounding gate `use_claim_consistency_gate=False` (`_claim_grounded_in_evidence`,
  overlap>=0.34).
- **StaticAnalyst pre-passes** (fail-safe, HTTP Ghidra only): sink-reachability priority hint
  (`analysis/sink_reachability.py`, ON, `use_sink_reachability=True`, max_funcs=12); function-hash
  attribution prior (`analysis/function_hash_attribution.py`, ON); family-feature RAG hint (OFF);
  ATT&CK case RAG hint (OFF). Tool allowlist expanded 12->20; prompt has ADVANCED TOOLS +
  VERIFICATION DISCIPLINE sections (>=0.8 confidence requires emulate_function/analyze_dataflow
  falsification; single-locus caps 0.7).
- **JudgeAgent**: NOT registered; `mediate()` + `give_verdict()` (runs postprocess +
  `enforce_bundle_integrity`). `LLMConfig.judge_max_tokens=8192` caps runaway decode.
- MCP client (`agents/mcp_client.py`): transports `stdio` (default) | `http`/`streamable-http` |
  `sse`; ctor kwargs `transport`, `http_url`, `http_headers`. DynamicAnalyst branches on
  `cfg.mcp.cape.transport`, Bearer token from `auth_token`, skips when url empty.

## 3. ISR & STIX Schemas
- `ClaimEvidence`: claim, evidence_ref, confidence, technique_id (`^T\d{4}(\.\d{3})?$`),
  `rule_platforms`. `AgentISR.domain`: "static"/"dynamic"/"network"/"yara"/"sigma" | str.
- Layer-0 heuristic ISRs use agent_ids `yara_layer`, `sigma_layer`, `network_dga`, `lolbin`.
- `AnalysisState` unchanged since May 30 (no new TypedDict fields). NOTE: judge returns an
  UNDECLARED state key `function_hash_matches` consumed by report_node (works via LangGraph
  dict-merge; not in the TypedDict).

## 4. Deterministic Analysis Layers
- `LAYER_WEIGHTS` (ttp_cascade.py:54): yara .90, sigma .55, dynamic .45, static .35, network .20;
  default .25; multipliers {1:1.00, 2:1.25, 3:1.50, 4:1.75, 5:1.90}. No lolbin/dga weights —
  lolbin ISR uses domain="dynamic", DGA uses domain="network".
- **Layer-0 deterministic surfacing (judge node, 2026-06-03)**: `build_dga_isr` (network_extractor;
  T1568.002; blend of normalised Shannon entropy + bigram rarity + digit ratio, threshold 0.55,
  min label len 10; IDN/punycode homograph checked first) and `build_lolbin_isr` (lolbin_layer;
  regsvr32->T1218.010, rundll32->T1218.011, mshta->T1218.005; requires suspicious indicator;
  conf 0.78; rule_platforms=["windows"]).
- **ATT&CK autocorrect (pre-cascade)**: `attck_validator.correct_isr_reports(...)` at nodes.py:700.
  `use_attck_autocorrect=True`; zero-regression default (`attck_autocorrect_swap_valid=False` —
  ablation showed swap_valid damages ~38% correct IDs to recover ~21%); min_alignment=0.08
  (TF-IDF scale). Layer-0 yara/sigma IDs skipped (rule-authoritative).
- Platform filter: `_MITRE_PLATFORM_MAP` now only windows/linux. Placeholder TTP denylist intact.
- `schema_pruner.infer_malware_category` (keyword) is default; alternative
  `analysis/semantic_category.py` `SemanticCategoryClassifier` via
  `PREPROCESSING__CATEGORY_INFERENCE_BACKEND` = "keyword"(default)|"semantic"|"hybrid".
  Eval: keyword 0.792 acc full-regime; semantic 0.376 (NEGATIVE); hybrid 0.812.

## 5. Memory / RAG (`src/maljan/memory/`)
- LTM: Qdrant default, `maljan_cases_v2`, fastembed BAAI/bge-small-en-v1.5 384-dim
  (`embeddings.py`, BoW fallback). InMemoryStore fallback.
- ATT&CK index family: `attck_index.py` (TF-IDF base) <- `semantic_attck_index.py`
  (dense BGE-384; fixes lexical failures like "AES" collision) <- `hybrid_attck_index.py`
  (**default backend**: semantic search/ranking + TF-IDF validate_and_score gate).
  Selector `attck_index_backend="hybrid"|"tfidf"|"semantic"`.
- `function_index.py` — TraceRAG per-sample ephemeral cosine index over decompiled chunks;
  `select_relevant_chunks`; gate `static_function_rag_top_k=0` (OFF), min_chunks=6.
- `family_fingerprint_index.py` — in-memory cosine index over family fingerprint texts; backs
  `analysis/family_feature_rag.py` (U3, OFF; catalog `data/family_fingerprints_v1.json`, top_k=5,
  min_score=0.3). Replaced the removed static-feature family classifier (b92f228).
- `attck_case_index.py` — in-memory cosine index over LTM-mined case texts; backs
  `analysis/attck_case_rag.py` (U2, OFF; corpus `data/attck_case_corpus_v1.json`, top_k=5,
  min_score=0.35, max_techniques=8).
- `function_hash_store.py` — Qdrant EXACT-match store (`maljan_function_hashes_v1`, 1-dim dummy
  vector, payload-filtered scrolls); backs function-hash attribution (ON; min_instructions=8,
  max_matches=8; judge write-side upserts under final family, static analyst read-side hint).

## 6. LLM & Config (`core/config.py`)
- Providers: openai/anthropic/ollama/gemini. OpenAI provider extras (base_url only):
  `disable_thinking` -> `chat_template_kwargs.enable_thinking=false`;
  `repetition_penalty` (default 1.0; ~1.15 breaks local-model ID-recall loops) ->
  `repeat_penalty` + `repetition_penalty` in extra_body.
- Env nesting: `__` delimiter, NO prefix (e.g. `PREPROCESSING__USE_FAMILY_FEATURE_RAG=true`).
- `PreprocessingConfig` holds most new gates (RAG toggles, sink-reachability, function-hash,
  category backend, attck autocorrect/backend, static_function_rag_*).
- `SandboxConfig`: backend mock|cape2|triage; cape2_base_url/api_token/timeout(300)/poll(10) —
  remote-VM docs recommend 1200/15. `MCPConfig`: ghidra + cape, each `MCPServerConfig`
  (enabled, transport stdio|http, command/args/env, url/auth_token).
- **TokenLedger** (`core/token_ledger.py`): one per run on container (`get_token_ledger()`),
  injected onto agents/judge; `record_response_usage` prefers usage_metadata, else len//4
  estimate; snapshot -> `RunSummary.tokens` (judge node, nodes.py:883).

## 7. API / Worker / Infrastructure
- See `mem:api_infrastructure`. ARQ analysis worker: `max_jobs=1`, `job_timeout=3600`,
  `max_tries=1` (memory before 2026-07 said 2/1800 — outdated). 5 alembic migrations, 8 Docker
  services (all unchanged since May).
