# Architecture Key Points

> Refreshed against code 2026-05-30. See also `mem:data_flow`, `mem:pipeline_deep_dive`,
> `mem:reporting_layer`, `mem:extractors_enrichment_qa`, `mem:api_infrastructure`.

## 0. Entry Point — MaljanApp Facade (`src/maljan/app.py`)
- `MaljanApp(config, mock, samples_dir)` is the **composition root facade**: builds `ServiceContainer`,
  compiles the LangGraph via `build_graph()`.
- `run(...)` wraps `asyncio.run(self.arun(...))`. `arun(...)` is the canonical async entry (CLI + ARQ worker).
- **Platform inference** at bootstrap: infers `file_type` + canonical `platform` from the sample
  (magic bytes -> sandbox hints -> MIME) and seeds `state["platform"]` (Wave 4).
- `_submit_to_sandbox(sample_path)`: pre-pipeline sandbox submission (Triage/CAPE/Mock).
  Result -> `state["sandbox_report"]` (+ `state["sandbox_cti"]` for Triage). Graceful: None on failure.

## 1. LangGraph Pipeline (`pipeline/builder.py`)
- Discovers agents from `AgentRegistry`. Nodes: per-agent analyst, negotiation, revision, judge,
  and **report** (added only when `config.reporting.enabled`; node also self-short-circuits).
- **Analyst topology toggle** `LLMConfig.parallel_analysts`:
  - True -> parallel fan-out (START -> all analysts -> negotiation). Right for hosted multi-slot LLMs.
  - False -> sequential chain in registry order. Right for single-slot local llama-server (avoids queue contention).
- Flow: START -> analysts -> negotiation -> [revision loop] -> judge -> report -> END
  (or judge -> END when reporting disabled).
- Nodes (`pipeline/nodes.py`): `make_analyst_node`, `make_negotiation_node`, `make_revision_node`,
  `make_judge_node`, **`make_report_node`**.
- Routing (`pipeline/routing.py`): `ConsensusRouter.should_continue` priority:
  hard-limit -> sycophancy+consensus override -> genuine consensus -> adaptive termination
  (`CONVERGENCE_STD_THRESHOLD=0.04`, `MIN_CONVERGENCE_CONFIDENCE=0.70`, `CONFIDENCE_WINDOW=3`) -> revision.

## 2. Dependency Injection & Caching (`core/container.py`)
- `ServiceContainer` — lazy caches: expert/judge/per-agent LLMs, agents, data `(sample_id, type)`,
  memory store, sandbox client, YARA layer, Sigma layer, function summarizer, **narrative agent**.
- `_configure_langsmith()` sets env when `langchain_tracing_v2=true`.
- Config via lazy `get_settings()` factory (replaced import-time singleton for testability).

## 3. Agent System
- **Base**: `BaseAnalyst` (abstract `analyze`/`revise`; ISR variants `analyze_isr`/`revise_isr`;
  `safe_*` wrappers; tiktoken truncation; `execute_tool_loop()` ReAct in thread-isolated event loop).
  Per-agent ReAct timeouts: static=1200s, judge=600s, dynamic=600s, network=300s (config).
- **Specialized**: StaticAnalyst (Ghidra MCP), DynamicAnalyst (CAPEv2 MCP), NetworkAnalyst (Network MCP).
  Registered as exactly `{static, dynamic, network}` via `@register_agent`.
- **JudgeAgent**: NOT a BaseAnalyst, NOT registered. `mediate()` + `give_verdict()` (structured Bundle).
  `give_verdict()` runs `postprocess_judge_bundle()` (J-01/J-02/REP-01/REP-02) before Bundle validation.
- **Heterogeneous Ensemble**: per-agent LLM via `LLM__AGENTS__<NAME>__PROVIDER` / `__MODEL`.

## 4. ISR & STIX Schemas
- `ClaimEvidence` (`schemas/isr_models.py`): `claim`, `evidence_ref`, `confidence` (0-1),
  `technique_id` (`^T\d{4}(\.\d{3})?$`), **`rule_platforms: list[str] | None`** (Wave 4).
- `AgentISR`: `agent_id`, `domain`, `claims`, `dissent_items`, `revision_round`.
  **`domain` Literal is now `["static","dynamic","network","yara","sigma"] | str`** (TIEF removed; `| str` for extensibility).
- STIX Bundle (`schemas/stix_models.py`): `ConfidenceAnnotatedRelationship` with `x_maljan_*` fields.
  Extended SDOs (Identity/Indicator/ObservedData/Note/Report) added later by `ExtendedSTIXRenderer`.
- `MediatorVerdict` in `pipeline/mediation_models.py`.
- `AnalysisState` (`pipeline/state.py`): generic agent-keyed dicts + many scalar fields. See `mem:pipeline_deep_dive`
  for the full field table (includes Wave 4 `file_type`/`platform`, Wave 6 `static_sample_path`,
  reporting outputs `malware_report`/`malware_report_markdown`/`stix_bundle_extended`,
  `degraded_mode`/`degradation_reasons`, `sandbox_cti`).

## 5. Deterministic Analysis Layers
- **YARA** (`yara_layer.py`): `from_default_rules()` loads `data/yara_ttp_rules.yaml`; injects `domain="yara"`.
- **Sigma** (`sigma_layer.py`): 2946 rules under `data/sigma_rules/`; injects `domain="sigma"`.
- **TTP Cascade** (`ttp_cascade.py`): stateless. Weights yara=0.90, sigma=0.55, dynamic=0.45,
  static=0.35, network=0.20 (`DEFAULT_LAYER_WEIGHT=0.25`). Multipliers 1->1.00 .. 5->1.90.
  **NO tief weight.** Pre-filters invalid/placeholder TTPs (T0000/T0000.000/T9999/T1234).
  **Platform-aware (Wave 4)**: `compute(isr_reports, sample_platform=...)` drops platform-incompatible
  claims via `_is_claim_platform_compatible()` (source rule_platforms -> MITRE catalog ->
  `MOBILE_ENTERPRISE_OVERLAP`); records `CascadeSummary.dropped_by_platform`.
- **Schema Pruner** (`schema_pruner.py`): keyword-weighted -> ransomware/RAT/dropper/worm/infostealer/unknown.
- **Chunk Merger** (`chunk_merger.py`): technique dedup -> text dedup -> cap `MAX_MERGED_CLAIMS=20`.

## 6. Memory / RAG
- MemoryStore protocol (`store`/`retrieve`/`count`/`clear`), `StoredCase`.
- **Default backend = qdrant** (`MemoryConfig`), collection `maljan_cases_v2`. InMemoryStore fallback.
- **Embeddings** (`memory/embeddings.py`): fastembed BAAI/bge-small-en-v1.5 (384-dim) + BoW fallback;
  `encode()`/`cosine()`; shared by both stores. (Old era used 512-dim hash vectors in `maljan_cases`.)
- ATT&CK: `attck_loader` (bundle fetch+cache, exposes platforms), `attck_index` (TF-IDF),
  `attck_validator` (thread-safe singleton; hallucination rate), `ttp_validation` (Pydantic models).

## 7. Reporting, Extractors, Enrichment, QA (NEW subsystems)
- See `mem:reporting_layer` (MalwareReport, builder, narrative, detection signatures, renderers, report_node).
- See `mem:extractors_enrichment_qa` (extractors/, platform-aware filtering, enrichment ARQ task,
  fp_linter C1-C6, judge_postprocess, _indicator_denylists).

## 8. LLM & Config (`core/config.py`)
- Provider registry (`llm/registry.py`): openai/anthropic/ollama/gemini. `build_model(role=expert|judge)`
  (expert temp 0.1, judge 0.0); `build_model_for_agent(name)`.
- 9 nested sections: LLM (+ per-provider + `agents` + `parallel_analysts`), Negotiation
  (`max_iterations=5`, `consensus_threshold=0.85`), Chunking, Memory, Sandbox (rich Triage options),
  Analysis, Preprocessing, MCP (ghidra+cape), **Reporting**. Root: token limits, ReAct limits +
  per-agent timeout overrides, LangSmith, flat shortcut keys. Lazy `get_settings()` + `settings` proxy.

## 9. API / Worker / Infrastructure
- See `mem:api_infrastructure` for the full FastAPI/ARQ/DB/middleware breakdown. Highlights:
  middleware stack (logging -> rate-limit -> CORS -> security-headers), 2 ARQ workers
  (analysis + enrich), 5 alembic migrations, 8 Docker services.
