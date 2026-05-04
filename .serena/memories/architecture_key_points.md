# Architecture Key Points

## 1. LangGraph Pipeline
- **Builder**: `src/maljan/pipeline/builder.py::build_graph()` dynamically constructs graph from AgentRegistry.
- **Flow**: START -> parallel analyst fan-out -> fan-in to negotiation -> [revision loop] -> judge -> END.
- **Nodes** (`src/maljan/pipeline/nodes.py`):
  - `make_analyst_node(name, container)` — Chunked analysis (single or multi-chunk via `safe_analyze_isr_chunked`).
  - `make_negotiation_node()` — Collects ISRs, runs sycophancy detection, calls `JudgeAgent.mediate()`.
  - `make_revision_node()` — Per-agent revision with `_build_revision_context()` (chunk-aware grounding).
  - `make_judge_node()` — YARA/Sigma scan, TTP cascade, ATT&CK validation, LTM retrieval, schema pruning, STIX verdict, RunSummary, LTM persist.
- **Routing** (`src/maljan/pipeline/routing.py`):
  - `ConsensusRouter.should_continue(state)` — Decision priority: (1) hard limit, (2) sycophancy override, (3) genuine consensus, (4) adaptive termination, (5) default revision.
  - Adaptive termination: rolling std over `CONFIDENCE_WINDOW=3` with `CONVERGENCE_STD_THRESHOLD=0.04` and `MIN_CONVERGENCE_CONFIDENCE=0.70`.
- **Sycophancy Detector** (`src/maljan/pipeline/sycophancy_detector.py`):
  - Cosine similarity of claim bags-of-words across rounds.
  - If `> SYCOPHANCY_THRESHOLD`, injects `DEVIL_ADVOCATE_DIRECTIVE` into revision.

## 2. Dependency Injection & Caching
- `ServiceContainer` (`src/maljan/core/container.py`) is the composition root with lazy initialization.
- **Caches**: expert LLM, judge LLM, per-agent LLMs, agent instances, data `(sample_id, type)`, memory store, sandbox client, YARA layer, Sigma layer, function summarizer.
- **LangSmith**: `_configure_langsmith()` sets env vars when `langchain_tracing_v2=true`.
- Never use global state.

## 3. Agent System
- **Base Class**: `BaseAnalyst` (`src/maljan/agents/base_agent.py`)
  - Abstract: `analyze()`, `revise()`.
  - ISR: `analyze_isr()`, `revise_isr()` (default wraps text output).
  - Safe wrappers: `safe_analyze_isr()`, `safe_analyze_isr_chunked()`, `safe_revise_isr()`.
  - Token truncation via `tiktoken` (cl100k_base) with fallback char-based.
  - `execute_tool_loop()`: ReAct agent with thread-isolated event loop (avoids nest_asyncio/anyio issues).
  - `_text_to_isr()`: Best-effort sentence splitting into ClaimEvidence (fallback for non-ISR agents).
- **Specialized Agents**:
  - `StaticAnalyst` — Ghidra MCP (225 tools, debugger excluded). Domain: static. Focus: T1027, T1106, T1055, T1140.
  - `DynamicAnalyst` — CAPEv2 MCP (12 essential tools). Domain: dynamic. Focus: T1547, T1055, T1059, T1112.
  - `NetworkAnalyst` — Network MCP (PCAP/DNS/HTTP extraction). Domain: network. Focus: T1071, T1571, T1048, T1568. PCAP path detection heuristic (`_detect_pcap_path`).
  - `JudgeAgent` — NOT extending BaseAnalyst. `mediate()` for negotiation, `give_verdict()` for final STIX Bundle. ThreatIntel MCP.
- **Heterogeneous Model Ensemble**: Per-agent LLM overrides via `LLM__AGENTS__<NAME>__PROVIDER` and `LLM__AGENTS__<NAME>__MODEL`. Reduces echo-chamber risk.
- **Registry**: `AgentRegistry` auto-discovers via `@register_agent("name")` decorator.

## 4. ISR & STIX Schemas
- `AgentISR` (`src/maljan/schemas/isr_models.py`):
  - `claims: list[ClaimEvidence]` (claim, evidence_ref, confidence 0-1, technique_id with regex `^T\d{4}(\.\d{3})?$`).
  - `dissent_items`: Empty list + revision_round > 0 = active convergence signal.
  - `mean_confidence`: Average across claims.
  - `to_text_summary()`: Compact LLM-ready format with convergence signal annotation.
- `STIX Bundle` (`src/maljan/schemas/stix_models.py`):
  - `ConfidenceAnnotatedRelationship` extends Relationship with `x_maljan_confidence`, `x_maljan_evidence_basis` (controlled vocab), `x_maljan_contributing_agents`, `x_maljan_technique_id`.
  - `Bundle.mean_relationship_confidence()`: Aggregate confidence metric.
- `AnalysisState` (`src/maljan/pipeline/state.py`):
  - Generic dicts keyed by agent name: `reports`, `revised_reports`, `isr_reports`.
  - Reducers: `_merge_dicts`, `_merge_isr_dicts`, `operator.add` for lists.
  - Fields: `file_hash`, `file_name`, `reports`, `revised_reports`, `isr_reports`, `discussion_history`, `sycophancy_detected`, `confidence_history`, `iteration_count`, `is_consensus`, `final_decision`, `judge_report`, `stix_output`, `run_summary`, `_max_iterations`.

## 5. Deterministic Analysis Layers
- **YARA** (`src/maljan/analysis/yara_layer.py`): `YaraLayer.from_default_rules()` loads `data/yara_ttp_rules.yaml`. `scan(text)` -> `YaraMatch` -> `to_isr()` injects as domain="yara".
- **Sigma** (`src/maljan/analysis/sigma_layer.py`): `SigmaLayer.from_rules_dir()` loads rules. `scan_report_text()` -> `to_isr()` injects as domain="sigma".
- **TTP Cascade** (`src/maljan/analysis/ttp_cascade.py`):
  - `TTPCascadeEngine.compute(isr_reports)` — stateless, microseconds.
  - Layer weights: yara=0.90, tief=0.80, sigma=0.55, dynamic=0.45, static=0.35, network=0.20.
  - Cross-layer multipliers: 1 layer=1.00, 2=1.25, 3=1.50, 4=1.75, 5=1.90.
  - Outputs `CascadeSummary` with `corroborated_count`, `consensus_count`, `top_techniques()`.
- **TIEF** (`src/maljan/analysis/tief_classifier.py`): Threat intelligence enrichment classifier.
- **Schema Pruner** (`src/maljan/analysis/schema_pruner.py`): Keyword-weighted malware category inference (ransomware, RAT, dropper, worm, infostealer, unknown). No LLM call. Guides STIX object type focus in Judge prompt (CTI-GEN methodology).
- **Chunk Merger** (`src/maljan/analysis/chunk_merger.py`): Hierarchical ISR merge — technique_id dedup (keep highest confidence), text dedup, cap at MAX_MERGED_CLAIMS=20.
- **Function Summarizer** (`src/maljan/analysis/function_summarizer.py`): Optional LLM-based preprocessing.

## 6. Memory / RAG System
- **MemoryStore Protocol** (`src/maljan/memory/long_term_memory.py`): `store(case)`, `retrieve(query, top_k)`, `count()`, `clear()`. Runtime-checkable. Upsert by sample_id.
- **StoredCase**: `sample_id`, `summary_text` (dense keyword string for similarity), `technique_ids`, `malware_category`, `stix_bundle_json`, `created_at`.
- **QdrantStore** (`src/maljan/memory/qdrant_store.py`): Vector backend with sentence-transformer embeddings (`_EMBED_DIM`). Collection auto-creation.
- **InMemoryStore**: Fallback pure-Python cosine similarity.
- **ATT&CK Index** (`src/maljan/memory/attck_index.py`): Pure-Python TF-IDF over MITRE ATT&CK bundle (~9MB). `search(query, top_k)`, `validate_and_score(technique_id, evidence_text)`.
- **ATTCKValidator** (`src/maljan/memory/attck_validator.py`): Thread-safe singleton. Lazy init on first use. `validate_isr_reports()` returns `TTPValidationSummary` with hallucination rate. `HALLUCINATION_SCORE_THRESHOLD=0.05`.

## 7. LLM & Config Infrastructure
- **Provider Registry** (`src/maljan/llm/registry.py`): `LLMProviderRegistry` with `@register_provider` decorator. Auto-discovery of openai, anthropic, ollama, gemini.
- `build_model(role="expert"|"judge")` — temperature defaults: expert=0.1, judge=0.0.
- `build_model_for_agent(agent_name)` — checks `LLMConfig.agents` override.
- **Core Config** (`src/maljan/core/config.py`): Nested Pydantic with `__` delimiter. Sections: LLM (with per-agent overrides), Negotiation, Chunking, Memory, Sandbox, Analysis, Preprocessing, MCP.
- **API Config** (`apps/api/app/config.py`): Flat env vars (DATABASE_URL, REDIS_URL, JWT_SECRET_KEY).

## 8. API / Worker / Infrastructure
- **FastAPI** (`apps/api/app/main.py`): Factory pattern, lifespan (DB + Redis healthcheck), CORS, `RequestLoggingMiddleware`, routes under `/api/v1`, WebSocket, `/health`.
- **AnalysisService** (`apps/api/app/services/analysis_service.py`): Job lifecycle (create, get, list, cancel), ARQ enqueue, user stats (verdict distribution, avg duration).
- **ARQ Worker** (`apps/api/app/worker/analysis_worker.py`):
  - `run_analysis(ctx, job_id)`: Loads job -> runs `MaljanApp.arun()` -> saves `AnalysisReport` + `AgentFinding` -> publishes Redis PubSub events.
  - Events: `pipeline_started`, `agent_progress`, `phase_change`, `completed`, `error`, `cancelled`.
  - Max concurrent: 2 jobs. Timeout: 30 min. Max tries: 1.
- **Database**: PostgreSQL + asyncpg + SQLAlchemy 2.0. Tables: users, api_keys, samples, analysis_jobs, analysis_reports, agent_findings, audit_log.
- **Redis**: ARQ queue + PubSub for real-time events.
- **MinIO**: S3-compatible object storage for samples.
