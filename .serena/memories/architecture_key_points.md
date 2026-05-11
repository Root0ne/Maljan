# Architecture Key Points

## 0. Entry Point — MaljanApp Facade (`src/maljan/app.py`)
- `MaljanApp(config, mock, samples_dir)` is the **composition root facade**.
- Constructs `ServiceContainer` and compiles the LangGraph via `build_graph()`.
- `run(file_hash, file_name, sample_path)` → wraps `asyncio.run(self.arun(...))`.
- `arun(...)` is the canonical async entry — used by CLI and ARQ worker (avoids "Event loop is closed" with google-genai).
- `_submit_to_sandbox(sample_path)`: pre-pipeline sandbox submission (Triage/CAPE/Mock). Result stored as `state["sandbox_report"]`. Tries `submit_and_wait`, falls back to manual `submit → wait_for_completion → SubmissionResult`. Graceful: returns None on failure.

## 1. LangGraph Pipeline
- **Builder**: `src/maljan/pipeline/builder.py::build_graph()` — discovers agents from `AgentRegistry`.
- **Flow**: START → parallel analyst fan-out → fan-in to negotiation → [revision loop] → judge → END.
- **Nodes** (`src/maljan/pipeline/nodes.py`):
  - `make_analyst_node(name, container)` — Chunked analysis (`safe_analyze_isr_chunked`).
  - `make_negotiation_node()` — Collects ISRs, sycophancy detection, `JudgeAgent.mediate()`.
  - `make_revision_node()` — Per-agent revision with `_build_revision_context()` chunk-aware grounding.
  - `make_judge_node()` — YARA/Sigma scan, TTP cascade, ATT&CK validation, LTM retrieval, schema pruning, STIX verdict, RunSummary, LTM persist.
- **Routing** (`src/maljan/pipeline/routing.py`): `ConsensusRouter.should_continue` priority: hard-limit → sycophancy override → genuine consensus → adaptive termination (`std<0.04`, `mean≥0.70`, window=3) → revision.
- **Sycophancy Detector**: cosine similarity on bag-of-words; > threshold → `DEVIL_ADVOCATE_DIRECTIVE`.

## 2. Dependency Injection & Caching
- `ServiceContainer` (`src/maljan/core/container.py`) — composition root with lazy init.
- Caches: expert LLM, judge LLM, per-agent LLMs, agents, data `(sample_id, type)`, memory store, sandbox client, YARA layer, Sigma layer, function summarizer.
- `_configure_langsmith()` sets env vars when `langchain_tracing_v2=true`.

## 3. Agent System
- **Base**: `BaseAnalyst` (abstract `analyze`, `revise`; ISR variants `analyze_isr`, `revise_isr`; safe wrappers `safe_*`; tiktoken truncation; `execute_tool_loop()` runs ReAct in thread-isolated event loop).
- **Specialized**:
  - `StaticAnalyst` — Ghidra MCP (225 tools, debugger excluded). T1027, T1106, T1055, T1140.
  - `DynamicAnalyst` — CAPEv2 MCP. T1547, T1055, T1059, T1112.
  - `NetworkAnalyst` — Network MCP + PCAP path heuristic. T1071, T1571, T1048, T1568.
  - `JudgeAgent` — NOT a BaseAnalyst. `mediate()` + `give_verdict()` (structured Bundle output) + ThreatIntel MCP.
- **Heterogeneous Ensemble**: per-agent LLM override via `LLM__AGENTS__<NAME>__PROVIDER` / `__MODEL`.
- **Registry**: `@register_agent("name")` decorator + auto-discovery.

## 4. ISR & STIX Schemas
- `ClaimEvidence` (`schemas/isr_models.py`): `claim`, `evidence_ref`, `confidence` (0-1), `technique_id` (`^T\d{4}(\.\d{3})?$`).
- `AgentISR`: `agent_id`, `domain`, `claims`, `dissent_items`, `revision_round`. `mean_confidence`, `to_text_summary()` (with `[CONVERGENCE SIGNAL]` annotation).
- `STIX Bundle` (`schemas/stix_models.py`): `ConfidenceAnnotatedRelationship` with `x_maljan_confidence`, `x_maljan_evidence_basis`, `x_maljan_contributing_agents`, `x_maljan_technique_id`.
- `MediatorVerdict` lives in **`pipeline/mediation_models.py`** (NOT under schemas/).
- `AnalysisState` (`pipeline/state.py`): TypedDict with reducers. Fields include `file_hash`, `file_name`, **`sample_path`**, **`sandbox_report`** (full normalized sandbox dict), `reports`, `revised_reports`, `isr_reports`, `discussion_history`, `sycophancy_detected`, `confidence_history`, `iteration_count`, `is_consensus`, `final_decision`, `judge_report`, `stix_output`, `run_summary`, `_max_iterations`.

## 5. Deterministic Analysis Layers
- **YARA** (`yara_layer.py`): `YaraLayer.from_default_rules()` loads `data/yara_ttp_rules.yaml`. `scan() → YaraMatch → to_isr()` injects as `domain="yara"`.
- **Sigma** (`sigma_layer.py`): 2946 rules. `scan_report_text() → to_isr()` injects as `domain="sigma"`.
- **TTP Cascade** (`ttp_cascade.py`): stateless, microseconds. Weights: yara=0.90, **tief=0.80** (weight retained even though `tief_classifier.py` was removed — TIEF claims may still arrive from other sources), sigma=0.55, dynamic=0.45, static=0.35, network=0.20. Multipliers: 1→1.00, 2→1.25, 3→1.50, 4→1.75, 5→1.90. `DEFAULT_LAYER_WEIGHT=0.25` for unknown domains.
- **Schema Pruner** (`schema_pruner.py`): keyword-weighted (ATT&CK IDs weight highest) → ransomware/RAT/dropper/worm/infostealer/unknown.
- **Chunk Merger** (`chunk_merger.py`): technique_id dedup (max conf) → text dedup → cap `MAX_MERGED_CLAIMS=20`.
- **Function Summarizer** (`function_summarizer.py`): optional LLM preprocessing.

## 6. Memory / RAG System
- **MemoryStore Protocol**: `store`, `retrieve`, `count`, `clear`. Upsert by sample_id.
- **StoredCase**: `sample_id`, `summary_text`, `technique_ids`, `malware_category`, `stix_bundle_json`, `created_at`.
- **QdrantStore**: vector backend with sentence-transformer embeddings.
- **InMemoryStore**: cosine similarity fallback.
- **ATT&CK Pipeline**:
  - `attck_loader.py` — fetches/caches ATT&CK Enterprise bundle (`ATTCK_BUNDLE_URL`, cache file).
  - `attck_index.py` — pure-Python TF-IDF index; `search()`, `validate_and_score()`.
  - `attck_validator.py` — thread-safe singleton (double-checked locking); `validate_isr_reports()` → `TTPValidationSummary` (hallucination rate, threshold 0.05).
  - `ttp_validation.py` — Pydantic models `TTPClaimValidation`, `TTPValidationSummary`.

## 7. Path & Utility Modules (new)
- `core/paths.py`:
  - `get_project_root(max_up=8)` — walks up looking for `pyproject.toml`/`.git`. Deterministic regardless of CWD.
  - `resolve_mcp_args(args)` — resolves relative paths in MCP config args against project root. Lets `.env` use portable relative paths.
- `utils/json_cleaner.py`: `extract_json`, `repair_json`, `safe_parse_json` — recover malformed LLM JSON output.
- `preprocessors/cfg_orderer.py`: `CFGOrderer` (NetworkX-backed) — topological sort of control-flow graph; used by `binary_chunker.py` for code-locality chunking.

## 8. LLM & Config Infrastructure
- Provider Registry (`llm/registry.py`) — `@register_provider` decorator, auto-discovers openai/anthropic/ollama/gemini.
- `build_model(role="expert"|"judge")`: expert temp=0.1, judge temp=0.0.
- `build_model_for_agent(agent_name)`: checks `LLMConfig.agents` override.
- Core Config (`core/config.py`): nested Pydantic with `__` delimiter. Sections: LLM, Negotiation, Chunking, Memory, Sandbox, Analysis, Preprocessing, MCP.
- API Config (`apps/api/app/config.py`): flat env vars.

## 9. API / Worker / Infrastructure
- **FastAPI** (`apps/api/app/main.py`): factory pattern, lifespan (DB + Redis), CORS, `RequestLoggingMiddleware`, routes under `/api/v1`, WebSocket `/ws/analysis/{job_id}`, `/health`.
- **AnalysisService**: job lifecycle, ARQ enqueue, user stats.
- **ARQ Worker**: `run_analysis(ctx, job_id)` — loads job → `MaljanApp.arun()` → saves `AnalysisReport` + `AgentFinding` → publishes Redis PubSub events. `max_jobs=2`, `job_timeout=1800s`, `max_tries=1`.
- **DB**: PostgreSQL + asyncpg + SQLAlchemy 2.0. Tables: users, api_keys, samples, analysis_jobs, analysis_reports, agent_findings, audit_log.
- **Alembic** dir exists under `apps/api/alembic/` (migrations in progress).
- **Redis**: ARQ queue + PubSub events channel `analysis:{job_id}`.
- **MinIO**: S3-compatible sample storage.
- **Docker**: 8 services (added Ghidra MCP HTTP server `:8089`).
