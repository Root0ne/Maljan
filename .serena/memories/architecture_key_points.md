# Maljan — Architecture Key Points

## Full-Stack Deployment (New Architecture)
- **apps/api**: FastAPI service. Exposes REST endpoints (`v1/jobs`, `v1/samples`, `v1/reports`, etc.) to trigger and manage analysis jobs. Uses a worker pattern (`apps/api/app/worker/analysis_worker.py`) to execute the LangGraph pipeline (`src/maljan`) asynchronously. Also uses Alembic for database migrations.
- **apps/web**: Next.js application providing a dashboard, job submission interface, and interactive report viewing.
- **docker**: Contains `Dockerfile.frontend`, `Dockerfile.backend`, and `docker-compose.yml` for orchestrating the multi-container environment.

## Pipeline Flow (LangGraph)
```
FileDataLoader -> [StaticAnalyst || DynamicAnalyst || NetworkAnalyst]  (parallel fan-out)
     -> MediatorNode (negotiation rounds, max 2)
     -> SycophancyDetector
     -> AdaptiveTermination (rolling std of confidence)
     -> TTPCascadeEngine (cross-domain corroboration)
     -> JudgeAgent (STIX 2.1 verdict)
     -> RunSummary
```

## MCP Tool Integration (NEW — core architectural addition)
Agents now use real-world tools via MCP servers:

| MCP Server         | File                      | Tools Provided                             |
|--------------------|---------------------------|--------------------------------------------|
| Ghidra MCP         | `external/` (third-party) | disassembly, import_file, debugger_*       |
| CAPEv2 MCP         | `external/` (third-party) | submit_file, cuckoo_status, task_report    |
| NetworkMCP         | `network-mcp/server.py`   | read_pcap_summary, extract_dns, ...        |
| ThreatIntelMCP     | `threatintel-mcp/server.py` | check_ip_reputation, check_domain_reputation, check_hash |

`MCPLangChainToolkit` (`agents/mcp_client.py`) bridges MCP servers to LangChain tools.
`AgentRegistry` (`agents/registry.py`) manages agent discovery and instantiation.

## Core Abstractions

### ServiceContainer (`core/container.py`)
- Singleton DI container
- Builds and caches: LLM clients, sandbox client, ATTCKIndex, LongTermMemory, etc.
- Configures LangSmith tracing on init
- `get_sandbox_client()` -> MockSandboxClient | CAPEv2Client | TriageClient (from Settings)

### MaljanApp (`app.py`)
- High-level application facade (Composition Root)
- `run(file_hash, file_name)` -> dict with final_decision, stix_output, run_summary
- Wires ServiceContainer + build_graph + AnalysisState

### Settings (`core/config.py`)
- `pydantic-settings` with nested config (e.g., `Settings.llm.openai.api_key`)
- Loaded from `.env` file
- Key settings: `LLM__PROVIDER`, `MEMORY__BACKEND`, `SANDBOX__BACKEND`

### AgentISR / ClaimEvidence (`schemas/isr_models.py`)
- Structured output from each analyst agent
- `ClaimEvidence(technique_id, confidence, evidence_ref, basis)`
- `AgentISR(agent_id, domain, claims, dissent_items, revision_round)`

### TTPCascadeEngine (`analysis/ttp_cascade.py`)
- Cross-domain confidence scoring for ATT&CK technique IDs
- Layer weights: dynamic=0.45, static=0.35, network=0.20
- Cross-layer multipliers: 1x (single) -> 1.25x (2 domains) -> 1.5x (3 domains)
- Layer 1: YaraLayer (YARA rules, 300+ MITRE-derived rules)
- Layer 1b: SigmaLayer (2,946 SigmaHQ rules, memory log evaluation)
- Layer 2: TIEFClassifier (DistilBERT NLP classifier, partial implementation)
- Layer 3: LLM agents (primary reasoning layer)

### YaraLayer (`analysis/yara_layer.py`)
- `YaraTTPRule`, `YaraMatch` dataclasses
- `YaraLayer`: loads YARA rules from configurable rules path
- Deterministic TTP detection from binary content
- Constants: `_DEFAULT_RULES_PATH`, `_CONFIDENCE_FLOOR`

### SigmaLayer (`analysis/sigma_layer.py`)
- `SigmaMemoryEvaluator`: evaluates log entries against SigmaHQ rules (in-memory)
- `SigmaLayer`: loads 2,946 SigmaHQ rules, classifies log sources via `_classify_log_source()`
- `SigmaMatch` dataclass for matches

### TIEFClassifier (`analysis/tief_classifier.py`)
- DistilBERT-based NLP ATT&CK technique classifier (Layer 2)
- Lazy initialization; gracefully degrades if `transformers` not installed
- Threshold-based confidence filtering

### FunctionSummarizer (`analysis/function_summarizer.py`)
- Pre-processing step: summarizes decompiled functions before LLM analysis
- Prevents context window overflow from large Ghidra Assembly dumps

### CFGOrderer (`preprocessors/cfg_orderer.py`)
- Control Flow Graph reordering for static analysis
- Prepares binary code structure for more effective analysis

### SycophancyDetector (`pipeline/sycophancy_detector.py`)
- Pure BoW cosine similarity (no external dependencies)
- Detects agents copying peer reports verbatim
- Forces additional dissent round if sycophancy detected

### Adaptive Termination (`pipeline/routing.py`)
- Rolling std of last 3-5 confidence scores
- Pure Python (no scipy)
- Exits early if confidence converges

### BinaryChunker (`loaders/binary_chunker.py`)
- Domain-aware: static=function boundaries, dynamic=PID/process, network=flow sessions
- Sliding window fallback
- `safe_analyze_isr_chunked()` in BaseAnalyst handles multi-chunk analysis

### SandboxClient Protocol (`loaders/sandbox_client.py`)
- `SubmissionResult` dataclass: carries raw JSON report dict
- Protocol-based: MockSandboxClient, CAPEv2Client, TriageClient are interchangeable
- `TriageClient` (`loaders/triage_client.py`): Hatching Triage sandbox (TODO-C DONE)

### ATTCKLoader (`memory/attck_loader.py`)
- Downloads and caches MITRE ATT&CK STIX bundle from `ATTCK_BUNDLE_URL`
- Parses bundle into `ATTCKTechnique` objects
- Local disk cache: `_DEFAULT_CACHE_DIR`

### MediatorVerdict (`pipeline/mediation_models.py`)
- Structured output from mediator negotiation round
- Also mirrored in `schemas/mediation_models.py`

## STIX Output (`schemas/stix_models.py`)
- Custom Pydantic v2 models (no stix2 library)
- `ConfidenceAnnotatedRelationship` with per-claim confidence intervals
- `EvidenceBasis` enum: "all", "static", "dynamic", "network"

## LLM Providers (`llm/`)
- OpenAI, Anthropic, Ollama, **Gemini** (langchain-google-genai)
- All registered via `@register_provider` decorator in `llm/registry.py`

## Memory Layer (`memory/`)
- `ATTCKLoader`: downloads and caches MITRE ATT&CK STIX bundle
- `ATTCKIndex`: local STIX cache, cosine search for TTP lookup
- `ATTCKValidator`: hallucination detection for technique IDs
- `TTPValidation`: `TTPClaimValidation`, `TTPValidationSummary` schemas
- `LongTermMemory`: few-shot injection into JudgeAgent prompts
- Backend: `InMemoryStore` (default) or `QdrantStore` (persistent)

## Evaluation (`tests/evaluation/`)
- `BenchmarkSuite`: aggregates metrics across fixtures
- `BenchmarkRunner`: bridges RunSummary -> BenchmarkReport
- `from_run_summary()`: convert pipeline state to benchmark-ready format
- Metrics: TTP F1, STIX quality, negotiation efficiency, sycophancy rate
- 5 synthetic fixtures (dropper, worm, infostealer, ransomware, rat)
- CLI: `maljan benchmark` or `make benchmark`

## Open TODOs (docs/TODO.md / current_todo.md)
| # | Task | Status | Priority |
|---|------|--------|----------|
| A | YARA ruleset expansion | DONE | Critical |
| B | Sigma Layer 0 | DONE | High |
| C | Hatching Triage sandbox client | DONE | Medium |
| D | FunctionSummarizer | DONE | Low |
| E | CAPEv2 MCP tool expansion & optimization | PENDING | High |
| F | Ghidra MCP prompt tuning (few-shot ReAct) | PENDING | High |
| G | End-to-end ReAct pipeline & orchestration | PENDING | Critical |
| H | Anti-Echo-Chamber Engine (Sycophancy full impl.) | PENDING | Critical |
| I | Adaptive Termination (K-S Test) | PENDING | High |
| J | Long-Term Memory / RAG (Qdrant & STIX Store) | PENDING | High |
