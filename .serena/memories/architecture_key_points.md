# Maljan — Architecture Key Points

## Pipeline Flow (LangGraph)
```
FileDataLoader → [StaticAnalyst || DynamicAnalyst || NetworkAnalyst]  (parallel fan-out)
     → MediatorNode (negotiation rounds, max 2)
     → SycophancyDetector
     → AdaptiveTermination (rolling std of confidence)
     → TTPCascadeEngine (cross-domain corroboration)
     → JudgeAgent (STIX 2.1 verdict)
     → RunSummary
```

## Core Abstractions

### ServiceContainer (`core/container.py`)
- Singleton DI container
- Builds and caches: LLM clients, sandbox client, ATTCKIndex, LongTermMemory, etc.
- Configures LangSmith tracing on init
- `get_sandbox_client()` → MockSandboxClient | CAPEv2Client (from Settings)

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
- Cross-layer multipliers: 1x (single) → 1.25x (2 domains) → 1.5x (3 domains)
- Currently: Layer 3 (LLM) only — Layer 1 (YARA/Sigma) is TODO-1

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

## STIX Output (`schemas/stix_models.py`)
- Custom Pydantic v2 models (no stix2 library)
- `ConfidenceAnnotatedRelationship` with per-claim confidence intervals
- `EvidenceBasis` enum: "all", "static", "dynamic", "network"

## Memory Layer (`memory/`)
- `ATTCKIndex`: local STIX cache, cosine search for TTP lookup
- `LongTermMemory`: few-shot injection into JudgeAgent prompts
- Backend: `InMemoryStore` (default) or `QdrantStore` (persistent)

## Evaluation (`tests/evaluation/`)
- `BenchmarkSuite`: aggregates metrics across fixtures
- `BenchmarkRunner`: bridges RunSummary → BenchmarkReport
- `from_run_summary()`: convert pipeline state to benchmark-ready format
- Metrics: TTP F1, STIX quality, negotiation efficiency, sycophancy rate
- 5 synthetic fixtures (dropper, worm, infostealer, ransomware, rat)
- CLI: `maljan benchmark` or `make benchmark`

## Open TODOs (docs/TODO.md)
1. **TODO-4** (Critical): aCTIon dataset (204 STIX bundles) for real benchmark
2. **TODO-1** (High): YARA + Sigma Layer 1 deterministic TTP detection
3. **TODO-3** (Medium): Hatching Triage sandbox client
4. **TODO-2** (Low): FunctionSummarizer for chunk pre-processing
5. **TODO-5** (Research): DistilBERT/CTI-BERT Layer 2
