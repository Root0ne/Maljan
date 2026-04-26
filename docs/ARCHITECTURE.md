# Maljan Architecture Reference

> Detailed technical architecture document for the Maljan multi-agent malware analysis framework.
> For installation and usage, see [README.md](README.md).

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Directory Layout](#directory-layout)
3. [Component Map](#component-map)
4. [Data Flow: End-to-End](#data-flow-end-to-end)
5. [Core Abstractions](#core-abstractions)
6. [Layer 1: Data Ingestion](#layer-1-data-ingestion)
7. [Layer 2: Parsing](#layer-2-parsing)
8. [Layer 3: Expert Analysts](#layer-3-expert-analysts)
9. [Layer 4: Negotiation Engine](#layer-4-negotiation-engine)
10. [Layer 5: Verdict Assembly](#layer-5-verdict-assembly)
11. [Layer 6: Memory Subsystem](#layer-6-memory-subsystem)
12. [Layer 7: Sandbox Integration](#layer-7-sandbox-integration)
13. [Configuration System](#configuration-system)
14. [Dependency Injection: ServiceContainer](#dependency-injection-servicecontainer)
15. [CI/CD Pipeline](#cicd-pipeline)
16. [Design Principles](#design-principles)
17. [Extension Points](#extension-points)

---

## System Overview

Maljan is a **multi-agent LLM pipeline** for automated malware triage. Three parallel domain-specialist agents
(static, dynamic, network) independently analyze malware artifacts, then debate their findings through a
structured negotiation protocol before a Chief Judge issues a MITRE ATT&CK-grounded STIX 2.1 verdict.

```
                     Input Artifact
                          |
              +-----------+-----------+
              |           |           |
        StaticParser  DynamicParser  NetworkParser
              |           |           |
        StaticAnalyst  DynamicAnalyst  NetworkAnalyst
              |           |           |
              +-----------+-----------+
                          |
                    Negotiation Loop
                   (JudgeAgent.mediate)
                          |
              +-----------+------+-----------+
              |           |      |           |
         ATTCKValidator  TTPCascade  YaraLayer  SigmaLayer
              |           |      |           |
              +-----------+------+-----------+
                          |
                 JudgeAgent.give_verdict
                          |
                    STIX 2.1 Bundle
                          |
                    Memory Store (RAG)
```

---

## Directory Layout

```
src/maljan/
    agents/          -- LLM agent implementations
        base_agent.py        BaseAnalyst + chunked analysis logic
        static_analyst.py    PE/Ghidra/Radare2 domain specialist
        dynamic_analyst.py   CAPEv2/Cuckoo behavioral specialist
        network_analyst.py   Zeek/PCAP network flow specialist
        judge_agent.py       Mediator + Chief Judge (not an analyst)
        registry.py          AgentRegistry (name -> agent instance)

    analysis/        -- Post-ISR analytics engines
        ttp_cascade.py       Three-layer cross-domain confidence scoring
        yara_layer.py        YARA Layer 0: deterministic signature scanner
        sigma_layer.py       Sigma Layer 0: pySigma engine (2,946 SigmaHQ rules)
        schema_pruner.py     Malware category inference + STIX schema hints
        run_summary.py       RunSummary observability report builder

    core/            -- Framework configuration and utilities
        config.py            Pydantic-settings Config root
        container.py         ServiceContainer (DI root)
        exceptions.py        Domain exception hierarchy
        logger.py            Structured logging setup

    loaders/         -- Data ingestion layer
        file_loader.py       FileDataLoader (local JSON fixtures)
        binary_chunker.py    BinaryChunker (domain-aware text splitting)
        sandbox_client.py    SandboxClient Protocol + SubmissionResult
        mock_sandbox_client.py  Fixture-backed offline sandbox
        cape2_client.py      Live CAPEv2 REST API client

    memory/          -- ATT&CK knowledge + long-term RAG memory
        attck_loader.py      MITRE ATT&CK STIX bundle downloader + parser
        attck_index.py       TF-IDF index for semantic TTP lookup
        attck_validator.py   Singleton validator (batch ISR claim validation)
        ttp_validation.py    TTPValidationSummary + prompt block renderer
        long_term_memory.py  MemoryStore Protocol + StoredCase + build_stored_case()
        in_memory_store.py   TF cosine similarity backend (zero dependencies)
        qdrant_store.py      Qdrant vector database backend

    parsers/         -- Domain-specific artifact parsers
        base_parser.py       ParserProtocol interface
        static_parser.py     PE header, strings, decompiled summary
        dynamic_parser.py    Behavioral signatures, API stats
        network_parser.py    C2 flows, DNS anomalies, beaconing
        registry.py          ParserRegistry (@register_parser decorator)

    pipeline/        -- LangGraph graph definition and state machine
        graph.py             build_pipeline() -> CompiledStateGraph
        nodes.py             Node factories (make_analyst_node, make_judge_node, etc.)
        state.py             AnalysisState TypedDict + merge reducers
        routing.py           Conditional edge logic (should_continue)
        sycophancy_detector.py  Cosine similarity echo-chamber detection
        mediation_models.py  MediatorVerdict structured output schema

    schemas/         -- Pydantic data models
        isr_models.py        AgentISR, ClaimEvidence, ISR merge logic
        stix_models.py       STIX 2.1 Bundle + ConfidenceAnnotatedRelationship

    llm/             -- LLM factory abstraction
        factory.py           build_llm() per config (OpenAI/Anthropic/Ollama)

    app.py           -- MaljanApp public API
    cli.py           -- Typer CLI (analyze, build-attck-cache, run-summary)
```

---

## Component Map

```
+--------------------+     +--------------------+     +--------------------+
|   FileDataLoader   |     |  MockSandboxClient |     |   CAPEv2Client     |
|  load_chunked()    |     |  (fixture-backed)  |     |  (live REST API)   |
+--------------------+     +--------------------+     +--------------------+
           |                         |                          |
           |            SandboxClient Protocol                  |
           +-------------------------+-------------------------+
                                     |
                               BinaryChunker
                           (domain-aware splitting)
                                     |
                           list[TextChunk]
                                     |
              +----------------------+----------------------+
              |                      |                      |
       StaticParser           DynamicParser          NetworkParser
       (ParserRegistry)       (ParserRegistry)       (ParserRegistry)
              |                      |                      |
       StaticAnalyst          DynamicAnalyst         NetworkAnalyst
       (BaseAnalyst)          (BaseAnalyst)          (BaseAnalyst)
              |                      |                      |
         AgentISR               AgentISR               AgentISR
              |                      |                      |
              +----------------------+----------------------+
                                     |
                             AnalysisState (TypedDict)
                                     |
                    +----------------+----------------+
                    |                                 |
             make_negotiation_node           make_revision_node
             (JudgeAgent.mediate)            (agent.safe_revise_isr)
             SycophancyDetector              _build_revision_context
                    |                                 |
                    +----------should_continue--------+
                               (routing.py)
                                     |
                             make_judge_node
                          +----------+----------+
                          |          |           |
                   ATTCKValidator  TTPCascade  SchemaPruner
                          |          |           |
                    JudgeAgent.give_verdict()
                          |
                    STIX 2.1 Bundle
                     (ConfidenceAnnotatedRelationship)
                          |
                    +-----+-----+
                    |           |
             InMemoryStore  QdrantStore
             (MemoryStore Protocol)
                          |
                    RunSummary
```

---

## Data Flow: End-to-End

### Step 1: Entry Point

```
MaljanApp.analyze(file_hash, file_name)
    -> build_pipeline(container)
    -> CompiledStateGraph.invoke(initial_state)
```

### Step 2: Analyst Nodes (parallel)

Each analyst node (`make_analyst_node`) runs independently:

```
container.load_chunked(file_hash, agent_name)
    -> [chunk_1, chunk_2, ...] or [single_chunk]
    -> if single chunk: agent.analyze_isr(text)
    -> if multi-chunk:  agent.safe_analyze_isr_chunked(chunks)
                            -> merge_chunk_isrs(partial_isrs)
    -> AgentISR written to state["isr_reports"]
```

### Step 3: Negotiation Loop

```
make_negotiation_node():
    isr_reports = state["isr_reports"]
    judge.mediate(reports, history, isr_reports)
        -> MediatorVerdict(finding, confidence, ...)
    detect_sycophancy(history)
        -> if echo-chamber: augment directive with devil's advocate injection
    -> state["revision_directive"], state["confidence_history"]

routing: should_continue(state)
    -> consensus  (confidence >= 0.85)
    -> convergence (rolling std < 0.02 over last 3 rounds)
    -> hard limit  (iteration_count >= max_iterations)
    -> else: make_revision_node
```

### Step 4: Revision

```
make_revision_node():
    _build_revision_context(state, container, agent_name)
        -> single chunk: raw text
        -> multi-chunk:  ISR summary + context header
    agent.safe_revise_isr(original_data, own_report, peer_reports, ...)
    -> updated state["revised_reports"], state["isr_reports"]
```

### Step 5: Verdict Assembly

```
make_judge_node():
    ATTCKValidator.get_instance()          -- singleton, lazy-loaded
    TTPCascadeEngine().compute(isr_reports) -- stateless
    container.get_memory_store()           -- cached singleton

    -- YARA Layer 0 --
    YaraLayer.scan(reports + evidence)     -- deterministic pattern match
    -> AgentISR(domain="yara") injected into isr_reports

    -- Sigma Layer 0 --
    SigmaLayer.scan_log_lines(reports + evidence)  -- pySigma engine
    -> AgentISR(domain="sigma") injected into isr_reports

    judge.give_verdict(
        reports, history, isr_reports,
        attck_validator, cascade_summary, memory_store
    )
    -> _build_validation_block()           -- ATT&CK TTP grounding
    -> _build_cascade_block()              -- confidence ranking
    -> _build_schema_hint()                -- malware category schema
    -> _build_confidence_instruction()     -- per-relationship instructions
    -> _build_memory_context()             -- RAG few-shot priors
    -> LLM call -> Bundle

    build_stored_case(...)
    memory_store.store(case)
    RunSummaryBuilder(...).build()
    -> state["final_decision"], state["stix_output"], state["run_summary"]
```

---

## Core Abstractions

### Protocols (structural typing)

All cross-subsystem boundaries use `Protocol` for loose coupling:

| Protocol | Location | Implementors |
|---|---|---|
| `SandboxClient` | `loaders/sandbox_client.py` | `MockSandboxClient`, `CAPEv2Client` |
| `MemoryStore` | `memory/long_term_memory.py` | `InMemoryStore`, `QdrantStore` |
| `ParserProtocol` | `parsers/base_parser.py` | `StaticParser`, `DynamicParser`, `NetworkParser` |

All Protocols are `@runtime_checkable` -- `isinstance()` checks work in tests and container validation
without importing concrete types.

### ISR: Intermediate Structural Representation

The ISR layer (`schemas/isr_models.py`) is the core data contract between analysts and the negotiation engine:

```python
class ClaimEvidence(BaseModel):
    claim: str                      # assertion text
    evidence_ref: str               # concrete artifact citation
    confidence: float               # [0.0, 1.0]
    technique_id: str | None        # MITRE ATT&CK ID or None

class AgentISR(BaseModel):
    agent_id: str
    domain: Literal["static", "dynamic", "network"]
    claims: list[ClaimEvidence]
    dissent_items: list[str]        # peer claims still disputed
    revision_round: int
    mean_confidence: float          # computed property
```

ISR objects serve four purposes:

1. **Sycophancy detection** -- similarity computed over `claims` text
2. **TTP validation** -- every `technique_id` validated against ATT&CK
3. **Cascade scoring** -- grouped by domain, weighted by layer weights
4. **Memory retrieval** -- `summary_text` built from `claims + evidence_refs`

### AnalysisState TypedDict

```python
class AnalysisState(TypedDict):
    file_hash: str
    file_name: str | None
    reports: Annotated[dict[str, str], _merge_dicts]
    isr_reports: Annotated[dict[str, AgentISR], _merge_dicts]
    revised_reports: dict[str, str]
    discussion_history: Annotated[list[AgentArgument], operator.add]
    confidence_history: list[float]
    sycophancy_detected: bool
    revision_directive: str
    is_consensus: bool
    iteration_count: int
    final_decision: str
    stix_output: dict
    run_summary: dict | None
```

`Annotated` reducers ensure parallel analyst nodes can write to `reports` and `isr_reports`
concurrently without race conditions.

---

## Layer 1: Data Ingestion

**`FileDataLoader`** (`loaders/file_loader.py`)

Loads artifacts from `data/samples/{domain}/{sample_id}.json`. Three entry points:

| Method | Use Case | Return |
|---|---|---|
| `load_data(file_hash, agent_name)` | Legacy / single-chunk fallback | `str` |
| `load_chunked(file_hash, agent_name)` | Primary pipeline path | `list[TextChunk]` |
| `load_from_sandbox(path, data_type, client)` | Live sandbox data | `list[TextChunk]` |

**`BinaryChunker`** (`loaders/binary_chunker.py`)

Domain-aware splitting strategy selected per `agent_name`:

| Strategy | Domain | Split boundary |
|---|---|---|
| `FUNCTION_BOUNDARY` | static | Ghidra/Radare2 function headers |
| `API_SEQUENCE` | dynamic | PID/process markers |
| `FLOW_SESSION` | network | Flow delimiters |
| `SLIDING_WINDOW` | any | Token-count window with overlap |

Each `TextChunk` carries `index`, `total`, `content`, `strategy`, `token_estimate`. Multi-chunk samples
trigger `safe_analyze_isr_chunked()` which merges partial ISR results via claim deduplication.

```bash
CHUNKING__MAX_TOKENS_PER_CHUNK=6000
CHUNKING__OVERLAP_TOKENS=200
CHUNKING__SKIP_IF_FITS=true
```

---

## Layer 2: Parsing

**`ParserRegistry`** (`parsers/registry.py`) -- decorator-based self-registration:

```python
@register_parser("dynamic")
class DynamicParser:
    def parse(self, raw: dict) -> str: ...
```

`ParserRegistry.create(domain)` returns the registered parser or raises `KeyError`. New parsers require
no changes to any core file.

| Parser | Input | Key Extraction |
|---|---|---|
| `StaticParser` | Ghidra/Radare2 JSON | PE header, imports, suspicious strings, decompiled summary |
| `DynamicParser` | CAPEv2/Cuckoo JSON | Behavioral signatures, notable API call categories, process tree |
| `NetworkParser` | Zeek connection logs | C2 IP/domain candidates, DNS anomalies, beaconing intervals |

---

## Layer 3: Expert Analysts

**`BaseAnalyst`** (`agents/base_agent.py`)

```python
class BaseAnalyst:
    def analyze_isr(self, data: str) -> AgentISR
    def safe_analyze_isr_chunked(self, chunks: list[TextChunk]) -> AgentISR
    def safe_revise_isr(self, original_data, own_report, peer_reports,
                        mediator_feedback, revision_round) -> tuple[str, AgentISR]
    def merge_chunk_isrs(self, isrs: list[AgentISR]) -> AgentISR
```

Multi-chunk analysis: each chunk is analyzed independently, then `merge_chunk_isrs()` deduplicates
claims by `(claim_text, technique_id)` pair and unions dissent items.

**Heterogeneous ensemble**: Each agent can be configured with a different LLM:

```bash
AGENT_OVERRIDES__STATIC__MODEL=gpt-4o
AGENT_OVERRIDES__DYNAMIC__MODEL=claude-3-5-sonnet-20241022
AGENT_OVERRIDES__NETWORK__MODEL=gpt-4o-mini
```

**`AgentRegistry`** (`agents/registry.py`): Maps `agent_name -> BaseAnalyst`. `list_agents()` drives the
graph node factory loop -- no hardcoded agent names anywhere in the pipeline.

---

## Layer 4: Negotiation Engine

### Sycophancy Detection

```
detect_sycophancy(history: list[AgentArgument]) -> bool
```

Computes cosine similarity between the current mediator finding and the last N arguments using
pure-Python TF-IDF. If similarity `>= SYCOPHANCY_THRESHOLD` (default 0.85), `build_revision_directive()`
injects a devil's advocate instruction into the next revision prompt, forcing genuine reassessment.

### Adaptive Termination (priority order)

```
should_continue(state) -> Literal["revise", "judge"]

1. Hard limit:    iteration_count >= max_iterations     -> "judge"
2. Consensus:     is_consensus == True                  -> "judge"
3. Convergence:   rolling_std(last_3_confidence) < 0.02 -> "judge"
4. Default:                                             -> "revise"
```

### Revision Grounding

`_build_revision_context(state, container, agent_name)` selects grounding context:

| Sample size | Revision context |
|---|---|
| Single chunk | Raw parsed text (same as initial analysis) |
| Multi-chunk | Consolidated ISR summary with chunking header |

Multi-chunk revision uses `state["reports"][agent_name]` (merged ISR summary text), not `load_data()`.
This prevents silent truncation when large samples are re-loaded and cut at the token limit during
revision rounds.

---

## Layer 5: Verdict Assembly

### TTPCascadeEngine

For each unique `technique_id` across all ISR reports:

```
raw_confidence = sum(domain_weight * layer_mean_confidence) / sum(domain_weights)

domain_weights:  yara=0.90  sigma=0.55  dynamic=0.45  static=0.35  network=0.20

multiplier:
    1 layer  -> x1.00  [SINGLE-LAYER]
    2 layers -> x1.25  [CORROBORATED]
    3 layers -> x1.50  [CONSENSUS]
    4+ layers -> x1.75 [FULL-CONSENSUS]

final_confidence = min(raw_confidence * multiplier, 1.0)
```

### SchemaPruner

Keyword-weighted category scoring over combined report text and ISR claims:

| Category | STIX focus |
|---|---|
| RANSOMWARE | FileSystemObject, EncryptionAlgorithm, NetworkTraffic (ransom drop) |
| RAT | NetworkTraffic, Process (C2 beacon patterns) |
| DROPPER | URL, File, Process (stage fetch patterns) |
| WORM | NetworkTraffic, File (lateral movement) |
| INFOSTEALER | UserAccount, File, NetworkTraffic (credential staging) |

Returns empty string for `UNKNOWN` -- full schema with no pruning.

### Judge Prompt Composition

`give_verdict()` assembles up to 5 grounding blocks before the LLM call:

| Block | Source | Purpose |
|---|---|---|
| ATT&CK validation | `ATTCKValidator` | Flags hallucinated IDs, suggests alternatives |
| Three-layer cascade | `TTPCascadeEngine` | Ranks TTPs by cross-domain weighted confidence |
| Schema pruning hint | `SchemaPruner` | Focuses STIX object types on detected category |
| Confidence instructions | Hardcoded | Guides per-relationship `x_maljan_confidence` values |
| Long-term memory | `MemoryStore.retrieve()` | Top-k similar past cases as few-shot priors |

All blocks are individually optional. Missing components are silently skipped -- verdict generation
never fails due to a missing optional component.

---

## Layer 6: Memory Subsystem

### ATT&CK Knowledge Base

```
ATTCKLoader.load_attck_bundle()
    -> downloads enterprise-attack.json (cached at ~/.cache/maljan/attck/)
    -> parses into list[ATTCKTechnique]

ATTCKIndex.from_techniques(techniques)
    -> builds TF-IDF matrix over searchable_text of each technique
    -> search(text, top_k) -> list[(ATTCKTechnique, score)]
    -> get_by_id(technique_id) -> ATTCKTechnique | None

ATTCKValidator.get_instance()
    -> thread-safe singleton (loaded once per process)
    -> validate_isr_reports(isr_reports) -> TTPValidationSummary
```

### Long-Term Memory (RAG)

```python
@dataclass
class StoredCase:
    sample_id: str         # sha256 or filename
    summary_text: str      # built from all ISR claims + evidence refs
    technique_ids: list[str]
    malware_category: str
    stix_bundle_json: str
    timestamp: float

class MemoryStore(Protocol):
    def store(self, case: StoredCase) -> None
    def retrieve(self, query: str, top_k: int) -> list[StoredCase]
    def count(self) -> int
    def clear(self) -> None
```

**`InMemoryStore`**: TF cosine similarity. Upsert by `sample_id`. No external dependencies.

**`QdrantStore`**:
- 512-dimensional hash-trick embedding (deterministic, no ML model required)
- Stable point ID via SHA-256 of `sample_id` (upsert-safe)
- `query_points()` API (qdrant-client >= 1.13)
- Auto-creates collection with cosine distance metric on first `store()` call

```bash
MEMORY__BACKEND=memory    # InMemoryStore (default)
MEMORY__BACKEND=qdrant    # QdrantStore
MEMORY__QDRANT_URL=http://localhost:6333
MEMORY__QDRANT_COLLECTION=maljan_cases
MEMORY__TOP_K=3
```

---

## Layer 7: Sandbox Integration

### SandboxClient Protocol

```python
class SandboxClient(Protocol):
    def submit(self, sample_path: str | Path) -> str           # task_id
    def wait_for_completion(self, task_id: str, ...) -> str    # status
    def fetch_report(self, task_id: str) -> SubmissionResult
```

### SubmissionResult

```python
@dataclass
class SubmissionResult:
    task_id: str
    sample_sha256: str
    sample_name: str
    status: str
    report: dict[str, Any]   # structurally identical to fixture JSON files
    error: str
```

The `report` dict matches existing `data/samples/` fixture files exactly -- `DynamicParser` and
`NetworkParser` require zero changes to consume live sandbox data.

### Backends

| Backend | Class | Use Case |
|---|---|---|
| `mock` | `MockSandboxClient` | Tests, offline development, CI |
| `cape2` | `CAPEv2Client` | Live CAPEv2 instances |

`MockSandboxClient` fixture lookup order:
1. `{fixtures_dir}/dynamic/{sha256}.json`
2. `{fixtures_dir}/dynamic/{sample_name}.json`
3. `default_dynamic_fixture` (configurable)
4. Minimal synthetic report (always-valid fallback)

`CAPEv2Client` uses `httpx` with persistent connection pooling, configurable timeout, and token
authentication. Endpoints: `POST /apiv2/tasks/create/file/`, `GET /apiv2/tasks/view/{id}/`,
`GET /apiv2/tasks/report/{id}/`.

```bash
SANDBOX__BACKEND=mock
# or:
SANDBOX__BACKEND=cape2
SANDBOX__CAPE2_BASE_URL=http://cape2-host:8000
SANDBOX__CAPE2_API_TOKEN=your_token
SANDBOX__CAPE2_TIMEOUT_SECONDS=300
```

---

## Configuration System

All configuration declared in `core/config.py` using Pydantic Settings. Loads from environment
variables or `.env` file. Types are validated at startup -- no runtime `KeyError` surprises.

```python
class Config(BaseSettings):
    llm: LLMConfig                              # model, provider, temperature
    negotiation: NegotiationConfig              # max_iterations, thresholds
    chunking: ChunkingConfig                    # max_tokens, overlap
    memory: MemoryConfig                        # backend, qdrant_url, top_k
    sandbox: SandboxConfig                      # backend, cape2 settings
    agent_overrides: dict[str, AgentOverride]   # per-agent LLM overrides
    langsmith: LangSmithConfig                  # tracing opt-in
```

---

## Dependency Injection: ServiceContainer

`ServiceContainer` (`core/container.py`) is the single DI root. All subsystem singletons are built
and cached here. Node factories receive the container at construction time.

```python
class ServiceContainer:
    def get_agent(self, name: str) -> BaseAnalyst       # cached per name
    def get_memory_store(self) -> MemoryStore           # cached singleton
    def get_sandbox_client(self) -> SandboxClient       # cached singleton
    def load_chunked(self, file_hash, agent_name) -> list[TextChunk]
    def load_data(self, file_hash, agent_name) -> str

    @property
    def agent_registry(self) -> AgentRegistry
    @property
    def is_mock(self) -> bool  # True -> all LLM calls return deterministic stubs
```

Setting `is_mock=True` makes the entire pipeline testable with no LLM calls. The container builds
the correct backend for each subsystem based on `Config`.

---

## CI/CD Pipeline

```
quality job:
    ruff check src/ tests/        -- lint
    ruff format --check           -- format
    uv run mypy src/              -- type check (config: pyproject.toml)

test job (needs: quality):
    pytest tests/
    matrix: Python 3.11 / 3.12 / 3.13

qdrant-live job (needs: quality):
    service: qdrant/qdrant:latest
    pytest tests/unit/test_qdrant_store.py
    (service readiness polled via HTTP before tests)
```

Local gates mirror CI exactly:

```bash
make check           # lint + format-check + typecheck + full test suite
make pre-commit-run  # run all hooks on all files (same as commit-time)
```

Pre-commit hooks (`.pre-commit-config.yaml`) enforce quality on every `git commit`:
- File hygiene: trailing whitespace, YAML/TOML syntax, merge conflicts, large file guard
- `ruff lint --fix` + `ruff format`
- `mypy src/`

---

## Design Principles

| Principle | Implementation |
|---|---|
| Protocol over inheritance | All cross-boundary interfaces use `Protocol`; concrete types never imported across subsystem boundaries |
| Graceful degradation | Every optional component (ATT&CK cache, memory store, cascade) is wrapped in `try/except`; pipeline never fails due to a missing enhancement |
| Upsert semantics | Both `InMemoryStore` and `QdrantStore` use stable IDs (SHA-256 of `sample_id`); re-analyzing the same sample updates, not duplicates |
| Zero truncation | Multi-chunk samples use ISR summaries for revision grounding; no silent data loss at the token limit |
| Stateless analytics | `TTPCascadeEngine`, `SchemaPruner`, `ATTCKValidator` are all stateless per-call; safe for concurrent use |
| Registry pattern | `AgentRegistry` and `ParserRegistry` use decorator registration; new agents/parsers require no core changes |
| Config as code | Pydantic Settings enforces types and required fields at startup |
| Forward compatibility | qdrant-client uses `query_points()` (>= 1.13), `upsert(wait=True)` for synchronous consistency |

---

## Extension Points

### Adding a New Agent Domain

1. Create `src/maljan/agents/my_agent.py` inheriting `BaseAnalyst`
2. Create `src/maljan/parsers/my_parser.py` with `@register_parser("my_domain")`
3. Add fixture data under `data/samples/my_domain/`
4. Register in `ServiceContainer` under the domain name

No changes to `pipeline/graph.py`, `pipeline/nodes.py`, or any other core file.

### Swapping the Memory Backend

Implement `MemoryStore` Protocol (4 methods: `store`, `retrieve`, `count`, `clear`), register in
`ServiceContainer.get_memory_store()`, set `MEMORY__BACKEND=your_backend`.

### Swapping the Sandbox Backend

Implement `SandboxClient` Protocol (3 methods: `submit`, `wait_for_completion`, `fetch_report`),
register in `ServiceContainer.get_sandbox_client()`, set `SANDBOX__BACKEND=your_backend`.

### Swapping the LLM Provider

```bash
LLM__PROVIDER=anthropic
LLM__MODEL=claude-3-5-sonnet-20241022

# Per-agent override:
AGENT_OVERRIDES__DYNAMIC__MODEL=gpt-4o
```
