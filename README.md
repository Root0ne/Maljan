# Maljan: Adaptive Multi-Agent Malware Analysis Framework

[![CI](https://github.com/Root0ne/Maljan/actions/workflows/ci.yml/badge.svg)](https://github.com/Root0ne/Maljan/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.13-blue)](https://www.python.org/)
[![Architecture](https://img.shields.io/badge/docs-architecture-informational)](docs/ARCHITECTURE.md)
[![Tests](https://img.shields.io/badge/tests-801%20passed-brightgreen)](tests/)

Maljan is an enterprise-grade cybersecurity analysis framework for automated, structured, and hallucination-resistant malware evaluation. It orchestrates a network of specialized LLM analyst agents that debate their findings through a structured negotiation protocol before a Chief Judge issues a validated, MITRE ATT&CK-grounded STIX 2.1 verdict.

---

## Key Capabilities

| Feature | Description |
|---|---|
| Multi-agent negotiation | Three parallel domain analysts (static, dynamic, network) exchange structured ISR reports and resolve contradictions before verdict |
| YARA Layer 0 (deterministic) | Pure-Python signature scanner runs before LLM agents — maps known patterns (VirtualAllocEx, mimikatz, vssadmin, etc.) directly to ATT&CK IDs at 0.85-0.95 confidence |
| Sigma Layer 0 (pySigma engine) | 2,946 SigmaHQ community rules across Windows, Linux, macOS, Cloud, and Network — 373 unique ATT&CK techniques via production-grade pySigma detection engine |
| Anti-echo-chamber engine | Sycophancy detection via cosine similarity; forced devil's advocate dissent when agents converge too fast |
| Adaptive termination | Rolling standard deviation convergence detection — exits negotiation early when confidence stabilizes |
| Binary chunker | Domain-aware input splitting for large samples; prevents LLM context overflow without truncation |
| Revision grounding | Multi-chunk revision rounds use consolidated ISR summaries, not raw binary data — eliminates hallucination in high-load scenarios |
| MITRE ATT&CK validation | In-memory TF-IDF index of the full ATT&CK Enterprise dataset; validates every TTP claim before STIX generation |
| Multi-layer TTP cascade | Cross-domain confidence scoring: YARA (0.90) > Sigma (0.55) > dynamic (0.45) > static (0.35) > network (0.20); corroboration multipliers up to 1.75x |
| Dynamic schema pruning | Keyword-weighted malware category inference (ransomware/RAT/dropper/worm/infostealer) narrows STIX object type guidance per sample |
| STIX 2.1 + confidence intervals | Structured, Pydantic-validated Bundle with per-relationship `x_maljan_confidence` and `x_maljan_evidence_basis` annotations |
| TIEF Classifier (Phase 4.2) | Local NLP-based MITRE ATT&CK technique extraction using HuggingFace models for high-speed, deterministic classification |
| Ghidra CFG Ordering (Phase 3) | NetworkX-powered topological sorting of function Call Graphs to ensure LLMs receive code in logical execution sequence |
| Heterogeneous model ensemble | Each agent can use a different LLM provider/model via config, reducing echo chamber risk across model families |
| LangSmith observability | Full trace visibility for all LLM calls, negotiation rounds, ISR construction, and TTP validation via `.env` opt-in |
| Long-term memory (RAG) | Past analysis cases are persisted and retrieved by cosine similarity; injected as few-shot context into every verdict call |
| Sandbox integration | `MockSandboxClient` for offline/CI use; `CAPEv2Client` for live sample submission, polling, and report ingestion via REST API |
| Empirical benchmark suite | 864 MITRE-authoritative ground truth fixtures (724 malware families + 140 TRAM2 CTI reports) for F1, hallucination rate, and cascade quality measurement |

---

## Architecture

```
Raw Artifacts (JSON/Logs)
        |
        v
[ FileDataLoader ] ---- BinaryChunker (domain-aware split for large inputs)
        |
        v
[ Parser Layer ] ---- StaticParser / DynamicParser / NetworkParser
        |
        +--------------------+--------------------+
        v                    v                    v
[ StaticAnalyst ]   [ DynamicAnalyst ]   [ NetworkAnalyst ]
  (per-agent LLM)    (per-agent LLM)     (per-agent LLM)
        |                    |                    |
        +--------------------+--------------------+
                             |
                    (ISR: AgentISR objects)
                             |
                             v
                   [ Negotiation Loop ]
                    - JudgeAgent.mediate()
                    - Sycophancy detection
                    - Forced dissent injection
                    - Adaptive convergence (rolling std)
                    - Revision grounding (ISR summaries, not raw data)
                             |
                   (consensus OR max_iterations OR confidence stable)
                             |
                             v
                   [ YaraLayer ]  <---------- Layer 0 (deterministic, pre-LLM)
                    - 40+ pattern rules -> ATT&CK IDs
                    - Confidence 0.85-0.95 (floor 0.70)
                    - Produces AgentISR(domain="yara")
                             |
                             v
                   [ SigmaLayer ]  <--------- Layer 0 (pySigma engine)
                    - 2,946 SigmaHQ community rules
                    - 373 unique ATT&CK techniques
                    - Windows / Linux / macOS / Cloud / Network
                    - Produces AgentISR(domain="sigma")
                             |
                             v
                   [ ATTCKValidator ]  <--- MITRE ATT&CK STIX bundle (cached)
                   [ TTPCascadeEngine ]  <-- multi-layer weighted scoring
                     yara=0.90 | tief=0.80 | sigma=0.55 | dynamic=0.45
                     static=0.35 | network=0.20
                   [ SchemaPruner ]  <------ malware category inference
                             |
                             v
                    [ JudgeAgent.give_verdict() ]
                     - ATT&CK TTP validation block
                     - Three-layer cascade grounding block
                     - Dynamic schema pruning hint
                     - Per-claim confidence interval instructions
                     - Long-term memory few-shot context block  <-- Phase 5
                              |
                              v
                    [ STIX 2.1 Bundle ]
                     - ConfidenceAnnotatedRelationship
                     - x_maljan_confidence per relationship
                     - x_maljan_evidence_basis annotation
                              |
                              v
                    [ InMemoryStore / QdrantStore ]  <-- Phase 5
                     - build_stored_case() persists result
                     - retrieved by next analysis run
```

---

## Pipeline Components

### Data Ingestion — `src/maljan/loaders/`

`FileDataLoader` loads JSON artifacts from `data/samples/{domain}/{sample_id}.json` and routes them through the registered parser. For samples exceeding the LLM token limit, `load_chunked()` splits the parsed text into overlapping windows using `BinaryChunker`.

**`load_from_sandbox(sample_path, data_type, sandbox_client)`** (Phase 6): Submits a sample to a sandbox backend, polls for completion, fetches the JSON report, and returns the same `list[TextChunk]` shape as `load_chunked()`. Pipeline nodes require zero changes to consume live sandbox data.

**`BinaryChunker`** (`loaders/binary_chunker.py`):
- `FUNCTION_BOUNDARY` — splits static data at Ghidra/Radare2 function headers
- `API_SEQUENCE` — splits dynamic data at PID/process boundaries
- `FLOW_SESSION` — splits network data at flow delimiters
- `SLIDING_WINDOW` — fallback for any domain without boundary markers

Configurable via `ChunkingConfig` in `.env`:
```
CHUNKING__MAX_TOKENS_PER_CHUNK=6000
CHUNKING__OVERLAP_TOKENS=200
CHUNKING__SKIP_IF_FITS=true
```

### Parsing Layer — `src/maljan/parsers/`

Domain-specific parsers strip noise from raw tool output before LLM consumption:

| Parser | Input | Key Extraction |
|---|---|---|
| `StaticParser` | Ghidra/Radare2 JSON | PE header, suspicious strings, decompiled summary |
| `DynamicParser` | CAPEv2/Cuckoo JSON | Behavioral signatures, notable API call stats |
| `NetworkParser` | Zeek connection logs | C2 flows, DNS anomalies, beaconing patterns |

New parsers can be registered with the `@register_parser("domain")` decorator — no core changes required.

### Expert Analysts — `src/maljan/agents/`

Three analysts inherit from `BaseAnalyst` and produce structured **ISR** (Intermediate Structural Representation) objects instead of raw text:

```python
class AgentISR(BaseModel):
    agent_id: str
    domain: Literal["static", "dynamic", "network"]
    claims: list[ClaimEvidence]      # each claim must cite a concrete artifact
    dissent_items: list[str]         # explicit list of peer claims still disputed
    revision_round: int
```

Each `ClaimEvidence` carries:
- `claim` — the assertion
- `evidence_ref` — concrete artifact reference (e.g., `API: WriteProcessMemory @ 0x401234`)
- `confidence` — float in [0.0, 1.0]
- `technique_id` — MITRE ATT&CK technique ID (e.g., `T1055`)

### Negotiation Engine — `src/maljan/pipeline/`

**Sycophancy Detection** (`pipeline/sycophancy_detector.py`):
Cosine similarity between the current mediator argument and the last N arguments is measured. If similarity exceeds `SYCOPHANCY_THRESHOLD`, the next revision prompt is augmented with a devil's advocate directive, forcing genuine re-evaluation.

**Adaptive Termination** (`pipeline/routing.py`):
Termination priority (highest to lowest):
1. Hard iteration limit (`NEGOTIATION__MAX_ITERATIONS`)
2. Sycophancy override (same-direction convergence detected)
3. LLM consensus (`mediator.confidence >= CONSENSUS_THRESHOLD = 0.85`)
4. Statistical convergence (rolling std of last 3 confidence values `< 0.02`)

**Revision Grounding** (`pipeline/nodes.py::_build_revision_context`):
For multi-chunk samples, revision rounds receive a consolidated ISR summary instead of the raw binary data. This prevents hallucinations that arise when an LLM is given partially-decoded binary content during later negotiation rounds.

**Negotiation State** (`pipeline/state.py`):
```python
class GraphState(TypedDict):
    reports: Annotated[dict[str, str], _merge_dicts]
    isr_reports: Annotated[dict[str, AgentISR], _merge_dicts]
    discussion_history: Annotated[list[AgentArgument], operator.add]
    confidence_history: list[float]
    sycophancy_detected: bool
    ...
```

### MITRE ATT&CK Memory — `src/maljan/memory/`

The memory module provides an authoritative grounding layer to prevent TTP hallucinations.

**`ATTCKLoader`** (`memory/attck_loader.py`):
Downloads the MITRE ATT&CK Enterprise STIX 2.1 bundle on first run and caches it locally (`~/.cache/maljan/attck/` or `MALJAN_ATTCK_CACHE` env var). Subsequent runs load from disk — no network dependency.

**`ATTCKIndex`** (`memory/attck_index.py`):
Pure-Python TF-IDF index over all technique descriptions. Provides:
- `search(text, top_k)` — semantic nearest-technique retrieval
- `get_by_id(technique_id)` — exact lookup
- `from_techniques(list)` — in-memory construction for tests

**`ATTCKValidator`** (`memory/attck_validator.py`):
Thread-safe singleton wrapping the index:
- `validate_ttp_id(id)` — existence check
- `validate_claim(id, evidence_text)` — existence + evidence-to-definition alignment
- `suggest_techniques(text, top_k)` — evidence-first alternative retrieval
- `validate_isr_reports(isr_reports)` — batch validate all ISR claims, returns `TTPValidationSummary`

**`TTPValidationSummary`** (`memory/ttp_validation.py`):
Carries per-claim validation results. `to_prompt_block()` renders a prompt-ready grounding text:
```
[HALLUCINATED] static: 'T9999' not in ATT&CK. Suggested: T1055, T1106
[SUSPICIOUS]   network: 'T1071' alignment=0.03. Evidence: registry_key_write...
```

### Multi-Layer TTP Cascade — `src/maljan/analysis/`

**`TTPCascadeEngine`** (`analysis/ttp_cascade.py`):

For each unique `technique_id` across all ISR reports (including YARA, TIEF, and Sigma):
1. Groups evidence by domain (yara / sigma / static / dynamic / network)
2. Computes per-layer mean confidence
3. Calculates domain-weighted average:
   - `yara`: weight 0.90 (deterministic signatures — Layer 0)
   - `tief`: weight 0.80 (NLP-based technique extraction — Layer 2)
   - `sigma`: weight 0.55 (pySigma rule-based detection — Layer 0)
   - `dynamic`: weight 0.45 (behavioral evidence is hardest to spoof)
   - `static`: weight 0.35 (code-level artifacts)
   - `network`: weight 0.20 (weakest alone, strongest corroborator)
4. Applies cross-layer multiplier based on number of contributing layers:
   - 1 layer → x1.00 (`SINGLE-LAYER`)
   - 2 layers → x1.25 (`CORROBORATED`)
   - 3 layers → x1.50 (`CONSENSUS`)
   - 4 layers → x1.75 (`FULL-CONSENSUS`)
   - 5 layers → x1.75 (`FULL-CONSENSUS` — YARA + Sigma + all 3 LLM domains)
5. Clips final confidence to [0.0, 1.0]

The resulting `CascadeSummary.to_prompt_block()` is injected into the Judge prompt to prioritize high-confidence, multi-corroborated TTPs.

### Dynamic Schema Pruning — `src/maljan/analysis/schema_pruner.py`

Implements the CTI-GEN (IEEE CSR 2025) schema-pruning methodology. Before verdict generation, the combined analyst reports and ISR claims are scored against keyword dictionaries to infer the malware's behavioral category:

| Category | Key Indicators |
|---|---|
| `RANSOMWARE` | encrypt, ransom, bitcoin, T1486, vssadmin, shadow |
| `RAT` | backdoor, reverse shell, C2, beacon, T1095 |
| `DROPPER` | loader, stage, URLDownloadToFile, certutil, T1105 |
| `WORM` | propagate, self-replicate, SMB, T1091, network share |
| `INFOSTEALER` | keylog, credential dump, mimikatz, exfiltrate, T1003 |

When a category is detected, a focused schema hint is injected into the Judge's system prompt, guiding STIX object type selection toward category-relevant SDOs and deprioritizing unrelated types. Returns empty string for `UNKNOWN` (no pruning applied — full schema used).

### STIX 2.1 Confidence Intervals — `src/maljan/schemas/stix_models.py`

Relationships in the output Bundle are enriched with per-claim confidence metadata using the STIX 2.1 custom property convention:

```python
class ConfidenceAnnotatedRelationship(Relationship):
    x_maljan_confidence: float             # cascade-informed [0.0, 1.0]
    x_maljan_evidence_basis: EvidenceBasis # "static_only" | "corroborated" | "consensus"
    x_maljan_technique_layers: int         # number of domains confirming this TTP
    x_maljan_rationale: str | None         # one-sentence justification
```

`EvidenceBasis` vocabulary maps directly to the cascade engine's corroboration levels, allowing downstream SIEM/SOAR platforms to filter relationships by evidential strength.

### Chief Judge — `src/maljan/agents/judge_agent.py`

`JudgeAgent` is not a domain analyst. It performs two tasks:

**`mediate(reports, history, isr_reports)`**: Finds contradictions between expert reports using `with_structured_output(MediatorVerdict)`. Falls back to text-based confidence extraction for providers that do not support structured output (e.g., some Ollama models).

**`give_verdict(reports, history, isr_reports, attck_validator, cascade_summary, memory_store)`**:
Before calling the LLM, injects five grounding blocks into the system prompt:
1. ATT&CK TTP validation block — flags hallucinated IDs, suggests alternatives
2. Three-layer cascade block — ranks TTPs by cross-domain weighted confidence
3. Dynamic schema pruning hint — focuses STIX object types on detected category
4. Confidence interval instructions — guides per-relationship `x_maljan_confidence` values
5. Long-term memory context block (Phase 5) — top-k similar past cases as few-shot priors

All blocks are optional and degrade gracefully — if the ATT&CK cache has not been built (offline environment), verdict generation continues without validation.

---

## Long-Term Memory / RAG (Phase 5)

Past analysis results are persisted as `StoredCase` objects and retrieved by cosine similarity over ISR claim text. Retrieved cases are injected into the Judge prompt as few-shot context before every verdict LLM call.

**`StoredCase`** (`memory/long_term_memory.py`): Captures `sample_id`, `summary_text` (built from all ISR claims and evidence references), `technique_ids`, `malware_category`, and `stix_bundle_json`.

**`MemoryStore` Protocol** (`memory/long_term_memory.py`): `store()`, `retrieve(query, top_k)`, `count()`, `clear()`. `@runtime_checkable` — swap backends without changing caller code.

**`InMemoryStore`** (`memory/in_memory_store.py`): Pure-Python TF cosine similarity. Zero external dependencies. Upsert semantics (same `sample_id` replaces old entry).

**`QdrantStore`** (`memory/qdrant_store.py`): Full Qdrant vector database backend. Uses a deterministic hash-trick embedding (512-dim, no external model) with `query_points()` for similarity search. Auto-creates collection on first `store()` call. Upsert semantics via stable SHA-256 point IDs. Requires `uv add qdrant-client` and a running Qdrant instance.

**`build_stored_case(sample_id, isr_reports, stix_bundle_json, malware_category)`**: Factory that builds a `StoredCase` from pipeline artifacts — called automatically in `make_judge_node()` after every successful verdict.

Configuration:
```bash
MEMORY__BACKEND=memory          # in-process (default)
# or:
MEMORY__BACKEND=qdrant
MEMORY__QDRANT_URL=http://localhost:6333
MEMORY__QDRANT_COLLECTION=maljan_cases
MEMORY__TOP_K=3
```

---

## YARA Layer 0 — Deterministic ATT&CK Grounding

**`YaraLayer`** (`analysis/yara_layer.py`):

The deterministic pre-LLM grounding step. Runs before the cascade engine and produces a synthetic `AgentISR` with `domain="yara"`. No external dependencies — pure Python regex matching.

**Rule format** (`data/yara_ttp_rules.yaml`):
```yaml
rules:
  - id: proc_injection_classic
    technique_id: "T1055"
    confidence: 0.88
    description: "Classic process injection via VirtualAllocEx + WriteProcessMemory"
    patterns: ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
```

The baseline rule set ships with 40+ rules covering:

| Category | Example Techniques |
|---|---|
| Process Injection | T1055, T1055.001, T1055.002, T1055.012 |
| Command Execution | T1059.001 (PowerShell), T1059.003 (cmd), T1218.005 (mshta) |
| Persistence | T1547.001 (Registry Run), T1053.005 (Scheduled Task), T1543.003 (Service) |
| Defense Evasion | T1027 (Obfuscation), T1562.001 (Disable AV), T1070.001 (Event Log) |
| Credential Access | T1003 (LSASS/Mimikatz), T1056.001 (Keylogger), T1555 (Vault) |
| C2 | T1071.001 (HTTP), T1071.004 (DNS), T1095 (Raw Socket) |
| Impact | T1486 (Ransomware), T1489 (Service Stop), T1490 (Shadow Delete) |

**Integration in the pipeline**:
- Input: `state["reports"]` (LLM summaries) + ISR `evidence_ref` fields
- YARA domain weight in cascade: **0.90** (highest — deterministic)
- 5-layer full-consensus multiplier: **x1.75**

**Extensibility**: Add new rules to `data/yara_ttp_rules.yaml` — zero code changes required.

---

## Sigma Layer 0 — pySigma Detection Engine

**`SigmaLayer`** (`analysis/sigma_layer.py`):

Production-grade detection layer powered by the [pySigma](https://github.com/SigmaHQ/pySigma) engine. Loads and evaluates Sigma detection rules from the [SigmaHQ](https://github.com/SigmaHQ/sigma) community repository — the industry-standard rule source used by SOC Prime, Elastic, Splunk, QRadar, and 20+ security platforms.

**Rule source**: 2,946 peer-reviewed rules from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License).

| Platform | Rules |
|---|---|
| Windows | 2,390 |
| Cloud (AWS, Azure, GCP, Google Workspace, Microsoft 365) | 226 |
| Linux | 209 |
| macOS | 69 |
| Network | 52 |
| **Total** | **2,946** |

**ATT&CK coverage**: **373 unique technique IDs** extracted from rule tags (e.g., `attack.t1003.001`).

**Two scan modes**:
- `scan_events(events, log_source)` — structured event matching (JSON/dict)
- `scan_log_lines(lines, log_source)` — unstructured text matching with heuristic field extraction

**Confidence scoring**: Based on rule `status` field:
- `stable` → 0.88
- `test` → 0.80
- `experimental` → 0.70
- Fallback → 0.65

**Integration in the pipeline**:
- Runs inside `make_judge_node()` immediately after YARA Layer
- Input: analyst report text + ISR evidence references
- Output: `AgentISR(domain="sigma")` injected into TTP Cascade
- Sigma domain weight in cascade: **0.55**

**Performance**:
- Rule loading: ~4s (one-time; cached via `ServiceContainer` singleton)
- Scan time: ~2.4s per 5-line batch

**Extensibility**: Drop new `.yml` rule files into `data/sigma_rules/` subdirectories — zero code changes required. SigmaHQ rules can be updated via `git pull` or CI/CD sync script.

---

## Evaluation Benchmark Framework

**Ground truth sources** (2 complementary datasets, 864 total fixtures):

| Source | Fixtures | Coverage | Question Answered |
|---|---|---|---|
| MITRE ATT&CK malware relationships | 724 | 724 malware/tool families | "Does Maljan correctly attribute known malware to its TTPs?" |
| TRAM2 CTI threat reports | 140 | Real-world threat intelligence reports | "Can the LLM layer extract TTPs from unstructured text?" |

**Validation universe**: `data/attck_valid_ids.json` — **691** active ATT&CK Enterprise technique IDs. Used to compute hallucination rate: any predicted TTP ID not in this set (or in the TRAM2-observed set) is classified as a hallucination.

**Generate ground truth fixtures**:
```bash
make prepare-attck   # Downloads ATT&CK bundle, generates 724 malware fixtures
make prepare-tram    # Downloads TRAM2 dataset, generates 140 CTI report fixtures
```

**Run the benchmark suite**:
```bash
make benchmark-attck   # Synthetic perfect-match baseline for ATT&CK fixtures
```

**Metrics computed**:
- `ttp_accuracy.f1` — precision/recall F1 over predicted vs. ground-truth technique IDs
- `ttp_accuracy.hallucination_rate` — fraction of predictions not in the valid universe
- `negotiation.efficiency_ratio` — rounds_used / max_rounds
- `stix_quality.confidence_coverage` — fraction of STIX relationships with confidence annotations

---

`SandboxClient` is a `@runtime_checkable` Protocol with three methods: `submit()`, `wait_for_completion()`, `fetch_report()`. Two backends are provided:

**`MockSandboxClient`** (`loaders/mock_sandbox_client.py`): Fixture-backed backend for tests and offline use. Looks up fixture files by SHA-256 hash, then sample name, then an optional default fixture, then returns a minimal synthetic report. No network access required.

**`CAPEv2Client`** (`loaders/cape2_client.py`): Full REST API client using `httpx`. Submits samples via `POST /apiv2/tasks/create/file/`, polls status via `GET /apiv2/tasks/view/{id}/`, and fetches reports via `GET /apiv2/tasks/report/{id}/`. Supports API token authentication, configurable timeout, and persistent connection pooling.

**`SubmissionResult`**: Carries `task_id`, `sample_sha256`, `status`, and `report` dict — same structure as existing fixture JSON files, so `DynamicParser` and `NetworkParser` require zero changes.

The container exposes `get_sandbox_client()` which builds the configured backend once and caches it:

```bash
SANDBOX__BACKEND=mock           # fixture files (default)
# or:
SANDBOX__BACKEND=cape2
SANDBOX__CAPE2_BASE_URL=http://cape2-host:8000
SANDBOX__CAPE2_API_TOKEN=your_token
SANDBOX__CAPE2_TIMEOUT_SECONDS=300
```

Usage:
```python
client = app.container.get_sandbox_client()
chunks = app.container.loader.load_from_sandbox(
    sample_path="malware.exe",
    data_type="dynamic",
    sandbox_client=client,
)
# chunks: list[TextChunk] — identical to load_chunked() output
```

---

## Ghidra MCP Headless Server

Maljan integrates with **Ghidra** via a headless REST API server running in Docker. No GUI, no WSL, no X11 required — the container exposes 165 analysis endpoints (decompile, xrefs, strings, imports, anti-analysis detection, etc.) over HTTP.

### Architecture

```
StaticAnalyst ──► GhidraHTTPClient ──► http://ghidra-mcp:8089
                      │
                      ├── /load_program         (load binary into Ghidra)
                      ├── /decompile_function   (C pseudocode)
                      ├── /list_imports         (suspicious API detection)
                      ├── /get_xrefs_to         (cross-reference tracing)
                      ├── /find_anti_analysis_techniques
                      └── /detect_malware_behaviors
```

### Configuration

Ghidra MCP supports two transports. The headless Docker deployment uses **HTTP**:

```bash
# .env — HTTP transport (recommended for Docker)
MCP__GHIDRA__ENABLED=true
MCP__GHIDRA__TRANSPORT=http
MCP__GHIDRA__URL=http://localhost:8089
MCP__GHIDRA__AUTH_TOKEN=maljan_ghidra_secret_2026
```

Legacy stdio transport (requires WSL + local Python bridge) is still supported:
```bash
# .env — stdio transport (legacy, local dev only)
MCP__GHIDRA__ENABLED=true
MCP__GHIDRA__TRANSPORT=stdio
MCP__GHIDRA__COMMAND=wsl.exe
MCP__GHIDRA__ARGS=["-d", "Ubuntu", "-e", "python", "external/ghidra-mcp/bridge_mcp_ghidra.py"]
```

### Lifecycle Management

The `scripts/ghidra_manager.py` tool automates version sync, smart rebuilds, and file watching:

```bash
# Check version alignment between pom.xml and Dockerfile
make ghidra-status

# Sync Dockerfile ARGs with pom.xml (auto-fetches release date from GitHub)
make ghidra-sync

# Smart rebuild — detects what changed and rebuilds only if necessary
make ghidra-build

# Auto-rebuild on every Java source file change (development mode)
make ghidra-watch
```

**How smart rebuild works:**
- Computes SHA-256 hash of all `src/**/*.java` files
- Tracks `Dockerfile` and `pom.xml` hashes in `.ghidra_mcp_state.json`
- If source changed → incremental rebuild (~1-2 min)
- If version/date changed → full `--no-cache` rebuild (~3-5 min, re-downloads Ghidra ZIP)
- If nothing changed → exits immediately with "already up-to-date"

### Updating Ghidra

When NSA releases a new Ghidra version (e.g., 12.0.4 → 12.0.5):

1. Update `external/ghidra-mcp/pom.xml`:
   ```xml
   <ghidra.version>12.0.5</ghidra.version>
   ```
2. Run `make ghidra-sync` — auto-updates `Dockerfile` ARGs and fetches release date from GitHub
3. Run `make ghidra-build` — performs full `--no-cache` rebuild

---

## Heterogeneous Model Ensemble

By default all agents share the global expert LLM. To reduce echo chamber risk, assign different model families to different agents:

```bash
# .env — each agent gets a dedicated provider/model
LLM__AGENTS__STATIC__PROVIDER=anthropic
LLM__AGENTS__STATIC__MODEL=claude-3-5-sonnet-20241022

LLM__AGENTS__DYNAMIC__PROVIDER=openai
LLM__AGENTS__DYNAMIC__MODEL=gpt-4o

LLM__AGENTS__NETWORK__PROVIDER=ollama
LLM__AGENTS__NETWORK__MODEL=llama3.1:8b

# Optional per-agent temperature override (default: 0.1)
LLM__AGENTS__STATIC__TEMPERATURE=0.15
```

Agents without an explicit entry fall back to the global expert LLM. The result is cached per agent name — no redundant client initialization across negotiation rounds.

Research basis: ReConcile (Chen et al., 2023) and Wu et al. (2024) demonstrate that heterogeneous model ensembles reduce sycophancy and improve factual accuracy compared to single-model multi-agent systems.

---

## LangSmith Observability

Full trace visibility into every LLM call, negotiation round, ISR construction, and TTP validation — zero code changes required.

```bash
# .env
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=ls_xxxxxxxxxxxxxxxx
LANGCHAIN_PROJECT=maljan-dev         # optional, default: "maljan"
```

When `LANGCHAIN_TRACING_V2=true`, `ServiceContainer._configure_langsmith()` propagates these settings into the OS environment variables that LangChain reads automatically. All downstream chains and LLM calls are traced without any explicit instrumentation.

The API key's last 4 characters are logged at startup; the full key never appears in logs.

---

## Configuration Reference

All settings are Pydantic `BaseSettings` with `__` as the nesting delimiter. Values can be set in `.env` or as environment variables.

### LLM Provider

| Variable | Default | Description |
|---|---|---|
| `LLM__PROVIDER` | `openai` | Active LLM backend (`openai`, `anthropic`, `ollama`) |
| `LLM__OPENAI__API_KEY` | — | OpenAI API key |
| `LLM__OPENAI__EXPERT_MODEL` | `gpt-4o-mini` | Model for analyst agents (global) |
| `LLM__OPENAI__JUDGE_MODEL` | `gpt-4o` | Model for JudgeAgent |
| `LLM__ANTHROPIC__API_KEY` | — | Anthropic API key |
| `LLM__ANTHROPIC__EXPERT_MODEL` | `claude-sonnet-4-20250514` | Anthropic expert model |
| `LLM__OLLAMA__BASE_URL` | `http://localhost:11434` | Ollama server URL |
| `LLM__OLLAMA__EXPERT_MODEL` | `qwen2.5-coder:7b` | Ollama expert model |
| `LLM__OLLAMA__JUDGE_MODEL` | `llama3.1:70b` | Ollama judge model |

### Heterogeneous Ensemble (per-agent overrides)

| Variable | Default | Description |
|---|---|---|
| `LLM__AGENTS__<NAME>__PROVIDER` | — | Override provider for agent `<name>` |
| `LLM__AGENTS__<NAME>__MODEL` | — | Override model for agent `<name>` |
| `LLM__AGENTS__<NAME>__TEMPERATURE` | `0.1` | Override temperature for agent `<name>` |

`<name>` is the agent registry key: `static`, `dynamic`, `network`.

### Negotiation Engine

| Variable | Default | Description |
|---|---|---|
| `NEGOTIATION__MAX_ITERATIONS` | `20` | Safety ceiling; adaptive termination exits earlier |
| `NEGOTIATION__CONSENSUS_THRESHOLD` | `0.85` | Confidence level for early consensus exit |

### Binary Chunker

| Variable | Default | Description |
|---|---|---|
| `CHUNKING__MAX_TOKENS_PER_CHUNK` | `6000` | Max tokens per data chunk sent to LLM |
| `CHUNKING__OVERLAP_TOKENS` | `200` | Overlap between adjacent chunks (context preservation) |
| `CHUNKING__SKIP_IF_FITS` | `true` | Skip chunking when data fits within token limit |

### Observability

| Variable | Default | Description |
|---|---|---|
| `LANGCHAIN_TRACING_V2` | `false` | Enable LangSmith trace collection |
| `LANGCHAIN_API_KEY` | — | LangSmith authentication key |
| `LANGCHAIN_PROJECT` | `maljan` | LangSmith project name |

### Long-Term Memory (Phase 5)

| Variable | Default | Description |
|---|---|---|
| `MEMORY__BACKEND` | `memory` | `memory` (in-process) or `qdrant` (persistent) |
| `MEMORY__QDRANT_URL` | `http://localhost:6333` | Qdrant server URL |
| `MEMORY__QDRANT_COLLECTION` | `maljan_cases` | Qdrant collection name |
| `MEMORY__TOP_K` | `3` | Max similar past cases injected into judge prompt |

### Sandbox Integration (Phase 6)

| Variable | Default | Description |
|---|---|---|
| `SANDBOX__BACKEND` | `mock` | `mock` (fixtures) or `cape2` (live REST API) |
| `SANDBOX__CAPE2_BASE_URL` | `http://localhost:8000` | CAPEv2 server URL |
| `SANDBOX__CAPE2_API_TOKEN` | — | CAPEv2 API token (empty for unauthenticated instances) |
| `SANDBOX__CAPE2_TIMEOUT_SECONDS` | `300` | Max wait time for task completion |
| `SANDBOX__CAPE2_POLL_INTERVAL_SECONDS` | `10` | Seconds between status poll requests |

### Miscellaneous

| Variable | Default | Description |
|---|---|---|
| `MAX_TOKEN_LIMIT` | `128000` | Global token safety cap (Gemini 1M+ compatible) |
| `MALJAN_ATTCK_CACHE` | `~/.cache/maljan/attck/` | ATT&CK bundle cache directory |

### Ghidra MCP

| Variable | Default | Description |
|---|---|---|
| `MCP__GHIDRA__ENABLED` | `false` | Enable Ghidra MCP integration |
| `MCP__GHIDRA__TRANSPORT` | `stdio` | `http` (headless Docker) or `stdio` (legacy WSL) |
| `MCP__GHIDRA__URL` | — | HTTP transport URL (e.g., `http://localhost:8089`) |
| `MCP__GHIDRA__AUTH_TOKEN` | — | Bearer token for HTTP transport authentication |
| `MCP__GHIDRA__COMMAND` | — | stdio transport: executable path |
| `MCP__GHIDRA__ARGS` | `[]` | stdio transport: command-line arguments (JSON array) |

---

## Security

### Dependency Audit (April 2026)

| Package | Change | Reason |
|---|---|---|
| `mcp` | `1.0.0` → `1.27.0` | CVE-2025-53365 / CVE-2025-53366 (CVSS 8.7) |
| `django` | Removed | GPL-1.0+ license risk; not used in codebase |
| `pymongo` | Removed | No MongoDB integration; unused dependency |
| `pillow` | Removed | GPL-2.0 license risk; not used in codebase |
| `python-magic-bin` | Removed | Windows-only binary; incompatible on Linux |

To verify no high/critical CVEs are present in current dependencies:
```bash
uv run pip-audit
```

---

## Installation

**Requirements**: Python 3.13+, [uv](https://astral.sh/uv/)

```bash
# 1. Clone the repository
git clone https://github.com/Root0ne/Maljan.git
cd Maljan

# 2. Install dependencies
uv sync

# 3. Configure environment
cp .env.example .env
# Edit .env — add your API key and set LLM__PROVIDER

# 4. Run the test suite
make check

# 5. Run a mock analysis (no API key required)
uv run maljan analyze sample_1 --mock --name test.exe

# 6. Pre-build the ATT&CK index cache (optional, recommended before first real run)
uv run python -c "from maljan.memory.attck_validator import ATTCKValidator; ATTCKValidator.get_instance()"
```

---

## Development

```bash
# Run all tests
uv run pytest tests/ -q

# Lint + format check
uv run ruff check src/ tests/
uv run ruff format --check src/ tests/

# Type check
uv run mypy src/

# All quality gates at once
make check
```

---

## Recommended Stack

| Component | Tool | Notes |
|---|---|---|
| LLM (cloud) | OpenAI `gpt-4o` (judge) + `gpt-4o-mini` (experts) | Best structured output support |
| LLM (local) | Ollama `llama3.1:70b` (judge) + `qwen2.5-coder:7b` (experts) | Air-gapped environments |
| Heterogeneous ensemble | Anthropic (static) + OpenAI (dynamic) + Ollama (network) | Maximum model family diversity |
| Sandbox | CAPEv2 (automatable via REST API) | Dynamic analysis source |
| Static analysis | Ghidra MCP Headless (Docker) + Radare2 | Decompilation, xrefs, strings, anti-analysis detection via REST API |
| Network capture | Zeek | PCAP to structured JSON |
| Output format | STIX 2.1 | Interoperable with SIEM/SOAR platforms |
| Observability | LangSmith | Full trace visibility; opt-in via `.env` |

---

## Design Principles

- **No hallucinated TTPs**: Every TTP ID claimed by an agent is validated against the authoritative ATT&CK dataset before the STIX bundle is generated.
- **No silent truncation**: The binary chunker splits large inputs into overlapping windows with context preservation — data is never silently cut off.
- **No sycophancy**: Agents cannot passively agree. Active dissent is required; cosmetic convergence triggers forced re-evaluation.
- **Grounded revision rounds**: Multi-chunk revision passes use ISR summaries as context, not raw binary data — preventing hallucinations caused by partially-decoded content.
- **Category-aware STIX generation**: Dynamic schema pruning focuses the judge on malware-specific STIX object types, reducing signal noise in the output bundle.
- **Per-claim uncertainty quantification**: Every relationship in the STIX output carries a cascade-informed confidence score and evidence basis, enabling downstream SIEM/SOAR platforms to filter by evidential strength.
- **Graceful degradation**: ATT&CK cache, TTP validation, cascade scoring, schema pruning, LangSmith tracing, long-term memory retrieval, and sandbox integration are all optional at runtime. The pipeline always produces a verdict, even in offline or restricted environments.
- **Dependency minimization**: All statistical computation (rolling std, TF-IDF cosine similarity, cascade weighting, keyword scoring, term-frequency retrieval) is implemented in pure Python to avoid runtime dependency overhead.
- **Few-shot learning from history**: Each completed analysis is persisted to the long-term memory store. Subsequent analyses retrieve the most similar past cases and inject them as weighted priors into the judge prompt, improving TTP selection consistency over time.
- **Protocol-based extensibility**: `MemoryStore`, `SandboxClient`, and `DataLoaderProtocol` are all `@runtime_checkable` Protocols. New backends (e.g., Pinecone, DragonFly sandbox) can be swapped in by implementing the Protocol — no changes to pipeline nodes or agent code required.

---

## Web UI (GTI-Inspired Dashboard)

Maljan includes a professional web interface built with **Next.js 16** and inspired by **Google Threat Intelligence**.

### Features

| Page | Description |
|---|---|
| Dashboard | Overview metrics, recent analyses, verdict distribution charts |
| Samples | Upload, manage, and trigger analysis of malware samples |
| Jobs | Monitor running and completed analysis jobs with status tracking |
| Analysis Detail | 6-tab detailed view: Summary, Agents, Rules, TTPs, Timeline, STIX |
| Live Analysis | Real-time WebSocket-powered analysis event stream |
| Reports | Filterable report list with PDF/JSON/STIX export capability |
| Settings | API key management, analysis configuration, application info |

### Design Language

- **Dark-first, flat design** — no gradients, no glassmorphism
- **Color palette**: `#0d1117` deep background, `#161b22` surface, `#4493f8` accent
- **Typography**: Inter (UI) + JetBrains Mono (code)
- **Verdict badges**: Red (malicious), Orange (suspicious), Green (benign), Gray (unknown)

### Running the Frontend

```bash
cd apps/web
npm install
npm run dev          # Development server on http://localhost:3000
npm run build        # Production build verification
```

---

## Full-Stack Docker Deployment

All infrastructure and application services run in Docker — no WSL or local package installations required.

```bash
# Copy environment template and configure
cp .env.example .env
# Edit .env with your API keys and LLM provider settings

# Windows host: PostgreSQL may conflict on port 5432
$env:POSTGRES_PORT="5433"

# Start all 8 services (build on first run)
cd docker
docker compose up -d --build

# Verify all services are healthy
docker compose ps

# Access the application
# Frontend:      http://localhost:3000
# Backend API:   http://localhost:8000/docs
# Ghidra MCP:    http://localhost:8089/check_connection
# MinIO Console: http://localhost:9001
```

### Service Architecture

| Service | Container | Port | Purpose |
|---|---|---|---|
| PostgreSQL 16 | maljan-postgres | 5433 | Relational data store (mapped to 5433 to avoid host conflict) |
| Redis 7 | maljan-redis | 6379 | Task queue, PubSub, cache |
| Qdrant | maljan-qdrant | 6333 | Vector database (LTM / RAG) |
| MinIO | maljan-minio | 9000/9001 | S3-compatible object storage |
| Ghidra MCP | maljan-ghidra-mcp | 8089 | Headless static analysis engine (Java/Ghidra) |
| Backend API | maljan-api | 8000 | FastAPI application server |
| Worker | maljan-worker | — | ARQ background task runner |
| Frontend | maljan-frontend | 3000 | Next.js web interface |

### Ollama Connectivity (Windows)

Containers cannot reach the host's Ollama via `localhost:11434`. The compose file automatically sets `LLM__OLLAMA__BASE_URL=http://host.docker.internal:11434` for backend and worker services. If your Ollama runs on a different host:

```powershell
$env:OLLAMA_HOST_URL="http://192.168.1.100:11434"
docker compose up -d --build
```
