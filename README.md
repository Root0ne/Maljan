# Maljan: Adaptive Multi-Agent Malware Analysis Framework

Maljan is an enterprise-grade cybersecurity analysis framework for automated, structured, and hallucination-resistant malware evaluation. It orchestrates a network of specialized LLM analyst agents that debate their findings through a structured negotiation protocol before a Chief Judge issues a validated, MITRE ATT&CK-grounded STIX 2.1 verdict.

---

## Key Capabilities

| Feature | Description |
|---|---|
| Multi-agent negotiation | Three parallel domain analysts (static, dynamic, network) exchange structured ISR reports and resolve contradictions before verdict |
| Anti-echo-chamber engine | Sycophancy detection via cosine similarity; forced devil's advocate dissent when agents converge too fast |
| Adaptive termination | Rolling standard deviation convergence detection — exits negotiation early when confidence stabilizes |
| Binary chunker | Domain-aware input splitting for large samples; prevents LLM context overflow without truncation |
| Revision grounding | Multi-chunk revision rounds use consolidated ISR summaries, not raw binary data — eliminates hallucination in high-load scenarios |
| MITRE ATT&CK validation | In-memory TF-IDF index of the full ATT&CK Enterprise dataset; validates every TTP claim before STIX generation |
| Three-layer TTP cascade | Cross-domain confidence scoring with corroboration multipliers (single-layer / corroborated / consensus) |
| Dynamic schema pruning | Keyword-weighted malware category inference (ransomware/RAT/dropper/worm/infostealer) narrows STIX object type guidance per sample |
| STIX 2.1 + confidence intervals | Structured, Pydantic-validated Bundle with per-relationship `x_maljan_confidence` and `x_maljan_evidence_basis` annotations |
| Heterogeneous model ensemble | Each agent can use a different LLM provider/model via config, reducing echo chamber risk across model families |
| LangSmith observability | Full trace visibility for all LLM calls, negotiation rounds, ISR construction, and TTP validation via `.env` opt-in |

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
                   [ ATTCKValidator ]  <--- MITRE ATT&CK STIX bundle (cached)
                   [ TTPCascadeEngine ]  <-- three-layer weighted scoring
                   [ SchemaPruner ]  <------ malware category inference
                             |
                             v
                   [ JudgeAgent.give_verdict() ]
                    - ATT&CK TTP validation block
                    - Three-layer cascade grounding block
                    - Dynamic schema pruning hint
                    - Per-claim confidence interval instructions
                             |
                             v
                   [ STIX 2.1 Bundle ]
                    - ConfidenceAnnotatedRelationship
                    - x_maljan_confidence per relationship
                    - x_maljan_evidence_basis annotation
```

---

## Pipeline Components

### Data Ingestion — `src/maljan/loaders/`

`FileDataLoader` loads JSON artifacts from `data/samples/{domain}/{sample_id}.json` and routes them through the registered parser. For samples exceeding the LLM token limit, `load_chunked()` splits the parsed text into overlapping windows using `BinaryChunker`.

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

### Three-Layer TTP Cascade — `src/maljan/analysis/`

**`TTPCascadeEngine`** (`analysis/ttp_cascade.py`):

For each unique `technique_id` across all ISR reports:
1. Groups evidence by domain (static / dynamic / network)
2. Computes per-layer mean confidence
3. Calculates domain-weighted average:
   - `dynamic`: weight 0.45 (behavioral evidence is hardest to spoof)
   - `static`: weight 0.35 (code-level artifacts)
   - `network`: weight 0.20 (weakest alone, strongest corroborator)
4. Applies cross-layer multiplier based on number of contributing layers:
   - 1 layer → x1.00 (`SINGLE-LAYER`)
   - 2 layers → x1.25 (`CORROBORATED`)
   - 3 layers → x1.50 (`CONSENSUS`)
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

**`give_verdict(reports, history, isr_reports, attck_validator, cascade_summary)`**:
Before calling the LLM, injects four grounding blocks into the system prompt:
1. ATT&CK TTP validation block — flags hallucinated IDs, suggests alternatives
2. Three-layer cascade block — ranks TTPs by cross-domain weighted confidence
3. Dynamic schema pruning hint — focuses STIX object types on detected category
4. Confidence interval instructions — guides per-relationship `x_maljan_confidence` values

All blocks are optional and degrade gracefully — if the ATT&CK cache has not been built (offline environment), verdict generation continues without validation.

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
| `NEGOTIATION__MAX_ITERATIONS` | `2` | Hard iteration cap |
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

### Miscellaneous

| Variable | Default | Description |
|---|---|---|
| `MAX_TOKEN_LIMIT` | `8000` | Global token safety cap |
| `MALJAN_ATTCK_CACHE` | `~/.cache/maljan/attck/` | ATT&CK bundle cache directory |

---

## Project Structure

```text
Maljan/
├── data/samples/
│   ├── static/                     # Ghidra / Radare2 JSON output
│   ├── dynamic/                    # CAPEv2 / Cuckoo behavioral JSON
│   └── network/                    # Zeek connection log JSON
├── src/maljan/
│   ├── analysis/
│   │   ├── schema_pruner.py        # Malware category inference + STIX schema hints
│   │   └── ttp_cascade.py          # Three-layer TTP confidence cascade engine
│   ├── agents/
│   │   ├── base_agent.py           # BaseAnalyst ABC — analyze_isr / revise_isr
│   │   ├── judge_agent.py          # Mediator + verdict; ATT&CK/cascade/schema grounding
│   │   ├── registry.py             # @register_agent + AgentRegistry
│   │   ├── static_analyst.py       # PE / Ghidra analysis
│   │   ├── dynamic_analyst.py      # Sandbox behavioral analysis
│   │   └── network_analyst.py      # Network traffic / C2 analysis
│   ├── core/
│   │   ├── config.py               # Hierarchical Settings (LLM, chunking, ensemble, tracing)
│   │   ├── container.py            # ServiceContainer (DI + caching + LangSmith setup)
│   │   ├── exceptions.py           # Exception hierarchy
│   │   ├── logger.py               # Centralized structured logging
│   │   └── protocols.py            # typing.Protocol contracts
│   ├── llm/
│   │   ├── registry.py             # @register_provider + LLMProviderRegistry
│   │   │                           #   build_model() + build_model_for_agent()
│   │   ├── openai_provider.py
│   │   ├── anthropic_provider.py
│   │   └── ollama_provider.py
│   ├── loaders/
│   │   ├── file_loader.py          # FileDataLoader — load() + load_chunked()
│   │   └── binary_chunker.py       # Domain-aware chunker + merge_summaries
│   ├── memory/
│   │   ├── attck_loader.py         # ATT&CK STIX bundle downloader + cache
│   │   ├── attck_index.py          # Pure-Python TF-IDF semantic index
│   │   ├── attck_validator.py      # Thread-safe singleton validator
│   │   └── ttp_validation.py       # TTPClaimValidation + TTPValidationSummary
│   ├── parsers/
│   │   ├── base_parser.py
│   │   ├── registry.py             # @register_parser + ParserRegistry
│   │   ├── static_parser.py
│   │   ├── dynamic_parser.py
│   │   └── network_parser.py
│   ├── pipeline/
│   │   ├── state.py                # GraphState TypedDict + LangGraph reducers
│   │   ├── nodes.py                # Node factories + _build_revision_context()
│   │   ├── builder.py              # Dynamic graph builder (parallel fan-out)
│   │   ├── routing.py              # Adaptive termination router
│   │   ├── sycophancy_detector.py  # Cosine similarity sycophancy guard
│   │   └── mediation_models.py     # MediatorVerdict structured output schema
│   ├── schemas/
│   │   ├── stix_models.py          # STIX 2.1 Bundle + ConfidenceAnnotatedRelationship
│   │   ├── isr_models.py           # AgentISR + ClaimEvidence
│   │   └── mediation_models.py     # MediatorVerdict
│   ├── app.py                      # MaljanApp facade (composition root)
│   └── cli.py                      # Typer CLI
├── tests/
│   ├── unit/                       # 477 unit tests (no network, no LLM)
│   └── integration/                # Full pipeline tests (mock mode)
├── .env.example
└── Makefile
```

---

## Installation

**Requirements**: Python 3.11+, [uv](https://astral.sh/uv/)

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
| Static analysis | Ghidra + Radare2 | Decompilation + string extraction |
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
- **Graceful degradation**: ATT&CK cache, TTP validation, cascade scoring, schema pruning, and LangSmith tracing are all optional at runtime. The pipeline always produces a verdict, even in offline or restricted environments.
- **Dependency minimization**: All statistical computation (rolling std, TF-IDF cosine similarity, cascade weighting, keyword scoring) is implemented in pure Python to avoid runtime dependency overhead.
