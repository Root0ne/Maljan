# Maljan: Architecture Design & Project Status

This document describes the architectural design, completed components, and future roadmap of the Maljan Multi-Agent Malware Analysis Framework.

---

## Architecture Overview

Maljan is a multi-layered LLM-based analysis framework where specialized expert agents analyze malware from three different perspectives, negotiate with each other, and a chief judge delivers the final verdict.

```
                    +------------------+
                    |   CLI (typer)    |
                    +--------+---------+
                             |
                    +--------v---------+
                    |   MaljanApp      |  <-- Composition Root
                    | (ServiceContainer)|
                    +--------+---------+
                             |
          +------------------+------------------+
          |                  |                  |
 +--------v---+     +--------v---+     +--------v---+
 |   Static   |     |  Dynamic   |     |   Network  |  <-- Parallel Fan-Out
 |  Analyst   |     |  Analyst   |     |   Analyst  |      (@register_agent)
 +------+-----+     +-----+------+     +------+-----+
          |                  |                  |
          +------------------+------------------+
                             |         Fan-In (LangGraph waits for all)
                    +--------v---------+
                    |   Negotiation    |  <-- Negotiation Loop
                    |   (Mediator)     |      MediatorVerdict (structured output)
                    +--------+---------+
                             |
                     consensus? -------+
                     |  no             | yes
              +------v-------+  +-----v------+
              |   Revision   |  |   Judge    |  <-- Final Decision
              |   (Loop)     |  |  (Verdict) |      (Standalone class)
              +--------------+  +-----+------+
                                      |
                              +-------v-------+
                              |  STIX 2.1     |
                              |  Bundle       |
                              +---------------+
```

---

## Layer 1: Data Enrichment & Pre-processing

LLM agents cannot process raw binary files (e.g., a `.exe`) directly. The first step of the system is an automation pipeline that decomposes malware across three distinct dimensions.

- **Static Data Extraction:** The binary is passed through `Ghidra` or `Radare2` command-line tools to obtain decompiled code snippets, string values, and PE header information.

- **Dynamic Behavior Extraction:** The file is executed in an isolated `CAPEv2` or `Cuckoo Sandbox` environment. System calls (API calls), filesystem activity, and registry changes are captured in JSON format.

- **Network Traffic Extraction:** The PCAP file captured during sandbox execution is processed through `Zeek` (formerly Bro) to extract DNS requests, HTTP/HTTPS connections, and beacon-like periodic communications.

### Implementation Status

| Component | Status | Description |
|-----------|--------|-------------|
| DataLoader | Complete | `FileDataLoader` + `ParserRegistry` with dynamic parser discovery |
| Advanced Parsers | Complete | Static, Dynamic, Network parsers registered via `@register_parser` |
| Behavioral Signature Matching | Complete | Detection of events like "Code Injection", "Persistence" at the parser level |
| Data Cache | Complete | `ServiceContainer.load_data()` prevents repeated disk I/O |
| Automated Tool Integration | Planned | Ghidra/CAPEv2/Zeek automatic pipeline (currently hand-crafted JSON files) |

---

## Layer 2: Expert Agent Layer

Each model in this layer sees only the data from its own domain and produces an analysis from its own perspective. All agents run **in parallel** (LangGraph fan-out), making total analysis time independent of agent count.

- **Agent 1 (Static Code Analyst):**
    - **Input:** Decompiled code and strings.
    - **Focus:** Is there obfuscation in the code? Are malicious libraries being used (e.g., cryptography or injection APIs)?

- **Agent 2 (Dynamic Analyst):**
    - **Input:** Sandbox behavioral logs in JSON format.
    - **Focus:** What persistence mechanisms are being used? Was a malicious payload dropped (dropper behavior)?

- **Agent 3 (Network & C2 Analyst):**
    - **Input:** Zeek connection logs and PCAP summaries.
    - **Focus:** Is data being exfiltrated? Which IPs or domains are being communicated with? Was a C2 infrastructure connection established?

### Implementation Status

| Component | Status | Description |
|-----------|--------|-------------|
| OOP Agent Structure | Complete | `BaseAnalyst` + `@register_agent` decorator for plugin architecture |
| Expert Analysts (3x) | Complete | Static, Dynamic, Network specialists |
| Parallel Execution | Complete | LangGraph fan-out: START -> [static \|\| dynamic \|\| network] |
| Revision Capability | Complete | `revise()` method for updating reports during negotiation |
| Token Overflow Protection | Complete | Input truncation via `tiktoken` |
| Error Handling | Complete | Graceful fallback via `safe_analyze()` / `safe_revise()` |
| Multi-Provider LLM | Complete | OpenAI, Anthropic, Ollama — extensible via `@register_provider` |
| Agent Cache | Complete | `ServiceContainer.get_agent()` eliminates repeated agent instantiation |

---

## Layer 3: Debate & Negotiation Engine

The most critical aspect of the system is that agents do not simply produce a static report and stop — they can inspect each other's findings and debate.

- **Infrastructure:** **LangGraph** (Python) framework is used to manage this communication. State Management enables agent turn order to be controlled through a graph-based structure.

- **Process:**
    1. Each agent writes its initial report and saves it to the `reports` dict.
    2. The Mediator accepts all reports as a generic `dict[str, str]` — no hardcoded agent names.
    3. The Mediator uses `with_structured_output(MediatorVerdict)` to produce a structured output: `contradictions`, `resolution_summary`, `confidence`. Regex parsing is eliminated.
    4. Agents revise their arguments on conflicting points (typically 2 or 3 negotiation rounds — iterations).

### Implementation Status

| Component | Status | Description |
|-----------|--------|-------------|
| LangGraph Orchestration | Complete | Dynamic graph builder with automatic node creation from `AgentRegistry` |
| Genuine Negotiation | Complete | Agents read and challenge each other's reports via `revision_node` |
| Generic Mediator API | Complete | `mediate(reports: dict[str, str])` — no hardcoded agent names |
| Structured Consensus Detection | Complete | Reliable confidence scoring via `MediatorVerdict` Pydantic model |
| Ollama Fallback | Complete | Text-based fallback for providers that do not support structured output |
| Early Exit | Complete | Early loop exit when consensus is reached |

---

## Layer 4: Judge & Output Generation

When the negotiation loop ends, the conversation history and the agents' final arguments are passed to the Judge model. The Judge model resolves contradictions, delivers the final decision ("Malware" or "Benign"), and produces a detailed report.

- **Judge Model:** `Llama-3.1` (Local/Ollama) or `GPT / Claude` (API).
- **Standalone Class:** `JudgeAgent` does not inherit from `BaseAnalyst`. It only has `mediate()` and `give_verdict()` methods.
- **Intelligence Integration:** The Judge model is instructed to output the analysis result not as raw text but as a **STIX 2.1** formatted structured JSON object (Structured Output).
- **Operational Flow:** Detected threat actor tactics (MITRE ATT&CK TTPs), IPs, domains, and hash values are produced as a STIX bundle.

### Implementation Status

| Component | Status | Description |
|-----------|--------|-------------|
| JudgeAgent Standalone Class | Complete | Separated from BaseAnalyst; responsibilities are clearly defined |
| STIX 2.1 Verdict | Complete | Strict STIX 2.1 Bundle format validated via Pydantic |
| MITRE ATT&CK Mapping | Complete | TTP mapping via AttackPattern objects |
| OpenCTI Integration | Planned | Automated intelligence transfer from STIX bundle |

---

## v1.0.0 Enterprise Architecture Patterns

### Registry Pattern (Plugin Architecture)

Adding a new agent/parser/LLM provider requires only **1 file** with a decorator:

```python
# Adding a new agent
@register_agent("memory")
class MemoryAnalyst(BaseAnalyst):
    def analyze(self, data: str) -> str: ...
    def revise(self, ...) -> str: ...

# Adding a new parser
@register_parser("memory")
class MemoryParser(BaseParser):
    def parse(self, raw_data) -> str: ...

# Adding a new LLM provider
@register_provider("groq")
class GroqProvider:
    def build_model(self, model, temperature, **kwargs) -> BaseChatModel: ...
```

**No other file needs to be changed.** The pipeline builder auto-discovers new components from the registry. The Mediator also accepts a generic `dict[str, str]`, so adding a new agent does not require changing the `mediate()` signature.

### Dependency Injection (ServiceContainer)

`ServiceContainer` wires together all dependencies. Mock/real mode switching is centrally controlled. LLM, agent, and data caches eliminate redundant object creation between revision rounds:

```python
container = ServiceContainer(config=settings, mock=True)
agents = container.agent_registry.list_agents()   # ["static", "dynamic", "network"]
agent = container.get_agent("static")             # cached — no new object on second call
data = container.load_data("abc123", "static")    # cached — no disk read on second call
llm = container.get_expert_llm()                  # raises RuntimeError in mock mode
```

### Protocol-Based Contracts

All subsystems operate through contracts defined with `typing.Protocol`:

- `AnalystProtocol` — Agent interface
- `ParserProtocol` — Parser interface
- `LLMProviderProtocol` — LLM provider interface
- `DataLoaderProtocol` — Data loader interface

---

## Project Structure

```
src/maljan/
    app.py                  # Composition Root (MaljanApp)
    cli.py                  # Thin CLI wrapper (typer)
    core/
        config.py           # Hierarchical nested config (Pydantic Settings)
        container.py        # ServiceContainer (Dependency Injection + Cache)
        protocols.py        # Interface contracts (typing.Protocol)
        exceptions.py       # MaljanError, AnalystError, LLMError, ...
        logger.py           # Centralized logging
    agents/
        registry.py         # @register_agent + AgentRegistry
        base_agent.py       # BaseAnalyst (ABC)
        static_analyst.py   # @register_agent("static")
        dynamic_analyst.py  # @register_agent("dynamic")
        network_analyst.py  # @register_agent("network")
        judge_agent.py      # JudgeAgent (standalone class, not BaseAnalyst)
    parsers/
        registry.py         # @register_parser + ParserRegistry
        base_parser.py      # BaseParser (ABC)
        static_parser.py    # @register_parser("static")
        dynamic_parser.py   # @register_parser("dynamic")
        network_parser.py   # @register_parser("network")
    llm/
        registry.py         # @register_provider + LLMProviderRegistry
        openai_provider.py  # @register_provider("openai")
        anthropic_provider.py  # @register_provider("anthropic")
        ollama_provider.py  # @register_provider("ollama")
    loaders/
        file_loader.py      # FileDataLoader (with ParserRegistry)
    pipeline/
        state.py            # AnalysisState (generic reports dict + reducers)
        nodes.py            # Generic node factories (no hardcoded agent names)
        builder.py          # Dynamic graph builder (parallel fan-out)
        routing.py          # ConsensusRouter
    schemas/
        stix_models.py      # STIX 2.1 Pydantic models
        mediation_models.py # MediatorVerdict (structured confidence output)
```

---

## Infrastructure Status

| Component | Status | Description |
|-----------|--------|-------------|
| CLI Entrypoint | Complete | `typer`-based thin wrapper (`analyze`, `info` commands) |
| Modern Tooling | Complete | `uv` package management, `ruff` linting, `mypy` strict typing |
| Advanced Logging | Complete | Centralized log structure tracking agent reasoning processes |
| Mock Mode | Complete | Full pipeline testing without API keys |
| Custom Exception System | Complete | `MaljanError`, `AnalystError`, `DataLoadError`, `LLMError`, `WorkflowError` |
| Test Suite | Complete | 46 tests: parser, agent, STIX model, registry, container, integration |
| Sample Data Files | Complete | Static/dynamic/network JSON samples under `data/samples/` |

---

## Recommended Technology Stack

| Component | Recommended Tool / Framework |
|-----------|------------------------------|
| Model Server | vLLM (High throughput) or Ollama (Easy setup) |
| Orchestration | LangGraph (Python) |
| Prompt Management | LangChain |
| Sandbox | CAPEv2 (auto-triggerable via REST API) |
| Output Format | STIX 2.1 (LLM output formatted and validated via Pydantic) |

---

## Future Roadmap

### 1. Automated Data Collection

- [ ] **Ghidra Headless Plugin**: Automated decompilation pipeline via `analyzeHeadless`.
- [ ] **CAPEv2 REST API Connector**: File submission + result retrieval automation.
- [ ] **Zeek Log Pipeline**: Automated JSON output generation from PCAP files.

### 2. Visualization & Observability (Web UI)

- [ ] **LangGraph Dashboard**: Web interface for real-time monitoring of agent debates.
- [ ] **STIX Visualizer**: Graphical viewer for produced STIX bundles.

### 3. Deep Analysis Tools

- [ ] **YARA/Sigma Generator**: Automatic YARA rule generation by analyst agents.
- [ ] **Additional Parsers**: Any.Run, IDA Pro, Procmon and Sysmon log support.
- [ ] **ML-based Pre-Scoring**: Binary entropy / PE header suspicion scoring model.

### 4. Automation & Response

- [ ] **Responder Agent**: Agent that proposes firewall rules or EDR block list entries.
- [ ] **Automated Report Export**: Professional report generator in PDF/HTML format.
- [ ] **OpenCTI Integration**: Automated intelligence transfer from STIX bundle.

### 5. Scalability

- [ ] **Async Execution**: Fully asynchronous agent execution (asyncio + LangGraph async).
- [ ] **Database Integration**: Past analysis memory in a vector database (RAG).
- [ ] **Genuine Multi-Turn Dialog**: Per-agent response sequencing in each revision round.
