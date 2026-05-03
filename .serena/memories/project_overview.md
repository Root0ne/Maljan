# Maljan — Project Overview

## Purpose
Maljan is an enterprise-grade, adaptive multi-agent malware analysis framework with a modern web interface.
It orchestrates three parallel domain expert LLM analysts (static, dynamic, network)
that debate findings through a structured negotiation protocol. A Chief Judge agent
then issues a validated, MITRE ATT&CK-grounded STIX 2.1 verdict.

It now features a full-stack deployment with a FastAPI backend and a Next.js frontend, containerized via Docker.

Agents use real-world tools via **Model Context Protocol (MCP)**: Ghidra (static analysis),
CAPEv2 (dynamic sandbox), NetworkMCP (PCAP analysis), and ThreatIntelMCP (IP/hash reputation).
The pipeline is built on ReAct (Reasoning and Acting) with `create_react_agent`.

## Key Design Goals
- Hallucination-resistant TTP mapping via cross-domain corroboration
- Sycophancy detection (agents forced to express dissent before consensus)
- Adaptive termination (rolling std of confidence — no unnecessary LLM rounds)
- Deterministic ATT&CK validation via YARA (300+ rules) + Sigma (2,946 rules) layers
- Long-term memory (RAG over past verdicts via in-memory or Qdrant)
- Full STIX 2.1 output with per-claim confidence intervals
- TIEF Classifier: DistilBERT-based Layer 2 NLP classifier (partial impl., TODO-5)

## Tech Stack
- **Python 3.13** (strict type hints, Pydantic v2)
- **FastAPI & Alembic** — Backend REST API and database migrations (`apps/api`)
- **Next.js & React** — Frontend Web UI (`apps/web`)
- **Docker & Docker Compose** — Containerized deployment (`docker/`)
- **LangGraph** — pipeline graph orchestration
- **LangChain** — LLM provider abstraction (OpenAI / Anthropic / Ollama / Gemini)
- **Pydantic v2 + pydantic-settings** — config, schemas, STIX models
- **Typer** — CLI (`maljan analyze`, `maljan benchmark`, `maljan info`)
- **Qdrant** — optional persistent vector store for long-term memory
- **httpx** — CAPEv2 / Triage sandbox REST clients
- **FastMCP** — MCP server framework (NetworkMCP, ThreatIntelMCP servers)
- **uv** — package manager and task runner
- **ruff** — linting + formatting
- **mypy** — strict static type checking
- **pytest** — test suite (unit + integration + evaluation)

## Entry Points
```bash
docker-compose -f docker/docker-compose.yml up -d # Run full stack environment
maljan analyze <file>   # Run full pipeline on a malware sample
maljan benchmark        # Run evaluation benchmark suite
maljan info             # Show current config and registered components
```

## Repository Layout
```
apps/
  api/            # FastAPI backend (routes, worker, database)
  web/            # Next.js frontend (React components, pages)
docker/           # Dockerfiles and docker-compose.yml
src/maljan/
  agents/         # BaseAnalyst, StaticAnalyst, DynamicAnalyst, NetworkAnalyst, JudgeAgent
                  # + MCPLangChainToolkit (MCP tool loader), AgentRegistry
  analysis/       # TTPCascadeEngine, ChunkMerger, SchemaPruner, RunSummary
                  # + YaraLayer, SigmaLayer, TIEFClassifier, FunctionSummarizer
  core/           # Settings (pydantic-settings), ServiceContainer, exceptions, logger, protocols
  loaders/        # BinaryChunker, FileDataLoader, CAPEv2Client, MockSandboxClient, TriageClient
                  # + SandboxClient (abstract Protocol + SubmissionResult dataclass)
  memory/         # ATTCKIndex, ATTCKLoader, ATTCKValidator, InMemoryStore, QdrantStore
                  # + LongTermMemory, TTPValidation
  pipeline/       # LangGraph nodes, routing (adaptive termination), SycophancyDetector, state
                  # + MediationModels, builder
  preprocessors/  # CFGOrderer (Control Flow Graph reordering for static analysis)
  schemas/        # AgentISR, ClaimEvidence, STIX models, MediationModels
  llm/            # LLM provider factory (OpenAI, Anthropic, Ollama, Gemini + registry)
  parsers/        # Parser registry (static, dynamic, network parsers + base)
  app.py          # MaljanApp facade (Composition Root)
  cli.py          # Typer CLI entry point

network-mcp/
  server.py       # FastMCP server: PCAP analysis tools (read_pcap_summary, extract_dns, ...)

threatintel-mcp/
  server.py       # FastMCP server: IP/domain/hash reputation tools (mock impl.)

external/         # External tool integrations (Ghidra MCP, CAPEv2 MCP)
config/           # Configuration files
data/             # Sample data, ATTCK bundle cache
reports/          # JSON output directory for analysis reports
scripts/          # Utility and run scripts

tests/
  unit/           # Per-module unit tests
  integration/    # End-to-end workflow tests
  evaluation/     # Benchmark suite, metrics, ground truth fixtures

docs/
  ARCHITECTURE.md         # Technical reference document
  TODO.md                 # Active TODO list (current_todo.md in root is the live copy)
  maljan_master_plan.md   # Original design document
  research/               # Academic papers and research notes
```
