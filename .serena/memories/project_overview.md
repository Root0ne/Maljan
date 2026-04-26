# Maljan — Project Overview

## Purpose
Maljan is an enterprise-grade, adaptive multi-agent malware analysis framework.
It orchestrates three parallel domain expert LLM analysts (static, dynamic, network)
that debate findings through a structured negotiation protocol. A Chief Judge agent
then issues a validated, MITRE ATT&CK-grounded STIX 2.1 verdict.

## Key Design Goals
- Hallucination-resistant TTP mapping via cross-domain corroboration
- Sycophancy detection (agents forced to express dissent before consensus)
- Adaptive termination (rolling std of confidence — no unnecessary LLM rounds)
- Deterministic ATT&CK validation (hallucination rate metric)
- Long-term memory (RAG over past verdicts via in-memory or Qdrant)
- Full STIX 2.1 output with per-claim confidence intervals

## Tech Stack
- **Python 3.13** (strict type hints, Pydantic v2)
- **LangGraph** — pipeline graph orchestration
- **LangChain** — LLM provider abstraction (OpenAI / Anthropic / Ollama)
- **Pydantic v2 + pydantic-settings** — config, schemas, STIX models
- **Typer** — CLI (`maljan analyze`, `maljan benchmark`, `maljan info`)
- **Qdrant** — optional persistent vector store for long-term memory
- **httpx** — CAPEv2 sandbox REST client
- **uv** — package manager and task runner
- **ruff** — linting + formatting
- **mypy** — strict static type checking
- **pytest** — 661 tests (unit + integration + evaluation)

## Entry Points
```
maljan analyze <file>   # Run full pipeline on a malware sample
maljan benchmark        # Run evaluation benchmark suite
maljan info             # Show current config and registered components
```

## Repository Layout
```
src/maljan/
  agents/       # BaseAnalyst, StaticAnalyst, DynamicAnalyst, NetworkAnalyst, JudgeAgent
  analysis/     # TTPCascadeEngine, ChunkMerger, SchemaPruner, RunSummary
  core/         # Settings (pydantic-settings), ServiceContainer, exceptions, logger, protocols
  loaders/      # BinaryChunker, FileDataLoader, CAPEv2Client, MockSandboxClient
  memory/       # ATTCKIndex, ATTCKValidator, InMemoryStore, QdrantStore, LongTermMemory
  pipeline/     # LangGraph nodes, routing (adaptive termination), SycophancyDetector, state
  schemas/      # AgentISR, ClaimEvidence, STIX models (ConfidenceAnnotatedRelationship)
  llm/          # LLM provider factory
  parsers/      # Parser registry

tests/
  unit/         # Per-module unit tests
  integration/  # End-to-end workflow tests
  evaluation/   # Benchmark suite, metrics, ground truth fixtures

docs/
  ARCHITECTURE.md         # 17-section technical reference
  TODO.md                 # Open tasks (5 items)
  maljan_master_plan.md   # Original design document
  research/               # Academic papers and research notes
```
