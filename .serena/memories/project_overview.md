# Project Overview
Maljan is a production-grade, multi-agent malware analysis framework powered by LangGraph. It uses adversarial multi-agent debate (Static, Dynamic, Network LLM analysts) to classify samples as Malware, Benign, or Suspicious, then outputs STIX 2.1 intelligence bundles with per-claim confidence annotations.

## Key Facts
- **Version**: 1.0.0 (pyproject.toml)
- **Python**: >=3.13
- **Package Manager**: uv
- **Test Count**: 35 unit test modules, 4 integration test modules
- **Entry Points**: CLI (`maljan analyze`), FastAPI backend, Next.js frontend
- **Containerization**: Docker Compose with 7 services (API, Worker, Frontend, PostgreSQL, Redis, MinIO, Qdrant)

## Core Capabilities
1. **Multi-Agent Negotiation**: Static, Dynamic, Network analysts run in parallel (fan-out), then enter a negotiation loop with Mediator and Judge for final verdict (fan-in).
2. **Deterministic Layers**: YARA (0.90), TIEF (0.80), Sigma (0.55), Dynamic (0.45), Static (0.35), Network (0.20) weighted TTP confidence cascade with cross-layer corroboration multipliers (1.25x to 1.90x).
3. **Sycophancy Detection**: Cosine-similarity based bag-of-words detection flags blind agreement; Devil's Advocate directive injected into revision.
4. **Adaptive Termination**: `ConsensusRouter` uses rolling confidence standard deviation (window=3, threshold=0.04, min_confidence=0.70) for convergence-based loop exit. Hard limit (default 20) as safety ceiling.
5. **Long-Term Memory**: Qdrant-backed vector store for few-shot RAG; pure-Python TF-IDF ATT&CK index for technique validation and hallucination detection.
6. **MCP Integration**: Built-in MCP client for agents. External integrations: CAPEv2 sandbox MCP, Ghidra MCP (225 analysis tools), Network MCP (PCAP analysis), ThreatIntel MCP.
7. **ISR (Intermediate Structural Representation)**: Agents exchange structured `AgentISR` objects (claims + evidence_ref + confidence + technique_id + dissent_items) instead of raw text. Empty dissent_items + revision_round>0 signals active convergence.
8. **Chunked Analysis**: Token-aware binary splitting (`BinaryChunker`) with overlap. Single chunk = fast path. Multi-chunk = per-chunk ISR + hierarchical merge (dedup, cap at 20 claims).
9. **Dynamic Schema Pruning**: Keyword-weighted malware category inference (ransomware/RAT/dropper/worm/infostealer) guides STIX object type focus without LLM call.
10. **Output**: STIX 2.1 Bundle with `ConfidenceAnnotatedRelationship` objects (x_maljan_confidence, x_maljan_evidence_basis, x_maljan_contributing_agents, x_maljan_technique_id) + RunSummary observability report.

## Project Layout
- `src/maljan/`: Core analysis engine (importable library)
  - `agents/`: LLM analyst agents (BaseAnalyst, Static, Dynamic, Network, Judge, registry, MCP client)
  - `pipeline/`: LangGraph workflow (builder, nodes, routing, state, sycophancy_detector)
  - `analysis/`: Deterministic layers (yara, sigma, ttp_cascade, tief, schema_pruner, chunk_merger, run_summary, function_summarizer)
  - `core/`: DI container, config, protocols, exceptions, logger
  - `llm/`: Provider registry and implementations (openai, anthropic, ollama, gemini)
  - `loaders/`: Data ingestion (file_loader, binary_chunker, sandbox clients)
  - `memory/`: LTM/RAG (qdrant_store, attck_index, attck_validator, in_memory_store)
  - `parsers/`: Sandbox output parsers (static, dynamic, network, registry)
  - `schemas/`: Pydantic domain models (isr_models, stix_models, mediation_models)
- `apps/api/`: FastAPI backend with async SQLAlchemy + ARQ worker
- `apps/web/`: Next.js 16 + React 19 + TailwindCSS 4 frontend
- `tests/unit/`: 35 pytest modules
- `tests/integration/`: 4 pytest modules
- `tests/evaluation/`: Benchmark suites (TRAM + ATT&CK malware)
- `scripts/`: Data preparation and utility scripts
- `external/`: CAPEv2 and Ghidra-MCP third-party integrations
- `network-mcp/`, `threatintel-mcp/`: Custom MCP servers
