# Project Overview
Maljan is a production-grade, multi-agent malware analysis framework powered by LangGraph. It uses adversarial multi-agent debate (Static, Dynamic, Network LLM analysts) to classify samples as Malware, Benign, or Suspicious, then outputs STIX 2.1 intelligence bundles with per-claim confidence annotations.

## Key Facts
- **Version**: 1.0.0 (pyproject.toml)
- **Python**: >=3.13, <3.14
- **Package Manager**: uv
- **Test Count**: 800+ tests passed (per README badge), 35+ unit modules, 4 integration modules
- **Entry Points**: CLI (`maljan analyze` via `src/maljan/cli.py`), `MaljanApp` facade (`src/maljan/app.py`), FastAPI backend, Next.js frontend
- **Containerization**: Docker Compose with **8 services** (API, Worker, Frontend, PostgreSQL, Redis, MinIO, Qdrant, Ghidra MCP)

## Core Capabilities
1. **Multi-Agent Negotiation**: Static, Dynamic, Network analysts in parallel fan-out → negotiation with Mediator/Judge fan-in.
2. **Deterministic Layers**: YARA (0.90), TIEF (0.80 — weight still in cascade table but classifier module removed), Sigma (0.55, 2946 rules), Dynamic (0.45), Static (0.35), Network (0.20) with cross-layer multipliers 1.00→1.90.
3. **Sycophancy Detection**: Cosine similarity bag-of-words; Devil's Advocate injection on revision.
4. **Adaptive Termination**: `ConsensusRouter` rolling std (window=3, threshold=0.04, min_confidence=0.70).
5. **Long-Term Memory**: Qdrant + pure-Python TF-IDF ATT&CK index.
6. **MCP Integration**: CAPEv2, Ghidra MCP (225 tools), Network MCP, ThreatIntel MCP.
7. **ISR (Intermediate Structural Representation)**: `AgentISR` (claims + evidence_ref + confidence + technique_id + dissent_items). Empty dissent + revision_round>0 = convergence signal.
8. **Chunked Analysis**: Token-aware `BinaryChunker` w/ overlap; hierarchical merge cap 20 claims.
9. **Dynamic Schema Pruning**: Keyword-weighted malware category inference (ransomware/RAT/dropper/worm/infostealer) — no LLM call.
10. **Sandbox Submission**: `MaljanApp._submit_to_sandbox()` (in `app.py`) submits the sample via `SandboxClient` (Triage/CAPE/Mock) before pipeline; result available in state as `sandbox_report`.
11. **Output**: STIX 2.1 Bundle with `ConfidenceAnnotatedRelationship` (x_maljan_*) + RunSummary observability report.

## Project Layout
- `src/maljan/`
  - `app.py`: **MaljanApp facade** (composition root: wires container, builds graph, runs `arun()` async).
  - `cli.py`: Typer CLI (`maljan analyze`).
  - `agents/`: BaseAnalyst, Static, Dynamic, Network, Judge, registry, MCP client, Ghidra HTTP client.
  - `pipeline/`: builder, nodes, routing, state, sycophancy_detector, **mediation_models (MediatorVerdict)**.
  - `analysis/`: yara_layer, sigma_layer, ttp_cascade, schema_pruner, chunk_merger, run_summary, function_summarizer. **NOTE**: `tief_classifier.py` removed; only weight remains in cascade table.
  - `core/`: container, config, exceptions, logger, **paths** (`get_project_root`, `resolve_mcp_args` — replaces brittle `os.path.dirname` chains).
  - `llm/`: registry + openai/anthropic/ollama/gemini providers.
  - `loaders/`: file_loader, binary_chunker, sandbox_client, mock_sandbox_client, cape2_client, **triage_client** (Triage Cloud sandbox), **pe_loader** (PE-specific binary loader).
  - `memory/`: long_term_memory, qdrant_store, in_memory_store, attck_index, attck_validator, **attck_loader** (bundle fetch + cache), **ttp_validation** (`TTPClaimValidation`, `TTPValidationSummary`).
  - `parsers/`: base_parser, static_parser, dynamic_parser, network_parser, registry.
  - `preprocessors/`: **cfg_orderer** (`CFGOrderer` — topological sort of CFG nodes, used by binary_chunker).
  - `schemas/`: isr_models, stix_models. **NOTE**: `mediation_models.py` lives under `pipeline/`, NOT `schemas/`.
  - `utils/`: **json_cleaner** (`extract_json`, `repair_json`, `safe_parse_json` — for LLM structured-output recovery).
- `apps/api/`: FastAPI + async SQLAlchemy + ARQ worker + alembic/.
- `apps/web/`: Next.js 16 + React 19 + TailwindCSS 4.
- `tests/unit`, `tests/integration`, `tests/evaluation` (TRAM + ATT&CK malware benchmarks).
- `scripts/`, `external/` (CAPEv2, Ghidra-MCP), `network-mcp/`, `threatintel-mcp/`.
