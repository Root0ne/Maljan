# Project Overview

Maljan is a production-grade, multi-agent malware analysis framework powered by LangGraph.
It uses adversarial multi-agent debate (Static, Dynamic, Network LLM analysts) to classify
samples as Malware, Benign, or Suspicious, grounds the verdict in deterministic layers
(YARA, Sigma) + ATT&CK validation, and then assembles a comprehensive `MalwareReport`
(CTI-analyst-grade) plus a STIX 2.1 intelligence bundle with per-claim confidence annotations.

> Memory last refreshed against code on 2026-05-30 (active "Wave 10" development). See
> `mem:wave_history` for the audit/fix timeline and audit-ID convention.

## Key Facts
- **Version**: 1.0.0 (pyproject.toml)
- **Python**: >=3.13, <3.14
- **Package Manager**: uv
- **Tests**: ~58 unit modules, 6 integration modules, 4 evaluation modules (README badge still
  shows the static "800+ passed" label).
- **Entry Points**: CLI (`maljan analyze` via `src/maljan/cli.py`), `MaljanApp` facade
  (`src/maljan/app.py`), FastAPI backend (`apps/api/`), Next.js frontend (`apps/web/`).
- **Containerization**: Docker Compose with **8 services** (postgres, redis, qdrant, minio,
  ghidra-mcp, backend-api, backend-worker, frontend) at `docker/docker-compose.yml`.
- **Default LLM deployment**: a local OpenAI-compatible **llama-server** at
  `host.docker.internal:8080/v1` (via the `openai` provider with a dummy key); Ollama
  (`qwen3.5:9b`, num_ctx 32768) is the fallback. Hosted OpenAI/Anthropic/Gemini also supported.

## Core Capabilities
1. **Multi-Agent Negotiation**: Static, Dynamic, Network analysts. Builder supports both a
   parallel fan-out (hosted multi-slot LLM) and a sequential chain (local single-slot
   llama-server) via `LLMConfig.parallel_analysts`. Mediator/Judge fan-in.
2. **Deterministic Layers**: YARA (0.90), Sigma (0.55, 2946 rules), Dynamic (0.45),
   Static (0.35), Network (0.20) with cross-layer multipliers 1.00->1.90.
   NOTE: TIEF has been fully removed (no weight, not in the ISR domain Literal).
3. **Platform-Aware Filtering (Wave 4)**: `sample_identity` infers a canonical platform
   (`state["platform"]`) at bootstrap; the cascade drops platform-incompatible techniques
   and the Sigma/YARA layers filter rules by platform. See `mem:extractors_enrichment_qa`.
4. **Sycophancy Detection**: Cosine similarity bag-of-words; Devil's Advocate injection on revision.
5. **Adaptive Termination**: `ConsensusRouter` rolling std (window=3, threshold=0.04, min_confidence=0.70).
6. **Long-Term Memory**: Qdrant (default backend) + pure-Python TF-IDF ATT&CK index;
   embeddings via fastembed BAAI/bge-small-en-v1.5 (384-dim) with BoW fallback (`memory/embeddings.py`).
7. **MCP Integration**: CAPEv2, Ghidra MCP (HTTP, ~225 tools), Network MCP, ThreatIntel MCP.
8. **ISR**: `AgentISR` (claims + evidence_ref + confidence + technique_id + rule_platforms +
   dissent_items). Empty dissent + revision_round>0 = convergence signal. See `mem:isr_lifecycle`.
9. **Judge Postprocess**: `agents/judge_postprocess.py` runs J-01/J-02/REP-01/REP-02 defensive
   passes on the judge STIX bundle (UUID rewrite, hallucinated-indicator dropout, MITRE ref
   backfill, cascade-orphan attack-pattern dropout).
10. **Comprehensive Reporting** (NEW): a `report_node` after the judge builds a `MalwareReport`
    (`reporting/`) from deterministic extractors (`extractors/`) + an LLM `NarrativeAgent` +
    auto-generated detection signatures (YARA/Sigma/Suricata) + markdown / extended-STIX
    renderers, then runs the `qa/fp_linter`. See `mem:reporting_layer`.
11. **Threat-Intel Enrichment** (NEW, out-of-band): `enrichment/` (VirusTotal, AbuseIPDB,
    WHOIS, Qdrant attribution) runs as an ARQ task `enrich_worker.py` after the verdict.
12. **Degraded-mode confidence cap (CONF-INFL-01)**: when a run produces TTPs but zero LLM
    analyst corroboration (or `[ERROR]` reports), `overall_confidence` is capped at 0.60.

## Project Layout
- `src/maljan/`
  - `app.py`: **MaljanApp facade** (composition root; wires container, infers platform,
    submits sandbox, builds graph, runs `arun()` async).
  - `cli.py`: Typer CLI (`maljan analyze`).
  - `agents/`: BaseAnalyst, Static, Dynamic, Network, Judge, registry, MCP client, Ghidra
    HTTP client, **judge_postprocess**, **_indicator_denylists**.
  - `pipeline/`: builder, nodes (analyst/negotiation/revision/judge/**report**), routing,
    state, sycophancy_detector, mediation_models.
  - `analysis/`: yara_layer, sigma_layer, ttp_cascade (now platform-aware), schema_pruner,
    chunk_merger, run_summary, function_summarizer. (tief_classifier removed.)
  - `core/`: container, config, exceptions, logger, paths.
  - `llm/`: registry + openai/anthropic/ollama/gemini providers.
  - `loaders/`: file_loader, binary_chunker, pe_loader, sandbox_client, mock_sandbox_client,
    cape2_client, triage_client.
  - `memory/`: long_term_memory, qdrant_store, in_memory_store, **embeddings**, attck_index,
    attck_loader, attck_validator, ttp_validation.
  - `extractors/` (NEW): sample_identity, pe_extractor, dynamic_extractor, network_extractor,
    persistence_extractor, capability_matrix, attribution.
  - `enrichment/` (NEW): virustotal_client, abuseipdb_client, whois_client, orchestrator.
  - `reporting/` (NEW): models (`MalwareReport`), builder, narrative_agent, detection_signatures,
    renderers/(markdown, stix_renderer).
  - `qa/` (NEW): fp_linter.
  - `parsers/`, `preprocessors/` (cfg_orderer), `schemas/` (isr_models, stix_models), `utils/` (json_cleaner).
- `apps/api/`: FastAPI + async SQLAlchemy + ARQ workers (analysis + enrich) + alembic (5 migrations).
- `apps/web/`: Next.js 16 + React 19 + TailwindCSS 4, ~18 analysis tabs, Playwright e2e. See `mem:frontend_web_app`.
- `tests/unit`, `tests/integration`, `tests/evaluation`.
- `docs/` (operator-runbook.md, triage_api/, research/), `scripts/`, `external/` (CAPEv2, Ghidra-MCP, ik_llama.cpp).
