# Maljan README Summary (Updated)

## Purpose
Maljan is a production-grade malware analysis platform using adversarial multi-agent debate (LangGraph) to classify samples as Malicious, Benign, or Suspicious. Combines LLM-powered reasoning with deterministic detection (YARA, Sigma) and outputs STIX 2.1 bundles.

## README Structure (as of latest update)
1. **Header** — badges + 2-sentence description
2. **Key Capabilities** — 8-row table (multi-agent negotiation, deterministic grounding, anti-echo-chamber, adaptive termination, ATT&CK validation, TTP cascade, LTM/RAG, heterogeneous ensemble)
3. **Architecture** — simple ASCII diagram + ISR + DI/AgentRegistry notes
4. **Quick Start** — standalone CLI + Docker full-stack + ATT&CK cache pre-build
5. **Project Structure** — tree diagram of src/maljan/, apps/api/, apps/web/
6. **Web UI** — feature table (Dashboard, Samples, Jobs, Analysis Detail with 7 tabs, Live, Reports)
7. **API Endpoints** — concise endpoint table
8. **Development** — make commands
9. **Configuration** — two-config-system note + critical vars + link to .env.example
10. **Design Principles** — 4 principles (no hallucinated TTPs, no sycophancy, graceful degradation, protocol-based extensibility)

## What was removed from README
- Pipeline Components (6 subsections) — moved to AGENTS.md
- YARA Layer 0 detailed section — redundant with Key Capabilities
- Sigma Layer 0 detailed section — redundant
- Long-Term Memory / RAG (Phase 5) — old terminology + redundant
- Evaluation Benchmark Framework — not README-appropriate
- SandboxClient details — AGENTS.md
- Ghidra MCP Headless Server details — AGENTS.md
- Heterogeneous Model Ensemble details — redundant
- LangSmith Observability — too narrow
- Full Configuration Reference (60+ rows) — .env.example exists
- Security / Dependency Audit — not README-appropriate
- Design Principles (10 items) → reduced to 4
- Web UI Design Language details — too detailed
- Full-Stack Docker Service Architecture table — redundant with Quick Start
- Ollama Connectivity details — AGENTS.md
- Recommended Stack table — outdated models
- Recent Changes — changelog content
- Active Issues / Next Steps — issue tracker content

## Key references in README
- Deep-dive docs: AGENTS.md, docs/ARCHITECTURE.md
- Config reference: .env.example
