# Project Overview
Maljan is an enterprise-grade, multi-agent malware analysis framework powered by LangGraph. It uses adversarial multi-agent debate (Static, Dynamic, Network LLM analysts) to classify samples as Malware, Benign, or Suspicious. It outputs STIX 2.1 intelligence bundles with confidence intervals.
Key features include:
- Multi-agent negotiation with sycophancy detection and adaptive termination.
- Deterministic detection layers (YARA, Sigma) mapped to MITRE ATT&CK.
- Qdrant-backed Long-Term Memory (RAG) for few-shot context.
- FastAPI backend, Next.js 16 frontend, PostgreSQL, Redis, MinIO infrastructure.
