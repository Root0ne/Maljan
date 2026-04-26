# Maljan: Comprehensive Research Report
## Multi-Agent LLM Framework for Malware Analysis

**Prepared for:** Maljan Development Team
**Date:** April 25, 2026
**Scope:** Academic literature review, technology evaluation, known limitations, and recommended improvements for the Maljan Multi-Agent Malware Analysis Framework.

---

## Table of Contents

1. [Academic Literature Review](#1-academic-literature-review)
   - 1a. Multi-Agent LLM Systems for Cybersecurity
   - 1b. LLM-Based Malware Analysis
   - 1c. Consensus & Negotiation in Multi-Agent AI
   - 1d. STIX 2.1 & Automated CTI Generation
2. [Technology & Framework Evaluation](#2-technology--framework-evaluation)
   - 2a. LangGraph vs. Alternatives
   - 2b. LLM Model Selection for Malware Analysis
   - 2c. Sandbox Integration Options
   - 2d. Vector Database for RAG
3. [Known Limitations & Open Problems](#3-known-limitations--open-problems)
4. [Recommended Improvements & Research Gaps](#4-recommended-improvements--research-gaps)

---

## 1. Academic Literature Review

### 1a. Multi-Agent LLM Systems for Cybersecurity (2022–2025)

---

**Paper 1: "The Evolution of Agentic AI in Cybersecurity: From Single Agents to Collaborative Systems"**
- **Authors:** Multiple (survey paper, IEEE / arXiv 2512.06659)
- **Year:** 2024–2025
- **Venue:** IEEE / arXiv
- **Summary:** This survey traces the progression from Gen-1 single-LLM copilots (which can parse phishing emails, extract IOCs, and map MITRE ATT&CK techniques but cannot run external queries or interact with security tools) to Gen-2 multi-agent architectures with planning, memory, and tool-use. The paper specifically highlights SOC cognitive burden reduction as a key use-case. It also catalogs "Audit-LLM" (arXiv:2408.08902), a multi-agent collaboration system for log-based insider threat detection.
- **Relevance to Maljan:** Directly validates Maljan's architectural premise — single LLM agents are insufficient for production cybersecurity work. The paper provides the academic grounding for using a coordinator + specialized task agent structure, and maps neatly onto Maljan's Static/Dynamic/Network analyst decomposition.

---

**Paper 2: "A Survey of Agentic AI and Cybersecurity: Challenges, Opportunities and Use-case Prototypes"**
- **Authors:** Multiple (arXiv:2601.05293)
- **Year:** 2026 (January)
- **Venue:** arXiv
- **Summary:** Defines agentic AI as systems that "use sophisticated reasoning and iterative planning to autonomously solve complex, multi-step problems." It formalizes the single-agent architecture (LLM + short-term memory + long-term vector store + tools) and the multi-agent architecture (coordinator + specialized task agents sharing short-term memory). Critically, it identifies that "progress remains centered on orchestration and workflow automation rather than unrestricted autonomous authority" and that "the open problem is how to grant execution power without enabling cascading or irreversible failures."
- **Relevance to Maljan:** Provides the formal architectural vocabulary for Maljan's design. The paper's warning about cascading failures from misconfigured agents directly motivates the negotiation + Judge pattern — a safety mechanism to avoid irreversible incorrect verdicts.

---

**Paper 3: "Multi-Agent Framework for Threat Mitigation and Resilience in AI-Based Systems"**
- **Authors:** Multiple (arXiv:2512.23132)
- **Year:** 2025 (December)
- **Venue:** arXiv
- **Summary:** Demonstrates a working multi-agent reasoning system that uses enhanced RAG (powered by GPT-4o at temperature 0.4) to automatically extract TTPs, vulnerabilities, and lifecycle stages from over 300 scientific articles using evidence-grounded reasoning. The resulting ontology-driven threat graph supports cross-source validation and lifecycle mapping, uncovering threats beyond existing ATLAS coverage.
- **Relevance to Maljan:** The cross-source validation architecture here is a direct analog of Maljan's negotiation loop. This paper provides empirical evidence that multi-agent cross-validation of findings (across static, dynamic, network sources) improves coverage beyond what a single agent achieves.

---

**Paper 4: "Uncovering Vulnerabilities of LLM-Assisted Cyber Threat Intelligence"**
- **Authors:** Multiple (arXiv:2509.23573)
- **Year:** 2025
- **Venue:** arXiv
- **Summary:** Identifies three dominant vulnerability categories in LLM-based CTI pipelines through large-scale evaluation: (1) spurious correlations (e.g., misattributing Mimikatz as actor-specific evidence), (2) contradictory knowledge from inconsistent CTI sources causing unstable predictions, and (3) constrained generalization on emerging zero-day attack surfaces. Includes a benchmark table comparing industry LLMs vs. cybersecurity-specialized models across CTI stages.
- **Relevance to Maljan:** This is a critical cautionary paper. The three failure modes identified map precisely onto what Maljan's negotiation loop is designed to catch — agents cross-checking each other's attributions should surface spurious correlations and contradictions. The benchmark is a potential evaluation framework for Maljan's Judge agent accuracy.

---

**Paper 5: "CFA-Bench: Cybersecurity Forensic LLM Agent Benchmark and Testing"**
- **Authors:** De Santis et al.
- **Year:** 2025
- **Venue:** IEEE European Symposium on Security and Privacy Workshops (EuroS&PW)
- **Summary:** Introduces a dynamic benchmark environment for evaluating LLM-based cybersecurity forensic agents, providing standardized task definitions and metrics for measuring agent performance on real-world CTI tasks including log analysis, artifact triage, and report generation.
- **Relevance to Maljan:** Maljan needs an evaluation framework. CFA-Bench can serve as a direct benchmark baseline for measuring the accuracy of Maljan's individual specialist agents and final Judge verdicts.

---

### 1b. LLM-Based Malware Analysis

---

**Paper 6: "Feasibility Study for Supporting Static Malware Analysis Using LLM"**
- **Authors:** Fujii, Shota et al.
- **Year:** 2024 (November)
- **Venue:** Workshop on Security and Artificial Intelligence (SECAI 2024)
- **Summary:** Demonstrates that LLMs can generate descriptions covering malware functions with up to 90.9% accuracy when applied to Ghidra-decompiled output. A user study with six static analysts confirmed practical applicability. Key finding: whole-malware decompilation output greatly exceeds LLM input limits, requiring chunked processing.
- **Relevance to Maljan:** Directly validates the feasibility of Maljan's Static Analyst agent. The 90.9% coverage figure is a useful baseline. The input-length finding reinforces the need for a chunked-summarization pre-processing stage before passing disassembly to the agent.

---

**Paper 7: "A Decompilation-Driven Framework for Malware Detection with Large Language Models"**
- **Authors:** Multiple (arXiv:2601.09035)
- **Year:** 2026 (January)
- **Venue:** arXiv
- **Summary:** Evaluates Llama 3.3 70B, Codestral, Claude 3.7 Sonnet, and Gemini 2.5 Pro on malware classification from Ghidra-decompiled C code. Establishes a vanilla baseline and demonstrates that fine-tuning (on Gemini 2.5 Pro) significantly improves performance. Identifies "lost-in-the-middle" failures when code sequences exceed the context window and highlights the need for multi-modal integration (dynamic traces + sandbox + provenance metadata).
- **Relevance to Maljan:** Provides direct model benchmarks for the Static Analyst agent and strongly recommends the multi-modal approach Maljan already takes. The "lost-in-the-middle" finding argues for the hierarchical summarization pipeline in Maljan's pre-processing stage.

---

**Paper 8: "Large Language Models for Code Analysis: Do LLMs Really Do Well?" (USENIX Security 2024)**
- **Authors:** Fang et al.
- **Year:** 2024
- **Venue:** USENIX Security 2024
- **Summary:** Comprehensively evaluates LLMs on code explanation, including obfuscated JavaScript. Finds that while LLMs handle de-obfuscated code well, performance degrades significantly on obfuscated code. GPT-3.5/4 are the strongest performers on de-obfuscation tasks, but no model reliably handles deeply obfuscated binaries without additional pre-processing.
- **Relevance to Maljan:** Maljan's Static Analyst must account for heavily obfuscated samples. This paper argues for a pre-processing de-obfuscation step (potentially using a tool-call to CyberChef or a symbolic executor) before the LLM performs analysis.

---

**Paper 9: "Assessing LLMs in Malicious Code Deobfuscation of Real-World Malware Campaigns"**
- **Authors:** Multiple (ScienceDirect, 2024)
- **Year:** 2024
- **Venue:** Expert Systems with Applications (ScienceDirect)
- **Summary:** Tests LLM deobfuscation capabilities on real-world Emotet campaign scripts. LLMs achieved 69.56% accuracy extracting dropper URLs and 88.78% accuracy on corresponding domains. Recommends fine-tuning for specialized de-obfuscation pipelines and proposes integrating LLMs into an augmented automated CTI pipeline.
- **Relevance to Maljan:** Emotet is a standard malware family benchmark. The IOC extraction accuracy figures (69–88%) provide a realistic performance baseline for Maljan's Network Analyst agent, which must extract C2 infrastructure from PCAP summaries.

---

**Paper 10: "Large Language Models for Malware Code Analysis" (Survey)**
- **Authors:** Multiple (arXiv:2504.07137)
- **Year:** 2025 (April)
- **Venue:** arXiv
- **Summary:** Systematic survey covering LLM applications across malware detection, generation, monitoring, family analysis, code reuse, and deobfuscation. Documents few-shot and zero-shot learning benchmarks (e.g., RMCBench using GPT and CodeLLaMA), and provides a taxonomy of NLP techniques applicable to each malware analysis task.
- **Relevance to Maljan:** Provides the broadest available map of the LLM-malware-analysis landscape. The few-shot learning results are directly applicable to designing prompts for Maljan's specialist agents without requiring fine-tuning.

---

**Paper 11: Bitdefender Research — "Large Language Models for Malware Analysis" (asmLLM)**
- **Authors:** Bitdefender ML team (bit-ml.github.io)
- **Year:** 2023–2024
- **Venue:** Bitdefender Research Blog
- **Summary:** Fine-tunes MPT-7B on 500M tokens of x86-64 assembly data (OSS-ASM dataset) using LoRA. The resulting asmLLM outperforms GPT-3.5/4 in zero-shot code summarization and downstream assembly classification tasks. Demonstrates that domain-specific pretraining on assembly substantially improves feature extraction for malware classification.
- **Relevance to Maljan:** Strong evidence that Maljan's Static Analyst would benefit from an assembly-tuned backbone rather than a generic code LLM. The asmLLM approach (fine-tuned MPT or similar) should be evaluated as the base model for the static analysis pipeline.

---

### 1c. Consensus & Negotiation in Multi-Agent AI

---

**Paper 12: "Should We Be Going MAD? A Look at Multi-Agent Debate Strategies for LLMs"**
- **Authors:** Breum, Buber, Balslev, Pera (arXiv:2311.17371)
- **Year:** 2023–2024
- **Venue:** arXiv
- **Summary:** Comprehensive evaluation of Multi-Agent Debate (MAD) strategies, surveying parallel answer generation for self-consistency (Wang et al., 2023) and debate/simulation approaches. Finds that debate improves reasoning on mathematical and strategic tasks but the gains are inconsistent across domains and heavily dependent on debate structure design.
- **Relevance to Maljan:** Core theoretical basis for Maljan's negotiation loop. The inconsistency finding argues that Maljan should not rely on raw MAD but should implement structured protocols (explicit contradiction flagging, evidence citation requirements) rather than free-form debate.

---

**Paper 13: "WISE: Weighted Iterative Society-of-Experts for Robust Multimodal Multi-Agent Debate"**
- **Authors:** Multiple (arXiv:2512.02405)
- **Year:** 2025
- **Venue:** arXiv
- **Summary:** Extends Society of Mind (Minsky) principles to multi-agent LLM debate. Proposes weighted message passing where agent outputs are weighted by confidence scores and cross-modal consistency. Demonstrates improvements on SMART-840 benchmark and argues that MAD benefits are larger when agents process different modalities (analogous to processing different data sources).
- **Relevance to Maljan:** The weighting mechanism is directly applicable to Maljan. A Static Analyst with high confidence in a specific TTP should carry more weight in the consensus than a Dynamic Analyst expressing uncertainty. WISE's architecture provides a template for Maljan's Judge agent's synthesis logic.

---

**Paper 14: "Multi-Agent Debate for LLM Judges with Adaptive Stability Detection"**
- **Authors:** Multiple (arXiv:2510.12697)
- **Year:** 2025
- **Venue:** arXiv
- **Summary:** Introduces a Beta-Binomial mixture model to track judge consensus dynamics and applies adaptive stopping via Kolmogorov–Smirnov testing. This statistically principled early-exit mechanism for debate rounds shows significant improvement in judgment accuracy over majority voting while maintaining computational efficiency.
- **Relevance to Maljan:** Maljan's negotiation loop needs a termination criterion. The adaptive stability detection mechanism in this paper is a production-ready solution — negotiation rounds stop when agent agreement has statistically stabilized, avoiding both premature convergence and runaway token cost.

---

**Paper 15: "Free-MAD: Consensus-Free Multi-Agent Debate"**
- **Authors:** Multiple (arXiv:2509.11035)
- **Year:** 2025
- **Venue:** arXiv
- **Summary:** Identifies a critical failure mode of consensus-driven MAD: the "Silent Agreement" problem, where agents stop providing new arguments due to conformity pressure even when they started with divergent views. This leads to stronger-than-warranted consensus on wrong answers. Proposes a consensus-free variant where agents are incentivized to maintain divergence.
- **Relevance to Maljan:** Critical finding for Maljan's negotiation design. The Silent Agreement problem is the academic name for the "echo chamber" risk. Maljan must implement explicit dissent requirements (e.g., each agent must cite at least one unresolved contradiction in its revision) to prevent conformity-driven false consensus.

---

**Paper 16: "Towards a Responsible LLM-Empowered Multi-Agent Systems" (Position Paper)**
- **Authors:** Multiple (arXiv:2502.01714)
- **Year:** 2025
- **Venue:** arXiv
- **Summary:** Documents the "conformity effect" and "authoritative bias" as systemic problems in multi-agent LLM debate: agents align with wrong consensus or defer to perceived authority, amplifying reasoning errors. Proposes adversarial self-play (Generator-Discriminator pattern) and structured prompting with domain ontologies as mitigations.
- **Relevance to Maljan:** Directly motivates Maljan's Judge-as-independent-arbiter architecture. The paper's recommendation to use domain ontologies (in Maljan's case, the MITRE ATT&CK ontology) as structured constraints in prompting is immediately actionable.

---

### 1d. STIX 2.1 & Automated CTI Generation

---

**Paper 17: "aCTIon: Automated Analysis of Cyber Threat Intelligence in the Wild"**
- **Authors:** Multiple (arXiv:2307.10214)
- **Year:** 2023
- **Venue:** arXiv / IEEE
- **Summary:** Curates a dataset of 204 real-world threat reports (from Palo Alto, Trend Micro, Fortinet) with corresponding STIX bundle representations — 36.1k entities and 13.6k relations. Develops an LLM-based (GPT-3.5) pipeline for structured STIX extraction and compares it to 10 prior methods. Achieves state-of-the-art performance and provides the largest open-source CTI-to-STIX dataset known at publication time.
- **Relevance to Maljan:** The aCTIon dataset (204 STIX bundles, 36k entities) is an immediately usable training/validation set for Maljan's Judge agent. The extraction pipeline is a direct template for converting Maljan's aggregated analysis into STIX 2.1 format.

---

**Paper 18: "TIEF: Threat Intelligence Extraction Framework for TTP Extraction"**
- **Authors:** Multiple (MDPI Sensors, 2025)
- **Year:** 2025
- **Venue:** MDPI Sensors
- **Summary:** Proposes a full pipeline using DistilBERT-Base-Uncased for multi-label TTP classification across all 560 MITRE ATT&CK sub-techniques, achieving F1=0.933. Combines LLM-based data augmentation, sentence grouping via semantic correlation, and end-to-end STIX 2.1 formatting. Operates with 40% fewer parameters than BERT-Base while preserving 97% of its performance.
- **Relevance to Maljan:** TIEF's 560-sub-technique classifier is a strong candidate for a non-LLM baseline in Maljan's TTP mapping stage. Using TIEF as a "first pass" classifier before LLM refinement could dramatically reduce false positives in the final STIX bundle.

---

**Paper 19: "SynthCTI: LLM-Driven Synthetic CTI Generation to Enhance MITRE Technique Mapping"**
- **Authors:** Multiple (arXiv:2507.16852)
- **Year:** 2025
- **Venue:** arXiv
- **Summary:** Addresses severe class imbalance in TTP training data (some ATT&CK techniques have only a few real-world examples). Uses HDBSCAN clustering + topic modeling + LLM generation to produce synthetic CTI sentences for underrepresented classes, achieving substantial macro-F1 gains on two real-world datasets.
- **Relevance to Maljan:** Maljan's Judge agent will encounter rare TTPs in real malware samples. SynthCTI's augmentation pipeline can bootstrap training data for the Judge's TTP classifier on low-frequency sub-techniques, improving confidence scores on uncommon attack patterns.

---

## 2. Technology & Framework Evaluation

### 2a. LangGraph vs. Alternatives

The framework landscape as of 2025–2026 consolidates around five major options for multi-agent orchestration. Here is a head-to-head analysis on the dimensions most critical to Maljan.

#### Framework Comparison Matrix

| Dimension | **LangGraph** | **AutoGen / AG2** | **CrewAI** | **MetaGPT** | **OpenAI Swarm (→ SDK)** |
|---|---|---|---|---|---|
| **Orchestration model** | Directed cyclic graph, state machine | Conversational GroupChat | Role-based crews + Flows | Role-based, code-first | Explicit handoffs |
| **Stateful negotiation loops** | ★★★★★ Native — graph supports cycles natively | ★★★★ GroupChat supports multi-turn debate | ★★★ Flows support cycles but less flexible | ★★ Sequential by design | ★★ No persistent state; ephemeral handoffs |
| **Conditional routing / early exit** | ★★★★★ First-class conditional edges | ★★★ Manual — requires custom logic | ★★★ Flows support branching | ★★ Hardcoded pipelines | ★★ No native early-exit |
| **State persistence** | ★★★★★ Built-in checkpointing + time-travel replay | ★★★ Conversation history (in-memory default) | ★★★ Task outputs passed sequentially | ★★★ Agent memory with Redis | ★★ Context variables (ephemeral) |
| **Human-in-the-loop** | ★★★★★ First-class workflow hook | ★★★ Supported but manual | ★★★ Checkpoint approval integration | ★★ Limited | ★★ Manual only |
| **Model agnosticism** | ★★★★★ Any provider | ★★★★★ Any provider | ★★★★★ Any provider | ★★★★ Primarily OpenAI-focused | ★ OpenAI models only |
| **Learning curve** | ★★★ Steep (graph-thinking required) | ★★★ Moderate | ★★★★ Low-moderate | ★★★ Moderate | ★★★★ Low |
| **Token efficiency** | ★★★★ Efficient — state is explicit, no redundant history | ★★ Expensive — every turn carries full conversation history | ★★★ Moderate | ★★★ Moderate | ★★★ Moderate |
| **Production readiness** | ★★★★★ v1.0, LangSmith observability, fault-tolerant | ★★★★ AG2 v0.4 rewrite is async-first | ★★★★ Production-deployed | ★★★ Research-oriented | ★★★ Released March 2025 |

#### Recommendation for Maljan: **LangGraph — confirmed correct choice.**

Maljan's pipeline requires: (1) stateful negotiation loops with conditional early-exit, (2) strict state transitions between analysis phases, (3) persistent checkpointing for reproducibility, and (4) a structured Judge node with access to all prior agent state. LangGraph is the only framework among these that treats all four as first-class primitives. The negotiation loop — where agents read each other's reports and revise — is a directed cycle in LangGraph terms, something that requires substantial custom engineering in CrewAI or AutoGen.

**Note on AutoGen as an alternative:** AutoGen's GroupChat pattern is architecturally designed for conversational debate, which makes it a compelling alternative specifically for the negotiation sub-loop. A hybrid architecture — LangGraph as the outer state machine, with an AutoGen GroupChat embedded as a single LangGraph node for the negotiation phase — is worth exploring and has precedent in production systems.

---

### 2b. LLM Model Selection for Malware Analysis

#### Open-Source Models for Code/Assembly Understanding

| Model | Context Window | Assembly Support | Malware-Specific Training | Recommendation |
|---|---|---|---|---|
| **LLaMA 3.3 70B** | 128K tokens | Good (general code) | None | Strong general baseline |
| **Codestral (Mistral)** | 256K tokens | Very good (code-first) | None | Best large-context code model |
| **CodeLLaMA 34B** | 100K tokens | Good | None | Strong for decompiled C |
| **DeepSeek-Coder-V2** | 128K tokens | Excellent | None | Best overall code reasoning |
| **asmLLM (Bitdefender)** | ~4K tokens (legacy) | Assembly-native | Yes (500M assembly tokens) | Best for raw assembly, small context |
| **Gemini 2.5 Pro (fine-tuned)** | 1M tokens | Good | Post-fine-tune | Best after fine-tuning (proprietary) |

**Key findings from the literature:**

1. **Context window is the binding constraint.** Real-world decompiled malware (e.g., full Babuk ransomware decompilation) easily exceeds 100K tokens. Codestral's 256K window and Gemini 2.5 Pro's 1M window are the current leaders. For production Maljan, chunked processing with hierarchical summarization is required even for large-context models.

2. **Domain pretraining matters for assembly.** General code LLMs describe assembly "line by line" without grasping the high-level structure. The Bitdefender asmLLM demonstrates that pretraining on 500M assembly tokens changes this qualitatively. For the Static Analyst agent, a LoRA-fine-tuned Codestral or LLaMA 3.3 on assembly data is the recommended production path.

3. **No mature malware-specific foundation model exists as of 2025.** SecureBERT (fine-tuned on cybersecurity text) and CyberPhi are NLP-focused, not code-focused. MalBERT (trained on malware bytecode) exists but is not an instruction-following LLM. The gap between "cybersecurity text models" and "assembly-capable code LLMs" is a genuine research opportunity.

4. **Benchmarks available:** The 2017 Baseline Dataset (used in the Decompilation-Driven paper) and MalwareBazaar samples are standard. RMCBench (from the survey, 2025) provides a structured zero/few-shot malware analysis benchmark.

#### Practical Recommendation for Maljan

- **Static Analyst Agent:** DeepSeek-Coder-V2 (128K) or Codestral (256K) as base; fine-tune with LoRA on x86-64 assembly data for production. Use chunked hierarchical summarization for large binaries.
- **Dynamic Analyst Agent:** LLaMA 3.3 70B or Codestral; the task is behavioral log interpretation (API call sequences), not raw assembly, so assembly pretraining is less critical.
- **Network Analyst Agent:** Any strong general LLM (Claude Sonnet 4.6, GPT-4o, LLaMA 3.3 70B); PCAP summary interpretation is closest to natural language reasoning.
- **Judge Agent:** Claude Sonnet 4.6 or GPT-4o; the synthesis task requires strong instruction-following, JSON schema compliance, and STIX structure generation — areas where frontier proprietary models currently excel.

---

### 2c. Sandbox Integration Options

#### Comparative Analysis

| Sandbox | Type | REST API Quality | JSON Output | Key Strengths | Limitations |
|---|---|---|---|---|---|
| **CAPEv2** | Self-hosted / Open-source | ★★★★★ Full REST API (`/apiv2/`) | Rich JSON (behavior, network, CAPE, memory dumps) | Anti-evasion bypasses, automated unpacking, YARA classification, PCAP capture, config extraction | Complex setup, resource-intensive, requires maintained VM infrastructure |
| **Hatching Triage** | SaaS + self-hosted | ★★★★★ REST API, structured JSON | Excellent — behavioral JSON, network JSON, screenshots | Multi-platform (Win/Linux/Android/macOS), fast turnaround, public free tier | Reports public unless enterprise; no Windows 11 yet |
| **Any.Run** | SaaS | ★★★★ API access (paid) | Good | Interactive sandbox, real-time observation, collaboration features | Paid API; interactive only (not batch-optimized) |
| **Cuckoo Sandbox** | Self-hosted / Open-source | ★★★★ REST API | Good JSON | Battle-tested, extensive community plugins | Python 2.7 legacy (community forks diverge), less maintained than CAPEv2 |
| **Joe Sandbox** | SaaS | ★★★★★ REST API | Excellent | Deep behavioral analysis, Windows/Linux/iOS | Expensive; no free tier for API |
| **VirusTotal Intelligence** | SaaS | ★★★★ REST API | Good (VT API v3) | 70+ AV engines, massive sample database | Upload becomes public (standard); sandbox behavioral data costs extra |

#### Recommendation for Maljan

**Primary (self-hosted production):** CAPEv2 — the richest JSON behavioral output, native PCAP capture, config extraction, and an active REST API (`apiv2/tasks_create_file`, `apiv2/tasks_list`) make it the ideal source for Maljan's Dynamic Analyst and Network Analyst agents. The `behavior.json`, `network.json`, and `CAPE.json` outputs from CAPEv2 map directly to Maljan's three analysis domains.

**Secondary (cloud/testing):** Hatching Triage — the free public tier enables rapid prototyping and evaluation without infrastructure overhead. The REST API is well-documented and returns structured JSON suitable for direct pipeline integration.

**Datasets for Training/Testing:**
- **MalwareBazaar** (abuse.ch): Free, large, tagged samples with family labels. No sandbox reports, but samples can be re-submitted to CAPEv2.
- **VirusTotal (Intelligence tier):** Behavioral sandbox reports available but expensive.
- **EMBER dataset (Endgame):** 1M PE samples with static feature vectors — useful for the Static Analyst pre-processing stage.
- **aCTIon dataset** (Paper 17 above): 204 STIX bundles from real threat reports — gold standard for Judge agent evaluation.

---

### 2d. Vector Database for RAG (Long-Term Memory)

#### Comparative Analysis

| Database | Query Model | STIX Support | Scalability | Self-Hosted | Key Strengths |
|---|---|---|---|---|---|
| **Qdrant** | Dense + Sparse (hybrid) | JSON storage natively | Excellent (Rust core) | Yes (Docker) | Best hybrid search performance, payload filtering, named collections |
| **ChromaDB** | Dense (HNSW) | JSON metadata | Moderate | Yes (Python-native) | Simplest integration with LangChain, zero-config for development |
| **Weaviate** | Dense + Sparse + BM25 | Native JSON schema | Excellent | Yes + SaaS | GraphQL API, multi-tenancy, strong schema enforcement |
| **Pinecone** | Dense + Sparse | JSON metadata | Excellent (managed) | No (SaaS only) | Lowest operational overhead | Vendor lock-in, cost at scale |
| **pgvector** | Dense (IVFFLAT/HNSW) | PostgreSQL JSONB | Good | Yes | Unified SQL+vector queries — join STIX entities with vector similarity |

#### Recommendation for Maljan

**Development/Prototyping:** ChromaDB — LangChain-native integration, zero operational overhead, sufficient for testing RAG workflows with STIX bundles.

**Production:** Qdrant — the Rust core delivers the best query throughput for malware analysis workloads. The payload filtering capability allows Maljan to retrieve similar analyses filtered by malware family, campaign, or time period before performing vector similarity search. Named collections can separate static analysis reports from behavioral reports from STIX bundles.

**STIX Bundle Indexing Strategy:**
1. Decompose each STIX bundle into individual STIX Domain Objects (SDOs): Malware, AttackPattern, Indicator, Campaign, ThreatActor.
2. Generate embeddings per SDO using a cybersecurity-tuned embedding model (e.g., SecureBERT embeddings, or text-embedding-3-large for proprietary stacks).
3. Store the full STIX JSON as payload alongside the embedding.
4. At retrieval time, query by the current malware's behavioral signature → retrieve top-k similar past analyses → inject them into the relevant specialist agent's context as few-shot examples.

This RAG approach is the "long-term memory" described in Maljan's architecture: past analyses inform current analysis, enabling family-level attribution even for novel variants.

---

## 3. Known Limitations & Open Problems

### 3a. Known Failure Modes of LLM-Based Malware Analysis

**1. Hallucination of IOCs and Attributions.**
LLMs confidently generate plausible-sounding but incorrect IP addresses, domain names, and threat actor attributions. The "Uncovering Vulnerabilities" paper (Paper 4) documents spurious correlations where commodity tools like Mimikatz are misattributed as actor-specific signatures. In a production CTI pipeline, hallucianted IOCs can corrupt threat intelligence databases and trigger false-positive incident responses.

**2. Context Window Exhaustion ("Lost in the Middle").**
The "Decompilation-Driven Framework" paper documents that models with limited context windows degrade on critical code segments when forced to process lengthy decompiled output. Performance drops are non-linear — not proportional to how much is truncated. Even 256K-context models exhibit this for very large binaries (>250KB compiled). The practical mitigation is hierarchical summarization: chunk → summarize per function → merge summaries → analyze.

**3. Obfuscated Code Blindspots.**
USENIX Security 2024 (Paper 8) demonstrates significant performance degradation on obfuscated code. Packers, polymorphic engines, and anti-analysis techniques that operate at the binary level are essentially invisible to LLMs trained on clean source code. LLMs describing obfuscated assembly tend to describe the obfuscation layer rather than the payload.

**4. Training Data Contamination.**
Known malware families (Emotet, WannaCry, Mirai) are heavily represented in LLM training data, causing models to recognize patterns by memorization rather than reasoning. For novel variants or zero-day malware, performance degrades unpredictably.

**5. Inconsistent Structured Output.**
LLMs generating STIX-formatted JSON show structural inconsistencies (invalid references, missing required fields, malformed timestamps) even when explicitly prompted. Schema validation with Pydantic v2 (already in Maljan's stack) is essential as a post-processing guard.

**6. Non-Determinism.**
Temperature > 0 introduces run-to-run variance. For reproducible CTI, Maljan must log the exact model, temperature, system prompt version, and input hash for every analysis. LangSmith (LangChain's observability layer) can provide this automatically.

---

### 3b. The Echo Chamber Problem in Multi-Agent Systems

The academic literature identifies this as the **"Silent Agreement" problem** (Free-MAD, arXiv:2509.11035) and the **"conformity effect"** (Position Paper, arXiv:2502.01714).

**Mechanism:** When LLM agents receive each other's analyses, they exhibit a strong tendency to update their own beliefs toward the most confident or most detailed peer report, regardless of whether that report is correct. This is not genuine Bayesian updating — it is a statistical artifact of the pre-training objective, which rewarded agreement with high-probability outputs.

**Documented failure mode:** "In multi-agent debates, an agent with a partially flawed understanding may generate persuasive yet erroneous rationales, potentially impacting others and collectively diverting the reasoning path from accurate solutions." (Position Paper, arXiv:2502.01714)

**Mitigation strategies supported by literature:**

1. **Forced dissent protocol:** Each agent, when revising its report in the negotiation loop, must explicitly cite at least one claim from a peer's report that it still disputes, with cited evidence. An agent that has no disputes must flag convergence explicitly (making agreement an active choice, not a passive default).

2. **Role-differentiated adversarial prompting:** Assign one agent the permanent role of "Devil's Advocate" per round, whose explicit task is to find the strongest counter-evidence to the emerging consensus. This is supported by the Generator-Discriminator pattern described in the Position Paper.

3. **Heterogeneous model ensemble:** Use different base models for different specialist agents (e.g., Claude for Static, GPT-4o for Dynamic, LLaMA for Network). Agents with different pretraining data and RLHF policies are less likely to share the same blind spots.

4. **Confidence-weighted, not vote-weighted, aggregation:** The WISE paper (Paper 13) demonstrates that naive majority voting is outperformed by weighted aggregation based on domain-specific confidence scores. Maljan's Judge should weight each agent's claims by a calibrated domain confidence score, not by consensus count.

---

### 3c. State of the Art for Automated MITRE ATT&CK TTP Mapping

**LLM-based approaches (current SOTA):**
The aCTIon system (Paper 17) using GPT-3.5 with custom extraction pipelines represents the strongest open benchmark result for full STIX generation from threat reports. For sub-technique-level classification, TIEF (Paper 18) achieves F1=0.933 across 560 sub-techniques using DistilBERT.

**Non-LLM baseline approaches (should be included as baselines):**

1. **TIEF / SecureBERT classifier** (F1=0.933): DistilBERT fine-tuned on cybersecurity text with LLM-augmented training data. Fastest inference, highest precision, but requires the behavioral description to already be in natural language form.

2. **CISA KEV + rule-based TTP mapping:** The original MITRE ATT&CK mapping methodology uses keyword matching + semantic similarity against the ATT&CK knowledge base. Tools like Sigma rules and YARA provide deterministic TTP signatures from behavioral artifacts.

3. **CAPE Signature Library:** CAPEv2 includes hundreds of YARA-based behavioral signatures that map directly to malware families and TTPs. These deterministic signatures should be the first-pass layer before LLM analysis.

4. **Graph-based attribution:** Recent work (arXiv:2512.23132) uses knowledge graph embedding (TransE, RotatE) to attribute TTPs from behavioral graphs, outperforming keyword-based methods on novel variants.

**Recommendation for Maljan:** A three-layer TTP mapping pipeline:
- **Layer 1:** CAPE YARA signatures + Sigma rules (deterministic, zero hallucination)
- **Layer 2:** TIEF/SecureBERT classifier (high-precision NLP over behavioral summaries)
- **Layer 3:** Judge agent LLM (contextual reasoning, confidence calibration, STIX generation)

---

## 4. Recommended Improvements & Research Gaps

### 4a. Concrete Architectural Improvements

**Improvement 1: Implement a Calibrated Confidence Protocol in the Negotiation Loop**
*Literature basis: WISE (arXiv:2512.02405), Multi-Agent Debate for LLM Judges (arXiv:2510.12697)*

Rather than agents communicating full reports, require each agent to output a structured confidence object: `{claim, evidence, confidence_score, supporting_artifacts}`. The negotiation loop then operates on this structured representation, and the adaptive stability detector (Beta-Binomial mixture model) terminates the loop when cross-agent confidence variance falls below a threshold. This eliminates both the echo chamber problem and runaway negotiation costs.

**Implementation in LangGraph:** Add a `NegotiationStateNode` that accumulates structured confidence objects per claim. Define a conditional edge `should_continue_negotiation` that evaluates the K-S statistic on confidence distributions and routes to either `CONTINUE` (another negotiation round) or `JUDGE` (finalize with Judge agent).

---

**Improvement 2: Three-Layer TTP Mapping Pipeline**
*Literature basis: TIEF (MDPI, 2025), aCTIon (arXiv:2307.10214), CAPE Signature Library*

Replace single LLM-based TTP mapping with a deterministic-to-LLM cascade:
1. CAPEv2 YARA signatures and Sigma rules produce high-confidence, zero-hallucination TTP candidates.
2. TIEF/DistilBERT classifies behavioral summaries into sub-technique labels.
3. Judge agent LLM performs contextual reasoning, resolves ambiguities, assigns confidence intervals, and generates the final STIX bundle.

This improves precision dramatically and provides a non-LLM ground truth for evaluation.

---

**Improvement 3: Heterogeneous Model Ensemble for Anti-Echo-Chamber Effect**
*Literature basis: Position Paper (arXiv:2502.01714), Free-MAD (arXiv:2509.11035)*

Assign different base models to each specialist agent (e.g., Claude Sonnet for Static Analyst, GPT-4o for Dynamic Analyst, DeepSeek-Coder for Network Analyst). Different pretraining corpora and RLHF policies mean agents have different systematic biases and blind spots. When they disagree, the disagreement is more likely to be genuine (different evidence weightings) than conformity-driven.

Additionally, implement the "forced dissent" protocol: in each negotiation round, each agent must produce a `dissent_items` list of claims it still disputes, with evidence. An empty `dissent_items` is treated as a convergence signal that is logged and reviewed, not automatically accepted.

---

**Improvement 4: Hierarchical Chunked Analysis with Function-Level Summarization**
*Literature basis: Decompilation-Driven Framework (arXiv:2601.09035), Feasibility Study (arXiv:2411.14905)*

For the Static Analyst agent, implement a two-stage processing pipeline:
1. **Function-level analysis:** The pre-processor decompiles binary → chunks by function → each chunk is analyzed independently with a smaller, faster model (e.g., CodeLLaMA 13B) → per-function summaries are generated.
2. **Program-level synthesis:** The summaries are ordered by CFG position (not raw order) and passed to the full-power Static Analyst LLM for cross-function pattern recognition, data flow analysis, and TTP identification.

This resolves the "lost in the middle" failure documented in the literature and allows analysis of arbitrarily large binaries.

---

**Improvement 5: RAG-Augmented Family Attribution**
*Literature basis: Multi-Agent Framework for Threat Mitigation (arXiv:2512.23132)*

At the start of each analysis, Maljan should query the Qdrant/Weaviate vector store for the top-3 most similar past STIX bundles. These bundles are injected into each specialist agent's context as few-shot examples before analysis begins. This enables:
- Family-level attribution for known malware variants without full re-analysis.
- Consistency: similar samples produce structurally similar STIX bundles.
- Continuous improvement: each new analysis enriches the knowledge base for future retrievals.

The embedding should encode both static features (import hash, section entropy) and behavioral features (API call n-grams from dynamic analysis) to ensure retrieval is multi-modal.

---

### 4b. Research Gaps Maljan Could Address

**Gap 1: Grounded Multi-Modal Negotiation for Malware Analysis**
No existing work combines static (disassembly), dynamic (sandbox behavioral logs), and network (PCAP) analysis within a single structured negotiation framework where agents cross-validate findings across modalities. The closest work (WISE) addresses multimodal debate in vision-language tasks, not in cybersecurity. Maljan's architecture is novel in this specific combination.

**Gap 2: Echo Chamber Measurement in Security-Specific Multi-Agent Systems**
The echo chamber/Silent Agreement problem is documented in general reasoning tasks (math, logic) but has never been quantitatively measured in a cybersecurity-specific multi-agent setting. Maljan could produce the first empirical study measuring how frequently agents in a malware analysis debate converge on incorrect TTPs vs. correct ones, and whether forced-dissent protocols improve accuracy.

**Gap 3: Structured STIX Generation with Uncertainty Quantification**
Current automated CTI tools produce deterministic STIX bundles without confidence annotations. Maljan could pioneer STIX bundles with per-relationship confidence intervals, enabling downstream analysts to prioritize uncertain attributions for human review. This is directly supported by the calibrated confidence protocol (Improvement 1) and has no precedent in the literature.

**Gap 4: Assembly-Native LLM for Malware Analysis**
The gap between NLP-focused cybersecurity models (SecureBERT, CyberPhi) and code-focused models (CodeLLaMA, DeepSeek-Coder) is unaddressed. No publicly available foundation model has been pretrained jointly on assembly code AND cybersecurity text AND behavioral API call sequences. Maljan's three-analyst architecture could generate a unique training dataset for such a model (static assembly summaries + dynamic API traces + network summaries, all labeled with STIX bundles).

**Gap 5: Automated Evaluation of Multi-Agent Malware Analysis Frameworks**
There is no standardized benchmark for evaluating complete malware analysis pipelines (input: malware artifacts; output: STIX bundle). CFA-Bench (Paper 5) addresses forensic agents but not full end-to-end malware analysis. Maljan could define and publish such a benchmark, positioning the framework as the reference implementation.

---

### 4c. Maljan as an Academic Paper: Novel Contribution and Positioning

**Title (proposed):** *"Maljan: Structured Multi-Agent Negotiation for Evidence-Grounded Malware Intelligence Generation"*

**Novel Contribution:**
The paper's primary claim would be the first demonstrated system combining three independently operating LLM specialist agents (static, dynamic, network) within a structured negotiation loop that: (1) explicitly quantifies cross-agent confidence, (2) applies adaptive termination when consensus stabilizes, and (3) generates STIX 2.1 bundles with per-claim uncertainty scores. The secondary contribution would be an empirical study of echo chamber effects in cybersecurity-specific multi-agent debate.

**Positioning relative to existing work:**

- vs. aCTIon (automated STIX from single-modality text): Maljan adds multi-modality, multi-agent negotiation, and uncertainty quantification.
- vs. TIEF (automated TTP classification): Maljan adds contextual reasoning, multi-modal fusion, and LLM-based synthesis beyond classification.
- vs. WISE (weighted multi-agent debate): Maljan applies the weighted aggregation principle to a novel security domain with real-world ground truth (STIX bundles from known malware campaigns).
- vs. general multi-agent debate papers (MAD, Free-MAD): Maljan provides a domain-specific instantiation with rigorous evaluation on real malware samples and quantitative TTP mapping accuracy.

**Target Venues:** IEEE S&P, USENIX Security, ACM CCS, or NDSS for full paper. arXiv preprint for rapid dissemination. The workshop track of any of these venues (e.g., AISEC co-located with CCS) would be appropriate for an early version.

---

## Appendix: Key Datasets

| Dataset | Type | Size | Access | Use in Maljan |
|---|---|---|---|---|
| MalwareBazaar | PE/ELF samples + metadata | 500K+ samples | Free (abuse.ch API) | Test samples for end-to-end pipeline |
| EMBER (Endgame) | Static PE features | 1M samples | Free (GitHub) | Static Analyst pre-processing features |
| aCTIon (arXiv:2307.10214) | Threat reports + STIX 2.1 bundles | 204 bundles, 36k entities | Research release | Judge agent training/evaluation |
| CAPEv2 public instance | Dynamic behavioral JSON | On-demand | Public API | Dynamic/Network Analyst test data |
| CTI-to-MITRE dataset | Text → ATT&CK technique labels | Thousands of labeled sentences | Research release | TTP classifier fine-tuning |
| MITRE ATT&CK STIX 2.1 | ATT&CK knowledge base | Full matrix (188 techniques) | Free (GitHub) | Judge agent RAG retrieval index |
| VirusTotal Intelligence | Multi-modal + sandbox reports | Millions (paid) | API (paid) | Production enrichment |

---

*Report compiled using academic papers from IEEE, ACM, arXiv (2022–2026), framework documentation, and security community benchmarks. All citations traceable to sources listed in the body of this report.*
