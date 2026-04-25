# Maljan: Multi-Agent Malware Analysis Framework — Comprehensive Research Report

---

## 1. ACADEMIC LITERATURE REVIEW

### 1a. Multi-Agent LLM Systems for Cybersecurity (2022–2025)

**Paper 1: DECODE — DEep Classification Of Dynamic Exploits**
*Authors:* (multi-institutional, published via PMC/Birkbeck, Oct 2025)
*Summary:* DECODE combines object detection, explainable AI (XAI), and agent-based LLMs to deliver a proportional multi-label, context-aware malware behavior analysis framework. It introduces the first object detection dataset specifically built for malware classification via an automated annotation pipeline. The framework demonstrates that integrating multiple AI paradigms (vision, LLM, XAI) yields interpretable and comprehensive malware analysis.
*Relevance to Maljan:* Directly demonstrates the value of agent-based LLM architectures for malware behavior analysis. Maljan's three-agent design (Static, Dynamic, Network) maps closely to DECODE's multi-modal integration philosophy. The automated annotation pipeline approach could inform Maljan's pre-processing layer.

**Paper 2: MalGEN — A Generative Agent Framework for Modeling Malicious Software**
*Authors:* Bikash Saha, Sandeep Kumar Shukla (arXiv:2506.07586, June 2025)
*Summary:* MalGEN presents a multi-agent framework that simulates coordinated adversarial behavior to generate diverse, activity-driven malware samples in a controlled ethical environment. Agents collaborate to emulate attacker workflows including payload planning, capability selection, and evasion strategies. The generated samples successfully bypassed leading antivirus systems.
*Relevance to Maljan:* While MalGEN is offensive (generation), its multi-agent architecture for modeling malware TTPs is the inverse of Maljan's defensive analysis pipeline. The TTP modeling and agent coordination patterns are transferable.

**Paper 3: CyberRAG — An Agentic RAG Cyber Attack Classification and Reporting Tool**
*Authors:* Francesco Blefari, Cristian Cosentino, Francesco A. Pironti, Angelo Furfaro, Fabrizio Marozzo (Future Generation Computer Systems, 2025)
*Summary:* CyberRAG is a modular agent-based RAG framework achieving high accuracy in cyber threat detection with interpretable explanations. A central LLM agent orchestrates fine-tuned classifiers specialized by attack family, tool adapters for enrichment, and an iterative retrieval-and-reason loop against a domain-specific knowledge base.
*Relevance to Maljan:* The agentic RAG pattern with iterative retrieval-and-reason loops is directly applicable to Maljan's long-term memory design. The classifier specialization by attack family informs agent specialization strategies.

**Paper 4: Automated LLM Malware Analysis — Building an Adversarial Consensus Engine**
*Authors:* Sentinel Labs (Red Sky Alliance, April 2026)
*Summary:* A multi-agent architecture for reversing macOS malware treats each reverse engineering tool (radare2, Ghidra, Binary Ninja, IDA Pro) as an independent, skeptical analyst in a serial pipeline. Each agent must verify or reject claims from previous agents. A "Gauntlet" phase runs agents in different order for peer review, with an explicit "Active Rejection Mandate." Only findings surviving adversarial review proceed to the final report.
*Relevance to Maljan:* **Highest relevance.** This is the closest existing work to Maljan's negotiation loop. The Active Rejection Mandate and Consensus field (AGREE/DISAGREE) directly inform Maljan's contradiction identification and revision design. The serial pipeline with cumulative evidence chain is a proven pattern.

**Paper 5: MALCDF — Multi-Agent LLM Cyber Defense Framework**
*Authors:* (distributed multi-agent approach, Dec 2025)
*Summary:* A practical framework where four LLM agents — Detection, Intelligence, Response, and Analysis — work together in real-time for cyber defense using secure, ontology-aligned messaging.
*Relevance to Maljan:* Demonstrates the viability of domain-specialized LLM agents in operational cybersecurity pipelines. The ontology-aligned messaging approach informs STIX output formatting.

**Paper 6: TTPDetect — Identifying Adversary Tactics and Techniques in Malware Binaries with an LLM Agent**
*Authors:* Zhou Xuan et al. (arXiv:2602.06325, Feb 2026)
*Summary:* The first LLM agent specifically designed for recognizing TTPs in stripped malware binaries. Combines dense retrieval with LLM-based neural retrieval to narrow analysis entry points, uses a function-level analyzing agent with on-demand incremental context retrieval and TTP-Specific Reasoning Guidelines. Achieves 93.25% precision and 93.81% recall on function-level TTP recognition, recovering 85.7% of documented TTPs and discovering 10.5 previously unreported TTPs per malware on average.
*Relevance to Maljan:* **Critical relevance** for the MITRE ATT&CK TTP mapping component. The function-level analysis agent design and retrieval-augmented approach to TTP matching directly inform Maljan's Judge agent architecture.

---

### 1b. LLM-Based Malware Analysis

**Paper 7: Large Language Model (LLM) for Software Security: Code Analysis, Malware Analysis, Reverse Engineering**
*Authors:* Hamed Jelodar et al. (arXiv:2504.07137 / ScienceDirect, April 2025)
*Summary:* A comprehensive survey of LLM-based approaches in malware code analysis. Categorizes approaches into static and dynamic analysis, covering detection, generation, monitoring, reverse engineering, and family analysis. Provides the first unified performance comparison table across multiple tasks. Key finding: LLMs show strong capability in interpreting code semantics and structure for identifying malicious behavior, but performance varies significantly by model, task, and data representation (source code vs. assembly vs. decompiled).
*Relevance to Maljan:* Foundational survey paper. Its taxonomy of malware analysis tasks and model comparison directly informs model selection and architecture design. Identifies critical research gaps Maljan could address.

**Paper 8: LLM4Decompile — Reverse Engineering: Decompiling Binary Code with Large Language Models**
*Authors:* (arXiv:2403.05286, March 2024)
*Summary:* Fine-tunes DeepSeek-Coder on 4 billion tokens of assembly-source pairs compiled from AnghaBench. Constructs Decompile-Eval, the first decompilation benchmark based on re-compilability and re-executability. Models range from 1.3B to 33B parameters. Demonstrates that fine-tuned code LLMs can achieve meaningful decompilation quality.
*Relevance to Maljan:* Directly relevant to the Static Analyst agent. LLM4Decompile provides both a model (DeepSeek-Coder fine-tuned) and evaluation methodology (re-compilability/re-executability) that can serve as the static analysis backbone.

**Paper 9: Asm2SrcEval — Evaluating LLMs for Assembly to Source Code Translation**
*Authors:* Parisa Hamedi, Hamed Jelodar et al. (NeurIPS 2025)
*Summary:* First comprehensive evaluation of five state-of-the-art LLMs on assembly-to-source translation using BLEU, ROUGE, METEOR, BERTScore, perplexity, and inference time. Reveals clear trade-offs: models excelling in text similarity may not be fastest or most fluent. Identifies key failure areas including control flow recovery and identifier reconstruction.
*Relevance to Maljan:* Provides empirical evidence for model selection decisions. The failure analysis (control flow, identifier reconstruction) directly maps to known limitations the Static Analyst must handle.

**Paper 10: An Empirical Study on the Effectiveness of LLMs for Binary Code Understanding**
*Authors:* Xiuwei Shang et al. (arXiv:2504.21803, April 2025)
*Summary:* Proposes a benchmark for LLM evaluation on binary code understanding via function name recovery and binary code summarization. Covers multiple architectures and optimization levels. Finds existing LLMs can understand binary code "to a certain extent," improving analysis efficiency.
*Relevance to Maljan:* Provides benchmarking methodology for evaluating Static Analyst performance. The finding that LLMs partially understand binary code supports Maljan's multi-agent cross-validation approach.

**Paper 11: ASMA-Tune — Unlocking LLMs' Assembly Code Comprehension via Structural-Semantic Instruction Tuning**
*Authors:* (2025, arXiv)
*Summary:* Achieves state-of-the-art in assembly comprehension with +39.7% Recall@1 and +17.8% MRR improvements over GPT-4-Turbo through structural-semantic instruction tuning.
*Relevance to Maljan:* Demonstrates that specialized fine-tuning significantly improves assembly understanding, suggesting Maljan should consider fine-tuned models for the Static Analyst rather than general-purpose LLMs.

**Key Datasets Identified:**
- **AnghaBench**: 1M C code samples compiled to assembly (used by LLM4Decompile)
- **Decompile-Eval**: Based on HumanEval, for re-compilability/re-executability
- **MalwareBazaar**: Public malware repository with tags, family attribution, delivery method; supports API-based bulk download
- **VirusTotal**: Community sandbox reports accessible via API
- **Cuckoo Sandbox reports dataset**: Contains static analysis data with top-1000 imported functions

---

### 1c. Consensus and Negotiation in Multi-Agent AI

**Paper 12: ReConcile — Round-Table Conference Improves Reasoning via Consensus among Diverse LLMs**
*Authors:* Justin Chen, Swarnadeep Saha, Mohit Bansal (ACL 2024, pp. 7066–7085)
*Summary:* Motivated by Minsky's "Society of Mind" (1988), ReConcile implements a round-table conference among diverse LLM agents. Agents engage in multiple discussion rounds, learning to convince others using a "discussion prompt" containing grouped answers, confidence scores, and demonstrations. Uses confidence-weighted voting for final consensus. Achieves up to 11.4% improvement over baselines, outperforming GPT-4 on three datasets. Model diversity is shown to be critical — different model combinations yield 8% improvement on MATH.
*Relevance to Maljan:* **Foundational.** The round-table consensus pattern, confidence-weighted voting, and demonstration of diversity-as-strength directly validate Maljan's multi-agent negotiation design. The "discussion prompt" structure (grouped answers + confidence + demonstrations) provides a concrete template for Maljan's cross-agent communication protocol.

**Paper 13: SELENE — Selective and Evidence-Weighted LLM Debating for Efficient and Reliable Reasoning**
*Authors:* Akshay Verma, Swapnil Gupta, Deepak Gupta, Prateek Sircar, Siddharth Pillai (EACL 2026, Industry Track, pp. 95–104)
*Summary:* Addresses two key MAD limitations: computational expense and degradation under prolonged debates. Introduces Selective Debate Initiation (SDI) that dynamically predicts when debate is necessary by detecting confidence-likelihood misalignment, and Evidence-Weighted Self-Consistency (EWSC) replacing single-judge verdicts. Reduces token consumption by ~50% while improving accuracy and calibration.
*Relevance to Maljan:* **Directly applicable.** SDI's debate-on-demand approach solves the token efficiency problem in Maljan's negotiation loop. EWSC's evidence-weighted aggregation provides a superior alternative to simple majority voting for the Judge agent.

**Paper 14: Can LLM Agents Really Debate? A Controlled Study of Multi-Agent Debate in Logical Reasoning**
*Authors:* Haolun Wu et al. (arXiv:2511.07784, Nov 2025)
*Summary:* A controlled study using Knight-Knave-Spy logic puzzles examines six structural and cognitive factors (team size, composition, confidence visibility, debate order, depth, difficulty). Key findings: (1) intrinsic reasoning strength and group diversity are dominant drivers of success, (2) structural parameters offer limited gains, (3) **majority pressure suppresses independent correction**, (4) effective teams overturn incorrect consensus, (5) rational, validity-aligned reasoning most strongly predicts improvement.
*Relevance to Maljan:* **Crucial finding for design.** The discovery that majority pressure suppresses independent correction is a warning for Maljan's negotiation design — agents must not simply converge to majority opinion. Validity-aligned (evidence-based) reasoning should be incentivized over agreement-seeking.

**Paper 15: Encouraging Divergent Thinking in LLMs through Multi-Agent Debate**
*Authors:* (ACL Anthology)
*Summary:* Proposes a MAD framework where agents express arguments in "tit for tat" with a judge managing the debate process. Explicitly designed to encourage divergent thinking and avoid the "Degeneration of Thought" (DoT) problem where agents converge prematurely.
*Relevance to Maljan:* Addresses the echo chamber problem directly. The "tit for tat" debate pattern and judge-managed process align with Maljan's architecture.

**Paper 16: Enhancing Multi-Agent Consensus through Third-Party LLM Integration**
*Authors:* Duan et al. (arXiv, Nov 2024)
*Summary:* Integrates different LLMs to expand knowledge boundaries, reduce single-model dependency, and promote in-depth debate. Third-party LLM integration optimizes consensus formation and mitigates hallucinations.
*Relevance to Maljan:* Supports using multiple distinct LLM providers (OpenAI, Anthropic, Ollama) for different agents to maximize diversity and reduce correlated errors.

**Paper 17: Polarization of Autonomous Generative AI Agents Under Echo Chambers**
*Authors:* Masaya Ohagi et al. (ACL 2024 Workshop, pp. 112–124)
*Summary:* Investigates polarization among autonomous AI agents in echo chamber environments. ChatGPT-based agents tended to polarize due to high prompt understanding and opinion-updating capability. Echo chambers generate polarization even among AI agents.
*Relevance to Maljan:* **Warning signal.** Demonstrates that AI agents can form echo chambers and polarize when they only hear reinforcing opinions. This directly validates the need for Maljan's adversarial review mechanism and diverse agent perspectives.

---

### 1d. STIX 2.1 and Automated Threat Intelligence Generation

**Paper 18: CTI-GEN — A Framework for Generating STIX 2.1 Compliant CTI Using Generative AI**
*Authors:* (IEEE CSR 2025, pp. 334–341)
*Summary:* First framework to generate complete CTI in STIX 2.1 from unstructured text using LLMs. Six-component pipeline with detailed prompt engineering and STIX schema preprocessing to simplify complex interdependencies. Achieves F1=81% for object generation, 57% for relationship generation, and 96% precision for attribute value assignment.
*Relevance to Maljan:* **Directly applicable** to the Judge agent's STIX bundle generation. The six-component pipeline and schema preprocessing approach informs output formatting. The 57% relationship F1 highlights a key challenge Maljan must address.

**Paper 19: eLLM-CTI — Enhanced LLM Extraction of CTI from Unstructured Threat Reports**
*Authors:* (ScienceDirect, April 2026)
*Summary:* Enhanced LLM-based approach (eLLM-CTI) for extracting threat intelligence from unstructured reports and converting to STIX 2.1. Addresses the tough problem of automated CTI extraction with improved accuracy.
*Relevance to Maljan:* Provides baseline methodology and metrics for evaluating Maljan's STIX output quality.

**Existing STIX Tools:**
- **txt2stix**: Python script extracting IoCs and TTPs from text, identifying relationships, converting to STIX 2.1 bundles
- **Stixify**: Takes files (PDFs, Word docs, HTML) and converts to structured threat intelligence via txt2stix
- **cve2stix**: Converts NVD CVE records to STIX 2.1 objects
- **GenAI-STIX2.1-Generator**: Azure OpenAI-based tool for web-to-STIX conversion

**Paper 20: Uncovering Vulnerabilities of LLM-Assisted Cyber Threat Intelligence**
*Authors:* Yuqiao Meng et al. (arXiv:2509.23573, Sep 2025–Feb 2026)
*Summary:* Comprehensive empirical study of LLM vulnerabilities in CTI reasoning. Identifies three domain-specific cognitive failures: spurious correlations from superficial metadata, contradictory knowledge from conflicting sources, and constrained generalization to emerging threats. Uses human-in-the-loop categorization to avoid brittle "LLM-as-a-judge" pipelines.
*Relevance to Maljan:* **Critical caution.** The finding that "LLM-as-a-judge" pipelines are brittle directly challenges Maljan's Judge agent design, suggesting human-in-the-loop safeguards. The three failure modes must be mitigated in Maljan's architecture.

---

## 2. TECHNOLOGY & FRAMEWORK EVALUATION

### 2a. LangGraph vs. Alternatives

| Criterion | **LangGraph** | **AutoGen** | **CrewAI** | **MetaGPT** |
|---|---|---|---|---|
| **Architecture** | Graph-based (Pregel), stateful nodes+edges | Conversational, agent-to-agent chat | Role-based, sequential task delegation | Software team simulation, SOP-based |
| **Stateful Negotiation** | ⭐⭐⭐ Native state persistence via checkpoints, subgraphs for agent teams | ⭐ Limited (conversation history) | ⭐ Partial (Flows) | ⭐ Limited (message history) |
| **Conditional Routing** | ⭐⭐⭐ Native conditional edges, interrupt/resume | ⭐⭐ Conversational branching | ⭐ Sequential only | ⭐ Predefined pipeline |
| **Loop Support** | ⭐⭐⭐ Built-in cycles via Pregel graph model | ⭐⭐ Multi-turn conversations | ⭐ Limited | ⭐ Limited |
| **Token Overhead** | +9% | +31% | +18% | Not benchmarked |
| **Median Latency** | 14.1s | 22.7s | 18.4s | Not benchmarked |
| **Cost/1K Tasks** | $41.70 | $67.40 | $48.20 | N/A |
| **Learning Curve** | Steep (graph theory + Python) | Moderate | Low (YAML config) | Moderate |

**Verdict:** LangGraph is the **uniquely suitable** choice for Maljan. Its Pregel-based graph architecture natively supports the stateful, iterative negotiation loop with conditional routing — features essential for Maljan's three-agent debate → revise → re-evaluate cycle. No other framework provides equivalent support for cyclic agent workflows, granular retry policies, and persistent checkpointing. The +9% token overhead (vs. +31% for AutoGen) makes it the most cost-efficient for production deployment.

MetaGPT and CrewAI are optimized for linear, role-based task decomposition (e.g., software development pipelines) and cannot easily express the cyclic negotiation pattern Maljan requires. AutoGen's conversational model theoretically supports debate, but its higher token overhead (+31%) and lack of state machine guarantees make it less suitable for deterministic malware analysis pipelines.

### 2b. LLM Model Selection for Malware Analysis

**Code/Assembly Understanding — Benchmarked Models:**

| Model | Task | Performance | Source |
|---|---|---|---|
| **DeepSeek-Coder** (LLM4Decompile) | Assembly→C decompilation | 0.21 re-executability |  |
| **GPT-4-Turbo** | Assembly comprehension | Baseline; outperformed by ASMA-Tune (+39.7% Recall) |  |
| **LLaMA 3.1 8B** | CTI tasks | Comparable to LLaMA 3.1 70B when fine-tuned (Foundation-Sec) |  |
| **Mistral-7B** (cybersecurity fine-tune) | YARA/Suricata rule generation | 32K context window |  |

**Malware-Specific Models:**
- **SecureBERT** (RoBERTa-based): Domain-specific for cybersecurity text. Trained on large cybersecurity corpora. Demonstrated superior masked word prediction in cyber contexts. Used for opcode sequence classification. *Limitation: BERT architecture, not generative.*
- **Foundation-Sec-8B-Instruct** (Aug 2025): Open-weight 8B parameter model built on LLaMA 3.1, specialized for cybersecurity applications. Instruction-tuned, permissive license, suitable for on-prem/air-gapped deployment. Comparable or better than LLaMA 3.1 70B on CTI tasks.
- **LLM4Decompile** (1.3B–33B): Fine-tuned DeepSeek-Coder specifically for decompilation. Multiple sizes available on Hugging Face.

**Context Window Requirements:**
- Typical decompiled malware binaries produce 20–30K tokens of analysis output.
- At ~2.6 bytes/token for binary content, 8,192 tokens covers ~21KB; 32,768 tokens covers ~84KB (often sufficient for complete small binaries).
- For realistic decompiled code input with multiple analysis tool outputs, a **minimum 32K context window** is recommended, with 128K+ preferred for complex samples.
- Gemini's 1M-token window has been demonstrated for entire-binary analysis; a distilled representation can fit within this.

**Recommendation:** Use **DeepSeek-Coder/LLM4Decompile** for the Static Analyst, **Foundation-Sec-8B** or **Claude** for general threat analysis, and ensure all models support ≥32K context windows. Provider diversity (OpenAI + Anthropic + Ollama) aligns with the ReConcile finding that model diversity drives superior consensus outcomes.

### 2c. Sandbox Integration Options

| Sandbox | Open Source | REST API | Behavioral JSON | Anti-Evasion | Maintenance Status |
|---|---|---|---|---|---|
| **CAPEv2** | ✅ Yes | ✅ Comprehensive REST API v2 | ✅ (API calls, processes, files, registry, network) | ✅ Advanced unpacking, config extraction | ✅ Active (Cuckoo fork) |
| **Cuckoo** | ✅ Yes | ✅ REST API | ✅ | ⚠️ Basic | ❌ **Discontinued** |
| **Any.Run** | ❌ Proprietary | ✅ API (limited free tier) | ✅ | ✅ Interactive analysis | ✅ Active |
| **Hatching Triage** | ❌ Proprietary | ✅ Comprehensive API | ✅ | ✅ Modern architecture | ✅ Active |

**Verdict: CAPEv2 is the recommended choice.** It provides the most comprehensive open-source REST API with full programmatic access to task submission, analysis management, and result retrieval. Its advanced payload extraction, automated unpacking, and YARA-based classification capabilities are critical for pre-processing. The API supports both authenticated and anonymous access.

CAPEv2 complements Cuckoo's traditional output with automated dynamic unpacking, configuration extraction, and behavioral monitoring including Windows API call hooking. Its Suricata integration provides network behavioral data.

**Public Datasets:**
- **MalwareBazaar** (abuse.ch): Public repository with API for bulk sample download, hash lookups, YARA rule matching, family attribution. Supports automated workflows.
- **VirusTotal API**: Sandbox reports from multiple engines, accessible programmatically.
- **Cuckoo Sandbox Reports Dataset**: Contains static analysis data with top-1000 imported functions, suitable for training.
- **Sandbox-Ransomware-Analysis-Dataset**: Curated dataset combining VirusTotal, MalwareBazaar, and VirusShare sources.

For training/testing Maljan, a pipeline ingesting MalwareBazaar samples → CAPEv2 sandbox execution → structured JSON output is the recommended data generation workflow.

### 2d. Vector Database for RAG (Long-Term Memory)

| Criterion | **Qdrant** | **ChromaDB** | **Weaviate** |
|---|---|---|---|
| **Performance** | ⭐⭐⭐ Highest RPS, lowest latency | ⭐⭐ Good for dev/experimentation | ⭐⭐⭐ Excellent for mixed workloads |
| **Upload Speed** | ⭐⭐⭐ Impressive for large datasets | ⭐⭐ Moderate | ⭐⭐ Moderate |
| **Deployment** | Self-hosted, cloud-native | Embedded, serverless | Self-hosted, SaaS |
| **Filtering** | ⭐⭐⭐ Advanced filtering, static sharding | ⭐⭐ Basic metadata filtering | ⭐⭐⭐ Hybrid search (vector+keyword) |
| **API Support** | Multiple client APIs | Python-native | GraphQL, REST |
| **Maturity** | Production-ready | Research/experimentation focused | Enterprise-grade |
| **Ecosystem** | Growing | Largest community (LangChain default) | Rich module ecosystem |

**Verdict: Qdrant for production; ChromaDB for rapid prototyping.** Qdrant's Rust-based implementation delivers "highest RPS and lowest latency in almost all scenarios," making it ideal for Maljan's production deployment where past STIX bundles must be retrieved quickly for similarity matching. Its advanced filtering enables precise retrieval (e.g., "find reports matching this MITRE technique ID").

**STIX Bundle Indexing Strategy:**
- Each STIX 2.1 bundle should be embedded using a cybersecurity-aware embedding model (e.g., SecureBERT embeddings or Foundation-Sec embeddings)
- Index by: malware family, MITRE ATT&CK technique IDs, IOCs (hashes, IPs, domains), behavioral patterns (API call sequences)
- Hybrid search (vector similarity + keyword filtering on structured STIX fields) enables "find similar analyses to this behavioral pattern"
- Weaviate's native hybrid search capability makes it an alternative if mixed structured/unstructured querying is critical

---

## 3. KNOWN LIMITATIONS & OPEN PROBLEMS

### 3a. Failure Modes of LLM-Based Malware Analysis

1. **Decompiler Artifact Contamination:** LLMs treat decompiler output as ground truth, but each tool (Ghidra, IDA, radare2) introduces parsing quirks. Ghidra may misclassify compiler stubs as application logic; IDA Hex-Rays can elide register-level details; string extraction tools mangle delimiters. The Sentinel Labs pipeline caught a real case where Radare2 rendered a C2 endpoint as `/api/req_res` while Ghidra correctly extracted `/api/req/res`.

2. **Hallucinated Capabilities:** LLMs produce confident, well-structured reports with fabricated function references, dead code misattributed as malicious capabilities, and hallucinated C2 endpoints. These are "not hallucinations in the usual sense" — the model reasons correctly over noisy data.

3. **Three Domain-Specific Cognitive Failures in CTI:** (a) Spurious correlations from superficial metadata; (b) Contradictory knowledge from conflicting sources; (c) Constrained generalization to emerging threats. Standard "LLM-as-a-judge" pipelines prove brittle for these failures.

4. **Context Window Limitations:** Decompiled code + multiple tool outputs easily exceed 20-30K tokens, challenging models with ≤8K context windows.

5. **Obfuscated Code Blindspots:** Packed, encrypted, or heavily obfuscated binaries produce decompiler output that is semantically impoverished, leading to degraded LLM analysis.

6. **Package Hallucination in Security Scans:** LLMs can hallucinate package names, creating AI supply chain compromise risks where attackers upload malicious packages under hallucinated names.

### 3b. The Echo Chamber Problem

Existing multi-agent debate systems face a fundamental paradox: **agents designed to reach consensus may prematurely converge on incorrect answers**, especially when a confident but wrong agent sways others. Wu et al. (2025) demonstrated that "majority pressure suppresses independent correction" — agents observing that most peers agree abandon their correct but minority positions.

Ohagi et al. (2024) showed that ChatGPT-based agents "tended to become polarized in echo chamber environments" — the very mechanism designed to surface truth can instead amplify errors when agents share model family biases.

The Sentinel Labs pipeline addresses this through the **Active Rejection Mandate**: agents are explicitly instructed to act as "highly skeptical peers" and formally reject claims with documented rationale. Every finding carries a Consensus field (AGREE/DISAGREE), and rejected claims are tracked with the rejecting tool's reasoning. This adversarial design caught real artifacts in production: a decompiler artifact claiming a non-existent "download" instruction type was actively rejected during peer review.

However, this approach assumes agents are adversarial by design. Research by Hadfield (2025) found that "stronger agents were more likely to change from correct to incorrect answers in response to weaker agents' reasoning than vice versa" — models favor agreement over critical evaluation.

### 3c. State of the Art for Automated MITRE ATT&CK TTP Mapping

**LLM-Based Approaches:**
- **TTPDetect** (Xuan et al., 2026): Achieves 93.25% precision / 93.81% recall on function-level TTP recognition using dense retrieval + LLM neural retrieval + TTP-Specific Reasoning Guidelines. The current state-of-the-art for binary-level TTP mapping.
- **LLM-based semantic reasoning** (ScienceDirect, 2025): Uses "Conceptual Definition Mapping" and "TTP Technical Keyword Mapping" constructs from official MITRE documentation, integrated with dynamic behavioral analysis.

**Non-LLM Baselines:**
- **Ensemble BERT for TTP Mapping** (University of Galway, 2025): Domain-adapted ensemble BERT models for mapping unstructured SOC reports to ATT&CK. Domain adaptation significantly improves automated TTP mapping, offering a non-LLM baseline.
- **LTDCT-TTPDBIO** (DOAJ, 2025): Uses Birch-inspired optimization to turn raw sandbox logs into precise ATT&CK labels with low latency. Bias-reduced malware-TTP corpus published.
- **DroidTTP** (arXiv, 2025): Problem Transformation Approach for mapping Android malware behaviors to TTPs, with a curated dataset linking MITRE TTPs to Android applications.
- **NEXUS** (NDSS 2026): Framework for automatically mapping CVEs to TTPs, covering 208 TTPs and 92K+ CVEs.

**Recommendation:** Maljan should use a **hybrid approach**: LLM-based TTPDetect-style reasoning for nuanced technique identification, combined with ensemble BERT or keyword-matching baselines as a validation layer. The non-LLM baseline serves as a "sanity check" against LLM hallucination in TTP assignment.

---

## 4. RECOMMENDED IMPROVEMENTS & RESEARCH GAPS

### 4a. Architectural Improvements (Literature-Supported)

**1. Adversarial Consensus with Active Rejection Mandate**
*Inspired by:* Sentinel Labs pipeline + SELENE
Implement an explicit "AGREE/DISAGREE" consensus field in agent inter-communication, with mandatory rationale for all rejections. Each agent reviews prior agents' claims and must formally accept or reject. This prevents silent error propagation.

**2. Selective Debate Initiation (Debate-on-Demand)**
*Inspired by:* SELENE's SDI mechanism
Instead of always running the full negotiation loop, detect when agents actually disagree (confidence-likelihood misalignment) and only trigger debate in those cases. This could reduce Maljan's token consumption by up to 50% while maintaining accuracy.

**3. Evidence-Weighted Judge Verdicts**
*Inspired by:* SELENE's EWSC + ReConcile's confidence-weighted voting
Replace simple majority voting with variance-aware evidence-weighted aggregation. The Judge agent should weight agent findings by: (a) each agent's self-reported confidence, (b) the specificity of evidence cited (virtual address, API call trace, PCAP excerpt), and (c) historical reliability of that agent/model on similar samples.

**4. Heterogeneous Model Diversity Requirement**
*Inspired by:* ReConcile + Wu et al. (2025)
Mandate that the three analyst agents use **different model families** (e.g., GPT-4 for one, Claude for another, DeepSeek-Coder for the third). ReConcile demonstrated that "diversity originating from different models is critical to superior performance." This directly mitigates the echo chamber problem by reducing correlated errors.

**5. Retrieval-Augmented TTP Mapping with Ground Truth Anchoring**
*Inspired by:* TTPDetect + Meng et al. (2025)
Ground the Judge agent's TTP assignments in retrievable evidence from past analyses stored in Qdrant. When assigning a MITRE technique, the Judge must cite a specific behavioral pattern (e.g., API call sequence) and link to similar past analyses. This addresses the "spurious correlations from superficial metadata" failure mode.

### 4b. Research Gaps Maljan Could Address

**Gap 1: Cross-Domain Contradiction Resolution.** No existing work addresses how to resolve contradictions when different analysis domains (static, dynamic, network) yield conflicting conclusions about the same malware. Static analysis might identify a registry persistence mechanism that dynamic execution never triggers; network analysis might show C2 traffic that static analysis missed entirely. Maljan's three-domain architecture is uniquely positioned to study cross-domain contradiction resolution.

**Gap 2: Structured STIX Output from Multi-Agent Deliberation.** CTI-GEN and eLLM-CTI generate STIX from single-pass LLM extraction. No existing system produces STIX 2.1 bundles as the output of a multi-agent negotiation process where agents debate TTP assignments before committing to structured intelligence. This is a novel contribution.

**Gap 3: Long-Term Memory for Malware Analysis Pipelines.** While RAG is widely used for knowledge-grounded generation, no existing malware analysis framework maintains a persistent vector memory of past analyses used to inform current analysis through similarity retrieval. Maljan's vector DB integration for STIX bundle indexing addresses this gap.

**Gap 4: Empirical Measurement of Debate Quality in Cybersecurity Domains.** Wu et al. (2025) studied debate quality in logical reasoning puzzles. No equivalent study exists for cybersecurity analysis tasks where ground truth is professionally annotated (e.g., expert-written malware reports). Maljan could produce the first benchmark dataset for multi-agent debate quality in malware analysis.

### 4c. Positioning Maljan as an Academic Paper

**Proposed Title:** "Maljan: A Multi-Agent LLM Framework for Cross-Domain Malware Analysis with Adversarial Consensus and Structured Threat Intelligence Generation"

**Novel Contributions:**
1. **First multi-agent LLM framework** that integrates static, dynamic, and network malware analysis domains with a structured negotiation loop.
2. **Adversarial consensus mechanism** adapted from Sentinel Labs' tool-level pipeline to domain-level analysis, with formal AGREE/DISAGREE tracking and evidence-weighted judge verdicts.
3. **End-to-end STIX 2.1 generation** from multi-agent deliberation — extending CTI-GEN's single-pass approach to debated, consensus-driven intelligence production.
4. **Long-term memory integration** via vector-indexed STIX bundles enabling retrieval-augmented analysis that improves with each sample analyzed.

**Positioning Relative to Existing Work:**
- **vs. Sentinel Labs**: Maljan operates at the *analysis domain* level (static/dynamic/network) rather than the *tool* level (Ghidra/IDA/radare2), making it complementary and potentially stackable.
- **vs. ReConcile/SELENE**: Maljan applies consensus mechanisms proven on NLP benchmarks to the high-stakes cybersecurity domain where errors have concrete operational consequences.
- **vs. CTI-GEN/eLLM-CTI**: Maljan generates STIX from raw analysis artifacts (disassembly, behavioral logs, PCAP) rather than from pre-written threat reports, addressing an earlier stage in the intelligence production pipeline.
- **vs. TTPDetect**: Maljan provides cross-domain behavioral corroboration for TTP assignments rather than relying solely on static binary evidence.

---


## Summary Reference Table

| # | Paper/Resource | Year | Venue | Key Insight for Maljan |
|---|---|---|---|---|
| 1 | DECODE | 2025 | PMC | Multi-modal agent-based malware analysis |
| 2 | MalGEN | 2025 | arXiv | Multi-agent TTP modeling architecture |
| 3 | CyberRAG | 2025 | FGCS | Agentic RAG pattern for iterative reasoning |
| 4 | Sentinel Labs Pipeline | 2026 | Red Sky Alliance | **Active Rejection Mandate, adversarial consensus** |
| 5 | TTPDetect | 2026 | arXiv | **SOTA LLM-based TTP mapping from binaries** |
| 6 | Jelodar et al. Survey | 2025 | ScienceDirect | Comprehensive LLM malware analysis taxonomy |
| 7 | LLM4Decompile | 2024 | arXiv | DeepSeek-Coder fine-tuned for decompilation |
| 8 | Asm2SrcEval | 2025 | NeurIPS | LLM assembly translation benchmarks |
| 9 | Binary Code Understanding | 2025 | arXiv | LLMs partially understand binary code |
| 10 | ASMA-Tune | 2025 | arXiv | +39.7% assembly comprehension over GPT-4 |
| 11 | **ReConcile** | 2024 | ACL | **Round-table consensus, diversity is critical** |
| 12 | **SELENE** | 2026 | EACL | **Selective debate, evidence-weighted judging** |
| 13 | Wu et al. | 2025 | arXiv | **Majority pressure suppresses correction** |
| 14 | Duan et al. | 2024 | arXiv | Third-party LLM integration for consensus |
| 15 | Ohagi et al. | 2024 | ACL Workshop | AI agents polarize in echo chambers |
| 16 | CTI-GEN | 2025 | IEEE CSR | STIX generation from LLM, F1=81% |
| 17 | eLLM-CTI | 2026 | ScienceDirect | Enhanced LLM CTI extraction |
| 18 | Meng et al. | 2025 | arXiv | **Three CTI cognitive failures, LLM-as-judge brittle** |
| 19 | Agentic AI Frameworks | 2025 | IEEE/arXiv | LangGraph vs. alternatives comparison |
| 20 | Tool-Calling Reliability | 2026 | Altersquare | LangGraph: +9% overhead, 14.1s latency |