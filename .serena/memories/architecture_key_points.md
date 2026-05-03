# Architecture Key Points
- **LangGraph Orchestration**: Fan-out to 3 specialized analysts (Static, Dynamic, Network) followed by a negotiation loop (with Mediator) and final Judge verdict.
- **Dependency Injection**: Uses `ServiceContainer` for DI and caching of LLMs, stores, and loaders. No global state.
- **Intermediate Structural Representation (ISR)**: Agents exchange structured `AgentISR` objects with claims, evidence references, and confidence scores instead of raw text.
- **Multi-Layer TTP Cascade**: Weighted scoring system prioritizing YARA (0.90) > TIEF (0.80) > Sigma (0.55) > Dynamic (0.45) > Static (0.35) > Network (0.20) for TTP confidence.
- **MITRE ATT&CK Memory**: Pure-Python TF-IDF index for semantic technique retrieval and validation.
- **Dynamic Schema Pruning**: Malware category inference (Ransomware, RAT, Dropper, etc.) to tailor STIX object output.
