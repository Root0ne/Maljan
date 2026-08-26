"""Analysis subsystem for Maljan.

Modules:
  - yara_layer:  Layer 0 — deterministic signature-based ATT&CK technique detection
                 via YAML-configured pattern rules. Zero hard dependencies.
  - ttp_cascade: Multi-layer TTP evidence cascade engine that cross-correlates
                 ClaimEvidence objects across yara, static, dynamic, and network layers.
  - schema_pruner: Malware category inference for dynamic STIX schema pruning.
  - run_summary:   RunSummary builder for pipeline observability.
  - chunk_merger:  ISR merging across BinaryChunker text windows.
"""
