"""Analysis subsystem for Maljan.

Modules:
  - yara_layer:    The compiled YARA corpus and its match model, behind
                   ``tools.rules.yara_scan``.
  - sigma_layer:   The Sigma rule collection and its event builder, behind
                   ``tools.rules.sigma_match``.
  - run_summary:   RunSummary builder for pipeline observability.
  - chunk_merger:  ISR merging across BinaryChunker text windows.
"""
