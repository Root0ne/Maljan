"""Deterministic extractors that populate ``MalwareReport`` sections.

Each module owns one report section and is independently testable. They
operate on the data the pipeline already collects (sandbox report dict,
sample bytes / path, ISR reports, cascade summary) and never invoke an
LLM. Graceful degradation is the rule: a missing input means a ``None``
or empty list, never an exception.
"""

from maljan.extractors.sample_identity import build_sample_identity

__all__ = ["build_sample_identity"]
