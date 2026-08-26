"""Maljan reporting package — comprehensive malware analysis report assembly.

Produces a real, CTI-analyst grade ``MalwareReport`` (schema, deterministic
builder, narrative LLM round, detection rule auto-generation, extended STIX
2.1 bundle, markdown / JSON / MISP renderers) from the data the pipeline
already collects.
"""

from maljan.reporting.models import MalwareReport

__all__ = ["MalwareReport"]
