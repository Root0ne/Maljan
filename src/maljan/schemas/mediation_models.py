"""Backward-compatible re-export shim.

MediatorVerdict has been moved to maljan.pipeline.mediation_models because
it is an internal negotiation concern, not a general-purpose schema.

This shim exists to avoid breaking any external imports during the transition.
"""

from maljan.pipeline.mediation_models import MediatorVerdict  # noqa: F401

__all__ = ["MediatorVerdict"]
