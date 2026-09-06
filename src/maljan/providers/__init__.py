"""Provider layer: static-analysis and sandbox adapters behind one contract.

Re-exports the contracts (``base``) and the registry's public lookup
functions so a caller writes ``from maljan.providers import
get_static_provider`` rather than reaching into the submodules.
``discover_providers`` is deliberately not re-exported here: every function
below already calls it, so nothing outside the registry module needs to.
"""

from __future__ import annotations

from maljan.providers.base import (
    MirrorSpec,
    ProviderProbe,
    SandboxCapabilities,
    SandboxProvider,
    StaticCapabilities,
    StaticEvidenceBundle,
    StaticJobContext,
    StaticProvider,
)
from maljan.providers.registry import (
    get_sandbox_provider,
    get_static_provider,
    register_sandbox_provider,
    register_static_provider,
    sandbox_provider_ids,
    static_provider_ids,
)

__all__ = [
    "MirrorSpec",
    "ProviderProbe",
    "SandboxCapabilities",
    "SandboxProvider",
    "StaticCapabilities",
    "StaticEvidenceBundle",
    "StaticJobContext",
    "StaticProvider",
    "get_sandbox_provider",
    "get_static_provider",
    "register_sandbox_provider",
    "register_static_provider",
    "sandbox_provider_ids",
    "static_provider_ids",
]
