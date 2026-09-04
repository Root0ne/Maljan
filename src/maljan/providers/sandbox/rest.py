"""Placeholder for the REST sandbox adapter.

``sandbox.provider`` gains the ``"rest"`` choice in Task 2 so that the
settings shape and the registry parity test agree on the vocabulary; the
adapter itself — the HTTP submit/poll/report cycle described by
``sandbox.rest.*`` — is Task 11's. This stub registers under ``"rest"`` so
``registry.sandbox_provider_ids()`` matches ``SandboxConfig.provider``'s
``Literal`` args, and refuses at construction time rather than pretending to
work.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from maljan.providers.base import ProviderProbe, SandboxCapabilities, SandboxProvider
from maljan.providers.errors import ProviderConfigurationError
from maljan.providers.registry import register_sandbox_provider

if TYPE_CHECKING:
    from maljan.core.config import Settings


@register_sandbox_provider("rest")
class RestSandboxProvider(SandboxProvider):
    """Not yet implemented; exists only to keep the registry in parity."""

    @classmethod
    def from_settings(cls, cfg: Settings) -> RestSandboxProvider:
        raise ProviderConfigurationError("rest provider is implemented in Task 11")

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            can_submit=False,
            can_poll=False,
            can_fetch_report=False,
            can_fetch_pcap=False,
            accepts_uploaded_report=False,
            provides_tools=False,
            degrade_on_failure=False,
        )

    async def probe(self) -> ProviderProbe:
        return ProviderProbe(ok=False, detail="rest provider is implemented in Task 11")
