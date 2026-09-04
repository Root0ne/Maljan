"""CAPEv2 sandbox; the working adapter arrives in Task 7."""

from __future__ import annotations

from typing import TYPE_CHECKING

from maljan.providers.base import SandboxCapabilities, SandboxProvider
from maljan.providers.registry import register_sandbox_provider

if TYPE_CHECKING:
    from maljan.core.config import Settings

_NOT_YET = "the cape2 sandbox provider arrives in Task 7"


@register_sandbox_provider("cape2")
class CAPE2SandboxProvider(SandboxProvider):
    """Registers the "cape2" id so the registry and the settings agree.

    Not implemented until Task 7; both abstract members raise so an
    accidental use fails loudly instead of silently degrading.
    """

    @classmethod
    def from_settings(cls, cfg: Settings) -> CAPE2SandboxProvider:
        raise NotImplementedError(_NOT_YET)

    @property
    def capabilities(self) -> SandboxCapabilities:
        raise NotImplementedError(_NOT_YET)
