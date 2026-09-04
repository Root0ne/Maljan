"""Hatching Triage cloud sandbox; the working adapter arrives in Task 16."""

from __future__ import annotations

from typing import TYPE_CHECKING

from maljan.providers.base import SandboxCapabilities, SandboxProvider
from maljan.providers.registry import register_sandbox_provider

if TYPE_CHECKING:
    from maljan.core.config import Settings

_NOT_YET = "the triage sandbox provider arrives in Task 16"


@register_sandbox_provider("triage")
class TriageSandboxProvider(SandboxProvider):
    """Registers the "triage" id so the registry and the settings agree.

    Not implemented until Task 16; both abstract members raise so an
    accidental use fails loudly instead of silently degrading.
    """

    @classmethod
    def from_settings(cls, cfg: Settings) -> TriageSandboxProvider:
        raise NotImplementedError(_NOT_YET)

    @property
    def capabilities(self) -> SandboxCapabilities:
        raise NotImplementedError(_NOT_YET)
