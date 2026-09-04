"""Operator-uploaded sandbox report, no detonation; the working adapter arrives in Task 15."""

from __future__ import annotations

from typing import TYPE_CHECKING

from maljan.providers.base import SandboxCapabilities, SandboxProvider
from maljan.providers.registry import register_sandbox_provider

if TYPE_CHECKING:
    from maljan.core.config import Settings

_NOT_YET = "the upload sandbox provider arrives in Task 15"


@register_sandbox_provider("upload")
class UploadSandboxProvider(SandboxProvider):
    """Registers the "upload" id so the registry and the settings agree.

    Not implemented until Task 15; both abstract members raise so an
    accidental use fails loudly instead of silently degrading.
    """

    @classmethod
    def from_settings(cls, cfg: Settings) -> UploadSandboxProvider:
        raise NotImplementedError(_NOT_YET)

    @property
    def capabilities(self) -> SandboxCapabilities:
        raise NotImplementedError(_NOT_YET)
