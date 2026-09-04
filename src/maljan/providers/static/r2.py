"""radare2 static analysis; the working adapter arrives in Task 18."""

from __future__ import annotations

from typing import TYPE_CHECKING

from maljan.providers.base import StaticCapabilities, StaticProvider
from maljan.providers.registry import register_static_provider

if TYPE_CHECKING:
    from maljan.core.config import Settings

_NOT_YET = "the r2 static provider arrives in Task 18"


@register_static_provider("r2")
class R2StaticProvider(StaticProvider):
    """Registers the "r2" id so the registry and the settings agree.

    Not implemented until Task 18; both abstract members raise so an
    accidental use fails loudly instead of silently degrading.
    """

    @classmethod
    def from_settings(cls, cfg: Settings) -> R2StaticProvider:
        raise NotImplementedError(_NOT_YET)

    @property
    def capabilities(self) -> StaticCapabilities:
        raise NotImplementedError(_NOT_YET)
