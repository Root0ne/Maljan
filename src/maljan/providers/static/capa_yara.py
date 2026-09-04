"""capa and YARA static evidence; the working adapter arrives in Task 19."""

from __future__ import annotations

from typing import TYPE_CHECKING

from maljan.providers.base import StaticCapabilities, StaticProvider
from maljan.providers.registry import register_static_provider

if TYPE_CHECKING:
    from maljan.core.config import Settings

_NOT_YET = "the capa_yara static provider arrives in Task 19"


@register_static_provider("capa_yara")
class CapaYaraStaticProvider(StaticProvider):
    """Registers the "capa_yara" id so the registry and the settings agree.

    Not implemented until Task 19; both abstract members raise so an
    accidental use fails loudly instead of silently degrading.
    """

    @classmethod
    def from_settings(cls, cfg: Settings) -> CapaYaraStaticProvider:
        raise NotImplementedError(_NOT_YET)

    @property
    def capabilities(self) -> StaticCapabilities:
        raise NotImplementedError(_NOT_YET)
