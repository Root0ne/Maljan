"""Ghidra MCP static analysis; the working adapter arrives in Task 9."""

from __future__ import annotations

from typing import TYPE_CHECKING

from maljan.providers.base import StaticCapabilities, StaticProvider
from maljan.providers.registry import register_static_provider

if TYPE_CHECKING:
    from maljan.core.config import Settings


@register_static_provider("ghidra")
class GhidraStaticProvider(StaticProvider):
    """Registered under the default static provider id.

    A working, capability-less instance so the registry's id-parity test and
    the default-settings test have something to build; Task 9 replaces this
    module with the real adapter (tool discovery, evidence collection,
    mirroring).
    """

    @classmethod
    def from_settings(cls, cfg: Settings) -> GhidraStaticProvider:
        return cls()

    @property
    def capabilities(self) -> StaticCapabilities:
        return StaticCapabilities()
