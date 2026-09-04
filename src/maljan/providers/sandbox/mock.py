"""Fixture-backed mock sandbox; the working adapter arrives in Task 7."""

from __future__ import annotations

from typing import TYPE_CHECKING

from maljan.providers.base import SandboxCapabilities, SandboxProvider
from maljan.providers.registry import register_sandbox_provider

if TYPE_CHECKING:
    from maljan.core.config import Settings


@register_sandbox_provider("mock")
class MockSandboxProvider(SandboxProvider):
    """Registered under the default sandbox provider id.

    A working, capability-less instance so the registry's id-parity test and
    the default-settings test have something to build; Task 7 replaces this
    module with the real adapter (fixture JSON, no network).
    """

    @classmethod
    def from_settings(cls, cfg: Settings) -> MockSandboxProvider:
        return cls()

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities()
