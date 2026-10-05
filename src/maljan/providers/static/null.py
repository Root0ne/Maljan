"""``static.provider=none`` — no static tool attached at all.

The spec amendment behind this file: today's legacy disabled-Ghidra
behaviour (the full Ghidra prompt, minus any tools, from a Ghidra block whose
``enabled`` setting is false) is reproduced by the alias table as
``static.provider=ghidra`` with ``static.ghidra.enabled=false`` — that is a
*disabled Ghidra*, not this. ``none`` is its own choice, with its own
tool-free prompt fragment, and its acceptance is the toolless behaviour the
analyst falls back to, not a byte-for-byte prompt match with anything else.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from maljan.providers.base import (
    STATIC_EVIDENCE_INSTRUCTIONS,
    StaticCapabilities,
    StaticProvider,
)
from maljan.providers.registry import register_static_provider

if TYPE_CHECKING:
    from maljan.core.config import Settings


@register_static_provider("none")
class NullStaticProvider(StaticProvider):
    """No static tool at all.

    The honest choice when a deployment has no reverse-engineering server: the
    analyst reasons over the deterministic extraction it already receives and
    over whatever tool servers its definition binds. Its prompt fragment keeps
    the provider-neutral instructions (cite a concrete artifact, the four
    ATT&CK techniques), says no disassembler or decompiler comes with it, and
    says nothing about the agent's other tools: that sentence is built from
    the tool list the request carries.
    """

    # What the provider is, and nothing about the agent's tools: the static
    # analyst is bound to tool servers of its own under every provider, and the
    # sentence about those is built from the list the request carries
    # (``prompt_fragments.tools_statement``). The fragment this replaced told
    # the model it had no tools while the same request carried 36.
    NO_PROVIDER_FRAGMENT: ClassVar[str] = (
        STATIC_EVIDENCE_INSTRUCTIONS
        + "\n\n"
        + "No static provider is attached, so no disassembler or decompiler comes with "
        "this analyst."
    )

    @classmethod
    def from_settings(cls, cfg: Settings) -> NullStaticProvider:
        return cls()

    @property
    def capabilities(self) -> StaticCapabilities:
        return StaticCapabilities(degrade_on_failure=True)

    def prompt_fragment(self) -> str:
        return self.NO_PROVIDER_FRAGMENT

    def absent_fragment(self) -> str:
        return self.NO_PROVIDER_FRAGMENT
