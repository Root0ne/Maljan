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

from maljan.providers.base import StaticCapabilities, StaticProvider
from maljan.providers.registry import register_static_provider

if TYPE_CHECKING:
    from maljan.core.config import Settings


@register_static_provider("none")
class NullStaticProvider(StaticProvider):
    """No static tool at all.

    The honest choice when a deployment has no reverse-engineering server: the
    analyst reasons over the deterministic PE extraction it already receives,
    and nothing pretends a tool loop happened. Its prompt fragment keeps the
    provider-neutral instructions (cite a concrete artifact, the four ATT&CK
    techniques) and drops every tool name, so the model is not told to call
    tools it does not have.
    """

    NO_TOOLS_FRAGMENT: ClassVar[str] = (
        "Analyze the deterministic static evidence you are given. "
        "For EVERY claim you make, you MUST cite a concrete artifact: a function name, "
        "string offset (.data+0xNN), API import, or hex pattern. "
        "Focus on MITRE ATT&CK: T1027 (Obfuscation), T1106 (Native API), "
        "T1055 (Process Injection), T1140 (Deobfuscation).\n\n"
        "You have no analysis tools in this configuration. Do not describe tool "
        "calls you did not make, and do not claim analysis was impossible: the "
        "extracted imports, sections and strings are real evidence."
    )

    @classmethod
    def from_settings(cls, cfg: Settings) -> NullStaticProvider:
        return cls()

    @property
    def capabilities(self) -> StaticCapabilities:
        return StaticCapabilities(degrade_on_failure=True)

    def prompt_fragment(self) -> str:
        return self.NO_TOOLS_FRAGMENT
