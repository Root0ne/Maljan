"""The default profile's prompts and allow-lists are frozen.

Captured from `dev` by ``scripts/capture_provider_goldens.py`` before the
provider refactor. Any change to a byte of the static (ghidra) or dynamic
(cape2) system prompt, or to either tool allow-list, is a behaviour change and
fails here — which is the point: sub-project A is a refactor.
"""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
PROMPTS = FIXTURES / "prompts"
GOLDEN = FIXTURES / "golden"


def _golden(name: str) -> str:
    return (PROMPTS / name).read_text(encoding="utf-8")


def test_static_ghidra_system_prompt_is_byte_identical():
    from maljan.agents.static_analyst import _ISR_SYSTEM

    assert _ISR_SYSTEM == _golden("static_isr_system_ghidra.txt")


def test_dynamic_cape2_system_prompt_is_byte_identical():
    from maljan.agents.dynamic_analyst import _ISR_SYSTEM

    assert _ISR_SYSTEM == _golden("dynamic_system_cape2.txt")


def test_ghidra_allow_list_and_core_set_are_unchanged():
    from maljan.providers.static.ghidra import GHIDRA_ALLOWED_TOOLS
    from maljan.providers.static.ghidra_tool_selector import _CORE_TOOLS

    expected = json.loads((GOLDEN / "allowlists.json").read_text(encoding="utf-8"))
    assert sorted(GHIDRA_ALLOWED_TOOLS) == expected["ghidra_allowed_tools"]
    assert len(expected["ghidra_allowed_tools"]) == 20
    assert sorted(_CORE_TOOLS) == expected["ghidra_core_tools"]


def test_cape_essential_tool_names_are_unchanged():
    """The 13 names the dynamic analyst keeps when the CAPE MCP toolkit attaches.

    Before Task 11 this was an inline literal inside
    ``DynamicAnalyst._initialize_mcp_client`` and this test read it out of the
    method's source. The essential-tool list now lives on the provider as
    ``CAPE_ESSENTIAL_TOOLS``, so the guard compares against that name instead,
    exactly as planned.
    """
    from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider

    expected = json.loads((GOLDEN / "allowlists.json").read_text(encoding="utf-8"))
    assert sorted(CAPE2SandboxProvider.CAPE_ESSENTIAL_TOOLS) == expected["cape_essential_tools"]
    assert len(expected["cape_essential_tools"]) == 13


def test_the_assembled_static_prompt_equals_the_golden():
    from maljan.agents.static_analyst import _ISR_HEAD, _ISR_TAIL
    from maljan.core.config import Settings
    from maljan.providers.static.ghidra import GhidraStaticProvider

    provider = GhidraStaticProvider.from_settings(Settings(_env_file=None))
    assembled = _ISR_HEAD + provider.prompt_fragment() + _ISR_TAIL
    assert assembled == _golden("static_isr_system_ghidra.txt")


def test_the_module_constant_is_still_the_assembled_prompt():
    from maljan.agents.static_analyst import _ISR_SYSTEM

    assert _ISR_SYSTEM == _golden("static_isr_system_ghidra.txt")


def test_the_assembled_dynamic_prompt_equals_the_golden():
    from maljan.agents.dynamic_analyst import _DYN_HEAD, _DYN_TAIL
    from maljan.core.config import Settings
    from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider

    provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
    assert _DYN_HEAD + provider.dynamic_prompt_fragment() + _DYN_TAIL == _golden(
        "dynamic_system_cape2.txt"
    )
