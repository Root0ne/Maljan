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
    from maljan.agents.ghidra_tool_selector import _CORE_TOOLS
    from maljan.agents.static_analyst import StaticAnalyst

    expected = json.loads((GOLDEN / "allowlists.json").read_text(encoding="utf-8"))
    assert sorted(StaticAnalyst._GHIDRA_ALLOWED_TOOLS) == expected["ghidra_allowed_tools"]
    assert len(expected["ghidra_allowed_tools"]) == 20
    assert sorted(_CORE_TOOLS) == expected["ghidra_core_tools"]


def test_cape_essential_tool_names_are_unchanged():
    """The 13 names the dynamic analyst keeps when ``mcp.cape.tools`` is empty.

    Read out of the module source rather than a constant, because today the set
    is an inline literal inside ``_initialize_mcp_client``. Task 11 turns it
    into ``CAPE_ESSENTIAL_TOOLS`` in the provider and this test then compares
    against that name; until then the literal is what ships.
    """
    import inspect

    from maljan.agents.dynamic_analyst import DynamicAnalyst

    expected = json.loads((GOLDEN / "allowlists.json").read_text(encoding="utf-8"))
    source = inspect.getsource(DynamicAnalyst._initialize_mcp_client)
    for name in expected["cape_essential_tools"]:
        assert f'"{name}"' in source, name
    assert len(expected["cape_essential_tools"]) == 13
