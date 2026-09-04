"""radare2 is the generic MCP provider with radare2's defaults."""

from __future__ import annotations

import json
from pathlib import Path

from maljan.core.config import Settings
from maljan.providers.static.generic_mcp import GenericMCPStaticProvider
from maljan.providers.static.r2 import R2StaticProvider

FIX = Path(__file__).resolve().parents[2] / "fixtures" / "golden" / "r2_tools.json"


class _T:
    def __init__(self, name):
        self.name = name


def _cfg():
    cfg = Settings(_env_file=None)
    cfg.static.provider = "r2"
    cfg.static.r2.enabled = True
    return cfg


def test_it_is_the_generic_adapter_with_defaults():
    assert issubclass(R2StaticProvider, GenericMCPStaticProvider)


def test_the_allow_list_is_the_pinned_fixture():
    pinned = {t["name"] for t in json.loads(FIX.read_text(encoding="utf-8"))["tools"]}
    assert R2StaticProvider.R2_ALLOWED_TOOLS <= pinned, "the allow-list names tools r2mcp has"
    assert R2StaticProvider.R2_ALLOWED_TOOLS, "an empty allow-list would expose everything"


def test_capabilities():
    caps = R2StaticProvider.from_settings(_cfg()).capabilities
    assert caps.provides_tools and caps.needs_sample_mirror and caps.supports_tool_curation
    assert caps.degrade_on_failure is True
    assert caps.provides_function_hashes is False


def test_the_command_defaults_to_the_configured_binary():
    cfg = _cfg()
    cfg.static.r2.binary_path = "/opt/r2/bin/r2mcp"
    provider = R2StaticProvider.from_settings(cfg)
    assert provider.server_command() == "/opt/r2/bin/r2mcp"


def test_selection_narrows_to_the_allow_list():
    provider = R2StaticProvider.from_settings(_cfg())
    tools = [_T(n) for n in sorted(R2StaticProvider.R2_ALLOWED_TOOLS)] + [_T("not_an_r2_tool")]
    assert {t.name for t in provider.select_tools(tools)} == R2StaticProvider.R2_ALLOWED_TOOLS


def test_the_prompt_fragment_names_r2_tools_and_no_ghidra_tool():
    fragment = R2StaticProvider.from_settings(_cfg()).prompt_fragment()
    assert "cite a concrete artifact" in fragment
    assert "load_program" not in fragment and "Ghidra" not in fragment
    assert any(name in fragment for name in R2StaticProvider.R2_ALLOWED_TOOLS)


def test_the_mirror_spec_uses_the_configured_directory():
    cfg = _cfg()
    cfg.static.r2.mirror_dir = "data/samples/.work"
    spec = R2StaticProvider.from_settings(cfg).mirror_spec()
    assert spec is not None and spec.work_subdir == ".work"
