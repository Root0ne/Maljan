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


def test_the_mirror_spec_has_no_container_prefix():
    """A co-located r2mcp opens the sample by its host path; there is no
    container mount to translate the mirrored path into."""
    spec = R2StaticProvider.from_settings(_cfg()).mirror_spec()
    assert spec is not None and spec.container_prefix == ""


def test_opening_never_writes_the_resolved_command_back_into_the_config(monkeypatch):
    """Regression: ``open()`` must resolve ``binary_path`` into the launched
    command without mutating ``self._cfg`` — that object is the shared,
    user-editable ``Settings`` leaf ``settings_snapshot()`` later persists into
    the job's run summary, so a write here would show the operator a
    ``command`` they never set."""
    from maljan.agents import mcp_client
    from maljan.providers.base import StaticJobContext

    recorded: dict[str, object] = {}

    class _FakeToolkit:
        def __init__(self, server_params, **kwargs):
            recorded["command"] = server_params.command

        async def initialize(self) -> None:
            return None

        def get_tools(self):
            return []

    monkeypatch.setattr(mcp_client, "MCPLangChainToolkit", _FakeToolkit)

    cfg = _cfg()
    original_command = cfg.static.r2.command
    provider = R2StaticProvider.from_settings(cfg)

    provider.open(StaticJobContext())

    assert recorded["command"] == "r2mcp", "the fake toolkit must receive binary_path as command"
    assert cfg.static.r2.command == original_command, "open() must not mutate the shared config"
