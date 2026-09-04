"""The Ghidra provider is the static analyst's Ghidra code, moved."""

from __future__ import annotations

import json
from pathlib import Path

from maljan.core.config import Settings
from maljan.providers.base import StaticJobContext
from maljan.providers.static.ghidra import GHIDRA_ALLOWED_TOOLS, GhidraStaticProvider

ROOT = Path(__file__).resolve().parents[3]


class _Tool:
    def __init__(self, name: str, description: str = "") -> None:
        self.name, self.description = name, description


def _provider(**over):
    cfg = Settings(_env_file=None)
    cfg.static.ghidra.enabled = True
    cfg.static.ghidra.transport = "http"
    cfg.static.ghidra.url = "http://ghidra.example:8089"
    for k, v in over.items():
        setattr(cfg.static.ghidra, k, v)
    return GhidraStaticProvider.from_settings(cfg)


def test_the_allow_list_is_the_golden_one():
    golden = json.loads(
        (ROOT / "tests" / "fixtures" / "golden" / "allowlists.json").read_text(encoding="utf-8")
    )
    assert sorted(GHIDRA_ALLOWED_TOOLS) == golden["ghidra_allowed_tools"]


def test_the_analyst_still_exports_the_allow_list_under_its_old_name():
    from maljan.agents.static_analyst import StaticAnalyst

    assert StaticAnalyst._GHIDRA_ALLOWED_TOOLS is GHIDRA_ALLOWED_TOOLS


def test_capabilities_track_the_transport():
    http = _provider().capabilities
    assert http.provides_tools and http.supports_tool_curation and http.needs_sample_mirror
    assert http.provides_function_hashes is True
    assert http.degrade_on_failure is False, "Ghidra is the static evidence; it fails loudly"
    stdio = _provider(transport="stdio").capabilities
    assert stdio.provides_function_hashes is False, "the hash pre-pass speaks the REST API"


def test_curated_mode_keeps_exactly_the_allow_list():
    provider = _provider(tool_selection="curated")
    tools = [_Tool(n) for n in sorted(GHIDRA_ALLOWED_TOOLS)] + [_Tool("unrelated_tool")]
    kept = {t.name for t in provider.select_tools(tools)}
    assert kept == set(GHIDRA_ALLOWED_TOOLS)


def test_all_mode_keeps_everything():
    provider = _provider(tool_selection="all")
    tools = [_Tool(f"t{i}") for i in range(50)]
    assert len(provider.select_tools(tools)) == 50


def test_dynamic_mode_uses_the_categories_from_the_job():
    provider = _provider(tool_selection="dynamic")
    provider.open(StaticJobContext(capability_categories=frozenset({"crypto"})))
    tools = [_Tool(f"filler_{i}") for i in range(80)] + [
        _Tool("detect_crypto_constants", "find AES and RC4 constants")
    ]
    names = {t.name for t in provider.select_tools(tools)}
    assert "detect_crypto_constants" in names
    assert len(names) <= 40


def test_use_all_tools_still_forces_all():
    provider = _provider(tool_selection="curated", use_all_tools=True)
    assert len(provider.select_tools([_Tool(f"t{i}") for i in range(30)])) == 30


def test_load_program_is_pinned_to_the_mirror_path():
    import asyncio

    from langchain_core.tools import StructuredTool
    from pydantic import create_model

    seen: dict[str, object] = {}

    async def inner(**kwargs):
        seen.update(kwargs)
        return "loaded"

    tool = StructuredTool.from_function(
        func=None,
        coroutine=inner,
        name="load_program",
        description="load",
        args_schema=create_model("Args", file=(str, ...)),
    )
    provider = _provider()
    provider.open(StaticJobContext(mirror_sample_path="/data/samples/.work/abc.exe"))
    pinned = provider.select_tools([tool])[0]
    asyncio.run(pinned.coroutine(file="/home/user/invented.exe"))
    assert seen["file"] == "/data/samples/.work/abc.exe"


def test_mirror_spec_is_todays_work_directory():
    spec = _provider().mirror_spec()
    assert spec.work_subdir == ".work"
    assert spec.container_prefix.endswith("/samples") or spec.container_prefix == "/data/samples"


def test_a_disabled_server_yields_no_tools_and_does_not_raise():
    cfg = Settings(_env_file=None)
    cfg.static.ghidra.enabled = False
    provider = GhidraStaticProvider.from_settings(cfg)
    provider.open(StaticJobContext())
    assert provider.get_tools() == []
