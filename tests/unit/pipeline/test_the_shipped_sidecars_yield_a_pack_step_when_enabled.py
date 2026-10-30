"""Each shipped sidecar, switched on as compose runs it, gives the pack its step (T-454).

A sidecar of ``services/`` is reached over streamable HTTP, a transport that
may carry the sample out to another host. The pack stops such a server's steps
when the sample would be sent to it (``core.pack_steps``), but never one whose
block declares where the server opens the samples (``sample_mount``): that is
the shipped compose file's read-only mount, not a delivery over the network.
These tests switch each shipped server on alone, as shipped, check its block
against the compose file's mount, and ask the run's step list for its steps;
and an HTTP server that mounts nothing, or whose tools say they send the sample
out, is still left out.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from maljan.core import config as config_module
from maljan.core.config import MCPServerConfig, Settings
from maljan.core.declared_reading import builtin_tools
from maljan.core.pack_steps import effective_steps, server_steps, steps_on_servers
from maljan.core.settings_overrides import build_settings

COMPOSE = Path(__file__).resolve().parents[3] / "docker" / "docker-compose.yml"

# Each shipped sidecar and the steps its tools give.
STEPS: dict[str, frozenset[str]] = {
    "die": frozenset({"die_scan"}),
    "ilspy": frozenset({"dotnet_types"}),
    "goresym": frozenset({"go_symbols", "go_types"}),
    "yarax": frozenset({"yarax_scan"}),
    "oletools": frozenset({"office_dde", "ole_vba", "rtf_objects"}),
    "webcrack": frozenset({"js_deobfuscate"}),
    "unblob": frozenset({"container_extract"}),
    "jadx": frozenset({"android_classes"}),
}


# The servers whose steps read one code runtime run where an identification
# step names it, so they are on beside the identification server.
NEEDS_IDENTIFICATION = ("ilspy", "goresym")
RUNTIME = {"ilspy": "dotnet", "goresym": "go"}


def _on_as_shipped(*keys: str) -> Settings:
    """The shipped settings with ``keys`` switched on and nothing else of their blocks changed."""
    servers = {}
    for key in keys:
        shipped = Settings(_env_file=None).mcp.servers[key]
        assert not shipped.enabled
        launch = shipped.model_dump(mode="json", include={"transport", "url", "command", "args"})
        servers[key] = {**launch, "enabled": True}
    return build_settings({"mcp.servers": servers})


def _with_what_it_needs(key: str) -> Settings:
    return _on_as_shipped(key, *(("die",) if key in NEEDS_IDENTIFICATION else ()))


@pytest.fixture
def in_force(monkeypatch: pytest.MonkeyPatch) -> Any:
    def use(settings: Settings) -> Settings:
        monkeypatch.setattr(config_module, "_settings_instance", settings)
        return settings

    return use


@pytest.mark.parametrize("key", sorted(STEPS))
class TestEachShippedSidecarYieldsItsStep:
    def test_its_block_names_the_mount_compose_gives_it(self, key: str) -> None:
        block = Settings(_env_file=None).mcp.servers[key]
        assert block.transport == "streamable-http" and block.sample_mount
        service = yaml.safe_load(COMPOSE.read_text())["services"][f"{key}-mcp"]
        assert any(v.endswith(f":{block.sample_mount}:ro") for v in service["volumes"])

    def test_switched_on_it_gives_its_steps_and_is_not_left_out(
        self, key: str, in_force: Any
    ) -> None:
        settings = in_force(_with_what_it_needs(key))
        steps, off = steps_on_servers(effective_steps(), settings.mcp.servers)
        assert key not in off, off.get(key)
        assert {s.id for s in steps if s.server == key} == STEPS[key]

    def test_without_its_mount_the_same_server_is_left_out(self, key: str, in_force: Any) -> None:
        settings = in_force(_with_what_it_needs(key))
        block = settings.mcp.servers[key].model_copy(update={"sample_mount": ""})
        found, off = server_steps(effective_steps(), {key: block})
        assert found == [] and off == {key: f"the sample would be sent to {key}"}


@pytest.mark.parametrize("key", NEEDS_IDENTIFICATION)
def test_a_runtime_step_waits_for_the_identification_server_alone(key: str, in_force: Any) -> None:
    settings = in_force(_on_as_shipped(key))
    steps, off = steps_on_servers(effective_steps(), settings.mcp.servers)
    assert not [s for s in steps if s.server == key]
    why = f"it reads {RUNTIME[key]} code, and no step of an identification tool names a "
    assert {off[i] for i in STEPS[key]} == {why + "file's runtime"}


class TestAnHttpServerThatSendsTheSampleIsLeftOut:
    @staticmethod
    def _server(effects: dict[str, Any], mount: str) -> MCPServerConfig:
        facts = builtin_tools("yarax")["yarax_scan"].model_dump(mode="json", exclude_defaults=True)
        return MCPServerConfig.model_validate(
            {
                "transport": "streamable-http",
                "url": "http://far.invalid/mcp",
                "enabled": True,
                "sample_mount": mount,
                "tool_facts": {"scan_it": {**facts, "effects": effects}},
            }
        )

    @pytest.mark.parametrize("mount", ["", "/data/samples"])
    def test_a_tool_declared_to_send_the_sample_out_is_no_step(
        self, mount: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        shipped = builtin_tools("yarax")["yarax_scan"]
        effects = shipped.model_dump(mode="json")["effects"]
        sends = {n: True for n in effects if "send" in n or "network" in n}
        assert sends, f"the shipped declaration names no effect to flip: {effects}"
        block = self._server({**effects, **sends}, mount)
        held = Settings(_env_file=None)
        held.mcp.servers["far"] = block
        monkeypatch.setattr(config_module, "_settings_instance", held)
        found, _off = server_steps(effective_steps(), {"far": block})
        assert found == []
