"""PS-L2: a ToolRef to a disabled server says so instead of returning nothing."""

from __future__ import annotations

from types import SimpleNamespace

from maljan.core.config import MCPServerConfig, Settings
from maljan.providers.servers import ServerRegistry


def test_a_ref_to_a_disabled_server_is_reported():
    cfg = Settings(_env_file=None)
    cfg.mcp.servers["off"] = MCPServerConfig(command="x", enabled=False)
    registry = ServerRegistry(cfg)
    for name in (None, "some_tool"):
        picked, reasons = registry._ref_tools(
            registry.get("off"), SimpleNamespace(server="off", name=name)
        )
        assert picked == []
        assert reasons and "disabled" in reasons[0] and "off" in reasons[0]
