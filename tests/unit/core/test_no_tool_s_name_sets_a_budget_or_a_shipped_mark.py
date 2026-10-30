"""A server's call budget and its shipped mark are read by no server's or tool's name (T-430).

A server whose block declares no budget gets the deployment's budget for such
a server, whatever it or its tools are called: no static block named for one
provider's tools sets it. A server is shipped by the mark its seed carries,
which nothing stored or posted can set; a copy under another key is an
operator's server like any other.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.core.config import MCPServerConfig, Settings, shipped_server_keys
from maljan.providers.server_guard import guard_from_settings, server_call_budget


def _with_a_renamed_copy(**over: Any) -> Settings:
    """Settings holding the analysis server's seed again under another key, its tool renamed."""
    seed = Settings(_env_file=None).mcp.servers["analysis"]
    stored = {**seed.model_dump(mode="json"), "tool_facts": {"capa": {"long_running": True}}}
    copy = {**stored, "tool_facts": {"rule_scan_renamed": {"long_running": True}}}
    servers = {"renamed_srv": copy, "analysis": stored}
    return Settings(_env_file=None, mcp={"servers": servers, **over.pop("mcp", {})}, **over)


class TestARenamedServerAndToolGetTheSameBudget:
    def test_the_same_budget_and_the_same_long_running_tool(self) -> None:
        settings = _with_a_renamed_copy()
        shipped = guard_from_settings("analysis", settings)
        renamed = guard_from_settings("renamed_srv", settings)

        assert shipped.call_timeout("any") == renamed.call_timeout("other") == 330.0
        assert shipped.call_timeout("capa") is None
        assert renamed.call_timeout("rule_scan_renamed") is None

    def test_the_deployment_budget_moves_both_alike(self) -> None:
        settings = _with_a_renamed_copy(mcp={"breaker": {"default_call_timeout_seconds": 900}})

        assert guard_from_settings("analysis", settings).call_timeout("any") == 930.0
        assert guard_from_settings("renamed_srv", settings).call_timeout("any") == 930.0

    def test_no_static_block_moves_either(self) -> None:
        """capa's and YARA's timeouts were the budget of every server; they are their own now."""
        settings = _with_a_renamed_copy(
            static={"capa": {"timeout_seconds": 900}},
            reporting={"detection_rule_check_seconds": 1200},
        )

        assert guard_from_settings("analysis", settings).call_timeout("any") == 330.0
        assert guard_from_settings("renamed_srv", settings).call_timeout("any") == 330.0
        for block in (settings.static.ghidra, settings.static.r2, settings.sandbox.cape2.mcp):
            assert server_call_budget(settings, block) == 300.0

    def test_zero_sends_the_calls_with_no_deadline(self) -> None:
        settings = _with_a_renamed_copy(mcp={"breaker": {"default_call_timeout_seconds": 0}})

        assert guard_from_settings("analysis", settings).call_timeout("any") is None
        assert guard_from_settings("renamed_srv", settings).call_timeout("any") is None


class TestTheShippedMark:
    def test_every_seeded_server_carries_it(self) -> None:
        servers = Settings(_env_file=None).mcp.servers

        assert shipped_server_keys(servers) == tuple(servers)
        assert all(block.shipped for block in servers.values())

    def test_no_operator_can_set_it(self) -> None:
        posted = {"command": "x", "shipped": True}
        settings = Settings(_env_file=None, mcp={"servers": {"mine": posted}})

        assert MCPServerConfig.model_validate(posted).shipped is False
        assert settings.mcp.servers["mine"].shipped is False
        assert "mine" not in shipped_server_keys(settings.mcp.servers)
        assert "shipped" not in settings.mcp.servers["analysis"].model_dump()

    def test_a_stored_block_under_a_seed_keeps_it_and_a_copy_elsewhere_does_not(self) -> None:
        settings = _with_a_renamed_copy()

        assert settings.mcp.servers["analysis"].shipped is True
        assert settings.mcp.servers["renamed_srv"].shipped is False
        assert settings.mcp.servers["analysis"].model_copy().shipped is True
        rebuilt = Settings.model_validate(settings.model_dump(mode="json"))
        assert rebuilt.mcp.servers["analysis"].shipped is True
        assert rebuilt.mcp.servers["renamed_srv"].shipped is False

    def test_a_copy_is_launched_as_an_operator_s_server(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The shipped sidecars' bare child environment is the mark's, not the key's."""
        from maljan.providers.servers import ServerRegistry

        monkeypatch.delenv("PYTHONIOENCODING", raising=False)
        seen: list[dict[str, str]] = []

        class _FakeToolkit:
            def __init__(self, server_params: Any, **_kwargs: Any) -> None:
                seen.append(dict(server_params.env))

            async def initialize(self) -> None:
                return None

            def get_tools(self) -> list[Any]:
                return []

        monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _FakeToolkit)
        registry = ServerRegistry(_with_a_renamed_copy())
        for name in ("analysis", "renamed_srv"):
            handle = registry.get(name)
            handle.open("test-job")
            handle.close()

        assert len(seen) == 2
        assert "PYTHONIOENCODING" not in seen[0]
        assert seen[1].get("PYTHONIOENCODING") == "utf-8"

    def test_a_stage_that_withholds_the_built_ins_withholds_every_shipped_server(self) -> None:
        from tests.unit.pipeline.test_stage_inputs import _settings

        from maljan.agents.composition import _withheld_servers

        settings = _settings(
            [
                {"key": "triage", "kind": "analysis", "agents": ["static"], "builtin_tools": False},
                {
                    "key": "verdict",
                    "kind": "verdict",
                    "agents": ["judge"],
                    "depends_on": ["triage"],
                },
            ]
        )

        withheld = _withheld_servers(settings, "static")
        assert withheld == set(settings.mcp.servers)
        # The container sidecars ship as the four stdio ones do.
        assert {"die", "yarax", "jadx"} <= withheld
        assert _withheld_servers(settings, "judge") == set()


def _tool_names(
    monkeypatch: pytest.MonkeyPatch,
    offered: dict[str, list[str]],
    servers: dict[str, dict[str, Any]],
    role: str,
    refs: tuple[str, ...] = (),
    seeds: dict[str, dict[str, Any]] | None = None,
) -> list[str]:
    """The tool names ``role`` is given from ``servers``, each offering ``offered[<args or url>]``.

    ``seeds`` are extra servers the deployment ships, built as every seed is
    (``config._declared``), so their marks come from their seed facts alone.
    """
    from langchain_core.tools import StructuredTool

    from maljan.core import config as config_module
    from maljan.core.config import ToolRef
    from maljan.providers.servers import ServerRegistry

    def _tool(name: str) -> Any:
        return StructuredTool.from_function(lambda: "ok", name=name, description=name)

    class _FakeToolkit:
        def __init__(self, server_params: Any = None, **kwargs: Any) -> None:
            where = server_params.args[0] if server_params is not None else kwargs["http_url"]
            self.names = offered[where]

        async def initialize(self) -> None:
            return None

        def get_tools(self) -> list[Any]:
            return [_tool(name) for name in self.names]

    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _FakeToolkit)
    if seeds:
        shipped = config_module._builtin_servers

        def _with_seeds() -> dict[str, MCPServerConfig]:
            extra = {key: config_module._declared(key, **fields) for key, fields in seeds.items()}
            return {**shipped(), **extra}

        monkeypatch.setattr(config_module, "_builtin_servers", _with_seeds)
    settings = Settings(_env_file=None, mcp={"servers": servers})
    registry = ServerRegistry(settings)
    tools, _ = registry.agent_tools(
        role, "test-job", [ToolRef(kind="mcp", server=key) for key in refs]
    )
    return [str(tool.name) for tool in tools]


class TestAShippedServerKeepsTheNamesItHadBeforeItWasMarked:
    """Which shipped servers attach with the built-ins is read from their seed facts alone.

    A seed that ships switched on, or that leaves its binding to the
    definitions (no ``agents`` of its own), attaches with the built-ins; one
    that ships off and bound to roles of its own runs only once an operator
    switches it on, and attaches as an operator's server does. Servers and
    tools under names no seed has, and VirusTotal's own case.
    """

    SHARED = "probe_manifest_q7"
    LAUNCH: dict[str, Any] = {"enabled": True, "transport": "stdio", "command": "x"}

    def _seeded(self, monkeypatch: pytest.MonkeyPatch, *, ships_on: bool, agents: list[str]) -> Any:
        offered = {
            "quarnby-srv": [self.SHARED, "quarnby_only_q7"],
            "vexwell-srv": [self.SHARED, "vexwell_only_q7"],
        }
        seeds = {
            "quarnby": {**self.LAUNCH, "args": ["quarnby-srv"], "agents": []},
            "vexwell": {
                **self.LAUNCH,
                "enabled": ships_on,
                "args": ["vexwell-srv"],
                "agents": agents,
            },
        }
        # Stored as an operator switches the second on and binds it to the role.
        servers = {
            "quarnby": seeds["quarnby"],
            "vexwell": {**seeds["vexwell"], "enabled": True, "agents": ["static"]},
        }
        return _tool_names(monkeypatch, offered, servers, "static", ("quarnby",), seeds)

    def test_a_sidecar_shipped_off_and_bound_leaves_the_definition_s_server_its_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        names = self._seeded(monkeypatch, ships_on=False, agents=["static"])

        assert self.SHARED in names
        assert f"vexwell__{self.SHARED}" in names
        assert f"quarnby__{self.SHARED}" not in names
        assert names.index(self.SHARED) < names.index(f"vexwell__{self.SHARED}")

    def test_a_server_shipped_on_and_bound_keeps_its_place_first(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """As the judge's role-bound reputation server always kept its names."""
        names = self._seeded(monkeypatch, ships_on=True, agents=["static"])

        assert f"quarnby__{self.SHARED}" in names
        assert f"vexwell__{self.SHARED}" not in names
        assert names.index("vexwell_only_q7") < names.index("quarnby_only_q7")

    def test_a_server_shipped_off_with_its_binding_left_to_the_definitions_stays_first(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bound to a role only by an operator, it keeps the built-ins' place."""
        names = self._seeded(monkeypatch, ships_on=False, agents=[])

        assert f"quarnby__{self.SHARED}" in names
        assert f"vexwell__{self.SHARED}" not in names

    def test_virustotal_bound_to_a_role_keeps_its_names_over_an_operator_s_server(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core import virustotal

        lookup = virustotal.LOOKUP_TOOLS[0]
        offered = {virustotal.MCP_ENDPOINT: [lookup], "mine-srv": [lookup, "mine_only_q7"]}
        servers = {
            # Its seed as stored, switched on with a token and bound to a role.
            virustotal.SERVER_KEY: {
                **Settings(_env_file=None).mcp.servers[virustotal.SERVER_KEY].model_dump(),
                "enabled": True,
                "auth_token": "t",
                "agents": ["reporter"],
            },
            "mine_q7": {**self.LAUNCH, "args": ["mine-srv"], "agents": ["reporter"]},
        }
        names = _tool_names(monkeypatch, offered, servers, "reporter")

        assert lookup in names
        assert f"mine_q7__{lookup}" in names
        assert f"{virustotal.SERVER_KEY}__{lookup}" not in names

    def test_the_seeds_attach_as_the_five_built_ins_always_did(self) -> None:
        """Every seed shipped on or bound by the definitions; the eight sidecars are not."""
        servers = Settings(_env_file=None).mcp.servers

        assert {key for key, block in servers.items() if block.attaches_as_builtin} == {
            "analysis",
            "knowledge",
            "network",
            "threatintel",
            "virustotal",
        }
        assert all(block.shipped for block in servers.values())
