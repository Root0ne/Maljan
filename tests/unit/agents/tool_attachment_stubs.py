"""A tool-server registry that answers both halves of an agent's tool set.

An agent's tools come from two bindings, and only a fake that serves both can
tell them apart: servers bound to the agent's role by ``MCPServerConfig.agents``
(``tools_for``), and the servers the agent's own definition names by
``ToolRef`` (``tools_for_ref``). A stub that answered only the first would let
the reference half be deleted with every test still green — which is exactly
the gap these stubs exist to close.

No sidecar is launched. Every tool here is a named stand-in, so the assertions
are about which binding produced a tool rather than about what any real server
happens to offer today.
"""

from __future__ import annotations

from typing import Any

# What each built-in server contributes when it is reached. One name apiece is
# enough to say which binding delivered it, and keeps an assertion readable.
SERVER_TOOLS: dict[str, list[str]] = {
    "analysis": ["pe_info"],
    "knowledge": ["attck_lookup"],
    "network": ["extract_dns"],
    "threatintel": ["check_ip_reputation"],
}


class FakeTool:
    """The shape ``merge_tools`` and the analysts need, and nothing else."""

    def __init__(self, name: str, server: str = "") -> None:
        self.name = name
        self.metadata = {"maljan_server": server} if server else None

    def model_copy(self, *, update: dict) -> FakeTool:
        copy = FakeTool(update.get("name", self.name))
        copy.metadata = update.get("metadata", self.metadata)
        return copy

    def __repr__(self) -> str:  # pragma: no cover - assertion output only
        return f"FakeTool({self.name!r})"


class FakeRegistry:
    """Serves ``tools_for`` from ``bound`` and ``tools_for_ref`` from ``by_server``.

    ``bound`` is ``{role: {server: [tool name]}}`` — the servers an operator
    bound to a role. ``by_server`` is ``{server: [tool name]}`` — what a server
    offers when a ``ToolRef`` names it.

    ``exclude`` is honoured the way the real registry honours it, ``"*"``
    included: a fake that ignored it would let a profile's exclusions pass a
    test they do not pass in production.
    """

    def __init__(
        self,
        bound: dict[str, dict[str, list[str]]] | None = None,
        by_server: dict[str, list[str]] | None = None,
    ) -> None:
        self.bound = bound or {}
        self.by_server = SERVER_TOOLS if by_server is None else by_server
        self.degradation_reasons: list[str] = []
        self.asked_roles: list[str] = []
        self.asked_refs: list[str] = []

    # -- the role-bound half ------------------------------------------------

    def tools_for(self, role, job_id, *, exclude="", seen=None, **context):  # type: ignore[no-untyped-def]
        self.asked_roles.append(role)
        excluded = {name.strip() for name in exclude.split(",") if name.strip()}
        if "*" in excluded:
            return [], []
        tools: list[Any] = []
        for server, names in sorted(self.bound.get(role, {}).items()):
            if server in excluded:
                continue
            self._merge(server, names, tools, seen)
        return tools, []

    # -- the reference half -------------------------------------------------

    def tools_for_ref(self, ref, job_id, *, seen=None, **context):  # type: ignore[no-untyped-def]
        server = str(ref.server)
        self.asked_refs.append(server)
        names = self.by_server.get(server)
        if names is None:
            reason = f"agent tool '{server}.{ref.name}' unavailable"
            self.degradation_reasons.append(reason)
            return [], [reason]
        tools: list[Any] = []
        self._merge(server, names, tools, seen)
        return tools, []

    async def atools_for(self, role, job_id, *, exclude="", seen=None, **context):  # type: ignore[no-untyped-def]
        return self.tools_for(role, job_id, exclude=exclude, seen=seen, **context)

    async def atools_for_ref(self, ref, job_id, *, seen=None, **context):  # type: ignore[no-untyped-def]
        return self.tools_for_ref(ref, job_id, seen=seen, **context)

    def _merge(self, server: str, names: list[str], tools: list[Any], seen) -> None:
        """The real registry's collision rule, in miniature.

        Reproduced rather than skipped because the two halves now share one
        ``seen`` map, and a fake that let both halves append blindly would hide
        a duplicate the real path collapses.
        """
        claimed = {} if seen is None else seen
        for name in names:
            owner = claimed.get(name)
            if owner == server:
                continue
            final = f"{server}__{name}" if owner is not None else name
            claimed[final] = server
            tools.append(FakeTool(final, server))


class StubProvider:
    """A static provider that opens nothing and offers nothing."""

    id = "none"
    server_name = ""

    class capabilities:  # noqa: N801 - a stand-in for the frozen dataclass
        provides_tools = False
        degrade_on_failure = True

    def open(self, job: Any) -> None:
        return None

    def get_tools(self) -> list[Any]:
        return []


class StubSandboxProvider:
    """A sandbox provider with no MCP tools of its own.

    The dynamic analyst has two tool sources that are easy to confuse: this
    provider's ``dynamic_tools()`` and the in-process sandbox-report tools a
    ``ToolRef(kind="sandbox")`` asks for. Emptying the first is what lets a
    test attribute anything it sees to the second.
    """

    id = "mock"

    class capabilities:  # noqa: N801 - a stand-in for the frozen dataclass
        provides_tools = False
        degrade_on_failure = True

    def dynamic_tools(self) -> list[Any]:
        return []
