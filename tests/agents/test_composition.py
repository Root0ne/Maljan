"""What ``resolve_agent`` hands one agent, and where each piece came from.

The four built-in resolutions are pinned in ``test_prompt_byte_identity.py``
because they are byte-identity statements. These are the composition rules:
a clone follows its own provider, a generic agent starts tool-less, an
explicit provider reference is the only way a generic agent gets provider
tools, duplicates collapse by name, and a tool a server does not have is a
degradation rather than a crash.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import Any

import pytest
from langchain_core.tools import StructuredTool

from maljan.agents.composition import (
    ResolvedAgent,
    analyst_keys,
    builtin_prompt,
    resolve_agent,
)
from maljan.agents.registry import AgentRegistry as _AgentRegistry
from maljan.core.config import Settings, ToolRef

# ``resolve_agent("network")``/``resolve_agent("static")`` import their built-in
# role modules directly, bypassing ``AgentRegistry.discover_agents()``'s fixed
# import order (dynamic, network, static). If this module is the first place
# in a test session to touch one of those modules, it would register that
# role before the others and perturb ``AgentRegistry.list_agents()`` for every
# later test that still reads registration order — ``test_graph_snapshot.py``
# among them. Forcing discovery here, before any test body runs, keeps that
# order pinned regardless of collection order.
_AgentRegistry()


def _tool(name: str) -> StructuredTool:
    return StructuredTool.from_function(func=lambda: name, name=name, description=name)


class _Provider:
    """A static provider that offers two tools and a recognisable fragment."""

    id = "r2"

    class capabilities:  # noqa: N801 - mirrors the provider attribute shape
        provides_tools = True
        needs_sample_mirror = True

    def prompt_fragment(self) -> str:
        return "R2-FRAGMENT "

    def open(self, job: Any) -> None:
        self.opened = True

    def get_tools(self) -> list[Any]:
        return [_tool("r2_open"), _tool("r2_analyze")]

    def select_tools(self, pool: list[Any], categories: Any) -> list[Any]:
        return list(pool)


class _Registry:
    """A stand-in ``ServerRegistry`` with a scripted answer per call."""

    def __init__(self, bound: dict[str, list[Any]], by_ref: dict[str, Any]) -> None:
        self.bound = bound
        self.by_ref = by_ref
        self.degradation_reasons: list[str] = []

    def tools_for(self, role, job_id, *, exclude="", **context):  # type: ignore[no-untyped-def]
        return list(self.bound.get(role, [])), []

    def tools_for_ref(self, ref, job_id, **context):  # type: ignore[no-untyped-def]
        key = f"{ref.server}.{ref.name}"
        answer = self.by_ref.get(key)
        if answer is None:
            reason = f"agent tool '{key}' unavailable"
            self.degradation_reasons.append(reason)
            return [], [reason]
        return list(answer), []


class _Container:
    def __init__(self, cfg: Settings, **over: Any) -> None:
        self.config = cfg
        self._provider = over.get("provider", _Provider())
        self._registry = over.get("registry", _Registry({}, {}))
        self.llm = object()

    def get_agent_llm(self, name: str) -> Any:
        return self.llm

    def get_static_provider(self, provider_id: str | None = None) -> Any:
        return self._provider

    def get_server_registry(self) -> Any:
        return self._registry


def test_a_clone_on_r2_gets_the_r2_fragment_in_the_built_in_assembly():
    from maljan.agents.static_analyst import _ISR_HEAD, _ISR_TAIL

    cfg = Settings(
        _env_file=None,
        agents={
            "definitions": {"static_r2": {"role": "static", "static_provider": "r2"}},
            "profiles": {"two": {"analysts": ["static", "static_r2"]}},
            "profile": "two",
        },
    )
    resolved = resolve_agent("static_r2", _Container(cfg))
    assert resolved.prompt == _ISR_HEAD + "R2-FRAGMENT " + _ISR_TAIL
    assert resolved.static_provider_id == "r2"
    assert resolved.role == "static"


def test_an_explicit_prompt_wins_over_the_built_in_assembly():
    cfg = Settings(
        _env_file=None,
        agents={
            "definitions": {"static_r2": {"role": "static", "prompt": "MINE"}},
            "profiles": {"two": {"analysts": ["static", "static_r2"]}},
            "profile": "two",
        },
    )
    assert resolve_agent("static_r2", _Container(cfg)).prompt == "MINE"


def test_a_generic_agent_with_no_references_and_no_bound_servers_is_tool_less():
    cfg = Settings(
        _env_file=None,
        agents={
            "definitions": {"strings": {"role": "generic", "prompt": "read strings"}},
            "profiles": {"one": {"analysts": ["strings"]}},
            "profile": "one",
        },
    )
    resolved = resolve_agent("strings", _Container(cfg))
    assert resolved.tools == []
    assert resolved.prompt == "read strings"


def test_a_provider_reference_is_the_only_way_a_generic_agent_gets_provider_tools():
    cfg = Settings(
        _env_file=None,
        agents={
            "definitions": {
                "strings": {
                    "role": "generic",
                    "prompt": "p",
                    "static_provider": "r2",
                    "tools": [{"kind": "provider"}],
                }
            },
            "profiles": {"one": {"analysts": ["strings"]}},
            "profile": "one",
        },
    )
    resolved = resolve_agent("strings", _Container(cfg))
    assert [t.name for t in resolved.tools] == ["r2_open", "r2_analyze"]


def test_a_bound_server_and_an_explicit_reference_to_it_produce_one_copy_of_each_tool():
    cfg = Settings(
        _env_file=None,
        mcp={"servers": {"mine": {"enabled": True, "command": "x", "agents": ["strings"]}}},
        agents={
            "definitions": {
                "strings": {
                    "role": "generic",
                    "prompt": "p",
                    "tools": [{"kind": "mcp", "server": "mine", "name": "grep"}],
                }
            },
            "profiles": {"one": {"analysts": ["strings"]}},
            "profile": "one",
        },
    )
    registry = _Registry(
        bound={"strings": [_tool("grep"), _tool("head")]},
        by_ref={"mine.grep": [_tool("grep")]},
    )
    resolved = resolve_agent("strings", _Container(cfg, registry=registry))
    assert [t.name for t in resolved.tools] == ["grep", "head"]


def test_a_tool_the_server_does_not_offer_is_a_degradation_not_an_error():
    cfg = Settings(
        _env_file=None,
        mcp={"servers": {"mine": {"enabled": True, "command": "x"}}},
        agents={
            "definitions": {
                "strings": {
                    "role": "generic",
                    "prompt": "p",
                    "tools": [{"kind": "mcp", "server": "mine", "name": "nope"}],
                }
            },
            "profiles": {"one": {"analysts": ["strings"]}},
            "profile": "one",
        },
    )
    resolved = resolve_agent("strings", _Container(cfg, registry=_Registry({}, {})))
    assert resolved.tools == []
    assert resolved.degradation_reasons == ("agent tool 'mine.nope' unavailable",)


def test_the_llm_comes_from_the_agents_own_key():
    cfg = Settings(_env_file=None)
    seen: list[str] = []

    class _C(_Container):
        def get_agent_llm(self, name: str) -> Any:
            seen.append(name)
            return self.llm

    resolve_agent("static", _C(cfg))
    assert seen == ["static"]


def test_analyst_keys_is_the_active_profiles_order():
    cfg = Settings(
        _env_file=None,
        agents={"profiles": {"rev": {"analysts": ["network", "static"]}}, "profile": "rev"},
    )
    assert analyst_keys(cfg) == ["network", "static"]


def test_the_default_settings_give_the_paper_triple():
    assert analyst_keys(Settings(_env_file=None)) == ["static", "dynamic", "network"]


def test_builtin_prompt_refuses_a_role_it_has_no_prompt_for():
    with pytest.raises(ValueError, match="no built-in prompt for role 'generic'"):
        builtin_prompt("generic", _Container(Settings(_env_file=None)), "ghidra")


def test_the_resolved_agent_is_frozen():
    resolved = resolve_agent("network", _Container(Settings(_env_file=None)))
    assert isinstance(resolved, ResolvedAgent)
    with pytest.raises(FrozenInstanceError):
        resolved.key = "other"  # type: ignore[misc]


def test_a_tool_ref_for_a_whole_server_asks_the_registry_for_the_whole_set():
    ref = ToolRef(kind="mcp", server="mine")
    registry = _Registry({}, {"mine.None": [_tool("a"), _tool("b")]})
    tools, reasons = registry.tools_for_ref(ref, "job")
    assert [t.name for t in tools] == ["a", "b"] and reasons == []
