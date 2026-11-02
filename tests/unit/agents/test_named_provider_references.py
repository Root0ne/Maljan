"""A provider tool reference may name its provider, so one agent holds several.

``ToolRef(kind="provider")`` with no ``provider`` stands for the definition's
own static provider, exactly as it always did; with ``provider="<id>"`` it
stands for that provider. Each provider is opened for the agent and exposes
its own tools; a later provider's tool whose name an earlier one holds is
offered as ``<provider>__<name>``, the servers' collision rule. The ids here
are two of the shipped providers only because a named reference must name a
known one; nothing below depends on which.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.tools import StructuredTool
from pydantic import ValidationError

from maljan.agents.composition import (
    PROVIDER_ID_METADATA_KEY,
    aresolve_agent,
    pin_provider_sample,
    referenced_provider_ids,
    resolve_agent,
    servers_a_job_calls,
    static_provider_ids_for,
)
from maljan.agents.tool_pinning import DECLARED_NAME_METADATA_KEY
from maljan.core.config import Settings, ToolRef
from maljan.core.model_assignments import assignments_for

FIRST, SECOND = "ghidra", "r2"


def _tool(name: str) -> StructuredTool:
    return StructuredTool.from_function(func=lambda: name, name=name, description=name)


class _Provider:
    """A static provider with its own tools, label and fragment."""

    class capabilities:  # noqa: N801 - mirrors the provider attribute shape
        provides_tools = True
        needs_sample_mirror = True

    def __init__(self, provider_id: str, tools: list[str]) -> None:
        self.id = provider_id
        self.label = f"{provider_id.upper()} LABEL"
        self._names = tools
        self.opened = 0
        self.pinned: list[str | None] = []

    def prompt_fragment(self) -> str:
        return f"{self.id.upper()}-FRAGMENT"

    def absent_fragment(self) -> str:
        return f"{self.id.upper()}-ABSENT"

    def open(self, job: Any) -> None:
        self.opened += 1
        self.job = job

    def get_tools(self) -> list[Any]:
        return [_tool(name) for name in self._names]

    def pin_sample(self, path: str | None) -> None:
        self.pinned.append(path)


class _Registry:
    def __init__(self) -> None:
        self.degradation_reasons: list[str] = []

    def agent_tools(self, role, job_id, refs, *, exclude="", seen=None, **context):  # type: ignore[no-untyped-def]
        return [], []

    async def aagent_tools(self, role, job_id, refs, *, exclude="", seen=None, **context):  # type: ignore[no-untyped-def]
        return [], []


class _Container:
    def __init__(self, cfg: Settings, providers: dict[str, _Provider]) -> None:
        from maljan.core.truncation_ledger import TruncationLedger
        from maljan.llm.context_window import budget_for_settings

        self.config = cfg
        self.providers = providers
        self.asked: list[str] = []
        self._registry = _Registry()
        self._ledger = TruncationLedger()
        self._budget = budget_for_settings(cfg, assignments_for(cfg, ["static"]), probe=False)

    def get_agent_llm(self, name: str) -> Any:
        return object()

    def job_key(self) -> str:
        return "job-under-test"

    def get_static_provider(self, provider_id: str | None = None) -> Any:
        wanted = str(provider_id or self.config.static.provider)
        self.asked.append(wanted)
        return self.providers[wanted]

    def get_truncation_ledger(self) -> Any:
        return self._ledger

    def get_context_budget(self) -> Any:
        return self._budget

    def get_server_registry(self) -> Any:
        return self._registry


def _settings(tools: list[dict[str, Any]], **extra: Any) -> Settings:
    return Settings(
        _env_file=None,
        agents={
            "definitions": {
                "reader": {"role": "generic", "prompt": "READ", "tools": tools, **extra}
            },
            "profiles": {"one": {"analysts": ["reader"]}},
            "profile": "one",
        },
    )


def _providers() -> dict[str, _Provider]:
    return {
        FIRST: _Provider(FIRST, ["open_file", "decompile"]),
        SECOND: _Provider(SECOND, ["open_file", "disassemble"]),
    }


# --- the reference itself --------------------------------------------------


def test_an_unnamed_provider_reference_dumps_exactly_as_it_always_did():
    assert ToolRef(kind="provider").model_dump() == {
        "kind": "provider",
        "server": None,
        "name": None,
    }


def test_a_named_provider_reference_dumps_its_provider():
    assert ToolRef(kind="provider", provider=SECOND).model_dump() == {
        "kind": "provider",
        "server": None,
        "name": None,
        "provider": SECOND,
    }


@pytest.mark.parametrize(
    "ref",
    [
        {"kind": "mcp", "server": "knowledge", "provider": SECOND},
        {"kind": "sandbox", "provider": SECOND},
        {"kind": "agent", "agent": "static", "provider": SECOND},
        {"kind": "provider", "provider": "  "},
        {"kind": "provider", "server": "knowledge", "provider": SECOND},
    ],
)
def test_a_provider_is_named_only_on_a_provider_reference(ref):
    with pytest.raises(ValidationError):
        ToolRef.model_validate(ref)


def test_an_unknown_provider_name_is_refused_at_the_reference():
    with pytest.raises(ValidationError) as exc:
        _settings([{"kind": "provider", "provider": "no_such_provider"}])
    assert "unknown static provider 'no_such_provider'" in str(exc.value)


def test_a_named_provider_reference_round_trips_through_the_settings():
    cfg = _settings([{"kind": "provider"}, {"kind": "provider", "provider": SECOND}])
    dumped = cfg.agents.model_dump(mode="json")
    again = Settings(_env_file=None, agents=dumped)
    assert again.agents.definitions["reader"].tools == cfg.agents.definitions["reader"].tools
    assert dumped["definitions"]["reader"]["tools"] == [
        {"kind": "provider", "server": None, "name": None},
        {"kind": "provider", "server": None, "name": None, "provider": SECOND},
    ]


def test_a_named_provider_reference_is_refused_on_a_built_in_role_like_any_other():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            agents={
                "definitions": {
                    "mine": {"role": "static", "tools": [{"kind": "provider", "provider": SECOND}]}
                }
            },
        )


# --- which providers an agent opens ----------------------------------------


def test_each_reference_stands_for_its_provider_in_reference_order():
    cfg = _settings(
        [{"kind": "provider", "provider": SECOND}, {"kind": "provider"}],
        static_provider=FIRST,
    )
    definition = cfg.agents.definitions["reader"]
    assert referenced_provider_ids(cfg, definition, FIRST) == [SECOND, FIRST]
    assert static_provider_ids_for(cfg, "reader") == [SECOND, FIRST]


def test_a_provider_named_twice_is_opened_once():
    cfg = _settings(
        [{"kind": "provider"}, {"kind": "provider", "provider": FIRST}], static_provider=FIRST
    )
    assert static_provider_ids_for(cfg, "reader") == [FIRST]


def test_a_team_that_forces_a_provider_forces_it_on_every_reference():
    cfg = _settings([{"kind": "provider"}, {"kind": "provider", "provider": SECOND}])
    cfg.agents.profiles["one"].static_provider = "none"
    assert static_provider_ids_for(cfg, "reader") == ["none"]


def test_an_agent_with_no_provider_reference_opens_none_and_the_static_role_its_own():
    cfg = _settings([])
    assert static_provider_ids_for(cfg, "reader") == []
    assert static_provider_ids_for(cfg, "static") == [str(cfg.static.provider)]


# --- resolution ------------------------------------------------------------


def test_an_agent_holding_two_named_providers_gets_both_toolsets_with_a_clash_namespaced():
    cfg = _settings(
        [{"kind": "provider", "provider": FIRST}, {"kind": "provider", "provider": SECOND}]
    )
    providers = _providers()
    resolved = resolve_agent("reader", _Container(cfg, providers))

    assert [t.name for t in resolved.tools] == [
        "open_file",
        "decompile",
        f"{SECOND}__open_file",
        "disassemble",
    ]
    clashing = resolved.tools[2]
    assert clashing.metadata[DECLARED_NAME_METADATA_KEY] == "open_file"
    assert [t.metadata[PROVIDER_ID_METADATA_KEY] for t in resolved.tools] == [
        FIRST,
        FIRST,
        SECOND,
        SECOND,
    ]
    # Each provider was opened under the job, once.
    assert providers[FIRST].opened == providers[SECOND].opened == 1
    assert providers[SECOND].job.job_key == "job-under-test"
    assert resolved.provider_ids == (FIRST, SECOND)
    assert resolved.static_provider_id == FIRST


def test_the_prompt_carries_each_providers_text_and_one_sentence_naming_both():
    cfg = _settings(
        [{"kind": "provider", "provider": FIRST}, {"kind": "provider", "provider": SECOND}]
    )
    resolved = resolve_agent("reader", _Container(cfg, _providers()))
    assert resolved.prompt.startswith("READ\n\n")
    assert resolved.prompt.index("GHIDRA-FRAGMENT") < resolved.prompt.index("R2-FRAGMENT")
    assert "the GHIDRA LABEL and R2 LABEL static providers" in resolved.prompt
    assert "ABSENT" not in resolved.prompt
    assert resolved.authored_prompt == "READ"


def test_a_provider_whose_tools_did_not_attach_says_so_beside_the_other():
    cfg = _settings(
        [{"kind": "provider", "provider": FIRST}, {"kind": "provider", "provider": SECOND}]
    )
    providers = _providers()
    providers[SECOND]._names = []
    resolved = resolve_agent("reader", _Container(cfg, providers))
    assert "GHIDRA-FRAGMENT" in resolved.prompt
    assert "R2-ABSENT" in resolved.prompt


def test_the_async_resolver_binds_the_same_tools():
    import asyncio

    cfg = _settings(
        [{"kind": "provider", "provider": FIRST}, {"kind": "provider", "provider": SECOND}]
    )
    resolved = asyncio.run(aresolve_agent("reader", _Container(cfg, _providers())))
    assert [t.name for t in resolved.tools] == [
        "open_file",
        "decompile",
        f"{SECOND}__open_file",
        "disassemble",
    ]
    assert resolved.provider_ids == (FIRST, SECOND)


def test_an_unnamed_reference_resolves_exactly_as_before():
    """One provider: the tools are the provider's own objects' copies, unmarked."""
    cfg = _settings([{"kind": "provider"}], static_provider=SECOND)
    providers = _providers()
    container = _Container(cfg, providers)
    resolved = resolve_agent("reader", container)
    assert [t.name for t in resolved.tools] == ["open_file", "disassemble"]
    assert not any(PROVIDER_ID_METADATA_KEY in (t.metadata or {}) for t in resolved.tools)
    assert resolved.provider_ids == (SECOND,)
    assert resolved.static_provider_id == SECOND
    assert providers[FIRST].opened == 0
    assert "R2-FRAGMENT" in resolved.prompt
    assert "the R2 LABEL static provider;" in resolved.prompt


def test_an_unnamed_and_a_named_reference_to_the_same_provider_are_one_provider():
    cfg = _settings(
        [{"kind": "provider"}, {"kind": "provider", "provider": SECOND}], static_provider=SECOND
    )
    providers = _providers()
    resolved = resolve_agent("reader", _Container(cfg, providers))
    assert [t.name for t in resolved.tools] == ["open_file", "disassemble"]
    assert providers[SECOND].opened == 1


def test_every_provider_of_the_agent_is_pinned_to_its_own_mirror():
    cfg = _settings(
        [{"kind": "provider", "provider": FIRST}, {"kind": "provider", "provider": SECOND}]
    )
    providers = _providers()
    container = _Container(cfg, providers)
    resolved = resolve_agent("reader", container)

    class _Agent:
        pass

    agent = _Agent()
    agent._container = container
    agent._resolved = resolved
    agent.tools = resolved.tools
    agent.degradation_reasons = []
    pin_provider_sample(agent, {FIRST: "/m/ghidra/s", SECOND: "/m/r2/s"})
    assert providers[FIRST].pinned == ["/m/ghidra/s"]
    assert providers[SECOND].pinned == ["/m/r2/s"]

    # A provider with no mirror is said, the other still pinned.
    pin_provider_sample(agent, {FIRST: "/m/ghidra/s"})
    assert providers[SECOND].pinned[-1] is None
    assert "sample not mirrored for r2" in agent.degradation_reasons


# --- the rest of the run reads the same answer -----------------------------


def test_the_worker_mirrors_the_sample_for_every_named_provider():
    from app.worker.analysis_worker import profile_static_providers
    from maljan.core.container import ServiceContainer

    cfg = _settings([{"kind": "provider", "provider": SECOND}])
    assert profile_static_providers(ServiceContainer(cfg, mock=True)) == [
        str(cfg.static.provider),
        SECOND,
    ]


def test_a_named_provider_is_selected_and_its_servers_counted():
    from maljan.core.tool_declarations import selected_static_providers
    from maljan.providers.registry import static_provider_servers

    cfg = _settings([{"kind": "provider", "provider": SECOND}])
    assert SECOND in selected_static_providers(cfg)
    assert static_provider_servers(SECOND, cfg) <= servers_a_job_calls(cfg)


def test_a_prompt_may_name_both_providers_tools_without_a_warning(monkeypatch):
    from maljan.agents.prompt_tools import declared_set
    from maljan.core import builtin_declarations

    declared = {
        FIRST: {"tool_facts": {"open_file": {}, "decompile": {}}},
        SECOND: {"tool_facts": {"open_file": {}, "disassemble": {}}},
    }
    cfg = _settings(
        [{"kind": "provider", "provider": FIRST}, {"kind": "provider", "provider": SECOND}]
    )
    one = _settings([{"kind": "provider"}], static_provider=SECOND)
    monkeypatch.setattr(builtin_declarations, "provider_declaration", declared.__getitem__)
    held = declared_set(cfg, "reader", cfg.agents.definitions["reader"])
    # Each provider's names, and a later provider's clashing name as it is offered.
    assert held == {"open_file", "decompile", "disassemble", f"{SECOND}__open_file"}

    assert declared_set(one, "reader", one.agents.definitions["reader"]) == {
        "open_file",
        "disassemble",
    }
