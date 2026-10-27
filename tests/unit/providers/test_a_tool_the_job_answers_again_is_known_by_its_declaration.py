"""Which tools a job answers again from its ledger is read from generic signals, never a name.

An identical call of the job is answered from the entry that holds it only for
a tool its own MCP server marks both read-only and idempotent when it is
attached (``tool_pinning.answers_the_job_again``). A read-only mark alone and a
tool its server says nothing of are not reused. A declaration may only veto:
one that states the tool is not read-only, or whose kind's answer moves by what
it means (``builtin_declarations.MOVING_KINDS``: a status, a submission), keeps
the tool running whatever its hints say; a declaration silent on both leaves the
hints to decide, and a declared read-only mark grants nothing on its own.

What may change a server between a read and its reuse is counted on the job's
change count (``ServerChanges``): every attach of a server (a reconnect, a
restart, a per-loop replica), and a provider's own walk on its server outside
any tool call.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.mcp_client import MCPLangChainToolkit
from maljan.agents.prompt_fragments import PROVIDER_FAMILY, stamp_source
from maljan.agents.tool_pinning import (
    SERVER_HINTS_METADATA_KEY,
    SERVER_METADATA_KEY,
    answers_again,
    answers_the_job_again,
)
from maljan.schemas.evidence import EvidenceCounter, ServerChanges

BOTH = {"readOnlyHint": True, "idempotentHint": True}


class _NoArgs(BaseModel):
    pass


def _attached(annotations: Any) -> Any:
    """A tool as the MCP toolkit builds it from a server's listing with ``annotations``."""
    listed = SimpleNamespace(
        name="lookup",
        description="lookup",
        inputSchema={"properties": {}, "required": []},
        annotations=annotations,
    )
    client = MCPLangChainToolkit.__new__(MCPLangChainToolkit)
    client._categories = {}
    return client._create_langchain_tool(listed)


def _provider(name: str, source: str) -> Any:
    tool = StructuredTool.from_function(
        func=lambda: "", name=name, description="d", args_schema=_NoArgs, infer_schema=False
    )
    (stamped,) = stamp_source([tool], PROVIDER_FAMILY, declared=source)
    return stamped


class TestAnMcpServersHints:
    def test_read_only_and_idempotent_is_answered_again(self) -> None:
        tool = _attached(SimpleNamespace(readOnlyHint=True, idempotentHint=True))
        assert answers_the_job_again(tool)

    def test_hints_given_as_a_mapping_are_read_the_same(self) -> None:
        tool = _attached({"readOnlyHint": True, "idempotentHint": True})
        assert answers_the_job_again(tool)

    @pytest.mark.parametrize(
        "annotations",
        [
            None,
            SimpleNamespace(readOnlyHint=True),
            SimpleNamespace(idempotentHint=True),
            SimpleNamespace(readOnlyHint=False, idempotentHint=True),
            SimpleNamespace(readOnlyHint=True, idempotentHint=False),
        ],
    )
    def test_anything_less_is_not(self, annotations: Any) -> None:
        assert not answers_the_job_again(_attached(annotations))

    def test_read_only_alone_still_seeds_a_revision_as_before(self) -> None:
        tool = _attached(SimpleNamespace(readOnlyHint=True))
        assert answers_again(tool) and not answers_the_job_again(tool)


class TestTheBuiltInDeclarations:
    @pytest.mark.parametrize("name", ["decompile_function", "batch_decompile", "list_imports"])
    def test_a_declared_read_only_mark_grants_nothing_without_the_hints(self, name: str) -> None:
        assert not answers_the_job_again(_provider(name, "provider:ghidra"))

    @pytest.mark.parametrize("name", ["decompile_function", "batch_decompile", "list_imports"])
    def test_a_declared_read_with_both_hints_is_answered_again(self, name: str) -> None:
        tool = _provider(name, "provider:ghidra")
        hinted = tool.model_copy(
            update={"metadata": {**tool.metadata, SERVER_HINTS_METADATA_KEY: BOTH}}
        )
        assert answers_the_job_again(hinted)

    @pytest.mark.parametrize("name", ["rename_function", "load_program", "emulate_hash_batch"])
    def test_a_decompiler_call_with_no_hints_is_not(self, name: str) -> None:
        assert not answers_the_job_again(_provider(name, "provider:ghidra"))

    def test_a_tool_nothing_stamped_is_not(self) -> None:
        tool = StructuredTool.from_function(
            func=lambda: "",
            name="decompile_function",
            description="d",
            args_schema=_NoArgs,
            infer_schema=False,
        )
        assert not answers_the_job_again(tool), "never read off the tool's name"


def _server_tool(server: str, name: str, hints: dict[str, bool] | None) -> Any:
    metadata: dict[str, Any] = {SERVER_METADATA_KEY: server}
    if hints is not None:
        metadata[SERVER_HINTS_METADATA_KEY] = hints
    return StructuredTool.from_function(
        func=lambda: "",
        name=name,
        description="d",
        args_schema=_NoArgs,
        infer_schema=False,
        metadata=metadata,
    )


class TestADeclarationMayOnlyVeto:
    def test_a_declaration_that_states_not_read_only_vetoes_both_hints(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core.tool_declarations import ToolFacts

        stated = ToolFacts.model_validate({"kind": "indicator_report", "read_only": False})
        monkeypatch.setattr("maljan.agents.tool_pinning.declared_facts_of", lambda _t: stated)
        assert not answers_the_job_again(_server_tool("undeclared-server", "lookup", BOTH))

    def test_a_declaration_silent_on_read_only_leaves_the_hints_to_decide(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core.tool_declarations import ToolFacts

        silent = ToolFacts.model_validate({"kind": "indicator_report"})
        monkeypatch.setattr("maljan.agents.tool_pinning.declared_facts_of", lambda _t: silent)
        assert answers_the_job_again(_server_tool("undeclared-server", "lookup", BOTH))

    @pytest.mark.parametrize(
        "name", ["get_file_report", "get_domain_report", "get_ip_report", "get_url_report"]
    )
    def test_a_report_lookup_is_reused_by_its_server_s_hints_alone(self, name: str) -> None:
        assert answers_the_job_again(_server_tool("virustotal", name, BOTH))
        assert not answers_the_job_again(_server_tool("virustotal", name, None))

    @pytest.mark.parametrize(
        "name", ["get_analysis", "get_submission", "submit_file", "submit_local_file"]
    )
    def test_a_moving_kind_is_not_reused_though_its_hints_say_so(self, name: str) -> None:
        assert not answers_the_job_again(_server_tool("virustotal", name, BOTH))

    def test_a_tool_nothing_declares_falls_back_to_its_server_s_hints(self) -> None:
        assert answers_the_job_again(_server_tool("undeclared-server", "lookup", BOTH))
        assert not answers_the_job_again(_server_tool("undeclared-server", "lookup", None))


class TestTheMovingKinds:
    def test_the_sandbox_status_kind_moves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from maljan.core.tool_declarations import ToolFacts

        status = ToolFacts.model_validate({"kind": "sandbox_status"})
        monkeypatch.setattr("maljan.agents.tool_pinning.declared_facts_of", lambda _t: status)
        assert not answers_the_job_again(_server_tool("undeclared-server", "lookup", BOTH))


class TestWhatAServerHandleSays:
    def _registry_handle(self, tools: list[Any]) -> Any:
        from maljan.core.config import MCPServerConfig
        from maljan.providers.servers import ServerHandle

        handle = ServerHandle("quietserver", MCPServerConfig())
        handle.tools = lambda: list(tools)  # type: ignore[method-assign]
        return handle

    def _merged(self, handle: Any) -> list[Any]:
        from maljan.core.config import Settings
        from maljan.providers.servers import ServerRegistry

        out: list[Any] = []
        ServerRegistry(Settings(_env_file=None)).merge_tools(
            handle.name, handle.tools(), out, {}, handle=handle
        )
        return out

    def _tool(self, name: str, *, read_only: bool) -> Any:
        from maljan.agents.tool_pinning import READ_ONLY_METADATA_KEY

        return StructuredTool.from_function(
            func=lambda: "",
            name=name,
            description="d",
            args_schema=_NoArgs,
            infer_schema=False,
            metadata={READ_ONLY_METADATA_KEY: True} if read_only else None,
        )

    def test_each_tool_carries_its_handle_s_token(self) -> None:
        from maljan.agents.tool_pinning import server_handle_of

        handle = self._registry_handle([self._tool("a", read_only=True)])
        (tool,) = self._merged(handle)
        assert server_handle_of(tool) == f"quietserver#{id(handle)}"

    def test_a_server_whose_every_tool_is_read_only_is_quiet(self) -> None:
        from maljan.agents.tool_pinning import server_changes_nothing

        tools = [self._tool("a", read_only=True), self._tool("b", read_only=True)]
        assert all(server_changes_nothing(t) for t in self._merged(self._registry_handle(tools)))

    def test_one_tool_that_may_change_it_makes_the_server_not_quiet(self) -> None:
        from maljan.agents.tool_pinning import server_changes_nothing

        tools = [self._tool("a", read_only=True), self._tool("rename", read_only=False)]
        merged = self._merged(self._registry_handle(tools))
        assert not any(server_changes_nothing(t) for t in merged)


class TestAProviderDrivenServer:
    def test_the_provider_s_handle_counts_its_attach_under_its_declared_source(self) -> None:
        from maljan.core.config import MCPServerConfig
        from maljan.providers.servers import ServerHandle
        from maljan.providers.static.generic_mcp import GenericMCPStaticProvider

        provider = GenericMCPStaticProvider(ServerHandle("decomp", MCPServerConfig()))
        changes = ServerChanges()
        provider.server_changes = changes
        assert provider._handle.server_changes is changes

        before = (changes.mark("decomp"), changes.mark(provider.declaration_source))
        provider._handle._note_attach()
        after = (changes.mark("decomp"), changes.mark(provider.declaration_source))
        assert provider.declaration_source == "mcp:decomp"
        assert before[0] != after[0] and before[1] != after[1]

    def test_the_container_gives_its_static_provider_the_job_s_count(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        cfg = Settings(_env_file=None)
        cfg.static.provider = "generic_mcp"  # type: ignore[assignment]
        container = ServiceContainer(cfg, mock=True)
        provider = container.get_static_provider()
        assert provider.server_changes is container.get_evidence_counter().changes  # type: ignore[attr-defined]


class TestAnAttachIsAChange:
    def _handle(self, changes: ServerChanges | None) -> Any:
        from maljan.core.config import MCPServerConfig
        from maljan.providers.servers import ServerHandle

        handle = ServerHandle("reputation", MCPServerConfig())
        handle.server_changes = changes
        handle._note_isolation = lambda: None  # type: ignore[method-assign]
        handle._read_capabilities = lambda: None  # type: ignore[method-assign]
        return handle

    def test_each_attach_of_a_server_moves_its_mark(self) -> None:
        changes = ServerChanges()
        handle = self._handle(changes)
        toolkit = SimpleNamespace(get_tools=lambda: [])

        before = changes.mark("reputation")
        handle._finish_open_sync(toolkit)
        first = changes.mark("reputation")
        handle._finish_open_sync(toolkit)

        assert before != first != changes.mark("reputation"), "a re-attach is a change too"
        assert changes.mark("analysis") == before, "another server's mark stays"

    def test_an_async_attach_moves_its_mark(self) -> None:
        import asyncio

        changes = ServerChanges()
        handle = self._handle(changes)

        async def _no_read() -> None:
            return None

        handle._aread_capabilities = _no_read  # type: ignore[method-assign]
        before = changes.mark("reputation")
        asyncio.run(handle._afinish_open(SimpleNamespace(get_tools=lambda: [])))
        assert changes.mark("reputation") != before

    def test_a_handle_with_no_job_count_attaches_as_before(self) -> None:
        self._handle(None)._finish_open_sync(SimpleNamespace(get_tools=lambda: []))

    def test_the_registry_gives_every_handle_and_replica_the_job_s_count(self) -> None:
        from maljan.core.config import Settings
        from maljan.providers.servers import ServerRegistry

        changes = EvidenceCounter().changes
        registry = ServerRegistry(Settings(_env_file=None), server_changes=changes)
        handles = list(registry._handles.values())
        assert handles and all(h.server_changes is changes for h in handles)

        bound = handles[0]
        bound._owner_loop = object()
        replica = registry._handle_for(bound, object())  # type: ignore[arg-type]
        assert replica is not bound and replica.server_changes is changes


class TestAProviderWalkIsAChange:
    def test_the_walk_is_counted_on_its_tools_source_as_it_starts_and_ends(self) -> None:
        from maljan.agents.static_analyst import server_changed_by

        counter = EvidenceCounter()
        agent = SimpleNamespace(evidence_counter=counter)
        provider = SimpleNamespace(id="ghidra", declaration_source="provider:ghidra")

        before = counter.changes.mark("provider:ghidra")
        ended = server_changed_by(agent, provider)
        started = counter.changes.mark("provider:ghidra")
        ended()

        assert before != started != counter.changes.mark("provider:ghidra")

    def test_an_agent_with_no_counter_counts_nothing(self) -> None:
        from maljan.agents.static_analyst import server_changed_by

        agent = SimpleNamespace(evidence_counter=None)
        provider = SimpleNamespace(id="ghidra", declaration_source="")
        server_changed_by(agent, provider)()
