"""The registry keeps a server's manifest, and a stage records the tools it cannot have.

Checked at the seam that carries each: the handle reads ``capabilities`` on
both attach paths and survives a wedged or bogus answer; the analysis node
records, once, each bound tool the manifest marks unavailable; and such a
reason is information, not a degraded run.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from langchain_core.tools import StructuredTool

from maljan.core.config import MCPServerConfig
from maljan.pipeline.nodes import note_unavailable_tools
from maljan.pipeline.triage_pack import run_is_degraded
from maljan.providers.servers import ServerHandle
from maljan.tools.capabilities import ServerCapabilities

MANIFEST = {
    "server": "analysis",
    "version": "1.0.0",
    "tools": [
        {"name": "hashes", "optional_dependency": None, "available": True, "reason": None},
        {
            "name": "document_info",
            "optional_dependency": "olefile",
            "available": False,
            "reason": "olefile is not installed",
            "remediation": "uv sync --extra tools",
        },
    ],
}


class _Tool:
    """A stand-in LangChain tool the registry reads ``name`` from and may invoke."""

    def __init__(self, name: str, answer: Any = None) -> None:
        self.name = name
        self.answer = answer
        self.metadata: dict[str, Any] = {}

    def model_copy(self, *, update: dict) -> _Tool:
        return _Tool(update.get("name", self.name), self.answer)

    async def ainvoke(self, _args: dict) -> Any:
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _toolkit(tools: list[_Tool]) -> MagicMock:
    instance = MagicMock()
    instance.initialize = AsyncMock(return_value=None)
    instance.get_tools = MagicMock(return_value=tools)
    instance.cleanup = AsyncMock(return_value=None)
    return instance


@pytest.fixture()
def attached(monkeypatch):
    """A handle that attaches without a live server or an event-loop hop."""
    made: list[MagicMock] = []

    def factory(*args, **kwargs):
        made.append(_toolkit(factory.tools))
        return made[-1]

    factory.tools = []
    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", factory)

    def _run_async(coro, label):
        coro.close()

    def _run_async_result(coro, label, hard_timeout):
        import asyncio

        return asyncio.run(coro)

    monkeypatch.setattr("maljan.providers.servers._run_async", _run_async)
    monkeypatch.setattr("maljan.providers.servers._run_async_result", _run_async_result)
    return factory


class TestTheRegistryKeepsTheManifest:
    def test_the_synchronous_attach_reads_capabilities_when_offered(self, attached) -> None:
        attached.tools = [_Tool("hashes"), _Tool("capabilities", json.dumps(MANIFEST))]
        handle = ServerHandle("analysis", MCPServerConfig(enabled=True, command="x"))
        handle.open("job-1")
        assert handle.capabilities is not None
        assert handle.capabilities.version == "1.0.0"
        assert [u.tool for u in handle.capabilities.unavailable()] == ["document_info"]
        # The manifest tool stays on the model's list like any other tool.
        assert "capabilities" in [t.name for t in handle.tools()]

    def test_a_server_without_the_tool_has_no_manifest(self, attached) -> None:
        attached.tools = [_Tool("open_file")]
        handle = ServerHandle("r2", MCPServerConfig(enabled=True, command="x"))
        handle.open("job-1")
        assert handle.capabilities is None and handle.is_open

    def test_a_manifest_that_cannot_be_read_never_costs_the_attach(self, attached) -> None:
        attached.tools = [_Tool("hashes"), _Tool("capabilities", RuntimeError("wedged"))]
        handle = ServerHandle("analysis", MCPServerConfig(enabled=True, command="x"))
        handle.open("job-1")
        assert handle.is_open and handle.capabilities is None

    def test_an_answer_that_is_not_a_manifest_is_not_kept(self, attached) -> None:
        attached.tools = [_Tool("capabilities", "not json at all")]
        handle = ServerHandle("analysis", MCPServerConfig(enabled=True, command="x"))
        handle.open("job-1")
        assert handle.capabilities is None

    def test_the_async_attach_reads_it_too(self, attached) -> None:
        import asyncio

        attached.tools = [_Tool("capabilities", MANIFEST)]
        handle = ServerHandle("analysis", MCPServerConfig(enabled=True, command="x"))

        async def _go():
            await handle.aopen("job-2")
            return handle.capabilities

        manifest = asyncio.run(_go())
        assert manifest is not None and "document_info" in manifest.tools


class _Registry:
    def __init__(self, manifests: dict[str, ServerCapabilities | None]) -> None:
        self.manifests = manifests
        self.degradation_reasons: list[str] = []

    def get(self, name: str) -> Any:
        if name not in self.manifests:
            raise KeyError(name)
        handle = MagicMock()
        handle.capabilities = self.manifests[name]
        return handle


class _Container:
    def __init__(self, registry: _Registry | None) -> None:
        self._server_registry_cache = registry


def _bound(name: str, server: str) -> StructuredTool:
    tool = StructuredTool.from_function(func=lambda: name, name=name, description=name)
    tool.metadata = {"maljan_server": server}
    return tool


class TestAStageRecordsWhatItCannotHave:
    def test_a_bound_tool_the_manifest_marks_unavailable_is_a_reason_once(self) -> None:
        manifest = ServerCapabilities.from_payload("analysis", MANIFEST)
        registry = _Registry({"analysis": manifest})
        agent = MagicMock()
        agent.tools = [_bound("hashes", "analysis"), _bound("document_info", "analysis")]
        noted = note_unavailable_tools(_Container(registry), agent)
        assert noted == [
            "server.analysis.document_info_unavailable(olefile is not installed); "
            "uv sync --extra tools"
        ]
        # A second agent binding the same tool adds nothing to the run's list.
        note_unavailable_tools(_Container(registry), agent)
        assert registry.degradation_reasons == noted

    def test_a_tool_the_collision_rule_renamed_is_still_found(self) -> None:
        """Two servers offering one name: the second is bound as ``<server>__<tool>``.

        The manifest is keyed by the name the server itself uses, so without
        the prefix coming off the renamed tool's cell is never found and its
        stage-start record is lost with nothing saying so.
        """
        manifest = ServerCapabilities.from_payload("analysis", MANIFEST)
        registry = _Registry({"analysis": manifest})
        agent = MagicMock()
        agent.tools = [_bound("analysis__document_info", "analysis")]

        noted = note_unavailable_tools(_Container(registry), agent)

        assert noted == [
            "server.analysis.document_info_unavailable(olefile is not installed); "
            "uv sync --extra tools"
        ]

    def test_a_parser_the_sample_s_format_never_needs_is_not_a_reason(self) -> None:
        """A missing document parser on a PE sample lost this run nothing."""
        manifest = ServerCapabilities.from_payload("analysis", MANIFEST)
        registry = _Registry({"analysis": manifest})
        agent = MagicMock()
        agent.tools = [_bound("document_info", "analysis")]

        assert note_unavailable_tools(_Container(registry), agent, "pe") == []
        assert registry.degradation_reasons == []
        assert note_unavailable_tools(_Container(registry), agent, "ole2") != []

    def test_a_sample_of_unknown_format_keeps_the_reason(self) -> None:
        manifest = ServerCapabilities.from_payload("analysis", MANIFEST)
        registry = _Registry({"analysis": manifest})
        agent = MagicMock()
        agent.tools = [_bound("document_info", "analysis")]

        assert note_unavailable_tools(_Container(registry), agent, "unknown") != []

    def test_a_tool_the_agent_does_not_bind_is_not_its_reason(self) -> None:
        manifest = ServerCapabilities.from_payload("analysis", MANIFEST)
        registry = _Registry({"analysis": manifest})
        agent = MagicMock()
        agent.tools = [_bound("hashes", "analysis")]
        assert note_unavailable_tools(_Container(registry), agent) == []

    def test_no_registry_or_no_manifest_records_nothing(self) -> None:
        agent = MagicMock()
        agent.tools = [_bound("document_info", "analysis")]
        assert note_unavailable_tools(_Container(None), agent) == []
        assert note_unavailable_tools(_Container(_Registry({"analysis": None})), agent) == []
        assert note_unavailable_tools(_Container(_Registry({})), agent) == []

    def test_an_unavailable_tool_does_not_degrade_the_run_by_itself(self) -> None:
        reason = "server.analysis.document_info_unavailable(olefile is not installed); install"
        assert run_is_degraded([reason]) is False
        assert run_is_degraded([reason, "mcp server 'analysis' unavailable"]) is True
        assert run_is_degraded(["triage.identify_file_failed"]) is True


class TestAServerReasonMeetsTheSample:
    """The registry records a withheld tool before any sample is known."""

    MACHO = (
        "server.analysis.macho_info_unavailable(macholib is not installed); uv sync --extra tools"
    )

    def test_a_mach_o_parser_is_nothing_to_a_pe_sample(self) -> None:
        from maljan.pipeline.nodes import reason_applies_to_format

        assert reason_applies_to_format(self.MACHO, "pe") is False
        assert reason_applies_to_format(self.MACHO, "mach-o") is True

    def test_every_other_reason_is_kept(self) -> None:
        from maljan.pipeline.nodes import reason_applies_to_format

        assert reason_applies_to_format("server 'vt' could not be attached", "pe") is True
        assert reason_applies_to_format(self.MACHO, "") is True
