"""One sha256 says what a run was set up with, and its parts say what changed.

The fingerprint hashes the system prompts as sent, the tool declarations, the
names and versions the tool servers gave for themselves, and the masked
settings; each component and each part is kept, so two fingerprints that
differ name the agent, the server or the settings section that did. A secret
never enters it: only whether it is set does.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import StructuredTool
from pydantic import SecretStr
from tests.credential_shapes import prefixed_key

from maljan.agents.base_agent import BudgetMeter
from maljan.agents.mcp_client import served_info
from maljan.analysis.efficiency import efficiency_lines, fingerprint_record
from maljan.core.config import Settings
from maljan.core.input_meter import InputMeter, digest, tool_digests

SECRET = prefixed_key("sk-")


def _tool(description: str) -> Any:
    def pe_info(path: str) -> str:
        return path

    return StructuredTool.from_function(func=pe_info, name="pe_info", description=description)


class _Agent(BudgetMeter):
    def __init__(self, name: str, container: Any) -> None:
        self.name = name
        self.pipeline_stage = "analysis"
        self.logger = SimpleNamespace(debug=lambda *a, **k: None)
        self._container = container


def _container(
    *,
    prompt: str = "You are the static analyst.",
    description: str = "Reads a PE header.",
    version: str = "1.0",
    settings: Settings | None = None,
) -> Any:
    meter = InputMeter()
    container = SimpleNamespace(
        input_meter=meter,
        server_versions=lambda: {"analysis": {"name": "analysis-mcp", "version": version}},
        config=settings or Settings(),
    )
    agent = _Agent("static", container)
    agent._note_request([SystemMessage(content=prompt), HumanMessage(content="go")], kind="x")
    agent._note_tools([_tool(description)])
    _Agent("judge", container)._note_request([SystemMessage(content="judge")], kind="verdict")
    return container


def _changed(a: dict, b: dict) -> set[str]:
    return {name for name in a["components"] if a["components"][name] != b["components"][name]}


def test_the_meter_keeps_digests_never_text() -> None:
    container = _container()
    meter = container.input_meter

    assert meter.prompt_digests() == {
        "judge": [digest("judge")],
        "static": [digest("You are the static analyst.")],
    }
    assert meter.tool_digests() == {"static": tool_digests([_tool("Reads a PE header.")])}
    assert "You are the static analyst." not in repr(fingerprint_record(container))


def test_the_same_setup_gives_the_same_fingerprint() -> None:
    first, second = fingerprint_record(_container()), fingerprint_record(_container())

    assert first is not None and second is not None
    assert first == second
    assert len(first["sha256"]) == 64
    assert "unread" not in first


def test_a_changed_prompt_is_named_by_its_agent() -> None:
    before = fingerprint_record(_container())
    after = fingerprint_record(_container(prompt="You are the static analyst. Be brief."))
    assert before is not None and after is not None

    assert before["sha256"] != after["sha256"]
    assert _changed(before, after) == {"prompts"}
    assert before["parts"]["prompts"]["judge"] == after["parts"]["prompts"]["judge"]
    assert before["parts"]["prompts"]["static"] != after["parts"]["prompts"]["static"]


def test_a_changed_declaration_and_a_new_server_version_are_named() -> None:
    before = fingerprint_record(_container())
    tools = fingerprint_record(_container(description="Reads the PE header."))
    server = fingerprint_record(_container(version="1.1"))
    assert before is not None and tools is not None and server is not None

    assert _changed(before, tools) == {"tools"}
    assert _changed(before, server) == {"servers"}
    assert server["parts"]["servers"] == {"analysis": {"name": "analysis-mcp", "version": "1.1"}}


def test_a_secret_enters_only_as_set_or_unset() -> None:
    unset = Settings()
    unset.llm.openai.api_key = None
    first = unset.model_copy(deep=True)
    first.llm.openai.api_key = SecretStr(SECRET)
    second = unset.model_copy(deep=True)
    second.llm.openai.api_key = SecretStr(SECRET[::-1])

    a = fingerprint_record(_container(settings=first))
    b = fingerprint_record(_container(settings=second))
    c = fingerprint_record(_container(settings=unset))
    assert a is not None and b is not None and c is not None

    assert "unread" not in a
    assert a == b
    assert SECRET not in repr(a)
    assert _changed(a, c) == {"settings"}
    assert {
        k for k in a["parts"]["settings"] if a["parts"]["settings"][k] != c["parts"]["settings"][k]
    } == {"llm"}


def test_a_changed_setting_is_named_by_its_section() -> None:
    changed = Settings()
    changed.reporting.evidence_budget_bytes = 12345
    before = fingerprint_record(_container())
    after = fingerprint_record(_container(settings=changed))
    assert before is not None and after is not None

    differ = {
        name
        for name, value in before["parts"]["settings"].items()
        if after["parts"]["settings"].get(name) != value
    }
    assert differ == {"reporting"}


def test_what_the_run_could_not_read_is_named_and_nothing_outside_a_run() -> None:
    record = fingerprint_record(SimpleNamespace(input_meter=InputMeter()))
    assert record is not None
    assert record["unread"] == ["settings"]
    assert fingerprint_record(SimpleNamespace()) is None


def test_the_server_info_is_read_as_the_server_gave_it() -> None:
    assert served_info(SimpleNamespace(name=" analysis ", version="2.0")) == {
        "name": "analysis",
        "version": "2.0",
    }
    assert served_info(SimpleNamespace(name="x", version=None)) == {"name": "x"}
    assert served_info(None) == {}


def test_the_registry_lists_each_attached_server_once() -> None:
    from maljan.providers.servers import ServerRegistry

    settings = Settings()
    registry = ServerRegistry(settings)
    handles = list(registry._handles.values())
    assert handles, "the shipped settings declare tool servers"
    handles[0].server_info = {"name": "n", "version": "v"}
    handles[0].attached_once = True

    assert registry.server_versions() == {handles[0].name: {"name": "n", "version": "v"}}


def test_the_report_lines_give_the_hash_and_the_servers() -> None:
    record = fingerprint_record(_container())
    assert record is not None
    lines = efficiency_lines({"v": 1, "fingerprint": record})

    assert lines[0].startswith(f"Run fingerprint: `{record['sha256']}` (sha256 of its components:")
    assert lines[1] == (
        "Tool servers as they gave themselves at attach: `analysis` as `analysis-mcp` version "
        "`1.0`. A tool's own version is not reported over MCP."
    )
