"""One sha256 says how a job was set up, never what its run sent, and its parts say what changed.

The fingerprint hashes every system prompt the platform can send for the job
(read from where each is built), the tool definitions each agent was resolved
with, the servers attached by then, and the masked settings. A retry, a
revision, a cleared tool answer, the mediator's fast path and the sample do
not move it; editing any built-in prompt, a tool definition, a server version
or a setting does, and names the part. A secret enters only as set or unset.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import StructuredTool
from pydantic import SecretStr
from tests.credential_shapes import prefixed_key

from maljan.agents.composition import ResolvedAgent, static_provider_id_for
from maljan.agents.mcp_client import served_info
from maljan.analysis.efficiency import efficiency_lines, fingerprint_record
from maljan.analysis.setup_prompts import PROMPT_CONSTANTS, PROMPT_SITES, covered_names
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.core.input_meter import request_parts

SRC = Path(__file__).resolve().parents[3] / "src" / "maljan"
SECRET = prefixed_key("sk-")


def _tool(description: str = "Reads a PE header.") -> Any:
    def pe_info(path: str) -> str:
        return path

    return StructuredTool.from_function(func=pe_info, name="pe_info", description=description)


def _container(
    *,
    settings: Settings | None = None,
    description: str = "Reads a PE header.",
    version: str = "1.0",
    sha: str = "ab" * 32,
    path: str = "/samples/job-1/invoice.exe",
    job: str = "job-0001",
    file_format: tuple[str, str] = ("pe", "windows"),
    judge_description: str = "Looks a hash up.",
) -> ServiceContainer:
    config = settings or Settings()
    container = ServiceContainer(config=config, mock=True, job_id=job)
    container.sample_sha256 = sha
    container.sample_path = path
    container.sample_format = file_format  # type: ignore[attr-defined]
    for key in ("static", "dynamic", "network"):
        container._note_the_setup(
            key,
            ResolvedAgent(
                key=key,
                role=key,
                prompt="",
                tools=[_tool(description)] if key == "static" else [],
                static_provider_id=static_provider_id_for(config, key),
                llm=None,
            ),
        )
    for key in ("judge", "mediator"):
        container.note_role_setup(key, [_tool(judge_description)], set())
    container._setup_servers = {"analysis": {"name": "analysis-mcp", "version": version}}
    return container


def _record(container: Any) -> dict[str, Any]:
    record = fingerprint_record(container)
    assert record is not None
    return record


def _changed(a: dict, b: dict, part: str = "") -> set[str]:
    if part:
        return {k for k in a["parts"][part] if a["parts"][part][k] != b["parts"][part].get(k)}
    return {name for name in a["components"] if a["components"][name] != b["components"][name]}


def test_the_same_setup_on_two_samples_gives_one_fingerprint() -> None:
    first = _record(_container())
    second = _record(
        _container(
            sha="cd" * 32, path="/samples/job-2/a.exe", job="job-0002", file_format=("elf", "linux")
        )
    )

    assert first == second
    assert len(first["sha256"]) == 64
    assert "unread" not in first


def test_what_a_run_sends_does_not_move_it() -> None:
    """A retry, a revision round, a cleared answer and the fast path send; none is setup."""
    container = _container()
    before = _record(container)
    meter = container.input_meter
    loop = object()
    for system in ("tool loop prompt", "tools-free retry prompt", "revision prompt"):
        meter.request("static", request_parts([SystemMessage(content=system)]), loop=loop)
    meter.request("static", request_parts([HumanMessage(content="retry")]), kind="validation retry")
    meter.close("static", loop, [{"input_tokens": 3}])
    # A server the judge attached on its own, after the agents were resolved.
    container._server_registry_cache = SimpleNamespace(  # type: ignore[assignment]
        server_versions=lambda: {"threatintel": {"name": "ti", "version": "9"}}
    )

    assert _record(container) == before


def test_a_server_attached_after_resolution_is_not_setup() -> None:
    container = _container()
    container._setup_servers = {}
    container._server_registry_cache = SimpleNamespace(  # type: ignore[assignment]
        server_versions=lambda: {"analysis": {"name": "analysis-mcp", "version": "1.0"}}
    )
    container._note_the_setup("static", container._resolved_agents["static"])
    container._server_registry_cache = SimpleNamespace(  # type: ignore[assignment]
        server_versions=lambda: {
            "analysis": {"name": "analysis-mcp", "version": "1.0"},
            "threatintel": {"name": "ti", "version": "9"},
        }
    )

    assert container.setup_server_versions() == {
        "analysis": {"name": "analysis-mcp", "version": "1.0"}
    }


def _edited(value: Any) -> Any:
    if isinstance(value, str):
        return value + " Edited."
    first = sorted(value)[0]
    return {**value, first: str(value[first]) + " Edited."}


@pytest.mark.parametrize(
    ("name", "module", "attr"),
    [
        (name, module, attr)
        for name, sources in PROMPT_CONSTANTS.items()
        for module, attr in sources
    ],
)
def test_editing_any_built_in_prompt_moves_it(
    name: str, module: str, attr: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = _record(_container())
    owner = importlib.import_module(module)
    monkeypatch.setattr(owner, attr, _edited(getattr(owner, attr)))
    after = _record(_container())

    assert _changed(before, after) == {"prompts"}
    assert name in _changed(before, after, "prompts")


def test_editing_an_analyst_s_built_in_prompt_moves_its_part(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.agents import static_analyst

    before = _record(_container())
    monkeypatch.setattr(static_analyst, "_ISR_HEAD", static_analyst._ISR_HEAD + " Edited.")
    after = _record(_container())

    assert _changed(before, after, "prompts") == {"analyst:static", "revision:static"}


def _system_prompt_sites() -> set[str]:
    """Every function in the source that builds a system message, as ``module:qualname``."""
    found: set[str] = set()
    for path in SRC.rglob("*.py"):
        module = ".".join(path.relative_to(SRC.parent).with_suffix("").parts)

        def walk(
            node: ast.AST, stack: list[str], parent: ast.AST | None, module: str = module
        ) -> None:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                stack = [*stack, node.name]
            hit = False
            if isinstance(node, ast.Call):
                func = node.func
                name = (
                    func.id
                    if isinstance(func, ast.Name)
                    else func.attr
                    if isinstance(func, ast.Attribute)
                    else ""
                )
                hit = name == "SystemMessage"
            if isinstance(node, ast.Tuple) and not isinstance(parent, ast.Compare):
                elts = node.elts
                hit = (
                    len(elts) == 2
                    and isinstance(elts[0], ast.Constant)
                    and elts[0].value == "system"
                    and not (isinstance(elts[1], ast.Constant) and elts[1].value == "human")
                )
            if hit:
                found.add(f"{module}:{'.'.join(stack) or '<module>'}")
            for child in ast.iter_child_nodes(node):
                walk(child, stack, node)

        walk(ast.parse(path.read_text(encoding="utf-8")), [], None)
    return found


def test_every_place_that_builds_a_system_prompt_is_in_the_fingerprint() -> None:
    sites = _system_prompt_sites()
    missing = sorted(sites - set(PROMPT_SITES))
    assert not missing, f"a system prompt the fingerprint does not name: {missing}"
    stale = sorted(set(PROMPT_SITES) - sites)
    assert not stale, f"named sites that build no system prompt any more: {stale}"
    hashed = covered_names(_record(_container())["parts"]["prompts"])
    named = {name for name in PROMPT_SITES.values() if name is not None}
    assert named <= hashed, f"named but not hashed: {sorted(named - hashed)}"


def test_a_changed_tool_definition_and_a_new_server_version_are_named() -> None:
    before = _record(_container())
    tools = _record(_container(description="Reads the PE header."))
    server = _record(_container(version="1.1"))

    assert _changed(before, tools) == {"tools"}
    assert _changed(before, tools, "tools") == {"static"}
    assert _changed(before, server) == {"servers"}


def test_a_secret_enters_only_as_set_or_unset() -> None:
    unset = Settings()
    unset.llm.openai.api_key = None
    first = unset.model_copy(deep=True)
    first.llm.openai.api_key = SecretStr(SECRET)
    second = unset.model_copy(deep=True)
    second.llm.openai.api_key = SecretStr(SECRET[::-1])

    a = _record(_container(settings=first))
    b = _record(_container(settings=second))
    c = _record(_container(settings=unset))

    assert a == b
    assert SECRET not in repr(a)
    assert _changed(a, c) == {"settings"}
    assert _changed(a, c, "settings") == {"llm"}


def test_a_changed_setting_is_named_by_its_section() -> None:
    changed = Settings()
    changed.reporting.evidence_budget_bytes = 12345

    assert _changed(_record(_container()), _record(_container(settings=changed)), "settings") == {
        "reporting"
    }


def test_outside_a_job_there_is_none() -> None:
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

    registry = ServerRegistry(Settings())
    handles = list(registry._handles.values())
    assert handles, "the shipped settings declare tool servers"
    handles[0].server_info = {"name": "n", "version": "v"}
    handles[0].attached_once = True

    assert registry.server_versions() == {handles[0].name: {"name": "n", "version": "v"}}


def test_the_report_lines_give_the_hash_and_the_servers() -> None:
    record = _record(_container())
    lines = efficiency_lines({"v": 2, "fingerprint": record})

    assert lines[0].startswith(f"Run fingerprint: `{record['sha256']}` (sha256 of its components:")
    assert "tool definitions as bound" in lines[0]
    assert lines[-1] == (
        "Tool servers as they gave themselves at attach: `analysis` as `analysis-mcp` version "
        "`1.0`. A tool's own version is not reported over MCP."
    )


def _on_host(root: str) -> Settings:
    settings = Settings()
    name = sorted(settings.mcp.servers)[0]
    server = settings.mcp.servers[name]
    server.command = f"{root}/.venv/bin/python"
    server.args = ["-m", "maljan.servers.analysis", "--root", f"{root}/data/samples"]
    server.cwd = f"{root}/services/analysis"
    return settings


def test_the_same_setup_on_two_hosts_hashes_equal() -> None:
    from maljan.analysis.efficiency import _settings_sections

    a = _settings_sections(_on_host("/home/one/repo"), [("/home/one/repo", "<checkout>")])
    b = _settings_sections(_on_host("/srv/two/wt-7"), [("/srv/two/wt-7", "<checkout>")])
    unlike = _on_host("/srv/two/wt-7")
    unlike.mcp.servers[sorted(unlike.mcp.servers)[0]].args.append("--verbose")
    c = _settings_sections(unlike, [("/srv/two/wt-7", "<checkout>")])

    assert a == b
    assert a["mcp"] != c["mcp"]


def test_a_host_path_is_replaced_only_as_a_whole_path() -> None:
    from maljan.analysis.efficiency import _without_host

    host = [("/home/one/repo", "<checkout>")]
    assert _without_host(
        ["/home/one/repo/bin", "/home/one/repo2/bin", "x=/home/one/repo"], host
    ) == [
        "<checkout>/bin",
        "/home/one/repo2/bin",
        "x=<checkout>",
    ]


def test_a_sample_whose_name_is_an_ordinary_word_changes_nothing() -> None:
    assert _record(_container(path="/samples/sample")) == _record(
        _container(path="/samples/main.exe")
    )


def test_editing_a_sentence_a_builder_writes_moves_its_part(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.agents import base_agent, judge_agent, prompt_fragments
    from maljan.reporting import narrative_agent

    before = _record(_container())
    edits = [
        (narrative_agent, "rule_pointer", lambda report=None: "a reworded pointer", "narrative"),
        (judge_agent, "MEDIATOR_TI_TOOLS", "Reworded.\n", "mediator"),
        (base_agent, "_REVISION_ISR_FRAMING", "Reworded.", "revision:static"),
        (prompt_fragments, "_ARCHIVE_FRAGMENT", "Reworded.", "format fragments"),
    ]
    for owner, attr, value, part in edits:
        with monkeypatch.context() as patch:
            patch.setattr(owner, attr, value)
            assert part in _changed(before, _record(_container()), "prompts"), attr


def test_the_judge_s_tools_are_in_it() -> None:
    before = _record(_container())
    after = _record(_container(judge_description="Looks a hash up, reworded."))

    assert {"judge", "mediator"} <= set(before["parts"]["tools"])
    assert _changed(before, after, "tools") == {"judge", "mediator"}


def test_an_agent_reached_only_by_delegation_is_named_and_never_hashed() -> None:
    from maljan.core.config import AgentDefinition

    settings = Settings()
    settings.agents.definitions["helper"] = AgentDefinition(role="generic", prompt="Help.")
    container = _container(settings=settings)
    before = _record(container)
    container._note_the_setup(
        "helper",
        ResolvedAgent(
            key="helper",
            role="generic",
            prompt="Help.",
            tools=[_tool()],
            static_provider_id="",
            llm=None,
        ),
    )

    assert "helper" in before["not_resolved"]
    assert "reporter" not in before["not_resolved"]
    assert _record(container) == before
    lines = efficiency_lines({"v": 2, "fingerprint": before})
    assert any(
        "reached only when an agent delegates" in line and "`helper`" in line for line in lines
    )


def test_an_agent_not_set_up_is_named() -> None:
    container = _container()
    del container._setup_tools["judge"]

    assert "judge (not set up)" in _record(container)["unread"]


def test_the_interpreter_s_own_installation_stays_as_written() -> None:
    from maljan.analysis.efficiency import _without_host, host_paths

    assert _without_host("/usr/bin/python3", host_paths()) == "/usr/bin/python3"
    assert all(mark != "<interpreter>" for _path, mark in host_paths())
