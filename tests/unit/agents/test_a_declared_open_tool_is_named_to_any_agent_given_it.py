"""A server's declared open tool is named to any agent given it, as the static role is told.

A declared ``sample_open`` only deduplicated repeat opens: a generic agent
bound to the server got the same help as with nothing declared, and a model
that never opened the sample read nothing. The server now marks its offered
open tool with its declaration, and an agent offered it is told, on the head
chunk, to open the sample with it first. An agent whose provider tools open
the sample before the loop is not told twice. A probe proposes ``sample_open``
when one tool takes only a path and others share the name of what it opened.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from langchain_core.tools import StructuredTool

from maljan.agents.composition import ResolvedAgent
from maljan.agents.configurable_analyst import ConfigurableAnalyst
from maljan.agents.prompt_fragments import PROVIDER_FAMILY, stamp_source
from maljan.core.declaration_proposals import propose, sample_open_in
from maljan.providers.sample_open import (
    OPEN_METADATA_KEY,
    declared_open,
    load_line,
    mark_open_tool,
)

PATH = "/data/samples/.work/x.exe"
HEAD_CHUNK = json.dumps({"analysis_file_path": PATH})
SPEC = SimpleNamespace(open_tool="import_it", path_argument="binary_path")


def _tool(name: str) -> StructuredTool:
    """A tool of an MCP server, as the registry offers it (its server key in metadata)."""
    return StructuredTool.from_function(
        func=lambda: name, name=name, description=name, metadata={"maljan_server": "programs"}
    )


def _generic(tools: list[Any]) -> ConfigurableAnalyst:
    resolved = ResolvedAgent(
        key="reverser_x",
        role="generic",
        prompt="reverse it",
        tools=tools,
        static_provider_id="acme",
        llm=None,
    )
    analyst = ConfigurableAnalyst("reverser_x", resolved, llm=None)  # type: ignore[arg-type]
    analyst._analysis_file_path = PATH
    return analyst


def test_the_open_tool_is_marked_on_a_copy() -> None:
    raw = [_tool("import_it"), _tool("list_it")]
    marked = mark_open_tool(raw, SPEC)
    assert marked[0].metadata[OPEN_METADATA_KEY] == {
        "open_tool": "import_it",
        "path_argument": "binary_path",
    }
    assert marked[0].metadata["maljan_server"] == "programs"
    assert OPEN_METADATA_KEY not in raw[0].metadata
    assert marked[1] is raw[1]
    assert mark_open_tool(raw, None) == raw
    held = declared_open(marked)
    assert (held.open_tool, held.path_argument) == ("import_it", "binary_path")
    assert declared_open(raw) is None


def test_an_agent_given_the_open_tool_is_told_to_open_first() -> None:
    tools = mark_open_tool([_tool("import_it"), _tool("list_it")], SPEC)
    analyst = _generic(tools)
    assert analyst._load_hint(HEAD_CHUNK) == load_line("import_it", "binary_path", PATH)
    assert load_line("import_it", "binary_path", PATH).startswith(
        f'LOAD THIS BINARY FIRST: call ``import_it(binary_path="{PATH}")``.'
    )
    # A later chunk, with no path, is not told.
    assert analyst._load_hint(json.dumps({"chunk": 2})) == ""


def test_nothing_changes_without_a_declaration_or_with_a_pre_open() -> None:
    assert _generic([_tool("import_it")])._load_hint(HEAD_CHUNK) == ""
    own = StructuredTool.from_function(func=lambda: 0, name="import_it", description="i")
    provider = stamp_source(mark_open_tool([own], SPEC), PROVIDER_FAMILY)
    assert _generic(provider)._load_hint(HEAD_CHUNK) == ""


def _definition(name: str, *required: str, **annotations: Any) -> dict[str, Any]:
    props = {arg: {"type": "string"} for arg in required}
    out: dict[str, Any] = {
        "name": name,
        "description": name,
        "inputSchema": {"type": "object", "properties": props, "required": list(required)},
    }
    if annotations:
        out["annotations"] = annotations
    return out


PROGRAM_SERVER = [
    {
        **_definition("import_it", "binary_path"),
        "description": "Import a binary into the project from a file path.",
    },
    _definition("list_programs"),
    _definition("list_exports", "binary_name"),
    _definition("decompile", "binary_name", "name_or_address"),
    _definition("delete_it", "binary_name", destructiveHint=True),
]


def test_a_probe_proposes_the_open_tool_of_a_program_server() -> None:
    proposed = sample_open_in(PROGRAM_SERVER)
    assert proposed is not None and proposed.confidence == "low"
    assert proposed.value == {"open_tool": "import_it", "path_argument": "binary_path"}
    assert proposed.evidence[0] == "import_it takes only binary_path"
    assert propose(PROGRAM_SERVER)["server"]["sample_open"]["value"] == proposed.value


def test_no_open_tool_is_proposed_where_the_schemas_do_not_say_one() -> None:
    # An open whose other tools work on the file opened, taking no name.
    assert sample_open_in([_definition("open_file", "file_path"), _definition("functions")]) is None
    # Many tools that each read a path: none opens for the others.
    many = [_definition(f"read_{n}", "file_path") for n in range(3)]
    assert sample_open_in([*many, *PROGRAM_SERVER[2:4]]) is None
    # A place in code is no name of what was opened.
    places = [
        _definition("open_it", "path"),
        _definition("a", "address"),
        _definition("b", "address"),
    ]
    assert sample_open_in(places) is None
    assert "sample_open" not in propose(many)["server"]


def _with(opener: dict[str, Any]) -> list[dict[str, Any]]:
    """The program server with its open tool replaced by ``opener``."""
    return [opener, *PROGRAM_SERVER[1:]]


def _described(name: str, argument: str, description: str, **annotations: Any) -> dict[str, Any]:
    """A tool taking one argument, with its own description and annotations."""
    out = _definition(name, argument, **annotations)
    out["description"] = description
    return out


def test_a_tool_that_writes_deletes_exports_wipes_or_lists_is_never_the_open_tool() -> None:
    for opener in (
        _described("delete_file", "path", "Deletes the file at path."),
        _described("export_report", "output_path", "Writes the report to output_path."),
        _described("wipe", "file_path", "Wipes the file.", readOnlyHint=False),
        _described("list_directory", "path", "Lists the entries of a directory."),
        _described("open_it", "path", "Opens the file.", readOnlyHint=False),
        _described("load_it", "path", "Loads the file.", destructiveHint=True),
        _described("load_and_save", "path", "Loads the file and saves the project."),
        # Read-only, but nothing says it opens the file.
        _described("hash_file", "path", "Hashes the file.", readOnlyHint=True),
    ):
        assert sample_open_in(_with(opener)) is None, opener["name"]


def test_a_tool_that_loads_something_other_than_the_sample_is_never_the_open_tool() -> None:
    for opener in (
        _described("load_config", "path", "Loads the config file."),
        _described("analyze_and_patch", "path", "Analyzes then patches the file."),
        _described("import_settings", "file", "Imports settings from file."),
        _described("load_plugin", "path", "Loads a plugin."),
        _described("open_url", "path", "Opens the URL."),
        # A name word alone is no evidence, and neither is a program from a project.
        _described("open_file", "path", "Open a file."),
        _described("open_program", "path", "Open a program from the current project"),
        # Annotations that do not mark it read-only.
        _described("load_binary", "path", "Loads a binary for analysis.", title="Load"),
    ):
        assert sample_open_in(_with(opener)) is None, opener["name"]


def test_a_real_open_tool_is_still_proposed() -> None:
    # The descriptions the repository's tool fixtures and the validation
    # scenario's server carry.
    for opener, argument in (
        (
            _described(
                "import_binary", "binary_path", "Import a binary into the project from a file path."
            ),
            "binary_path",
        ),
        (
            _described(
                "open_file",
                "file_path",
                "Opens a binary file with radare2 for analysis <think>Call this tool before any "
                "other one. Use an absolute file_path</think>",
            ),
            "file_path",
        ),
        (
            _described(
                "load_program",
                "file",
                "[NAV] Load a binary file into the headless server for analysis",
            ),
            "file",
        ),
        (
            _described(
                "import_file",
                "file_path",
                "[IMPORT] Import a binary file from disk into the current project and open it.",
            ),
            "file_path",
        ),
        (_described("loadProgram", "file", "Reads it in.", readOnlyHint=True), "file"),
    ):
        proposed = sample_open_in(_with(opener))
        assert proposed is not None, opener["name"]
        assert proposed.value == {"open_tool": opener["name"], "path_argument": argument}


def test_the_real_tool_fixtures_name_only_their_open_tools() -> None:
    from pathlib import Path

    from maljan.core.declaration_proposals import _opens_read_only

    root = Path(__file__).resolve().parents[2] / "fixtures" / "tools"
    accepted = set()
    for name in ("reverser_ghidra_tool_definitions.json", "r2mcp_tool_definitions.json"):
        held = json.loads((root / name).read_text())
        for tool in held if isinstance(held, list) else held.get("tools", held):
            if _opens_read_only(tool["name"], tool, tool.get("annotations")):
                accepted.add(tool["name"])
    assert accepted == {"import_file", "load_program", "open_file"}


def _human_turn_of(analyst: ConfigurableAnalyst, call: Any) -> str:
    """The human turn ``call`` sends, the loop stopped before any model runs."""
    from maljan.agents.configurable_analyst import _Run

    sent: list[list[tuple[str, str]]] = []

    def _capture(messages: list[tuple[str, str]], what: str) -> _Run:
        sent.append(messages)
        return _Run(text="", degraded=True)

    analyst._run = _capture  # type: ignore[method-assign]
    call()
    return dict(sent[0])["human"]


def test_the_isr_analysis_names_the_open_tool_as_the_text_analysis_does() -> None:
    analyst = _generic(mark_open_tool([_tool("import_it"), _tool("list_it")], SPEC))
    human = _human_turn_of(analyst, lambda: analyst.analyze_isr(HEAD_CHUNK))
    assert load_line("import_it", "binary_path", PATH) in human


def test_a_delegated_task_names_the_open_tool_to_its_callee() -> None:
    from maljan.agents.delegation import _task_turn

    callee = _generic(mark_open_tool([_tool("import_it"), _tool("list_it")], SPEC))
    turn = _task_turn("lead", "list the exports", "", callee)
    assert load_line("import_it", "binary_path", PATH).rstrip() in turn
    # A callee offered no declared open tool is told the path alone.
    plain = _task_turn("lead", "list the exports", "", _generic([_tool("list_it")]))
    assert "LOAD THIS BINARY FIRST" not in plain
    assert PATH in plain


def test_a_built_in_callee_is_told_its_declared_open_tool() -> None:
    from unittest.mock import MagicMock

    from maljan.agents.delegation import _task_turn
    from maljan.agents.dynamic_analyst import DynamicAnalyst

    callee = DynamicAnalyst(llm=MagicMock(), name="dynamic")
    callee.tools = mark_open_tool([_tool("import_it"), _tool("list_it")], SPEC)
    callee._analysis_file_path = PATH
    assert load_line("import_it", "binary_path", PATH).rstrip() in _task_turn(
        "lead", "t", "", callee
    )
    callee.tools = [_tool("list_it")]
    assert "LOAD THIS BINARY FIRST" not in _task_turn("lead", "t", "", callee)
