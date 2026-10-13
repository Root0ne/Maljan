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
    _definition("import_it", "binary_path"),
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
