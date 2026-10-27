"""A ``null`` an optional, non-nullable argument was given is the argument left out.

In a recorded run a model sent Ghidra ``decompile_function`` ``{"address":
..., "program": null, "timeout": null}`` and ``list_imports`` ``{"limit":
null, "offset": null, ...}``, and every one of those calls was refused with
"Input should be a valid integer". At the tool boundary of every tool server
such a ``null`` is now dropped before validation, so the call is sent,
recorded and compared exactly as one that left the field out; a field that
admits ``null`` keeps it (an MCP transport then does not send it, and the
record says so), a required field given ``null`` is refused as before, and the
ledger entry and the start event name each such field by its path segments.

No server runs here: the Ghidra schemas are the recorded definitions
(``tests/fixtures/tools/reverser_ghidra_tool_definitions.json``), served once
in the shape ``/mcp/schema`` gives them and once as an MCP server's
``inputSchema``.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from langchain_core.tools import StructuredTool
from mcp.types import CallToolResult, TextContent
from pydantic import ValidationError, create_model

from maljan.agents.evidence_recorder import EvidenceRecorder, RepeatGuard, record_tools
from maljan.agents.mcp_client import MCPLangChainToolkit
from maljan.agents.null_arguments import (
    DROPPED_KEY,
    admits_null,
    drop_unset_nulls,
    rules_of,
    schema_rules,
)
from maljan.agents.tool_pinning import _pin_tool, _schema_without
from maljan.pipeline.events import TOOL_CALL_STARTED
from maljan.providers.static.ghidra.http_client import GhidraHTTPClient
from maljan.schemas.evidence import EvidenceCounter, LedgerEntry, build_entry

DEFINITIONS = (
    Path(__file__).parents[2] / "fixtures" / "tools" / "reverser_ghidra_tool_definitions.json"
)
ADDRESS = "0x180001000"


def _recorded_schema(tool: str) -> dict[str, Any]:
    for definition in json.loads(DEFINITIONS.read_text(encoding="utf-8")):
        if definition["name"] == tool:
            return definition["input_schema"]
    raise LookupError(tool)


class _Sink:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append((event_type, data))

    def started(self) -> list[dict[str, Any]]:
        return [data for kind, data in self.events if kind == TOOL_CALL_STARTED]


def _recorder() -> tuple[EvidenceRecorder, _Sink]:
    sink = _Sink()
    return EvidenceRecorder("static", counter=EvidenceCounter(), sink=sink), sink


def _call(tool: Any, args: dict[str, Any]) -> str:
    return str(asyncio.run(tool.ainvoke(args)))


# -- Ghidra over its REST API ---------------------------------------------------


class _Ghidra:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(200, text='{"items": []}')


def _rest_entry(tool: str) -> dict[str, Any]:
    """The recorded definition of ``tool`` in the shape ``/mcp/schema`` serves it."""
    schema = _recorded_schema(tool)
    required = set(schema.get("required") or ())
    return {
        "path": f"/{tool}",
        "method": "GET",
        "description": f"recorded {tool}",
        "params": [
            {"name": name, "type": field["type"], "required": name in required, "source": "query"}
            for name, field in schema["properties"].items()
        ],
    }


def _ghidra_tool(tool: str) -> tuple[Any, _Ghidra, EvidenceRecorder, _Sink]:
    ghidra = _Ghidra()
    client = GhidraHTTPClient(base_url="http://ghidra.invalid")
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(ghidra.handler))
    recorder, sink = _recorder()
    (recorded,) = record_tools([client._create_langchain_tool(_rest_entry(tool))], recorder)
    return recorded, ghidra, recorder, sink


class TestANullOptionalIntIsLeftOut:
    def test_list_imports_with_null_paging_runs_and_sends_none_of_them(self) -> None:
        tool, ghidra, recorder, _ = _ghidra_tool("list_imports")

        answer = _call(tool, {"limit": None, "offset": None, "program": None})

        assert "ValidationError" not in answer
        assert len(ghidra.requests) == 1
        assert dict(ghidra.requests[0].url.params) == {}
        (entry,) = recorder.entries
        assert entry.ok
        assert entry.args_nulls_dropped == [["limit"], ["offset"], ["program"]]

    def test_decompile_function_keeps_the_address_and_leaves_out_the_nulls(self) -> None:
        tool, ghidra, recorder, _ = _ghidra_tool("decompile_function")

        _call(tool, {"address": ADDRESS, "program": None, "timeout": None})

        assert dict(ghidra.requests[0].url.params) == {"address": ADDRESS}
        assert recorder.entries[0].ok

    def test_a_dropped_null_is_recorded_as_the_field_left_out(self) -> None:
        dropped_tool, dropped_ghidra, dropped, _ = _ghidra_tool("get_xrefs_to")
        omitted_tool, omitted_ghidra, omitted, _ = _ghidra_tool("get_xrefs_to")

        _call(dropped_tool, {"address": ADDRESS, "limit": None, "offset": 5})
        _call(omitted_tool, {"address": ADDRESS, "offset": 5})

        assert str(dropped_ghidra.requests[0].url) == str(omitted_ghidra.requests[0].url)
        assert dropped.entries[0].args == omitted.entries[0].args
        assert dropped.entries[0].args_nulls_dropped == [["limit"]]
        assert omitted.entries[0].args_nulls_dropped == []

    def test_a_call_with_no_null_is_sent_and_recorded_as_before(self) -> None:
        tool, ghidra, recorder, sink = _ghidra_tool("get_xrefs_to")

        _call(tool, {"address": ADDRESS, "limit": 50})

        assert dict(ghidra.requests[0].url.params) == {"address": ADDRESS, "limit": "50"}
        (entry,) = recorder.entries
        assert entry.args == {"address": ADDRESS, "limit": 50, "offset": None, "program": None}
        dumped = entry.model_dump()
        assert "args_nulls_dropped" not in dumped
        assert "args_nulls_withheld" not in dumped
        (started,) = sink.started()
        assert "nulls_dropped" not in started
        assert "nulls_withheld" not in started

    def test_the_schema_the_model_is_offered_is_the_recorded_one(self) -> None:
        for name in ("decompile_function", "get_xrefs_to", "list_exports", "list_imports"):
            tool, _, _, _ = _ghidra_tool(name)
            offered = tool.tool_call_schema.model_json_schema()
            offered.pop("description", None)
            assert _untitled(offered) == _recorded_schema(name)


class TestARequiredFieldGivenNullIsRefused:
    def test_ghidra_refuses_a_null_address_with_the_existing_message(self) -> None:
        tool, ghidra, _, _ = _ghidra_tool("decompile_function")

        with pytest.raises(ValidationError) as refused:
            _call(tool, {"address": None, "program": None, "timeout": None})

        assert ghidra.requests == []
        errors = refused.value.errors(include_url=False)
        assert [(e["loc"], e["type"]) for e in errors] == [(("address",), "string_type")]
        assert "Input should be a valid string" in str(refused.value)

    def test_an_mcp_server_refuses_a_null_required_field(self) -> None:
        tool, session, _, _ = _mcp_tool(_recorded_schema("decompile_function"))

        with pytest.raises(ValidationError, match="Input should be a valid string"):
            _call(tool, {"address": None})

        assert session.calls == []


# -- the same schemas offered by an MCP server -----------------------------------


class _Session:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def call_tool(self, name: str, arguments: dict[str, Any], **_: Any) -> Any:
        self.calls.append(arguments)
        return CallToolResult(content=[TextContent(type="text", text="ok")], isError=False)


def _mcp_tool(schema: dict[str, Any]) -> tuple[Any, _Session, EvidenceRecorder, _Sink]:
    session = _Session()
    toolkit = MCPLangChainToolkit(None)
    toolkit.session = session  # type: ignore[assignment]
    attached = toolkit._create_langchain_tool(
        SimpleNamespace(name="probe", description="probe", inputSchema=schema, annotations=None)
    )
    recorder, sink = _recorder()
    (recorded,) = record_tools([attached], recorder, RepeatGuard())
    return recorded, session, recorder, sink


NESTED = {
    "type": "object",
    "properties": {
        "address": {"type": "string"},
        "depth": {"anyOf": [{"type": "integer"}, {"type": "null"}]},
        "options": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "limit": {"type": "integer", "default": 10},
                "mode": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                "inner": {"type": "object", "properties": {"step": {"type": "integer"}}},
            },
            "required": ["name"],
        },
    },
    "required": ["address"],
}

# A token typed like the CAPE server's: a string with a declared default.
TOKENED = {
    "type": "object",
    "properties": {"task_id": {"type": "integer"}, "token": {"type": "string", "default": ""}},
    "required": ["task_id"],
}

# Nested models as a pydantic-built server emits them: behind ``$ref`` into
# ``$defs``, an optional one as ``anyOf`` with ``null``, and one that holds itself.
REFERENCED = {
    "type": "object",
    "$defs": {
        "Window": {
            "type": "object",
            "properties": {
                "start": {"type": "integer"},
                "size": {"type": "integer", "default": 16},
                "label": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None},
            },
            "required": ["start"],
        },
        "Node": {
            "type": "object",
            "properties": {
                "weight": {"type": "integer", "default": 1},
                "child": {"anyOf": [{"$ref": "#/$defs/Node"}, {"type": "null"}], "default": None},
            },
        },
    },
    "properties": {
        "window": {"$ref": "#/$defs/Window"},
        "spare": {"anyOf": [{"$ref": "#/$defs/Window"}, {"type": "null"}], "default": None},
        "tree": {"$ref": "#/$defs/Node"},
    },
    "required": ["window"],
}


class TestOverAnMcpServer:
    def test_null_optional_ints_are_left_out_of_the_call(self) -> None:
        tool, session, recorder, _ = _mcp_tool(_recorded_schema("decompile_function"))

        _call(tool, {"address": ADDRESS, "program": None, "timeout": None})

        assert session.calls == [{"address": ADDRESS}]
        assert recorder.entries[0].args_nulls_dropped == [["program"], ["timeout"]]

    def test_a_dropped_null_is_sent_recorded_and_keyed_as_the_field_left_out(self) -> None:
        dropped_tool, dropped_session, dropped, _ = _mcp_tool(TOKENED)
        omitted_tool, omitted_session, omitted, _ = _mcp_tool(TOKENED)

        _call(dropped_tool, {"task_id": 7, "token": None})
        _call(omitted_tool, {"task_id": 7})

        assert dropped_session.calls == omitted_session.calls == [{"task_id": 7, "token": ""}]
        assert dropped.entries[0].args == omitted.entries[0].args == {"task_id": 7, "token": ""}
        assert dropped.entries[0].args_nulls_dropped == [["token"]]

    def test_an_admitted_top_level_null_is_not_sent_and_the_record_says_so(self) -> None:
        tool, session, recorder, sink = _mcp_tool(NESTED)
        omitted_tool, omitted_session, omitted, _ = _mcp_tool(NESTED)

        _call(tool, {"address": ADDRESS, "depth": None})
        _call(omitted_tool, {"address": ADDRESS})

        # Never sent, and recorded as its default: as the call that left it out.
        assert session.calls == omitted_session.calls == [{"address": ADDRESS}]
        (entry,) = recorder.entries
        assert entry.args == omitted.entries[0].args
        assert entry.args_nulls_withheld == [["depth"]]
        assert entry.args_nulls_dropped == []
        assert omitted.entries[0].args_nulls_withheld == []
        (started,) = sink.started()
        assert started["nulls_withheld"] == [["depth"]]

    def test_an_admitted_nested_null_is_sent_as_given(self) -> None:
        tool, session, recorder, _ = _mcp_tool(NESTED)

        _call(tool, {"address": ADDRESS, "options": {"name": "a", "mode": None}})

        assert session.calls[0]["options"] == {"name": "a", "mode": None}
        (entry,) = recorder.entries
        assert entry.args["options"] == {"name": "a", "mode": None}
        assert entry.args_nulls_dropped == []
        assert entry.args_nulls_withheld == []

    def test_a_nested_object_follows_the_same_rules(self) -> None:
        tool, session, recorder, _ = _mcp_tool(NESTED)

        _call(
            tool,
            {
                "address": ADDRESS,
                "options": {"name": "a", "limit": None, "mode": None, "inner": {"step": None}},
            },
        )

        (sent,) = session.calls
        assert sent["options"] == {"name": "a", "mode": None, "inner": {}}
        assert recorder.entries[0].args_nulls_dropped == [
            ["options", "limit"],
            ["options", "inner", "step"],
        ]

    def test_a_nested_required_field_given_null_is_not_left_out(self) -> None:
        tool, session, recorder, _ = _mcp_tool(NESTED)

        _call(tool, {"address": ADDRESS, "options": {"name": None}})

        assert session.calls[0]["options"] == {"name": None}
        assert recorder.entries[0].args_nulls_dropped == []

    def test_nested_objects_behind_local_refs_follow_the_same_rules(self) -> None:
        # Read off the rule: the MCP client annotates a property with no
        # ``type`` (a bare ``$ref``) as a string, so such an argument cannot
        # reach a server through it, null or not; that is apart from this.
        rule = schema_rules(REFERENCED).dropped
        args = {
            "window": {"start": 1, "size": None, "label": None},
            "spare": {"start": 2, "size": None},
            "tree": {"weight": None, "child": {"weight": None, "child": None}},
        }

        kept, dropped = drop_unset_nulls(args, rule)

        assert kept == {
            "window": {"start": 1, "label": None},
            "spare": {"start": 2},
            "tree": {"child": {"child": None}},
        }
        assert dropped == (
            ("window", "size"),
            ("spare", "size"),
            ("tree", "weight"),
            ("tree", "child", "weight"),
        )
        assert args["window"]["size"] is None


class TestTheRecordedArgumentsCarryTheNote:
    def test_the_start_event_names_them_by_path_segments(self) -> None:
        tool, _, _, sink = _ghidra_tool("list_imports")

        _call(tool, {"limit": None, "offset": 10, "program": None})

        (started,) = sink.started()
        assert started["nulls_dropped"] == [["limit"], ["program"]]

    def test_a_field_name_with_a_dot_is_one_segment(self) -> None:
        tool, _, recorder, _ = _mcp_tool(
            {"type": "object", "properties": {"a.b": {"type": "integer"}}}
        )

        _call(tool, {"a.b": None})

        assert recorder.entries[0].args_nulls_dropped == [["a.b"]]

    def test_a_stored_entry_reads_and_dumps_as_it_did(self) -> None:
        stored = build_entry(
            entry_id="ev_0052",
            seq=52,
            agent="static",
            tool="list_imports",
            args={"limit": None, "offset": None, "program": None},
            server=None,
            output="ValidationError: refused",
            ok=False,
            error="ValidationError: refused",
        ).model_dump(mode="json")

        assert "args_nulls_dropped" not in stored
        assert "args_nulls_withheld" not in stored
        assert LedgerEntry.model_validate(stored).model_dump(mode="json") == stored


class TestAModelCannotWriteTheNote:
    def test_a_dict_schema_tool_keeps_the_key_as_an_argument_and_records_it(self) -> None:
        received: list[dict[str, Any]] = []

        async def run(**kwargs: Any) -> str:
            received.append(kwargs)
            return "ran"

        raw = StructuredTool.from_function(
            coroutine=run,
            name="shell",
            description="shell",
            args_schema={"type": "object", "properties": {"cmd": {"type": "string"}}},
        )
        recorder, sink = _recorder()
        (tool,) = record_tools([raw], recorder)
        forged = {"cmd": "rm -rf /", DROPPED_KEY: ["cmd"]}

        _call(tool, forged)

        assert received == [forged]
        (entry,) = recorder.entries
        assert entry.args == forged
        assert entry.args_nulls_dropped == []
        (started,) = sink.started()
        assert "nulls_dropped" not in started
        assert "cmd=" in started["args_summary"]

    def test_a_ruled_tool_ignores_a_note_the_model_wrote(self) -> None:
        tool, ghidra, recorder, _ = _ghidra_tool("get_xrefs_to")

        _call(tool, {"address": ADDRESS, "limit": 3, DROPPED_KEY: [["address"], ["limit"]]})

        assert dict(ghidra.requests[0].url.params) == {"address": ADDRESS, "limit": "3"}
        (entry,) = recorder.entries
        assert entry.args["address"] == ADDRESS
        assert entry.args["limit"] == 3
        assert entry.args_nulls_dropped == []


# -- the rule itself ---------------------------------------------------------------


class TestTheRule:
    def test_what_admits_null(self) -> None:
        assert admits_null({"type": ["integer", "null"]})
        assert admits_null({"anyOf": [{"type": "integer"}, {"type": "null"}]})
        assert admits_null({"oneOf": [{"type": "null"}, {"type": "string"}]})
        assert admits_null({"type": "integer", "nullable": True})
        assert admits_null({"description": "no type stated"})
        assert admits_null({"const": None})
        assert admits_null({"enum": ["a", None]})
        assert not admits_null({"type": "integer", "default": None})
        assert not admits_null({"anyOf": [{"type": "integer"}, {"type": "string"}]})
        assert not admits_null({"enum": ["a", "b"]})
        assert not admits_null({"const": 5})
        assert not admits_null({"type": ["string", "null"], "enum": ["a", "b"]})

    def test_what_is_not_read_keeps_its_null(self) -> None:
        assert admits_null({"allOf": [{"type": "integer"}]})
        assert admits_null({"$ref": "#/$defs/Mode"})
        assert admits_null({"$ref": "https://example.invalid/schema.json"})

    def test_an_openapi_nullable_field_keeps_its_null_over_mcp(self) -> None:
        tool, session, recorder, _ = _mcp_tool(
            {"type": "object", "properties": {"n": {"type": "integer", "nullable": True}}}
        )

        _call(tool, {"n": None})

        assert recorder.entries[0].args_nulls_dropped == []
        assert recorder.entries[0].args_nulls_withheld == [["n"]]
        assert session.calls == [{}]

    def test_arguments_with_nothing_to_drop_come_back_as_the_same_object(self) -> None:
        args = {"address": ADDRESS, "limit": 5}
        rule = schema_rules(_recorded_schema("get_xrefs_to")).dropped

        assert drop_unset_nulls(args, rule) == (args, ())
        assert drop_unset_nulls(args, rule)[0] is args

    def test_a_schema_with_nothing_to_drop_has_no_rules(self) -> None:
        assert not schema_rules({"properties": {"a": {"type": "string"}}, "required": ["a"]})

    def test_a_self_reference_declared_before_a_droppable_sibling_holds(self) -> None:
        schema = {
            "type": "object",
            "$defs": {
                "N": {
                    "type": "object",
                    "properties": {"child": {"$ref": "#/$defs/N"}, "v": {"type": "integer"}},
                }
            },
            "properties": {"n": {"type": "object", "$ref": "#/$defs/N"}},
        }
        tool, session, recorder, _ = _mcp_tool(schema)

        _call(tool, {"n": {"v": None, "child": {"v": None, "child": {"v": 1}}}})

        assert session.calls == [{"n": {"child": {"child": {"v": 1}}}}]
        assert recorder.entries[0].args_nulls_dropped == [["n", "v"], ["n", "child", "v"]]

    def test_an_unresolvable_ref_describes_no_object(self) -> None:
        rules = schema_rules({"properties": {"w": {"$ref": "#/$defs/Missing"}}})

        assert not rules

    def test_one_walk_over_wide_arguments(self) -> None:
        width = 20_000
        schema = {"properties": {f"f{i}": {"type": "integer"} for i in range(width)}}
        args = {f"f{i}": None for i in range(width)}

        kept, dropped = drop_unset_nulls(args, schema_rules(schema).dropped)

        assert kept == {}
        assert len(dropped) == width


def _untitled(schema: Any) -> Any:
    """``schema`` without pydantic's ``title`` keys, as the recorded definitions hold it."""
    if isinstance(schema, dict):
        return {k: _untitled(v) for k, v in schema.items() if k != "title"}
    if isinstance(schema, list):
        return [_untitled(v) for v in schema]
    return schema


def test_the_json_schema_is_the_same_as_without_the_rule() -> None:
    """The validator that drops the nulls is not part of what the model is offered."""
    plain = create_model(
        "GhidraTool_list_importsSchema",
        offset=(int, None),
        limit=(int, None),
        program=(str, None),
    )
    tool, _, _, _ = _ghidra_tool("list_imports")

    assert json.dumps(tool.args_schema.model_json_schema()) == json.dumps(plain.model_json_schema())


def test_a_schema_narrowed_for_a_pinned_tool_keeps_the_rules() -> None:
    """The schema a pinned tool binds to (``tool_pinning._schema_without``) keeps its own rules."""
    tool, _, _, _ = _ghidra_tool("decompile_function")
    narrowed = _schema_without(tool.args_schema, ("program",))

    assert list(narrowed.model_fields) == ["address", "timeout"]
    assert rules_of(narrowed).dropped == {"timeout": (True, None)}
    assert narrowed.model_validate({"address": ADDRESS, "timeout": None}).timeout is None


def test_a_hidden_field_of_a_pinned_tool_is_the_platform_s_not_a_null() -> None:
    """A field the platform fills (``_pin_tool`` with ``hidden``) is never named as a null."""
    for field in ({"type": "string"}, {"anyOf": [{"type": "string"}, {"type": "null"}]}):
        schema = {
            "type": "object",
            "properties": {"file_path": field, "x": {"type": "integer"}, "n": {"type": "integer"}},
            "required": ["x"],
        }
        session = _Session()
        toolkit = MCPLangChainToolkit(None)
        toolkit.session = session  # type: ignore[assignment]
        attached = toolkit._create_langchain_tool(
            SimpleNamespace(name="p", description="p", inputSchema=schema, annotations=None)
        )
        pinned = _pin_tool(
            attached, "/job/sample.exe", frozenset(), frozenset(), "a", hidden=("file_path",)
        )
        recorder, _ = _recorder()
        (tool,) = record_tools([pinned], recorder, RepeatGuard())

        _call(tool, {"x": 1, "file_path": None, "n": None})

        assert session.calls == [{"x": 1, "file_path": "/job/sample.exe"}]
        (entry,) = recorder.entries
        assert entry.args_nulls_dropped == [["n"]]
        assert entry.args_nulls_withheld == []
