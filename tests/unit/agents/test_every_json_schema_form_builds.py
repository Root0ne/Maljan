"""Every JSON-schema form an MCP server declares an argument in builds and reaches the server.

The argument model of an MCP tool was built from each property's ``"type"``
alone. A type list (``["integer", "null"]``) crashed the build with
``TypeError: unhashable type: 'list'`` (T-349), so the whole server was lost;
a property with no ``"type"`` was annotated ``str`` (T-352), so an object
behind a ``$ref``, an integer in an ``anyOf`` and a number in an ``enum`` were
refused before they could reach the server.

A property whose schema is a plain type keeps exactly the annotation it had,
so a simple tool is offered byte for byte what it was. Any other property is
offered the server's own schema with every local ``$ref`` resolved (a
recursive one stops where it would repeat), and is checked for the Python
shape of its value only: the server checks the rest.

The corpus is every tool of the ``services/*`` MCP servers, read in process
from each ``server.py``, plus the VirusTotal tools the golden
``mcp_tools/virustotal.json`` names, from a later live listing of the same
server.
``offered_on_dev.json`` is what the build offered for each of them before this
change.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from langchain_anthropic.chat_models import convert_to_anthropic_tool
from langchain_core.utils.function_calling import convert_to_openai_tool
from langchain_google_genai._function_utils import convert_to_genai_function_declarations

from maljan.agents.argument_schema import STRUCTURAL
from maljan.agents.mcp_client import MCPLangChainToolkit
from maljan.agents.null_arguments import rules_of
from maljan.agents.tool_pinning import _schema_without
from maljan.llm.gemini_provider import gemini_tools

FIXTURES = Path(__file__).parents[2] / "fixtures"
CORPUS = FIXTURES / "mcp_schema_corpus"
GOLDEN = FIXTURES / "golden" / "mcp_tools"


class _Result:
    def __init__(self) -> None:
        self.isError = False
        self.content = [SimpleNamespace(text="ok")]


class _Session:
    """Records the argument dict that would go over the wire."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def call_tool(self, name: str, arguments: dict[str, Any], **_: Any) -> _Result:
        self.calls.append(dict(arguments))
        return _Result()


def _build(schema: dict[str, Any], name: str = "probe") -> tuple[Any, _Session]:
    session = _Session()
    toolkit = MCPLangChainToolkit(None)
    toolkit.session = session  # type: ignore[assignment]
    tool = toolkit._create_langchain_tool(
        SimpleNamespace(name=name, inputSchema=schema, description=f"{name} tool.")
    )
    return tool, session


def _sent(schema: dict[str, Any], args: dict[str, Any]) -> dict[str, Any]:
    tool, session = _build(schema)
    asyncio.run(tool.ainvoke(args))
    assert session.calls, "the call never reached the server"
    return session.calls[-1]


def _offered(tool: Any) -> dict[str, Any]:
    return convert_to_openai_tool(tool)["function"]["parameters"]


def _one(field: dict[str, Any], *, required: bool = True, **root: Any) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "properties": {"x": field}, **root}
    if required:
        schema["required"] = ["x"]
    return schema


OPTIONS = {
    "type": "object",
    "properties": {"depth": {"type": "integer"}, "mode": {"type": "string"}},
    "required": ["mode"],
}


class TestATypeList:
    def test_a_type_list_builds_and_its_values_reach_the_server(self) -> None:
        schema = _one({"type": ["integer", "null"]})
        assert _sent(schema, {"x": 5}) == {"x": 5}
        assert _sent(schema, {"x": None}) == {"x": None}

    def test_a_type_list_is_offered_as_the_server_wrote_it(self) -> None:
        tool, _ = _build(_one({"type": ["integer", "string"], "description": "id or name"}))
        assert _offered(tool)["properties"]["x"] == {
            "type": ["integer", "string"],
            "description": "id or name",
        }

    def test_a_type_list_without_null_still_drops_an_optional_null(self) -> None:
        # T-330: the field does not admit null and is optional, so a null is
        # the argument left out.
        schema = _one({"type": ["integer", "string"]}, required=False)
        assert _sent(schema, {"x": None}) == {}


class TestNullable:
    def test_an_openapi_nullable_required_field_accepts_null(self) -> None:
        schema = _one({"type": "integer", "nullable": True})
        assert _sent(schema, {"x": None}) == {"x": None}
        assert _sent(schema, {"x": 3}) == {"x": 3}


class TestCombinators:
    def test_an_optional_integer_written_as_any_of_is_offered_and_sent_as_an_integer(self) -> None:
        field = {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": None}
        tool, _ = _build(_one(field, required=False))
        assert _offered(tool)["properties"]["x"] == field
        assert _sent(_one(field, required=False), {"x": 30}) == {"x": 30}

    def test_one_of_takes_each_branch(self) -> None:
        schema = _one({"oneOf": [{"type": "string"}, {"type": "integer"}]})
        assert _sent(schema, {"x": "abc"}) == {"x": "abc"}
        assert _sent(schema, {"x": 7}) == {"x": 7}

    def test_all_of_around_a_ref_carries_the_object(self) -> None:
        schema = _one({"allOf": [{"$ref": "#/$defs/Options"}]}, **{"$defs": {"Options": OPTIONS}})
        value = {"mode": "fast", "depth": 2}
        assert _sent(schema, {"x": value}) == {"x": value}
        tool, _ = _build(schema)
        assert _offered(tool)["properties"]["x"] == {"allOf": [OPTIONS]}


class TestEnumAndConst:
    def test_an_untyped_integer_enum_is_sent_as_the_integer(self) -> None:
        schema = _one({"enum": [1, 2, 3]})
        assert _sent(schema, {"x": 2}) == {"x": 2}
        tool, _ = _build(schema)
        assert _offered(tool)["properties"]["x"] == {"enum": [1, 2, 3]}

    def test_a_typed_string_enum_is_offered_its_values(self) -> None:
        tool, _ = _build(_one({"type": "string", "enum": ["fast", "deep"]}))
        assert _offered(tool)["properties"]["x"] == {"type": "string", "enum": ["fast", "deep"]}

    def test_a_const_is_offered_and_sent(self) -> None:
        schema = _one({"const": 4})
        assert _sent(schema, {"x": 4}) == {"x": 4}
        tool, _ = _build(schema)
        assert _offered(tool)["properties"]["x"] == {"const": 4}


class TestObjectsAndArrays:
    def test_a_nested_object_is_offered_its_properties_and_reaches_the_server(self) -> None:
        schema = _one(OPTIONS)
        value = {"mode": "deep", "depth": 1}
        assert _sent(schema, {"x": value}) == {"x": value}
        tool, _ = _build(schema)
        assert _offered(tool)["properties"]["x"] == OPTIONS

    def test_an_array_with_items_is_offered_its_items(self) -> None:
        schema = _one({"type": "array", "items": {"type": "integer"}})
        assert _sent(schema, {"x": [1, 2]}) == {"x": [1, 2]}
        tool, _ = _build(schema)
        assert _offered(tool)["properties"]["x"] == {"type": "array", "items": {"type": "integer"}}

    def test_additional_properties_is_offered_and_the_map_reaches_the_server(self) -> None:
        field = {"type": "object", "additionalProperties": {"type": "integer"}}
        assert _sent(_one(field), {"x": {"a": 1}}) == {"x": {"a": 1}}
        tool, _ = _build(_one(field))
        assert _offered(tool)["properties"]["x"] == field

    def test_a_property_with_no_type_takes_any_value(self) -> None:
        schema = _one({"description": "anything"})
        assert _sent(schema, {"x": {"k": [1]}}) == {"x": {"k": [1]}}
        assert _sent(schema, {"x": 12}) == {"x": 12}
        tool, _ = _build(schema)
        assert _offered(tool)["properties"]["x"] == {"description": "anything"}


class TestRefs:
    def test_an_object_behind_a_defs_ref_reaches_the_server(self) -> None:
        schema = _one({"$ref": "#/$defs/Options"}, **{"$defs": {"Options": OPTIONS}})
        value = {"mode": "fast"}
        assert _sent(schema, {"x": value}) == {"x": value}
        tool, _ = _build(schema)
        assert _offered(tool)["properties"]["x"] == OPTIONS

    def test_a_definitions_ref_resolves_and_keeps_its_own_description(self) -> None:
        schema = _one(
            {"$ref": "#/definitions/Options", "description": "how to run"},
            definitions={"Options": OPTIONS},
        )
        tool, _ = _build(schema)
        assert _offered(tool)["properties"]["x"] == {**OPTIONS, "description": "how to run"}

    def test_a_nested_ref_resolves_all_the_way_down(self) -> None:
        defs = {
            "Outer": {"type": "object", "properties": {"inner": {"$ref": "#/$defs/Inner"}}},
            "Inner": {"type": "array", "items": {"$ref": "#/$defs/Leaf"}},
            "Leaf": {"type": "string", "enum": ["a", "b"]},
        }
        tool, _ = _build(_one({"$ref": "#/$defs/Outer"}, **{"$defs": defs}))
        assert _offered(tool)["properties"]["x"] == {
            "type": "object",
            "properties": {
                "inner": {"type": "array", "items": {"type": "string", "enum": ["a", "b"]}}
            },
        }
        assert "$ref" not in json.dumps(_offered(tool))

    def test_a_recursive_ref_builds_once_and_a_tree_reaches_the_server(self) -> None:
        node = {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "children": {"type": "array", "items": {"$ref": "#/$defs/Node"}},
            },
        }
        schema = _one({"$ref": "#/$defs/Node"}, **{"$defs": {"Node": node}})
        tree = {"name": "root", "children": [{"name": "leaf", "children": []}]}
        assert _sent(schema, {"x": tree}) == {"x": tree}
        tool, _ = _build(schema)
        offered = _offered(tool)["properties"]["x"]
        # One level is spelled out; the repeat is the object it stands for.
        assert offered["properties"]["children"]["items"] == {"type": "object"}
        assert "$ref" not in json.dumps(offered)

    def test_mutually_recursive_refs_and_a_root_ref_do_not_loop(self) -> None:
        defs = {
            "A": {"type": "object", "properties": {"b": {"$ref": "#/$defs/B"}}},
            "B": {
                "type": "object",
                "properties": {"a": {"$ref": "#/$defs/A"}, "up": {"$ref": "#"}},
            },
        }
        tool, _ = _build(_one({"$ref": "#/$defs/A"}, **{"$defs": defs}))
        assert "$ref" not in json.dumps(_offered(tool))

    def test_an_unresolvable_ref_still_builds_and_takes_any_value(self) -> None:
        schema = _one({"$ref": "https://example.com/schema.json", "description": "remote"})
        assert _sent(schema, {"x": {"a": 1}}) == {"x": {"a": 1}}
        tool, _ = _build(schema)
        assert _offered(tool)["properties"]["x"] == {"description": "remote"}

    def test_a_null_inside_an_optional_ref_object_is_still_dropped(self) -> None:
        # T-330 reads the raw schema, refs included: ``depth`` is optional and
        # not nullable, so its null is the argument left out.
        schema = _one({"$ref": "#/$defs/Options"}, **{"$defs": {"Options": OPTIONS}})
        assert _sent(schema, {"x": {"mode": "fast", "depth": None}}) == {"x": {"mode": "fast"}}


class TestAPinnedToolKeepsTheShape:
    def test_narrowing_a_rich_schema_keeps_what_each_kept_field_is_offered(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "options": {"$ref": "#/$defs/Options"},
                "timeout": {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": None},
            },
            "required": ["path"],
            "$defs": {"Options": OPTIONS},
        }
        tool, _ = _build(schema)
        narrowed = _schema_without(tool.args_schema, ("path",))
        assert narrowed is not None
        before = tool.args_schema.model_json_schema()["properties"]
        after = narrowed.model_json_schema()["properties"]
        assert after == {k: v for k, v in before.items() if k != "path"}
        assert rules_of(narrowed)


# -- An untrusted server ----------------------------------------------------------

# Beside every hostile property: one that is read in full whatever happens to
# its neighbour.
NEIGHBOUR = {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": None}
NEIGHBOUR_OFFERED = {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": None}


def _beside(field: Any, **root: Any) -> dict[str, Any]:
    return {"type": "object", "properties": {"x": field, "y": NEIGHBOUR}, **root}


def _laughs(levels: int) -> dict[str, Any]:
    """Each definition names the next one twice: written out, it doubles at every level."""
    defs: dict[str, Any] = {
        f"a{i}": {"anyOf": [{"$ref": f"#/$defs/a{i + 1}"}, {"$ref": f"#/$defs/a{i + 1}"}]}
        for i in range(levels)
    }
    defs[f"a{levels}"] = {"type": "string"}
    return _beside({"$ref": "#/$defs/a0"}, **{"$defs": defs})


def _chain(links: int) -> dict[str, Any]:
    defs: dict[str, Any] = {f"a{i}": {"$ref": f"#/$defs/a{i + 1}"} for i in range(links)}
    defs[f"a{links}"] = {"type": "string"}
    return _beside({"$ref": "#/$defs/a0"}, **{"$defs": defs})


def _nested(levels: int) -> dict[str, Any]:
    field: dict[str, Any] = {"type": "string"}
    for _ in range(levels):
        field = {"type": "object", "properties": {"a": field}}
    return _beside(field)


ANCHORED = {"$defs": {"H": {"$anchor": "Hash", "type": "string"}}}
DEFS_A = {"$defs": {"A": {"type": "object", "properties": {"v": {"type": "integer"}}}}}

# Inputs a hostile or old-draft server can send. Each must build in bounded
# time, offer a valid Draft 2020-12 schema with no reference left in it, and
# leave its neighbour as it would be on its own.
HOSTILE: dict[str, dict[str, Any]] = {
    "laughs_10": _laughs(10),
    "laughs_18": _laughs(18),
    "laughs_40": _laughs(40),
    "ref_chain_2000": _chain(2000),
    "nested_40": _nested(40),
    "nested_3000": _nested(3000),
    "tuple_items": _beside({"type": "array", "items": [{"type": "string"}, {"type": "integer"}]}),
    "draft7_items_and_additional": _beside(
        {
            "type": "array",
            "items": [{"$ref": "#/$defs/A"}],
            "additionalItems": {"$ref": "#/$defs/A"},
        },
        **DEFS_A,
    ),
    "draft4_exclusive_minimum": _beside(
        {
            "type": "object",
            "properties": {"n": {"type": "number", "minimum": 0, "exclusiveMinimum": True}},
        }
    ),
    "required_true": _beside(
        {"type": "object", "properties": {"a": {"type": "string", "required": True}}}
    ),
    "type_empty": _beside({"type": []}),
    "type_duplicated": _beside({"type": ["string", "string"]}),
    "type_unknown_in_list": _beside({"type": ["foo", "null"]}),
    "type_object": _beside({"type": {"a": 1}}),
    "any_of_not_a_list": _beside({"anyOf": {"type": "string"}}),
    "title_not_a_string": _beside({"type": ["string", "null"], "title": {"x": 1}}),
    "ref_under_x_keyword": _beside(
        {"type": "object", "properties": {"a": {"type": "string"}}, "x-foo": {"$ref": "#/$defs/A"}},
        **DEFS_A,
    ),
    "ref_under_dependencies": _beside(
        {
            "type": "object",
            "properties": {"a": {"type": "string"}},
            "dependencies": {"a": {"$ref": "#/$defs/A"}, "b": ["a"]},
        },
        **DEFS_A,
    ),
    "ref_under_examples": _beside(
        {"type": "object", "properties": {"a": {"type": "string"}}, "examples": [{"$ref": "#"}]},
    ),
    "ref_under_const": _beside({"const": {"$ref": "#/$defs/A"}}, **DEFS_A),
    "ref_not_a_string": _beside({"type": "object", "properties": {"a": {"$ref": 5}}}),
    "ref_not_a_string_nested": _beside(
        {"type": "object", "properties": {"a": {"anyOf": [{"$ref": 5}, {"type": "null"}]}}}
    ),
    "ref_under_content_schema": _beside(
        {"type": "string", "contentSchema": {"$ref": "#/$defs/A"}}, **DEFS_A
    ),
    "ref_to_an_anchor": _beside({"$ref": "#Hash"}, **ANCHORED),
    "ref_index_too_long": _beside({"$ref": "#/a/" + "9" * 5000}),
    "ref_remote": _beside({"$ref": "file:///etc/passwd"}),
    "default_holds_a_ref": _beside(
        {"type": "object", "properties": {"a": {"type": "string"}}, "default": {"$ref": "#/nope"}}
    ),
    "plain_default_holds_a_ref": _beside({"type": "object", "default": {"$ref": "#/nope"}}),
    "integer_enum": _beside({"type": "integer", "enum": [1, 2]}),
    "enum_with_null": _beside({"enum": ["a", None]}),
    "boolean_schema": _beside(True),
}


@pytest.mark.parametrize("case", sorted(HOSTILE))
def test_a_hostile_property_costs_only_itself(case: str) -> None:
    began = time.monotonic()
    tool, session = _build(HOSTILE[case], case)
    offered = _offered(tool)
    assert time.monotonic() - began < 20.0
    text = json.dumps(offered)
    assert len(text) < 70_000
    assert "$ref" not in text
    Draft202012Validator.check_schema(offered)
    assert offered["properties"]["y"] == NEIGHBOUR_OFFERED
    asyncio.run(tool.ainvoke({"y": 3}))
    assert session.calls[-1] == {"y": 3}


@pytest.mark.parametrize(
    "case",
    [
        "laughs_18",
        "nested_40",
        "tuple_items",
        "draft4_exclusive_minimum",
        "required_true",
        "type_empty",
        "type_duplicated",
    ],
)
def test_an_unusable_property_is_offered_as_its_plain_type_and_named(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.agents import mcp_client

    said: list[str] = []
    monkeypatch.setattr(mcp_client.logger, "warning", lambda msg, *a: said.append(msg % a))
    schema = HOSTILE[case]
    tool, _ = _build(schema, case)
    field = schema["properties"]["x"]
    stated = field.get("type", "string")
    # Offered exactly as an optional field of its stated type alone is; a
    # ``type`` that is not a name is a type nobody knows.
    alone, _ = _build(_beside({"type": stated if isinstance(stated, str) else "unknown"}))
    assert _offered(tool)["properties"]["x"] == _offered(alone)["properties"]["x"]
    assert any(case in line and "'x'" in line and "plain type" in line for line in said), said


def test_an_anchor_ref_is_not_read_as_the_whole_schema() -> None:
    schema = _one({"$ref": "#Hash"}, **ANCHORED)
    tool, _ = _build(schema)
    assert _offered(tool)["properties"]["x"] == {}
    assert _sent(schema, {"x": "abc"}) == {"x": "abc"}


def test_a_default_holding_a_ref_leaves_the_argument_to_the_server() -> None:
    assert _sent(HOSTILE["plain_default_holds_a_ref"], {"y": 1}) == {"y": 1}
    assert _sent(HOSTILE["default_holds_a_ref"], {"y": 1}) == {"y": 1}


def test_a_deep_schema_keeps_its_top_level_null_handling() -> None:
    schema = _nested(3000)
    assert _sent(schema, {"x": None, "y": 2}) == {"y": 2}


# -- The corpus -------------------------------------------------------------------


def _corpus() -> dict[str, dict[str, Any]]:
    return json.loads((CORPUS / "schemas.json").read_text(encoding="utf-8"))


def _on_dev() -> dict[str, dict[str, Any]]:
    return json.loads((CORPUS / "offered_on_dev.json").read_text(encoding="utf-8"))


def _plain(field: Any) -> bool:
    return (
        isinstance(field, dict)
        and isinstance(field.get("type"), str)
        and not (STRUCTURAL & set(field))
    )


def _cases() -> list[tuple[str, str]]:
    return [(server, name) for server, tools in _corpus().items() for name in tools]


@pytest.mark.parametrize(("server", "name"), _cases())
def test_every_corpus_schema_builds_and_its_plain_fields_are_offered_as_before(
    server: str, name: str
) -> None:
    schema = _corpus()[server][name]
    tool, _ = _build(schema, name)
    offered = convert_to_openai_tool(tool)
    before = _on_dev()[server][name]
    fields = schema.get("properties", {})
    if all(map(_plain, fields.values())):
        # A simple tool: byte for byte what it was.
        assert json.dumps(offered) == json.dumps(before)
        return
    now, then = offered["function"]["parameters"], before["function"]["parameters"]
    assert list(now["properties"]) == list(then["properties"])
    assert now.get("required") == then.get("required")
    for field_name, field in fields.items():
        if _plain(field):
            assert now["properties"][field_name] == then["properties"][field_name]
        else:
            assert "$ref" not in json.dumps(now["properties"][field_name])


def test_the_corpus_has_both_kinds_of_tool() -> None:
    simple = rich = 0
    for tools in _corpus().values():
        for schema in tools.values():
            if all(map(_plain, schema.get("properties", {}).values())):
                simple += 1
            else:
                rich += 1
    assert simple >= 50
    assert rich >= 15


def test_the_corpus_carries_every_tool_the_goldens_name() -> None:
    corpus = _corpus()
    for golden, server in (
        ("analysis", "analysis-mcp"),
        ("knowledge", "knowledge-mcp"),
        ("network", "network-mcp"),
        ("threatintel", "threatintel-mcp"),
        ("virustotal", "virustotal"),
    ):
        payload = json.loads((GOLDEN / f"{golden}.json").read_text(encoding="utf-8"))
        assert sorted(corpus[server]) == payload["tools"], golden
        if golden == "virustotal":
            # The corpus holds a later listing of the same server than the
            # vendored golden, which has since gained optional arguments.
            continue
        for tool, arguments in (payload.get("arguments") or {}).items():
            assert sorted(corpus[server][tool].get("properties", {})) == arguments, tool


# -- A name a field cannot carry ------------------------------------------------------

# Every kind of argument name a pydantic field or a Python keyword argument
# cannot be: ``model_config`` crashed the build, a leading underscore made the
# field private so the argument was neither offered nor sent, a ``BaseModel``
# member crashed or shadowed it, a keyword or a name that is not an identifier
# was sent but never offered, and a keyword of the tool's own call was lost or
# crashed the call (T-360). Each is offered and sent under the server's name.
RESERVED: dict[str, tuple[str, ...]] = {
    "pydantic_config": ("model_config",),
    "private": ("__x", "_x", "__init__", "_"),
    "basemodel_member": (
        "model_dump",
        "model_post_init",
        "model_fields",
        "schema",
        "json",
        "dict",
        "copy",
        "validate",
    ),
    "model_namespace": ("model_dump_extra", "model_validate_this"),
    "keyword": ("class", "from", "None"),
    "not_an_identifier": ("a-b", "1x", "x y", ""),
    "tool_call_keyword": ("self", "config", "run_manager"),
}

RESERVED_CASES = [(kind, name) for kind, names in RESERVED.items() for name in names]
RESERVED_IDS = [
    f"{kind}-{index}" for kind, names in RESERVED.items() for index in range(len(names))
]


def _named(name: str, field: dict[str, Any], *, required: bool = True) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {name: field, "y": {"type": "integer"}},
    }
    if required:
        schema["required"] = [name]
    return schema


@pytest.mark.parametrize(("kind", "name"), RESERVED_CASES, ids=RESERVED_IDS)
class TestAReservedName:
    def test_a_plain_field_builds_is_offered_and_sent_under_the_servers_name(
        self, kind: str, name: str
    ) -> None:
        schema = _named(name, {"type": "string"})
        tool, _ = _build(schema)
        offered = _offered(tool)
        assert list(offered["properties"]) == [name, "y"]
        assert offered["properties"][name] == {"type": "string"}
        assert offered["required"] == [name]
        assert _sent(schema, {name: "v", "y": 2}) == {name: "v", "y": 2}

    def test_a_shaped_field_builds_is_offered_and_sent_under_the_servers_name(
        self, kind: str, name: str
    ) -> None:
        field = {"anyOf": [{"type": "integer"}, {"type": "string"}]}
        schema = _named(name, field)
        tool, _ = _build(schema)
        assert _offered(tool)["properties"][name] == field
        assert _sent(schema, {name: 7}) == {name: 7}
        assert _sent(schema, {name: "seven"}) == {name: "seven"}

    def test_its_value_is_still_checked_under_the_servers_name(self, kind: str, name: str) -> None:
        from pydantic import ValidationError

        tool, session = _build(_named(name, {"type": "integer"}))
        with pytest.raises(ValidationError):
            asyncio.run(tool.ainvoke({name: [1]}))
        with pytest.raises(ValidationError):
            asyncio.run(tool.ainvoke({"y": 1}))
        assert session.calls == []

    def test_the_null_rules_read_it_by_the_servers_name(self, kind: str, name: str) -> None:
        # T-330: an optional field that does not admit null takes a null as
        # left out; one that admits it is not sent a top-level null; a required
        # one that admits it is sent its null; a nested one is dropped inside.
        optional = _named(name, {"type": "integer"}, required=False)
        assert _sent(optional, {name: None, "y": 1}) == {"y": 1}
        assert _sent(optional, {name: 4}) == {name: 4}
        admitted = _named(name, {"type": ["integer", "null"]}, required=False)
        assert _sent(admitted, {name: None}) == {}
        needed = _named(name, {"type": ["integer", "null"]})
        assert _sent(needed, {name: None}) == {name: None}
        nested = _named(name, OPTIONS, required=False)
        value = {"mode": "fast", "depth": None}
        assert _sent(nested, {name: value}) == {name: {"mode": "fast"}}
        tool, _ = _build(admitted)
        assert name in rules_of(tool.args_schema).withheld

    def test_the_build_warns_of_nothing(self, kind: str, name: str) -> None:
        import warnings

        with warnings.catch_warnings(record=True) as said:
            warnings.simplefilter("always")
            _build(_named(name, {"type": "string"}))
        assert [str(w.message) for w in said] == []

    def test_a_tool_rebuilt_around_it_offers_and_sends_the_servers_name(
        self, kind: str, name: str
    ) -> None:
        from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
        from maljan.providers.declared_errors import ErrorPattern, with_declared_errors

        schema = _named(name, {"type": "string"})
        tool, session = _build(schema)
        pattern = ErrorPattern.model_validate({"match": "never said", "remediation": "none"})
        (declared,) = with_declared_errors([tool], [pattern])
        (recorded,) = record_tools([declared], EvidenceRecorder("static"))
        for rebuilt in (declared, recorded):
            assert list(_offered(rebuilt)["properties"]) == [name, "y"]
            asyncio.run(rebuilt.ainvoke({name: "v"}))
            assert session.calls[-1] == {name: "v"}


def test_the_ledger_records_cites_and_keys_a_call_by_what_was_sent() -> None:
    from maljan.agents.evidence_recorder import EvidenceRecorder, RepeatGuard, record_tools

    tool, session = _build(_named("class", {"type": "string"}))
    recorder = EvidenceRecorder("static")
    repeats = RepeatGuard()
    (recorded,) = record_tools([tool], recorder, repeats)
    arguments = {"class": "PE", "y": 1}
    answers = [asyncio.run(recorded.ainvoke(arguments)) for _ in range(3)]
    assert session.calls == [arguments, arguments]
    # Recorded, and cited by the repeat, under the name the server was sent.
    assert [entry.args for entry in recorder.entries] == [arguments] * 3
    assert [entry.repeated_of for entry in recorder.entries] == [None, None, "ev_0001"]
    assert "[ev_0001]" in answers[2]
    # The repeat key is the server's name, never the field that held it.
    assert repeats.answered_by("probe", arguments) == "ev_0001"
    assert repeats.answered_by("probe", {"arg_class": "PE", "y": 1}) is None


def test_the_null_rules_read_an_argument_written_by_its_field_name() -> None:
    from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools

    schema = _named("class", OPTIONS, required=False)
    by_field = {"arg_class": {"mode": "f", "depth": None}}
    assert _sent(schema, by_field) == {"class": {"mode": "f"}}
    tool, session = _build(schema)
    recorder = EvidenceRecorder("static")
    (recorded,) = record_tools([tool], recorder)
    asyncio.run(recorded.ainvoke(by_field))
    assert session.calls[-1] == {"class": {"mode": "f"}}
    # Recorded as every call is, with the optional ``y`` at its default.
    assert recorder.entries[-1].args == {"class": {"mode": "f"}, "y": None}
    assert recorder.entries[-1].args_nulls_dropped == [["class", "depth"]]


def test_the_offered_schema_is_written_once() -> None:
    tool, _ = _build(_named("class", {"type": "string"}))
    offered = tool.tool_call_schema
    assert offered is tool.tool_call_schema
    assert offered.model_json_schema() is offered.model_json_schema()
    assert list(offered.model_json_schema()["properties"]) == ["class", "y"]


def test_a_guard_hides_and_fills_an_argument_by_the_servers_name() -> None:
    from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
    from maljan.agents.tool_pinning import _pin_tool

    schema = {
        "type": "object",
        "properties": {"from": {"type": "string"}, "path": {"type": "string"}},
        "required": ["from", "path"],
    }
    tool, session = _build(schema)
    pinned = _pin_tool(
        tool,
        "/samples/evil.exe",
        frozenset({"evil.exe"}),
        frozenset(),
        "probe",
        filled={"from": "/job/one.pcap"},
    )
    assert list(_offered(pinned)["properties"]) == ["path"]
    recorder = EvidenceRecorder("static")
    (recorded,) = record_tools([pinned], recorder)
    asyncio.run(recorded.ainvoke({"path": "evil.exe"}))
    sent = {"path": "/samples/evil.exe", "from": "/job/one.pcap"}
    assert session.calls[-1] == sent
    assert recorder.entries[-1].args == {"path": "evil.exe"}


def test_a_server_name_equal_to_an_internal_one_keeps_both_arguments() -> None:
    schema = {
        "type": "object",
        "properties": {
            "class": {"type": "string"},
            "arg_class": {"type": "integer"},
            "arg_class_2": {"type": "boolean"},
        },
        "required": ["class", "arg_class"],
    }
    tool, _ = _build(schema)
    assert list(_offered(tool)["properties"]) == ["class", "arg_class", "arg_class_2"]
    sent = {"class": "c", "arg_class": 1, "arg_class_2": True}
    assert _sent(schema, sent) == sent


def test_a_narrowed_tool_keeps_the_servers_names() -> None:
    schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "from": {"type": "integer"},
            "model_config": {"anyOf": [{"type": "integer"}, {"type": "null"}]},
        },
        "required": ["path", "from"],
    }
    tool, _ = _build(schema)
    narrowed = _schema_without(tool.args_schema, ("path",))
    assert narrowed is not None
    before = tool.args_schema.model_json_schema()["properties"]
    after = narrowed.model_json_schema()["properties"]
    assert list(after) == ["from", "model_config"]
    assert after == {k: v for k, v in before.items() if k != "path"}
    assert narrowed.model_validate({"from": 3}).model_dump(by_alias=True) == {
        "from": 3,
        "model_config": None,
    }


RESERVED_FORMS: dict[str, dict[str, Any]] = {
    f"{form}_{kind}_{index}": _named(name, field)
    for form, field in (("plain", {"type": "string"}), ("shaped", {"type": ["integer", "null"]}))
    for kind, names in RESERVED.items()
    for index, name in enumerate(names)
}


# -- Every provider's client takes what is offered ----------------------------------

NODE = {
    "type": "object",
    "properties": {
        "name": {"type": "string"},
        "children": {"type": "array", "items": {"$ref": "#/$defs/Node"}},
    },
}

FORMS: dict[str, dict[str, Any]] = {
    "type_list": _one({"type": ["integer", "null"]}),
    "type_list_mixed": _one({"type": ["integer", "string"]}),
    "nullable": _one({"type": "integer", "nullable": True}),
    "any_of": _one(NEIGHBOUR, required=False),
    "one_of": _one({"oneOf": [{"type": "string"}, {"type": "integer"}]}),
    "all_of_ref": _one({"allOf": [{"$ref": "#/$defs/Options"}]}, **{"$defs": {"Options": OPTIONS}}),
    "enum_untyped": _one({"enum": [1, 2, 3]}),
    "enum_typed_integer": _one({"type": "integer", "enum": [1, 2]}),
    "enum_with_null": _one({"enum": ["a", None]}),
    "enum_typed_string": _one({"type": "string", "enum": ["fast", "deep"]}),
    "const": _one({"const": 4}),
    "const_boolean": _one({"const": True}),
    "nested_object": _one(OPTIONS),
    "array_items": _one({"type": "array", "items": {"type": "integer"}}),
    "prefix_items": _one({"type": "array", "prefixItems": [{"type": "string"}]}),
    "additional_properties": _one({"type": "object", "additionalProperties": {"type": "integer"}}),
    "no_type": _one({"description": "anything"}),
    "if_then": _one({"type": "object", "if": {"required": ["a"]}, "then": {"required": ["b"]}}),
    "recursive": _one({"$ref": "#/$defs/Node"}, **{"$defs": {"Node": NODE}}),
}


def _every_client_takes(tool: Any) -> None:
    from langchain_ollama import ChatOllama

    # OpenAI, DeepSeek and the fallback chain bind the OpenAI shape.
    Draft202012Validator.check_schema(convert_to_openai_tool(tool)["function"]["parameters"])
    convert_to_anthropic_tool(tool)
    convert_to_genai_function_declarations(gemini_tools([tool]))
    ChatOllama(model="probe").bind_tools([tool])


def _all_schemas() -> list[tuple[str, dict[str, Any]]]:
    cases = [
        (f"{server}/{name}", schema)
        for server, tools in _corpus().items()
        for name, schema in tools.items()
    ]
    cases += [(f"form/{name}", schema) for name, schema in FORMS.items()]
    cases += [(f"hostile/{name}", schema) for name, schema in HOSTILE.items()]
    cases += [(f"reserved/{name}", schema) for name, schema in RESERVED_FORMS.items()]
    return cases


@pytest.mark.parametrize(("case", "schema"), _all_schemas(), ids=[c for c, _ in _all_schemas()])
def test_every_provider_client_takes_every_built_tool(case: str, schema: dict[str, Any]) -> None:
    tool, _ = _build(schema, case.rsplit("/", 1)[-1])
    _every_client_takes(tool)


class TestGeminiToolSchemas:
    def _parameters(self, schema: dict[str, Any]) -> dict[str, Any]:
        tool, _ = _build(schema)
        (adapted,) = gemini_tools([tool])
        assert isinstance(adapted, dict)
        return adapted["function"]["parameters"]["properties"]["x"]

    def test_a_typed_integer_enum_keeps_its_type_and_names_its_values(self) -> None:
        x = self._parameters(_one({"type": "integer", "enum": [1, 2], "description": "level"}))
        assert x == {"type": "integer", "description": "level One of: 1, 2."}

    def test_an_untyped_integer_enum_takes_the_type_its_values_share(self) -> None:
        x = self._parameters(_one({"enum": [1, 2]}))
        assert x == {"type": "integer", "description": "One of: 1, 2."}

    def test_a_null_in_a_string_enum_is_left_out(self) -> None:
        assert self._parameters(_one({"enum": ["a", None]})) == {"enum": ["a"]}

    def test_a_type_with_null_is_an_any_of_the_client_reads_as_nullable(self) -> None:
        tool, _ = _build(_one({"type": ["integer", "null"]}))
        (adapted,) = gemini_tools([tool])
        x = adapted["function"]["parameters"]["properties"]["x"]
        assert x == {"anyOf": [{"type": "integer"}, {"type": "null"}]}
        ((declarations,),) = [
            t.function_declarations for t in convert_to_genai_function_declarations([adapted])
        ]
        read = declarations.parameters.properties["x"]
        assert (read.type.name, read.nullable) == ("INTEGER", True)

    def test_data_values_are_never_rewritten(self) -> None:
        # ``default``, ``examples`` and ``const`` hold values, not schemas: an
        # ``enum`` or a type list inside one is the server's data.
        data = {"enum": [1, None], "type": ["integer", "null"]}
        field = {
            "type": "object",
            "properties": {"level": {"type": "integer", "enum": [1, 2]}},
            "default": data,
            "examples": [data],
        }
        tool, _ = _build(_one(field))
        (adapted,) = gemini_tools([tool])
        x = adapted["function"]["parameters"]["properties"]["x"]
        assert x["default"] == data
        assert x["examples"] == [data]
        assert x["properties"]["level"] == {"type": "integer", "description": "One of: 1, 2."}
        tool, _ = _build(_one({"const": data}))
        assert gemini_tools([tool])[0] is tool

    def test_a_tool_that_needs_nothing_is_passed_as_it_was(self) -> None:
        tool, _ = _build(_one({"type": "string", "enum": ["a", "b"]}))
        google_search = {"google_search": {}}
        assert gemini_tools([tool, google_search]) == [tool, google_search]
        assert gemini_tools([tool])[0] is tool

    def test_the_gemini_client_binds_through_the_adaptation(self) -> None:
        from langchain_google_genai import ChatGoogleGenerativeAI

        from maljan.llm.gemini_provider import _with_gemini_tool_schemas

        tool, _ = _build(_one({"type": "integer", "enum": [1, 2]}))
        chat_class = _with_gemini_tool_schemas(ChatGoogleGenerativeAI)
        assert _with_gemini_tool_schemas(ChatGoogleGenerativeAI) is chat_class
        # The client keeps what it is bound and converts it per request; no
        # request is made here.
        plain = ChatGoogleGenerativeAI(model="gemini-probe", google_api_key="probe-key")
        with pytest.raises(ValueError):
            convert_to_genai_function_declarations(plain.bind_tools([tool]).kwargs["tools"])
        chat = chat_class(model="gemini-probe", google_api_key="probe-key")
        convert_to_genai_function_declarations(chat.bind_tools([tool]).kwargs["tools"])
