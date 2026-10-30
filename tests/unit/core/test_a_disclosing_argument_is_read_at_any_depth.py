"""A path or the file's content is read as disclosing at any depth of an argument's schema.

The disclosure reading (``core.derived_declarations``) walks every argument an
untrusted server lists, through nested objects, local references, alternatives,
array items and every other keyword that holds a schema, to any depth:

* a path or content argument three to six objects down is read as sending the
  sample, however the levels are written;
* the walk keeps to its caps (schemas read, schemas waiting, references one
  chain follows) and to its cycle guard, and grows with the schema's size;
* where it stops at a cap, the tool is read as sending whenever what it left
  unread could take a path or the file's content, never as safe; so is an
  argument whose reference cannot be followed, and an untrusted server's
  argument named in letters NFKC does not bring to ASCII;
* the shipped Ghidra, radare2 and VirusTotal listings read as they did.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.conftest import ghidra_listing, r2_listing
from tests.linear_cost import assert_scales

from maljan.core import derived_declarations as dd
from maljan.core.derived_declarations import discloses, program_readings_of
from maljan.core.tool_declarations import THIRD_PARTY_BYTES

PATH_LEAF = {"path": {"type": "string"}}
CONTENT_LEAF = {"blob": {"type": "string", "contentEncoding": "base64"}}
QUIET_LEAF = {"count": {"type": "integer"}, "query": {"type": "string"}}
FIXTURES = Path(__file__).parents[2] / "fixtures"
VT_LISTING = FIXTURES / "virustotal_listing.json"
PINNED = FIXTURES / "tools" / "disclosure_readings_pinned.json"


def _tool(schema: dict[str, Any], **hints: Any) -> dict[str, Any]:
    return {"name": "scan", "description": "", "inputSchema": schema, "annotations": hints}


def _by_properties(depth: int, leaf: dict[str, Any]) -> dict[str, Any]:
    """``leaf``'s arguments ``depth`` objects below the root, each level a plain property."""
    node: dict[str, Any] = {"type": "object", "properties": leaf}
    for level in range(depth - 1):
        node = {"type": "object", "properties": {f"level{level}": node}}
    return node


def _by_forms(depth: int, leaf: dict[str, Any]) -> dict[str, Any]:
    """``leaf``'s arguments ``depth`` objects below the root, each level behind a reference,
    an ``anyOf`` member or an array's items in turn."""
    defs: dict[str, Any] = {}
    node: dict[str, Any] = {"type": "object", "properties": leaf}
    for level in range(depth - 1):
        way = level % 3
        if way == 0:
            defs[f"L{level}"] = node
            held: dict[str, Any] = {"$ref": f"#/$defs/L{level}"}
        elif way == 1:
            held = {"anyOf": [{"type": "null"}, node]}
        else:
            held = {"type": "array", "items": node}
        node = {"type": "object", "properties": {f"level{level}": held}}
    return {**node, "$defs": defs}


@pytest.mark.parametrize("depth", [3, 4, 5, 6])
@pytest.mark.parametrize("build", [_by_properties, _by_forms], ids=["properties", "forms"])
@pytest.mark.parametrize("leaf", [PATH_LEAF, CONTENT_LEAF], ids=["path", "content"])
def test_a_deep_path_or_content_argument_is_read_as_sending(
    depth: int, build: Any, leaf: dict[str, Any]
) -> None:
    assert discloses(_tool(build(depth, leaf)))


@pytest.mark.parametrize("depth", [3, 4, 5, 6])
@pytest.mark.parametrize("build", [_by_properties, _by_forms], ids=["properties", "forms"])
def test_deep_content_is_read_as_sending_whatever_an_untrusted_server_s_hints(
    depth: int, build: Any
) -> None:
    closed = {"readOnlyHint": True, "openWorldHint": False}
    assert discloses(_tool(build(depth, CONTENT_LEAF), **closed))
    # A trusted server's own read-only and closed marks lift it, as at the top.
    assert not discloses(_tool(build(depth, CONTENT_LEAF), **closed), trusted=True)


@pytest.mark.parametrize("depth", [3, 6])
def test_a_program_tool_that_takes_deep_content_sends_its_bytes(depth: int) -> None:
    definition = {**_tool(_by_forms(depth, CONTENT_LEAF)), "name": "load_bytes"}
    facts = program_readings_of([definition])["load_bytes"]
    assert facts.effects is not None
    assert facts.effects.third_party == THIRD_PARTY_BYTES


@pytest.mark.parametrize("depth", [3, 6, 40])
@pytest.mark.parametrize("build", [_by_properties, _by_forms], ids=["properties", "forms"])
def test_a_deep_argument_that_takes_no_file_is_read_as_nothing(depth: int, build: Any) -> None:
    assert not discloses(_tool(build(depth, QUIET_LEAF)))


def test_a_definition_shared_by_many_arguments_is_read_once_per_argument() -> None:
    # Two arguments at every level reach the next definition: 2**60 ways down,
    # read in a few hundred steps, the path at the bottom included.
    levels = 60
    defs: dict[str, Any] = {f"D{levels}": {"type": "object", "properties": PATH_LEAF}}
    for level in range(levels - 1, -1, -1):
        to = {"$ref": f"#/$defs/D{level + 1}"}
        defs[f"D{level}"] = {"type": "object", "properties": {"left": to, "right": to}}
    schema = {"$ref": "#/$defs/D0", "$defs": defs}
    arguments, unread = dd._walk(schema)
    assert not unread
    assert len(arguments) <= 2 * (levels + 1)
    assert discloses(_tool(schema))
    defs[f"D{levels}"] = {"type": "object", "properties": QUIET_LEAF}
    assert not discloses(_tool(schema))


def test_a_cycle_through_properties_ends_and_reads_what_it_holds() -> None:
    schema = {
        "type": "object",
        "properties": {"node": {"$ref": "#/$defs/N"}},
        "$defs": {
            "N": {
                "type": "object",
                "properties": {"next": {"$ref": "#/$defs/N"}, "label": {"type": "string"}},
            }
        },
    }
    assert not discloses(_tool(schema))
    schema["$defs"]["N"]["properties"]["file"] = {"type": "string"}
    assert discloses(_tool(schema))


def test_a_schema_deeper_than_the_cap_fails_closed() -> None:
    # Nothing it reads takes the file, but the walk stops with objects unread.
    schema = _by_properties(dd._MAX_ARGUMENTS * 4, QUIET_LEAF)
    _arguments, unread = dd._walk(schema)
    assert unread
    assert discloses(_tool(schema, readOnlyHint=True, openWorldHint=False), trusted=True)


def test_a_schema_wider_than_the_cap_fails_closed_only_where_the_rest_could_carry() -> None:
    wide = dd._MAX_ARGUMENTS * 8
    quiet = {f"n{i}": {"type": "integer"} for i in range(wide)}
    assert not discloses(_tool({"type": "object", "properties": quiet}))
    # A path's name past the cap, unread, is still read by its name. Listed
    # first, it is the last the walk would reach, so it is among the unread.
    with_path = {"path": {"type": "string"}, **quiet}
    arguments, unread = dd._walk({"type": "object", "properties": with_path})
    assert unread
    assert "path" not in {name for name, _schema in arguments}
    assert discloses(_tool({"type": "object", "properties": with_path}))
    # An object past the cap could hold anything: read as sending.
    with_object = {**quiet, "more": {"type": "object", "properties": QUIET_LEAF}}
    assert discloses(_tool({"type": "object", "properties": with_object}))
    # As many alternatives of one argument as the cap, and one more holding an object.
    members = [{"type": "integer"} for _ in range(wide)]
    alternatives = {"type": "object", "properties": {"limit": {"anyOf": members}}}
    assert not discloses(_tool(alternatives))
    members.append({"type": "object", "properties": QUIET_LEAF})
    assert discloses(_tool(alternatives))


def test_an_argument_past_the_reference_cap_fails_closed() -> None:
    def chain(length: int) -> dict[str, Any]:
        defs: dict[str, Any] = {f"R{length}": {"type": "string"}}
        for i in range(length):
            defs[f"R{i}"] = {"$ref": f"#/$defs/R{i + 1}"}
        return {
            "type": "object",
            "properties": {"query": {"$ref": "#/$defs/R0"}},
            "$defs": defs,
        }

    assert not discloses(_tool(chain(dd._MAX_REFERENCES - 1)))
    assert discloses(_tool(chain(dd._MAX_REFERENCES + 8)))


def test_the_walk_grows_with_the_schema_s_size() -> None:
    # Within the caps: a chain of nested objects, read whole.
    def deep(size: int) -> Any:
        definition = _tool(_by_forms(size, QUIET_LEAF))
        return lambda: [discloses(definition) for _ in range(20)]

    assert_scales(deep, 40)

    # Past them: one object of many arguments, read to the cap and the rest by name.
    def wide(size: int) -> Any:
        props = {f"n{i}": {"type": "integer"} for i in range(size)}
        definition = _tool({"type": "object", "properties": props})
        return lambda: [discloses(definition) for _ in range(5)]

    assert_scales(wide, 2000)


def _shipped() -> dict[str, list[dict[str, Any]]]:
    return {
        "ghidra": ghidra_listing(),
        "r2": r2_listing(),
        "virustotal": json.loads(VT_LISTING.read_text())["tools"],
    }


def test_the_shipped_listings_are_read_whole() -> None:
    for source, definitions in _shipped().items():
        for definition in definitions:
            _arguments, unread = dd._walk(definition.get("inputSchema"))
            assert not unread, (source, definition.get("name"))


def test_the_shipped_listings_read_as_pinned() -> None:
    # Pinned from the depth-two walk: reading deeper finds nothing new in them.
    pinned = json.loads(PINNED.read_text())
    for source, definitions in _shipped().items():
        read = {d["name"]: [discloses(d), discloses(d, trusted=True)] for d in definitions}
        assert read == pinned[source]["discloses"], source
        assert repr(program_readings_of(definitions)) == pinned[source]["program_readings"], source


def _with_ref(ref: dict[str, Any], **defs: Any) -> dict[str, Any]:
    return {"type": "object", "properties": {"opts": ref}, "$defs": defs}


@pytest.mark.parametrize(
    "ref",
    [
        "https://example.invalid/schema.json",
        "other.json#/$defs/S",
        "#/$defs/Missing",
        "#NoSuchAnchor",
        "#/$defs/S/properties/count/type",
    ],
    ids=["remote", "relative", "missing", "missing-anchor", "not-a-schema"],
)
def test_an_argument_whose_reference_cannot_be_followed_fails_closed(ref: str) -> None:
    schema = _with_ref({"$ref": ref}, S={"type": "object", "properties": QUIET_LEAF})
    arguments, unread = dd._walk(schema)
    assert unread
    # Its name is kept, so the name rules still read it.
    assert "opts" in {name for name, _schema in arguments}
    assert discloses(_tool(schema, readOnlyHint=True, openWorldHint=False), trusted=True)


def test_a_dynamic_reference_is_never_followed_and_fails_closed() -> None:
    schema = _with_ref({"$dynamicRef": "#/$defs/S"}, S={"type": "object", "properties": QUIET_LEAF})
    assert dd._walk(schema)[1]
    assert discloses(_tool(schema))


@pytest.mark.parametrize(
    ("ref", "defs"),
    [
        ("#/$defs/a%20b", {"a b": {"type": "object", "properties": PATH_LEAF}}),
        ("#/$defs/a~1b", {"a/b": {"type": "object", "properties": PATH_LEAF}}),
        ("#/$defs/a~0b", {"a~b": {"type": "object", "properties": PATH_LEAF}}),
        ("#Holder", {"H": {"$anchor": "Holder", "type": "object", "properties": PATH_LEAF}}),
        ("#/$defs/L/0", {"L": [{"type": "object", "properties": PATH_LEAF}]}),
    ],
    ids=["percent", "slash", "tilde", "anchor", "list-index"],
)
def test_a_local_reference_is_followed_however_it_is_written(
    ref: str, defs: dict[str, Any]
) -> None:
    schema = _with_ref({"$ref": ref}, **defs)
    assert not dd._walk(schema)[1]
    assert discloses(_tool(schema))
    quiet = json.loads(json.dumps(schema).replace('"path"', '"count"'))
    assert not discloses(_tool(quiet))


def test_a_reference_s_siblings_are_read_beside_its_target() -> None:
    schema = _with_ref(
        {"$ref": "#/$defs/B", "properties": PATH_LEAF}, B={"type": "object", "properties": {}}
    )
    assert discloses(_tool(schema))
    # The root's own reference, beside its properties.
    root = {"$ref": "#/$defs/B", "properties": CONTENT_LEAF, "$defs": {"B": {"type": "object"}}}
    assert discloses(_tool(root))


def test_the_root_reference_ends_where_it_began() -> None:
    schema = {"type": "object", "properties": {"self": {"$ref": "#"}, **QUIET_LEAF}}
    assert dd._walk(schema) == (dd._walk(schema)[0], False)
    assert not discloses(_tool(schema))


def _object(**props: Any) -> dict[str, Any]:
    return {"type": "object", "properties": props}


PATH_OBJECT = {"type": "object", "properties": PATH_LEAF}


@pytest.mark.parametrize(
    "opts",
    [
        {"type": "object", "additionalProperties": {"type": "string", "format": "binary"}},
        {"type": "object", "additionalProperties": PATH_OBJECT},
        {"type": "object", "unevaluatedProperties": PATH_OBJECT},
        {"type": "object", "patternProperties": {"^path$": {"type": "string"}}},
        {"type": "array", "prefixItems": [PATH_OBJECT]},
        {"type": "array", "items": [PATH_OBJECT]},
        {"type": "array", "items": [{"type": "integer"}], "additionalItems": PATH_OBJECT},
        {"type": "array", "contains": PATH_OBJECT},
        {"type": "array", "unevaluatedItems": PATH_OBJECT},
        {"type": "object", "if": {}, "then": PATH_OBJECT},
        {"type": "object", "if": {}, "else": PATH_OBJECT},
        {"type": "object", "if": PATH_OBJECT},
        {"type": "object", "dependentSchemas": {"x": PATH_OBJECT}},
    ],
    ids=[
        "additional-properties-bytes",
        "additional-properties",
        "unevaluated-properties",
        "pattern-properties",
        "prefix-items",
        "tuple-items",
        "additional-items",
        "contains",
        "unevaluated-items",
        "then",
        "else",
        "if",
        "dependent-schemas",
    ],
)
def test_every_keyword_that_holds_a_schema_is_read(opts: dict[str, Any]) -> None:
    assert discloses(_tool(_object(opts=_object(inner=opts))))


def test_not_says_what_an_argument_is_not_and_is_not_read() -> None:
    assert not discloses(_tool(_object(opts={"not": PATH_OBJECT})))


def test_each_alternative_s_chain_of_references_has_its_own_budget() -> None:
    # More sibling references than one chain may follow, each to a quiet
    # object: none is a chain past the cap, so nothing is left unread.
    many = dd._MAX_REFERENCES + 8
    schema = {
        "type": "object",
        "properties": {"query": {"anyOf": [{"$ref": f"#/$defs/D{i}"} for i in range(many)]}},
        "$defs": {f"D{i}": {"type": "object", "properties": QUIET_LEAF} for i in range(many)},
    }
    assert not dd._walk(schema)[1]
    closed = {"readOnlyHint": True, "openWorldHint": False}
    assert not discloses(_tool(schema, **closed), trusted=True)
    assert not discloses(_tool(schema, **closed))


def test_a_name_is_read_nfkc_normalised_and_a_foreign_one_fails_closed() -> None:
    full_width = "".join(chr(0xFF00 + ord(c) - 0x20) for c in "path")
    assert discloses(_tool(_object(opts=_object(**{full_width: {"type": "string"}}))))
    # A Cyrillic letter in place of a Latin one: NFKC leaves it as it is.
    look_alike = "pаth"
    definition = _tool(
        _object(opts=_object(**{look_alike: {"type": "string"}})), openWorldHint=False
    )
    assert discloses(definition)
    assert not discloses(definition, trusted=True)


@pytest.mark.parametrize(
    ("opts", "sends"),
    [
        ({"type": "object", "additionalProperties": {"type": "string"}}, True),
        ({"type": "object", "unevaluatedProperties": {"type": "string"}}, True),
        ({"type": "object", "additionalProperties": {"anyOf": [{"type": "string"}]}}, True),
        ({"type": "object", "additionalProperties": {"type": "integer"}}, False),
        ({"type": "object", "additionalProperties": {"type": ["number", "null"]}}, False),
        ({"type": "object", "patternProperties": {"^x.*$": {"type": "string"}}}, True),
        ({"type": "object", "patternProperties": {"[a-z]+": {"type": "boolean"}}}, False),
        # An anchored literal names its one argument, read by the name rules.
        ({"type": "object", "patternProperties": {"^count$": {"type": "string"}}}, False),
        # A free-form map says nothing of its keys: read by its own name.
        ({"type": "object", "additionalProperties": True}, False),
        ({"type": "object", "additionalProperties": {}}, False),
        ({"type": "object", "additionalProperties": False}, False),
    ],
    ids=[
        "additional-string",
        "unevaluated-string",
        "additional-alternative",
        "additional-integer",
        "additional-number-or-null",
        "pattern-string",
        "pattern-boolean",
        "pattern-literal",
        "additional-true",
        "additional-empty",
        "additional-false",
    ],
)
def test_an_argument_with_no_name_of_its_own_fails_closed_unless_its_type_holds_no_file(
    opts: dict[str, Any], sends: bool
) -> None:
    assert discloses(_tool(_object(opts=opts))) is sends


def test_a_true_schema_is_any_value_and_its_name_is_still_read() -> None:
    assert discloses(_tool(_object(opts=_object(path=True))))
    assert not discloses(_tool(_object(opts=_object(query=True, options={"anyOf": [True]}))))
    assert not discloses(_tool(_object(opts={"type": "array", "items": True})))
    # A false schema is no value: nothing to read.
    assert not discloses(_tool(_object(opts={"type": "array", "items": False})))


@pytest.mark.parametrize(
    "opts",
    [
        _object(count=5),
        {"anyOf": "string"},
        {"type": "array", "items": None},
        {"type": "object", "properties": ["path"]},
        {"type": "array", "prefixItems": [1]},
    ],
    ids=["property", "alternatives", "items", "properties", "prefix-item"],
)
def test_a_value_where_a_schema_belongs_that_is_no_schema_fails_closed(
    opts: dict[str, Any],
) -> None:
    schema = _object(opts=opts)
    assert dd._walk(schema)[1]
    assert discloses(_tool(schema, readOnlyHint=True, openWorldHint=False), trusted=True)


def test_an_ambiguous_anchor_fails_closed() -> None:
    quiet = {"type": "object", "properties": QUIET_LEAF}
    single = _with_ref({"$ref": "#A"}, One={**quiet, "$anchor": "A"})
    assert not dd._walk(single)[1]
    assert not discloses(_tool(single))
    # Defined twice: which schema it names is not read.
    twice = _with_ref({"$ref": "#A"}, One={**quiet, "$anchor": "A"}, Two={**quiet, "$anchor": "A"})
    assert dd._walk(twice)[1]
    assert discloses(_tool(twice))
    # Inside an embedded resource, where it is that resource's anchor.
    embedded = _with_ref(
        {"$ref": "#A"},
        Res={"$id": "https://example.invalid/inner", "$defs": {"In": {**quiet, "$anchor": "A"}}},
    )
    assert dd._walk(embedded)[1]
    assert discloses(_tool(embedded))
    # Even from the root itself, with nothing beside the reference.
    root = {"$ref": "#A", "$defs": twice["$defs"]}
    assert dd._walk(root)[1]


@pytest.mark.parametrize(
    "name",
    [
        "pa‍th",  # a zero-width joiner (Cf) between the letters
        "páth",  # a combining accent (Mn)
        "pa\tth",  # a control character (Cc)
        "count•",  # a symbol outside ASCII, no letter
    ],
    ids=["format", "combining", "control", "symbol"],
)
def test_a_name_with_hidden_or_non_ascii_characters_is_foreign(name: str) -> None:
    definition = _tool(_object(opts=_object(**{name: {"type": "string"}})), openWorldHint=False)
    assert discloses(definition)
    assert not discloses(definition, trusted=True)
    # Left unread at a cap, it could carry the file.
    assert dd._could_carry(name, {"type": "string"})


def test_dependencies_schemas_are_read_and_their_lists_are_not() -> None:
    assert discloses(_tool(_object(opts={"type": "object", "dependencies": {"x": PATH_OBJECT}})))
    quiet = {"type": "object", "dependencies": {"x": ["y", "z"], "w": _object(**QUIET_LEAF)}}
    assert not dd._walk(_object(opts=quiet))[1]
    assert not discloses(_tool(_object(opts=quiet)))


@pytest.mark.parametrize(
    ("keyword", "value"),
    [("propertyNames", {"type": "string"}), ("contentSchema", PATH_OBJECT), ("unknown", True)],
)
def test_an_unknown_keyword_that_holds_a_schema_fails_closed(keyword: str, value: Any) -> None:
    schema = _object(opts={"type": "object", keyword: value})
    assert dd._walk(schema)[1]
    assert discloses(_tool(schema, readOnlyHint=True, openWorldHint=False), trusted=True)


def test_annotations_flags_and_vendor_keywords_are_no_schema() -> None:
    opts = {
        "type": "array",
        "title": "Options",
        "default": {"a": 1},
        "examples": [{"a": 1}],
        "const": {"a": 1},
        "readOnly": True,
        "deprecated": False,
        "uniqueItems": True,
        "nullable": True,
        "x-vendor": {"path": {"type": "string"}},
        "$defs": {"Unused": PATH_OBJECT},
        "not": PATH_OBJECT,
        "items": {"type": "integer"},
    }
    assert not dd._walk(_object(opts=opts))[1]
    assert not discloses(_tool(_object(opts=opts)))


@pytest.mark.parametrize(
    "schema",
    [
        {"$ref": "https://example.invalid/schema.json"},
        {"allOf": [{"$ref": "#/$defs/Missing"}], "$defs": {}},
        {"anyOf": [{"$ref": "https://example.invalid/schema.json"}, _object(**QUIET_LEAF)]},
        {"$dynamicRef": "#meta"},
    ],
    ids=["root-remote", "root-all-of-missing", "root-any-of-remote", "root-dynamic"],
)
def test_a_reference_that_cannot_be_followed_fails_closed_at_the_root_too(
    schema: dict[str, Any],
) -> None:
    assert dd._walk(schema)[1]
    assert discloses(_tool(schema, readOnlyHint=True, openWorldHint=False), trusted=True)


def test_the_root_s_own_reference_is_a_cycle_not_a_failure() -> None:
    schema = {"type": "object", "properties": {"next": {"$ref": "#"}, **QUIET_LEAF}}
    assert not dd._walk(schema)[1]


def test_a_reference_inside_an_embedded_resource_fails_closed() -> None:
    quiet = _object(**QUIET_LEAF)
    # Inside a schema with an ``$id`` of its own, ``#/$defs/Q`` names that
    # resource's definition, which this walk does not resolve against.
    inner = {
        "$id": "https://example.invalid/inner",
        "type": "object",
        "properties": {"opts": {"$ref": "#/$defs/Q"}},
        "$defs": {"Q": quiet},
    }
    schema = {"type": "object", "properties": {"req": inner}, "$defs": {"Q": quiet}}
    assert dd._walk(schema)[1]
    assert discloses(_tool(schema))
    # Reached by a pointer through the resource, its references are its own too.
    through = {
        "type": "object",
        "properties": {"req": {"$ref": "#/$defs/Res/$defs/Holder"}},
        "$defs": {
            "Res": {
                "$id": "https://example.invalid/res",
                "$defs": {"Holder": _object(opts={"$ref": "#/$defs/Q"}), "Q": quiet},
            }
        },
    }
    assert dd._walk(through)[1]
    # The root's own ``$id`` opens no embedded resource.
    rooted = {
        "$id": "https://example.invalid/root",
        "type": "object",
        "properties": {"opts": {"$ref": "#/$defs/Q"}},
        "$defs": {"Q": quiet},
    }
    assert not dd._walk(rooted)[1]
    assert not discloses(_tool(rooted))


@pytest.mark.parametrize(
    "pattern",
    ["^pat[h]$", "^(path)$", "^path", "^file_path$|^x$", ".*"],
)
@pytest.mark.parametrize("value", [{}, True], ids=["empty", "true"])
def test_a_pattern_that_is_no_literal_name_fails_closed_whatever_its_value(
    pattern: str, value: Any
) -> None:
    schema = _object(opts={"type": "object", "patternProperties": {pattern: value}})
    assert dd._walk(schema)[1]
    assert discloses(_tool(schema, readOnlyHint=True, openWorldHint=False), trusted=True)


@pytest.mark.parametrize(
    "opts",
    [
        {"type": "object", "required": ["path"], "additionalProperties": {}},
        {"type": "object", "dependentRequired": {"a": ["path"]}, "additionalProperties": {}},
        {"type": "object", "dependencies": {"a": ["path"]}, "additionalProperties": True},
        {"type": "object", "propertyNames": {"const": "path"}, "additionalProperties": {}},
        {"type": "object", "propertyNames": {"enum": ["q", "path"]}, "additionalProperties": {}},
    ],
    ids=["required", "dependent-required", "dependencies", "property-names-const", "-enum"],
)
def test_an_argument_named_outside_properties_is_read_by_its_name(opts: dict[str, Any]) -> None:
    schema = _object(opts=opts)
    assert "path" in {name for name, _schema in dd._walk(schema)[0]}
    assert discloses(_tool(schema))


def test_a_required_name_at_the_root_is_read_and_a_listed_one_is_not_read_twice() -> None:
    assert discloses(_tool({"type": "object", "required": ["path"], "properties": {}}))
    quiet = {"type": "object", "required": ["count"], "properties": QUIET_LEAF}
    assert [name for name, _schema in dd._walk(quiet)[0]].count("count") == 1
    assert not discloses(_tool(quiet))
