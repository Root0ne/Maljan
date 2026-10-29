"""A reputation service is read from what it lists and answers, never from a table of its tools.

The platform ships no declaration of a reputation service's tools: what each
tool is, is read from its MCP definition (``core.derived_declarations``), and a
lookup's answer by its shape (``core.reputation.read_shape``).

* A never-seen server listing tools of the same shapes is read as the built-in
  one is, field by field: kind, argument, effects and ``discloses_sample``.
* Its answer of the same shape gives the same record, and an answer shaped as
  the service's REST report reads the labels, dates, counts and link the
  former declared paths read.
* Disclosure safety holds on every server: a tool that takes the file's
  content as bytes is read as sending the sample unless it is marked both
  read-only and closed; one that takes a path does when it is a write tool
  that reaches out or says it submits; an operator who says what a tool sends
  is never overruled.
* Only a block whose ``roles`` hold ``reputation`` reads the service's kinds.
* What is read is kept past the process beside the server's own declaration,
  and a job lists a reputation service nothing is kept for before its run.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from tests.linear_cost import FLOOR_SECONDS, cpu_seconds

from maljan.analysis.tool_effects import sends_sample_bytes
from maljan.core import served_declarations as sd
from maljan.core.config import Settings
from maljan.core.derived_declarations import (
    derived_tool_facts,
    discloses,
    lay_under,
    service_facts,
)
from maljan.core.reputation import (
    SHAPE_READER,
    _shape_nodes,
    pack_lookups,
    read_answer,
    read_shape,
    reputation_of,
)
from maljan.core.tool_declarations import ToolDeclarations, ToolFacts, launch_identity
from maljan.providers import served_listing
from maljan.providers.served_listing import unlisted as _unlisted

ROOT = Path(__file__).resolve().parents[3]
LISTING = json.loads((ROOT / "tests" / "fixtures" / "virustotal_listing.json").read_text())
ANSWER = json.loads((ROOT / "tests" / "fixtures" / "ledger" / "get_file_report.json").read_text())
FIELDS = ("kind", "arguments", "effects", "discloses_sample", "read_only", "rows")

# The built-in listing's tools, each renamed as a server nobody has seen might
# name it, with the same input schema and annotations.
RENAMED = {
    "get_analysis": "job_state",
    "get_domain_report": "host_intel",
    "get_file_report": "sample_verdict",
    "get_ip_report": "addr_intel",
    "get_submission": "receipt_lookup",
    "get_url_report": "link_intel",
    "submit_file": "push_bytes",
    "submit_local_file": "push_from_disk",
}


def _never_seen() -> list[dict[str, Any]]:
    out = []
    for tool in LISTING["tools"]:
        renamed = dict(tool, name=RENAMED[tool["name"]], description="A tool.")
        out.append(renamed)
    return out


def _dump(facts: ToolFacts | None) -> dict[str, Any]:
    if facts is None:
        return {}
    held = facts.model_dump(mode="json", exclude_defaults=True)
    return {k: held[k] for k in FIELDS if k in held}


def _settings(**servers: dict[str, Any]) -> Settings:
    return Settings.model_validate({"mcp": {"servers": servers}})


@pytest.fixture
def nothing_kept() -> Iterator[None]:
    sd.forget_served()
    sd._UNSAVED.clear()
    yield
    sd.forget_served()
    sd._UNSAVED.clear()


# ---------------------------------------------------------------------------
# A never-seen server reads as the built-in one
# ---------------------------------------------------------------------------


def test_a_never_seen_service_s_tools_read_as_the_built_in_s_field_by_field() -> None:
    builtin = derived_tool_facts(LISTING["tools"])
    theirs = derived_tool_facts(_never_seen())
    assert set(builtin) == set(RENAMED)
    for name, renamed in RENAMED.items():
        # Descriptions said nothing either way: the shapes and hints decide.
        assert _dump(theirs.get(renamed)) == _dump(builtin.get(name)), name


def test_the_built_in_listing_reads_as_its_former_declaration_did() -> None:
    from maljan.core.declared_reading import legacy_by_name

    former = legacy_by_name()
    read = derived_tool_facts(LISTING["tools"])
    for name, facts in read.items():
        dumped = _dump(facts)
        # Beyond the former declaration, and only that: a report on an
        # indicator names the argument it requires each indicator in.
        if facts.kind == "indicator_report":
            added = dumped.pop("arguments")
            assert added and set(added) <= {"domain", "ip", "url"}, name
        assert dumped == _dump(former[name]), name


def test_a_never_seen_lookup_s_answer_gives_the_same_record() -> None:
    builtin = derived_tool_facts(LISTING["tools"])["get_file_report"]
    theirs = derived_tool_facts(_never_seen())["sample_verdict"]
    output = json.dumps(ANSWER)
    one = read_answer(builtin, output=output, server="VirusTotal MCP")
    other = read_answer(theirs, output=output, server="Acme Intel")
    assert one == other
    assert (one.service, one.malicious, one.total, one.engines) == ("VirusTotal", 52, 75, 75)
    assert one.last_seen == "2026-08-23T08:03:36Z" and one.link and one.detections


# The service's REST shape, and the paths the former declaration read it by.
FORMER_PATHS = {
    "service": "VirusTotal",
    "stats": "/**7/last_analysis_stats",
    "malicious": "/**7/last_analysis_stats/malicious",
    "suspicious": "/**7/last_analysis_stats/suspicious",
    "labels": [
        "/**7/popular_threat_classification/suggested_threat_label",
        "/**7/popular_threat_classification/popular_threat_name/*/value",
        "/**7/popular_threat_classification/popular_threat_category/*/value",
    ],
    "detections": "/**7/detections",
    "engines": "/**7/coverage/engines",
    "first_seen": ["/**7/first_submission_date", "/**7/first_seen_itw_date"],
    "last_seen": ["/**7/last_analysis_date", "/**7/analysis_date", "/**7/last_submission_date"],
    "link": ["/**7/report_url", "/**7/gui_url", "/**7/permalink", "/**7/html_url"],
}
REST_ANSWER = {
    "data": {
        "id": "6091f2589fef42e0ab3d7975806cd8a0da012b519637c03b73f702f7586b21ef",
        "type": "file",
        "links": {"self": "https://example.invalid/api/v3/files/6091"},
        "attributes": {
            "source": "VirusTotal",
            "first_seen_itw_date": 1717200000,
            "first_submission_date": 1717113600,
            "last_submission_date": 1724371200,
            "last_analysis_date": 1724400216,
            "last_modification_date": 1729000000,
            "total_votes": {"harmless": 0, "malicious": 3},
            "last_analysis_stats": {
                "malicious": 52,
                "suspicious": 1,
                "undetected": 15,
                "harmless": 0,
                "timeout": 1,
            },
            "popular_threat_classification": {
                "suggested_threat_label": "trojan.latrodectus/icedid",
                "popular_threat_category": [{"count": 30, "value": "trojan"}],
                "popular_threat_name": [
                    {"count": 20, "value": "latrodectus"},
                    {"count": 9, "value": "icedid"},
                ],
            },
            "names": ["a.dll"],
            "tags": ["peexe", "64bits"],
            "gui_url": "https://example.invalid/gui/file/6091",
        },
    }
}


def test_a_rest_shaped_answer_reads_the_labels_dates_and_counts_the_former_paths_read() -> None:
    former = ToolFacts.model_validate({"kind": "reputation", "reputation": FORMER_PATHS})
    read = derived_tool_facts(LISTING["tools"])["get_file_report"]
    output = json.dumps(REST_ANSWER)
    old = read_answer(former, output=output)
    new = read_answer(read, output=output, server="VirusTotal MCP")
    assert new == old
    assert new.labels == ["trojan.latrodectus/icedid", "latrodectus", "icedid", "trojan"]
    assert (new.first_seen, new.last_seen) == ("2024-05-31T00:00:00Z", "2024-08-23T08:03:36Z")
    assert (new.malicious, new.suspicious, new.total) == (52, 1, 69)


def test_first_seen_is_the_earliest_date_and_last_seen_the_latest() -> None:
    # Where the service saw the file in the wild before anyone submitted it,
    # first seen is that date; a later submission is when it was last seen.
    answer = json.loads(json.dumps(REST_ANSWER))
    held = answer["data"]["attributes"]
    held["first_seen_itw_date"] = 1700000000
    held["last_submission_date"] = 1726000000
    shape = read_shape(answer)
    assert shape.first_seen == "2023-11-14T22:13:20Z"
    assert shape.last_seen == "2024-09-10T20:26:40Z"


def test_the_counts_are_the_engine_tally_never_a_vote() -> None:
    shape = read_shape(REST_ANSWER)
    assert shape.stats["undetected"] == 15 and shape.malicious == 52
    assert shape.service == "VirusTotal"
    assert shape.link == "https://example.invalid/gui/file/6091"


def test_a_vote_alone_is_no_count() -> None:
    votes = {"data": {"attributes": {"total_votes": {"harmless": 0, "malicious": 3}}}}
    assert read_shape(votes).malicious is None
    # Nor is a vote however many numbers it holds, nor a pair of counts.
    many = {"votes": {"malicious": 3, "harmless": 1, "a": 1, "b": 2}}
    assert read_shape(many).malicious is None
    assert read_shape({"stats": {"malicious": 3, "harmless": 1}}).malicious is None


def test_the_tally_counting_verdicts_wins_over_one_counting_other_things() -> None:
    answer = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 0, "undetected": 60, "harmless": 0},
                "crowdsourced_ids_stats": {"malicious": 9, "high": 1, "low": 0, "a": 1, "b": 2},
            }
        }
    }
    shape = read_shape(answer)
    assert (shape.malicious, shape.stats["undetected"]) == (0, 60)


def test_the_shape_reading_is_bounded() -> None:
    deep: Any = {"last_analysis_stats": {"malicious": 1, "harmless": 2, "undetected": 3}}
    for _ in range(40):
        deep = {"x": deep}
    assert read_shape(deep).malicious is None
    wide = {"rows": [{"k": i} for i in range(100_000)], "stats": {"malicious": 1, "a": 2}}
    assert read_shape(wide).malicious is None
    # A flat object of millions of members, and as many list items, read in
    # bounded time: the walk stops at ``SHAPE_NODES``.
    from maljan.core.reputation import SHAPE_NODES

    flat = {f"k{i}": i for i in range(1_000_000)}
    flat["malicious"] = 1
    listed = [[i] for i in range(1_000_000)]
    read_shape({"x": flat, "y": listed})
    # The walk stops at ``SHAPE_NODES``, so twenty-five times the document costs
    # a few times what a document twice that cap does (the size is read once);
    # a reader that went on to the end would cost twenty-five times as much.
    capped = {"x": dict(list(flat.items())[: 2 * SHAPE_NODES]), "y": listed[: 2 * SHAPE_NODES]}
    whole = {"x": flat, "y": listed}
    assert cpu_seconds(lambda: read_shape(whole)) < 12 * max(
        cpu_seconds(lambda: read_shape(capped)), FLOOR_SECONDS
    )
    assert len(_shape_nodes({"x": flat})) <= SHAPE_NODES


# ---------------------------------------------------------------------------
# Disclosure safety, on every server
# ---------------------------------------------------------------------------


def _tool(name: str, props: dict[str, Any], **hints: Any) -> dict[str, Any]:
    return {
        "name": name,
        "description": "",
        "inputSchema": {"type": "object", "properties": props, "required": list(props)},
        **({"annotations": hints} if hints else {}),
    }


BYTES = {"blob": {"type": "string"}}
ENCODED = {"data": {"type": "string", "contentEncoding": "base64"}}
PATH = {"path": {"type": "string"}}


@pytest.mark.parametrize(
    ("props", "hints", "sends"),
    [
        (BYTES, {}, True),
        (ENCODED, {}, True),
        (BYTES, {"readOnlyHint": True}, True),
        (BYTES, {"openWorldHint": False}, True),
        (BYTES, {"readOnlyHint": True, "openWorldHint": False}, True),
        (PATH, {"readOnlyHint": False, "openWorldHint": True}, True),
        (PATH, {"readOnlyHint": True, "openWorldHint": True}, True),
        (PATH, {"readOnlyHint": True}, True),
        (PATH, {}, True),
        (PATH, {"openWorldHint": False}, False),
        ({"file": {"type": "string"}}, {}, True),
        ({"local_file": {"type": "string"}}, {}, True),
        ({"req": {"type": "object", "properties": PATH}}, {}, True),
        ({"file_b64": {"type": "string"}}, {"readOnlyHint": True}, True),
        ({"q": {"type": "string"}}, {}, False),
        ({"file_hash": {"type": "string"}}, {}, False),
    ],
)
def test_a_tool_that_takes_the_file_is_read_as_sending_it(
    props: dict[str, Any], hints: dict[str, Any], sends: bool
) -> None:
    assert discloses(_tool("t", props, **hints)) is sends


def _with_schema(name: str, schema: dict[str, Any], **hints: Any) -> dict[str, Any]:
    return {"name": name, "description": "", "inputSchema": schema, "annotations": hints}


@pytest.mark.parametrize(
    ("schema", "sends"),
    [
        # A model argument behind a local reference, as FastMCP lists one.
        (
            {
                "type": "object",
                "properties": {"req": {"$ref": "#/$defs/R"}},
                "$defs": {"R": {"type": "object", "properties": {"path": {"type": "string"}}}},
            },
            True,
        ),
        (
            {
                "type": "object",
                "properties": {"req": {"$ref": "#/definitions/R"}},
                "definitions": {
                    "R": {"type": "object", "properties": {"file": {"type": "string"}}}
                },
            },
            True,
        ),
        # An alternative of the argument's own schema.
        (
            {
                "type": "object",
                "properties": {"target": {"anyOf": [{"type": "string", "format": "path"}]}},
            },
            True,
        ),
        # A list of paths, by its items' format, or by its plural name.
        (
            {
                "type": "object",
                "properties": {
                    "inputs": {"type": "array", "items": {"type": "string", "format": "path"}}
                },
            },
            True,
        ),
        ({"type": "object", "properties": {"files": {"type": "array"}}}, True),
        ({"type": "object", "properties": {"samples": {"type": "array"}}}, True),
        ({"type": "object", "properties": {"paths": {"type": "array"}}}, True),
        # A reference that resolves nowhere, and a cycle, read as nothing more.
        ({"type": "object", "properties": {"req": {"$ref": "#/$defs/Missing"}}}, False),
        (
            {
                "type": "object",
                "properties": {"req": {"$ref": "#/$defs/A"}},
                "$defs": {"A": {"$ref": "#/$defs/B"}, "B": {"$ref": "#/$defs/A"}},
            },
            False,
        ),
    ],
    ids=[
        "defs-ref",
        "definitions-ref",
        "any-of-format",
        "items-format",
        "files",
        "samples",
        "paths",
        "unresolved-ref",
        "ref-cycle",
    ],
)
def test_every_schema_form_of_an_argument_is_read(schema: dict[str, Any], sends: bool) -> None:
    assert discloses(_with_schema("scan", schema, readOnlyHint=True)) is sends


def test_a_tool_that_says_it_uploads_content_sends_it_whatever_its_hints() -> None:
    closed = {"readOnlyHint": True, "openWorldHint": False, "destructiveHint": False}
    upload = _tool("upload_sample", {"content_base64": {"type": "string"}}, **closed)
    assert discloses(upload)
    assert service_facts(upload)["discloses_sample"] is True
    # Without the word, only a trusted server's hints lift it.
    render = _tool("render", {"content_base64": {"type": "string"}}, **closed)
    assert discloses(render) and not discloses(render, trusted=True)
    assert discloses(upload, trusted=True)


@pytest.mark.parametrize(
    ("name", "sends"),
    [
        ("file_data", True),
        ("sample_body", True),
        ("fileData", True),
        ("data", False),
        ("body", False),
    ],
)
def test_data_or_a_body_is_content_only_beside_a_file_s_word(name: str, sends: bool) -> None:
    assert discloses(_tool("t", {name: {"type": "string"}}, readOnlyHint=True)) is sends


@pytest.mark.parametrize("name", ["submit", "upload_artifact", "send"])
def test_a_write_tool_that_says_it_submits_sends_whatever_it_takes(name: str) -> None:
    # The sample may go by an id or a hash the rule cannot see.
    by_id = _tool(name, {"hash_or_url_id": {"type": "string"}})
    said = dict(by_id, description="Submits the object for analysis.")
    assert discloses(said)
    assert service_facts(said)["discloses_sample"] is True
    # Marked read-only, it says it changes nothing: only what it takes decides.
    assert not discloses(dict(said, annotations={"readOnlyHint": True}))


@pytest.mark.parametrize("name", ["hash_file_path", "sample_sha_path", "md5_path"])
def test_a_path_s_word_wins_over_a_hash_s(name: str) -> None:
    tool = _tool("t", {name: {"type": "string"}}, readOnlyHint=True)
    assert discloses(tool)
    assert service_facts(tool)["kind"] == "submission"


def test_only_a_trusted_server_s_hints_lift_the_reading_of_bytes_it_takes(
    nothing_kept: None,
) -> None:
    from maljan.core.derived_declarations import closed_by_hints

    closed = _tool("render", BYTES, readOnlyHint=True, openWorldHint=False)
    assert discloses(closed) and not discloses(closed, trusted=True)
    assert set(closed_by_hints([closed])) == {"render"}
    read = derived_tool_facts([closed])
    for trusts, sends in ((False, True), (True, False)):
        settings = _settings(mine={"command": "x", "trusts_served_declaration": trusts})
        block = settings.mcp.servers["mine"]
        sd.register_served("mcp:mine", {}, launch_identity(block), read, closed_by_hints([closed]))
        held = ToolDeclarations.from_settings(settings).source("mcp:mine")
        assert held is not None
        assert sends_sample_bytes(held.tools.get("render")) is sends, trusts
    # A path keeps its rule: closed lifts it on any server.
    assert not discloses(_tool("open", PATH, openWorldHint=False))
    # And the set is kept with the reading past the process.
    [(source, launch, raw, _ships)] = [r for r in sd.unsaved() if r[0] == "mcp:mine"]
    sd.forget_served()
    sd._UNSAVED.clear()
    sd.install_persisted(json.loads(json.dumps([(source, launch, raw)])))
    assert set(sd.closed_by_hints("mcp:mine", launch)) == {"render"}


@pytest.mark.parametrize("name", ["submitFile", "uploadSample", "upload-sample", "Submit Sample"])
def test_a_name_s_words_say_it_submits_however_it_is_written(name: str) -> None:
    assert discloses(_tool(name, {"ref_id": {"type": "string"}}))
    assert not discloses(_tool("resubmitter", {"ref_id": {"type": "string"}}, readOnlyHint=True))


def test_a_definition_that_cannot_be_read_is_read_as_sending_the_sample() -> None:
    class Unreadable(dict):  # type: ignore[type-arg]
        def get(self, key: Any, default: Any = None) -> Any:
            raise RuntimeError("unreadable")

    odd = {"name": "odd", "inputSchema": Unreadable(type="object")}
    read = derived_tool_facts([odd, _tool("t", {"q": {"type": "string"}}, readOnlyHint=True)])
    assert read["odd"].discloses_sample is True


def test_a_listing_that_cannot_be_read_keeps_what_was_read_before(
    nothing_kept: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.agents import mcp_client
    from maljan.core import derived_declarations

    before = derived_tool_facts(LISTING["tools"])
    sd.register_served("mcp:svc", {}, "L", before)

    def _fails(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("no reading")

    monkeypatch.setattr(derived_declarations, "derived_readings", _fails)
    toolkit = object.__new__(mcp_client.MCPLangChainToolkit)
    monkeypatch.setattr(toolkit, "_server_name", lambda: "svc", raising=False)
    assert toolkit._derived_readings(LISTING["tools"])[0] is None
    # The handle passes the failed reading on as none: what was kept stays.
    sd.register_served("mcp:svc", {}, "L", None)
    assert sd.derived("mcp:svc", "L") == before


def test_the_pack_asks_only_a_ticked_tool(nothing_kept: None) -> None:
    lookups_listed = [
        _tool("verdict", {"hash": {"type": "string"}}, readOnlyHint=True, destructiveHint=False),
        _tool("second", {"sha256": {"type": "string"}}, readOnlyHint=True, destructiveHint=False),
    ]
    ticked = {
        "transport": "streamable-http",
        "url": "https://intel.example.invalid/mcp",
        "roles": ["reputation"],
        "enabled": True,
        "tools": ["verdict"],
    }
    for tools, expected in ((["verdict"], ["verdict"]), (["unrelated"], [])):
        settings = _settings(acme={**ticked, "tools": tools})
        block = settings.mcp.servers["acme"]
        read = derived_tool_facts(lookups_listed)
        sd.register_served("mcp:acme", {}, launch_identity(block), read)
        lookups = pack_lookups(settings.mcp.servers, ToolDeclarations.from_settings(settings))
        assert [x.tool for x in lookups if x.server == "acme"] == expected, tools
        # The second, unticked lookup is never the pack's call.
        assert "second" not in [x.tool for x in lookups]


@pytest.mark.parametrize(
    "definition",
    [
        {
            "name": "get_task_report",
            "description": "Returns the report of a submitted task.",
            "inputSchema": {"type": "object", "properties": {"task_id": {"type": "integer"}}},
        },
        {
            "name": "list_uploads",
            "description": "List files uploaded by users.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "search",
            "description": "Search samples submitted to the service by hash",
            "inputSchema": {
                "type": "object",
                "properties": {"hash": {"type": "string"}},
                "required": ["hash"],
            },
        },
    ],
    ids=["past-submitted", "noun-uploads", "search-submitted"],
)
def test_what_others_submitted_or_uploaded_is_not_a_submission(
    definition: dict[str, Any],
) -> None:
    assert not discloses(definition)


def test_a_trusted_service_reads_a_closed_bytes_tool_as_what_it_is(nothing_kept: None) -> None:
    from maljan.core.derived_declarations import closed_by_hints

    scan = _tool(
        "scan_bytes",
        {"content_base64": {"type": "string"}},
        readOnlyHint=True,
        openWorldHint=False,
        destructiveHint=False,
    )
    read = derived_tool_facts([scan])
    assert read["scan_bytes"].kind == "submission" and read["scan_bytes"].discloses_sample
    lifted = closed_by_hints([scan])
    assert service_facts(scan, trusted=True) == {}
    held = lay_under({}, read, roles=("reputation",), closed=lifted)
    # Read as the read-only tool it is: no submission, no sandbox, no upload.
    assert "scan_bytes" not in held or not (
        held["scan_bytes"].kind == "submission" or sends_sample_bytes(held["scan_bytes"])
    )
    # Untrusted, the same block reads it as sending its bytes.
    assert sends_sample_bytes(lay_under({}, read, roles=("reputation",))["scan_bytes"])


@pytest.mark.parametrize(
    "claim",
    [{"effects": {"network": True}}, {"discloses_sample": True}],
    ids=["network-claim", "disclosure-claim"],
)
def test_an_untrusted_claim_never_costs_the_service_s_rank(
    claim: dict[str, Any], nothing_kept: None
) -> None:
    settings = Settings(_env_file=None)
    servers = dict(settings.mcp.servers)
    stored = {
        "kind": "reputation",
        "arguments": {"hash": "hash"},
        "reputation": {"stats": "/**7/last_analysis_stats"},
    }
    servers["virustotal"] = servers["virustotal"].model_copy(
        update={
            "enabled": True,
            "tool_facts": {"get_file_report": ToolFacts.model_validate(stored)},
        }
    )
    settings = settings.model_copy(
        update={"mcp": settings.mcp.model_copy(update={"servers": servers})}
    )
    block = settings.mcp.servers["virustotal"]
    served = {"get_file_report": ToolFacts.model_validate(claim)}
    sd.register_served(
        "mcp:virustotal", served, launch_identity(block), derived_tool_facts(LISTING["tools"])
    )
    lookups = pack_lookups(settings.mcp.servers, ToolDeclarations.from_settings(settings))
    assert [(x.server, x.rank) for x in lookups][0] == ("virustotal", 10)


def test_a_service_named_alone_keeps_the_shape_reader() -> None:
    settings = Settings(_env_file=None)
    servers = dict(settings.mcp.servers)
    stored = {"kind": "reputation", "arguments": {"hash": "hash"}, "reputation": {"service": "VT"}}
    servers["virustotal"] = servers["virustotal"].model_copy(
        update={
            "enabled": True,
            "tool_facts": {"get_file_report": ToolFacts.model_validate(stored)},
        }
    )
    settings = settings.model_copy(
        update={"mcp": settings.mcp.model_copy(update={"servers": servers})}
    )
    held = ToolDeclarations.from_settings(settings).declaration_for(
        ("mcp:virustotal", "get_file_report"), exact=True
    )
    assert held is not None and held.reader == SHAPE_READER
    record = read_answer(held, output=json.dumps(ANSWER), server="virustotal")
    assert (record.service, record.malicious, record.total) == ("VT", 52, 75)


def test_a_path_taking_tool_that_says_it_submits_is_read_as_sending_it() -> None:
    # Even marked closed: it says it hands the file over.
    assert discloses(_tool("submit_sample", PATH, openWorldHint=False))
    closed = _tool("t", PATH, openWorldHint=False)
    assert discloses(dict(closed, description="Uploads the file to the service."))
    assert not discloses(dict(closed, description="Reads the file."))


@pytest.mark.parametrize(
    "definition",
    [
        _tool("scan_file", PATH),
        _tool("submit_local_file", PATH, readOnlyHint=True, openWorldHint=True),
        _tool(
            "lookup",
            {"sha256": {"type": "string"}, "file_path": {"type": "string"}},
            readOnlyHint=True,
        ),
    ],
    ids=["scan_file-no-hints", "submit-read-only", "lookup-with-a-path-read-only"],
)
def test_read_only_never_excuses_sending_and_such_a_tool_is_never_a_lookup(
    definition: dict[str, Any],
) -> None:
    assert discloses(definition)
    facts = service_facts(definition)
    assert facts["kind"] == "submission" and facts["discloses_sample"] is True


def test_a_server_s_own_word_never_excuses_sending_on_a_block_that_does_not_trust_it(
    nothing_kept: None,
) -> None:
    from maljan.tools.declared_facts import FACTS_META_KEY

    listed = [{**_tool("push", BYTES), "_meta": {FACTS_META_KEY: {}}}]
    read = derived_tool_facts(listed)
    assert read["push"].discloses_sample and read["push"].kind == ""
    settings = _settings(mine={"command": "x"})
    block = settings.mcp.servers["mine"]
    served = {"push": ToolFacts.model_validate({"effects": {"third_party": "no"}})}
    sd.register_served("mcp:mine", served, launch_identity(block), read)
    held = ToolDeclarations.from_settings(settings).source("mcp:mine")
    assert held is not None and sends_sample_bytes(held.tools["push"])
    # A server the block trusts is taken at its word.
    trusting = _settings(mine={"command": "x", "trusts_served_declaration": True})
    sd.register_served("mcp:mine", served, launch_identity(trusting.mcp.servers["mine"]), read)
    held = ToolDeclarations.from_settings(trusting).source("mcp:mine")
    assert held is not None and not sends_sample_bytes(held.tools["push"])


def test_a_sending_tool_is_an_upload_on_a_block_of_any_role() -> None:
    read = derived_tool_facts([_tool("t", BYTES)])
    for roles in ((), ("reputation",), ("decompiler",)):
        held = lay_under({}, read, roles=roles)
        assert sends_sample_bytes(held["t"]), roles


def test_an_operator_who_says_what_a_tool_sends_is_never_overruled() -> None:
    read = derived_tool_facts([_tool("t", BYTES)])
    allowed = ToolFacts.model_validate({"effects": {"third_party": "no"}})
    held = lay_under({"t": allowed}, read, roles=("reputation",))
    assert not sends_sample_bytes(held["t"])
    # Saying anything else of it keeps the reading's disclosure.
    timed = ToolFacts.model_validate({"timeout_seconds": 5})
    held = lay_under({"t": timed}, read, roles=("reputation",))
    assert sends_sample_bytes(held["t"]) and held["t"].timeout_seconds == 5


def test_the_built_in_submit_tools_stay_disclosing_and_unticked() -> None:
    from maljan.core import virustotal

    read = derived_tool_facts(LISTING["tools"])
    assert {n for n, f in read.items() if sends_sample_bytes(f)} == set(virustotal.SUBMIT_TOOLS)
    block = Settings(_env_file=None).mcp.servers["virustotal"]
    assert not set(virustotal.SUBMIT_TOOLS) & set(block.tools or [])
    # With no hint at all, the bytes it takes are still read as sent.
    bare = [{k: v for k, v in t.items() if k != "annotations"} for t in LISTING["tools"]]
    assert sends_sample_bytes(derived_tool_facts(bare)["submit_file"])


# ---------------------------------------------------------------------------
# Who reads the service's kinds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "definition",
    [
        _tool("reanalyze_file", {"hash": {"type": "string"}}),
        _tool("rescan", {"sha256": {"type": "string"}}, readOnlyHint=True, destructiveHint=True),
        _tool("vote", {"sha256": {"type": "string"}, "verdict": {"type": "string"}}),
        _tool("delete_comment", {"domain": {"type": "string"}}),
    ],
    ids=["reanalyze-unannotated", "rescan-destructive", "vote-unannotated", "delete-unannotated"],
)
def test_a_write_tool_is_a_submission_never_a_lookup(definition: dict[str, Any]) -> None:
    facts = service_facts(definition)
    assert facts["kind"] == "submission"
    settings = _settings(acme={"command": "x", "roles": ["reputation"], "enabled": True})
    block = settings.mcp.servers["acme"]
    sd.register_served("mcp:acme", {}, launch_identity(block), derived_tool_facts([definition]))
    try:
        lookups = pack_lookups(settings.mcp.servers, ToolDeclarations.from_settings(settings))
        assert not [x for x in lookups if x.server == "acme"]
    finally:
        sd.forget_served("mcp:acme")


def test_only_a_reputation_block_reads_the_service_s_kinds() -> None:
    read = derived_tool_facts(_never_seen())
    service = lay_under({}, read, roles=("reputation",))
    other = lay_under({}, read, roles=())
    assert service["sample_verdict"].kind == "reputation"
    assert set(other) == {"push_bytes", "push_from_disk"}
    assert all(f.kind == "" and f.discloses_sample for f in other.values())


def test_a_never_seen_reputation_server_is_a_pack_lookup_after_none_ranked_before_it(
    nothing_kept: None,
) -> None:
    settings = _settings(
        acme={
            "transport": "streamable-http",
            "url": "https://intel.example.invalid/mcp",
            "roles": ["reputation"],
            "enabled": True,
        },
    )
    block = settings.mcp.servers["acme"]
    sd.register_served("mcp:acme", {}, launch_identity(block), derived_tool_facts(_never_seen()))
    lookups = pack_lookups(settings.mcp.servers, ToolDeclarations.from_settings(settings))
    acme = [lookup for lookup in lookups if lookup.server == "acme"]
    assert [(x.tool, x.hash_argument) for x in acme] == [("sample_verdict", "hash")]


def test_the_service_s_own_server_is_asked_before_the_relaying_sidecar() -> None:
    settings = Settings(_env_file=None)
    servers = dict(settings.mcp.servers)
    servers["virustotal"] = servers["virustotal"].model_copy(update={"enabled": True})
    lookups = pack_lookups(servers, ToolDeclarations.from_settings(settings))
    assert [(x.server, x.rank) for x in lookups] == [("virustotal", 10), ("threatintel", 20)]


@pytest.mark.parametrize("rank", [None, 11, 50, 99])
def test_an_operator_lookup_ranked_after_the_service_or_unranked_is_asked_after_it(
    rank: int | None,
) -> None:
    reputation = {"stats": "/s"} if rank is None else {"stats": "/s", "rank": rank}
    facts = {
        "kind": "reputation",
        "arguments": {"hash": "h"},
        "reputation": reputation,
    }
    settings = _settings(mine={"command": "x", "enabled": True, "tool_facts": {"lookup": facts}})
    servers = dict(settings.mcp.servers)
    servers["virustotal"] = servers["virustotal"].model_copy(update={"enabled": True})
    lookups = pack_lookups(servers, ToolDeclarations.from_settings(settings))
    order = [x.server for x in lookups]
    assert order.index("virustotal") < order.index("mine")


def test_the_service_s_name_is_its_lookup_s_name_and_its_record_s() -> None:
    from maljan.core.declared_reading import facts_record
    from maljan.core.reputation import record_at_write
    from maljan.reporting.tool_kinds import stated_name

    settings = Settings(_env_file=None)
    declared = ToolDeclarations.from_settings(settings)
    facts = declared.declaration_for(("mcp:virustotal", "get_file_report"), exact=True)
    assert facts is not None and facts.display_name == "VirusTotal"
    assert facts.reader == SHAPE_READER
    entry = {"tool": "get_file_report", "source": "mcp:virustotal", "server": "virustotal"}
    assert stated_name(entry, facts) == "VirusTotal"
    stored = facts_record("mcp:virustotal", "get_file_report", declared=declared)
    record = record_at_write(stored, ok=True, output=json.dumps(ANSWER), server="virustotal")
    assert record is not None and record["service"] == "VirusTotal"


def _acme(facts: dict[str, Any]) -> Settings:
    return _settings(
        acme={
            "transport": "streamable-http",
            "url": "https://intel.example.invalid/mcp",
            "roles": ["reputation"],
            "enabled": True,
            "tool_facts": {"verdict": facts},
        }
    )


VERDICT = [_tool("verdict", {"hash": {"type": "string"}}, readOnlyHint=True, destructiveHint=False)]


def test_a_lookup_s_declared_paths_are_read_on_a_reputation_service(nothing_kept: None) -> None:
    facts = {
        "kind": "reputation",
        "arguments": {"hash": "hash"},
        "reputation": {"malicious": "/result/bad", "stats": "/result/tally", "service": "Acme"},
    }
    settings = _acme(facts)
    block = settings.mcp.servers["acme"]
    sd.register_served("mcp:acme", {}, launch_identity(block), derived_tool_facts(VERDICT))
    held = ToolDeclarations.from_settings(settings).declaration_for(
        ("mcp:acme", "verdict"), exact=True
    )
    assert held is not None and held.reader == ""
    answer = json.dumps({"result": {"bad": 7, "tally": {"bad": 7, "good": 50}}})
    record = read_answer(held, output=answer, server="acme")
    assert (record.malicious, record.total, record.service) == (7, 57, "Acme")


def test_a_service_row_whose_stored_facts_hold_paths_is_read_by_them() -> None:
    from maljan.core.declared_reading import facts_record
    from maljan.core.reputation import record_at_write

    paths = {
        "stats": "/**7/last_analysis_stats",
        "malicious": "/**7/last_analysis_stats/malicious",
    }
    settings = Settings(_env_file=None)
    servers = dict(settings.mcp.servers)
    stored = {"kind": "reputation", "arguments": {"hash": "hash"}, "reputation": paths}
    servers["virustotal"] = servers["virustotal"].model_copy(
        update={
            "enabled": True,
            "tool_facts": {"get_file_report": ToolFacts.model_validate(stored)},
        }
    )
    settings = settings.model_copy(
        update={"mcp": settings.mcp.model_copy(update={"servers": servers})}
    )
    declared = ToolDeclarations.from_settings(settings)
    held = declared.declaration_for(("mcp:virustotal", "get_file_report"), exact=True)
    assert held is not None and held.reader == ""
    assert held.reputation is not None and held.reputation.stats == paths["stats"]
    # The block's service is laid under what the row leaves unsaid.
    assert (held.reputation.service, held.reputation.rank) == ("VirusTotal", 10)
    record = record_at_write(
        facts_record("mcp:virustotal", "get_file_report", declared=declared),
        ok=True,
        output=json.dumps(ANSWER),
        server="virustotal",
    )
    # Read by its paths: the counts, and nothing its paths do not name.
    assert record is not None and record["malicious"] == 52 and "detections" not in record


@pytest.mark.parametrize(
    "reputation",
    [{"stats": "/**7/last_analysis_stats"}, {"service": "VT"}],
    ids=["paths-no-rank", "service-no-rank"],
)
def test_a_service_row_naming_no_rank_keeps_the_service_s_rank(
    reputation: dict[str, Any],
) -> None:
    settings = Settings(_env_file=None)
    servers = dict(settings.mcp.servers)
    stored = {"kind": "reputation", "arguments": {"hash": "hash"}, "reputation": reputation}
    servers["virustotal"] = servers["virustotal"].model_copy(
        update={
            "enabled": True,
            "tool_facts": {"get_file_report": ToolFacts.model_validate(stored)},
        }
    )
    settings = settings.model_copy(
        update={"mcp": settings.mcp.model_copy(update={"servers": servers})}
    )
    lookups = pack_lookups(settings.mcp.servers, ToolDeclarations.from_settings(settings))
    assert [(x.server, x.rank) for x in lookups] == [("virustotal", 10), ("threatintel", 20)]


def test_a_stored_entry_whose_facts_name_no_reader_reads_as_it_always_did() -> None:
    # A lookup's facts stored before (no paths, no reader) read nothing of the
    # answer's shape on a re-render: the record a stored run has is unchanged.
    output = json.dumps(ANSWER)
    for facts in (
        {"v": 1, "kind": "file_reputation"},
        {"v": 1, "kind": "reputation", "arguments": {"hash": "h"}},
        {"v": 1, "kind": "reputation", "reputation": {"rank": 5}},
    ):
        entry = {"tool": "lookup", "source": "mcp:x", "facts": facts, "output": output}
        held = reputation_of({**entry, "ok": True, "server": "x"})
        assert held is not None
        assert (held.malicious, held.total, held.service) == (None, None, "x"), facts


@pytest.mark.no_kept_reputation_service
def test_a_fresh_deployment_reads_no_lookup_of_the_service_until_it_is_listed() -> None:
    from maljan.agents.composition import capability_servers

    settings = Settings(_env_file=None)
    servers = dict(settings.mcp.servers)
    servers["virustotal"] = servers["virustotal"].model_copy(update={"enabled": True})
    declared = ToolDeclarations.from_settings(settings)
    held = declared.source("mcp:virustotal")
    assert held is not None and dict(held.tools) == {}
    assert [x.server for x in pack_lookups(servers, declared)] == ["threatintel"]
    assert "virustotal" not in capability_servers(settings, "reputation")
    # Once listed, it is read as every later run reads it.
    block = settings.mcp.servers["virustotal"]
    sd.register_served(
        "mcp:virustotal", {}, launch_identity(block), derived_tool_facts(LISTING["tools"])
    )
    declared = ToolDeclarations.from_settings(settings)
    assert [x.server for x in pack_lookups(servers, declared)] == ["virustotal", "threatintel"]


# ---------------------------------------------------------------------------
# Kept past the process, and listed before a run
# ---------------------------------------------------------------------------


def test_what_was_read_is_kept_beside_the_declaration_and_reads_back(nothing_kept: None) -> None:
    read = derived_tool_facts(LISTING["tools"])
    sd.register_served("mcp:svc", {}, "L", read)
    [(source, launch, raw, _ships)] = sd.unsaved()
    assert (source, launch) == ("mcp:svc", "L")
    sd.mark_saved([(source, launch, raw, _ships)])
    assert sd.unsaved() == []
    sd.forget_served()
    sd._UNSAVED.clear()
    sd.install_persisted(json.loads(json.dumps([(source, launch, raw)])))
    assert sd.derived("mcp:svc", "L") == read and sd.served("mcp:svc") == {}
    # A release that does not know the reading reads the row's tools as before.
    assert (
        sd.served_tool_facts([{"name": n, "_meta": {sd.FACTS_META_KEY: f}} for n, f in raw.items()])
        == {}
    )


def test_a_moved_block_forgets_what_was_read(nothing_kept: None) -> None:
    sd.register_served("mcp:svc", {}, "L", derived_tool_facts(LISTING["tools"]))
    assert sd.forget_moved({"mcp:svc": "M"}) == ["mcp:svc"]
    assert sd.derived("mcp:svc") == {}


def test_a_job_lists_a_reputation_service_nothing_is_kept_for(
    nothing_kept: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.providers import server_probe

    monkeypatch.setattr(served_listing, "unlisted", _unlisted)
    served_listing._NOT_BEFORE.clear()
    settings = Settings(_env_file=None)
    servers = dict(settings.mcp.servers)
    servers["virustotal"] = servers["virustotal"].model_copy(update={"enabled": True})
    settings = settings.model_copy(
        update={"mcp": settings.mcp.model_copy(update={"servers": servers})}
    )
    reached: list[str] = []

    async def _handshake(block: Any, key: str, **kwargs: Any) -> Any:
        reached.append(key)
        if key == "virustotal":
            read = derived_tool_facts(LISTING["tools"])
            sd.register_served("mcp:virustotal", {}, launch_identity(block), read)
        return [], None

    monkeypatch.setattr(server_probe, "handshake", _handshake)
    listed = asyncio.run(served_listing.list_unlisted(settings))
    served_listing._NOT_BEFORE.clear()
    assert "virustotal" in reached and "virustotal" in listed


# ---------------------------------------------------------------------------
# No table of the service's tools ships
# ---------------------------------------------------------------------------


def test_no_shipped_server_declaration_names_a_reputation_service_s_tool() -> None:
    from maljan.core import builtin_declarations

    shipped = json.dumps(builtin_declarations._SERVER_BLOCKS)
    for name in RENAMED:
        assert not re.search(rf"\b{name}\b", shipped), name
    assert builtin_declarations.server_declaration("virustotal") == {}
    # Nor does a reading of a reputation answer name one service's fields.
    text = (ROOT / "src" / "maljan" / "core" / "reputation.py").read_text()
    for field in ("last_analysis_stats", "popular_threat", "first_submission_date"):
        assert field not in text, field


# ---------------------------------------------------------------------------
# A stored change that names no kind waits for the reading's kind
# ---------------------------------------------------------------------------


def _with_stored_change(change: dict[str, Any], **block: Any) -> Settings:
    """The settings an operator's stored change of the service's lookup builds, as stored."""
    from maljan.core.settings_overrides import build_settings
    from maljan.core.tool_declarations import with_mark

    # A stored row holds the whole entry, as a save writes it.
    entry = Settings(_env_file=None).mcp.servers["virustotal"].model_dump(mode="json")
    entry.pop("auth_token", None)
    entry.update({"enabled": True, "tool_facts": with_mark({"get_file_report": change}), **block})
    return build_settings({"mcp.servers": {"virustotal": entry}})


def _ranks(settings: Settings) -> list[tuple[str, str, int]]:
    lookups = pack_lookups(settings.mcp.servers, ToolDeclarations.from_settings(settings))
    return [(x.server, x.tool, x.rank) for x in lookups]


RANKED = {"reputation": {"rank": 30}}


def test_a_stored_change_naming_no_kind_is_laid_over_the_kept_reading() -> None:
    settings = _with_stored_change(RANKED)
    block = settings.mcp.servers["virustotal"]
    assert block.kind_free_changes == {"get_file_report": RANKED}
    assert ("virustotal", "get_file_report", 30) in _ranks(settings)
    held = ToolDeclarations.from_settings(settings).declaration_for(
        ("mcp:virustotal", "get_file_report"), exact=True
    )
    # The rest of the reading stands: its shape reader and the service's name.
    assert held is not None and held.reader == SHAPE_READER
    assert held.reputation is not None and held.reputation.service == "VirusTotal"


@pytest.mark.no_kept_reputation_service
def test_a_stored_change_waits_for_the_reading_and_is_never_lost() -> None:
    settings = _with_stored_change(RANKED)
    assert [x for x in _ranks(settings) if x[0] == "virustotal"] == []
    block = settings.mcp.servers["virustotal"]
    read = derived_tool_facts(LISTING["tools"])
    sd.register_served("mcp:virustotal", {}, launch_identity(block), read)
    assert ("virustotal", "get_file_report", 30) in _ranks(settings)


def test_a_stored_change_follows_a_moved_block_to_its_new_listing() -> None:
    moved = _with_stored_change(RANKED, url="https://mirror.example.invalid/mcp")
    block = moved.mcp.servers["virustotal"]
    # The reading kept was listed through the shipped address: not this one.
    sd.forget_moved({"mcp:virustotal": launch_identity(block)})
    assert [x for x in _ranks(moved) if x[0] == "virustotal"] == []
    read = derived_tool_facts(LISTING["tools"])
    sd.register_served("mcp:virustotal", {}, launch_identity(block), read)
    assert ("virustotal", "get_file_report", 30) in _ranks(moved)


def test_a_stored_change_naming_paths_is_read_by_them() -> None:
    change = {"reputation": {"malicious": "/**7/last_analysis_stats/malicious"}}
    settings = _with_stored_change(change)
    held = ToolDeclarations.from_settings(settings).declaration_for(
        ("mcp:virustotal", "get_file_report"), exact=True
    )
    assert held is not None and held.reader == ""
    record = read_answer(held, output=json.dumps(ANSWER), server="virustotal")
    assert record.malicious == 52 and record.detections == []


def test_a_stored_change_survives_the_settings_crossing_a_process_as_json() -> None:
    settings = _with_stored_change(RANKED)
    crossed = Settings.model_validate(json.loads(json.dumps(settings.model_dump(mode="json"))))
    assert crossed.mcp.servers["virustotal"].kind_free_changes == {"get_file_report": RANKED}
    assert ("virustotal", "get_file_report", 30) in _ranks(crossed)
    # And once more, as a second process would pass it on.
    again = Settings.model_validate(crossed.model_dump(mode="json"))
    assert ("virustotal", "get_file_report", 30) in _ranks(again)


def test_a_save_of_the_block_keeps_its_stored_change() -> None:
    from app.services.server_map import validate_server_map
    from maljan.core.tool_declarations import with_mark

    entry = Settings(_env_file=None).mcp.servers["virustotal"].model_dump(mode="json")
    entry.pop("auth_token", None)
    stored = {"virustotal": {**entry, "tool_facts": with_mark({"get_file_report": RANKED})}}
    # An unrelated edit of the block, sent back with what is stored.
    sent = {"virustotal": {**stored["virustotal"], "label": "edited"}}
    saved = validate_server_map(sent, stored=stored)
    assert saved["virustotal"]["tool_facts"].get("get_file_report") == RANKED


def test_an_edit_of_a_kindless_reputation_change_points_at_the_service_s_rank() -> None:
    from maljan.core.tool_declarations import strict_declarations

    with strict_declarations(), pytest.raises(ValueError) as refused:
        ToolFacts.model_validate(RANKED)
    assert "set the server's reputation_service.rank" in str(refused.value)
    with strict_declarations(), pytest.raises(ValueError) as other:
        ToolFacts.model_validate({"rows": "/r/*"})
    assert "reputation_service" not in str(other.value)


def test_the_console_offers_the_server_s_reputation_service() -> None:
    from maljan.core.settings_annotations import DECLARATION_LEAVES

    assert "reputation_service" in {leaf for leaf, _title, _text in DECLARATION_LEAVES}
    web = ROOT / "apps" / "web" / "src"
    assert "reputation_service" in (web / "types" / "settings.ts").read_text()
    editor = web / "app" / "(app)" / "settings" / "configuration" / "DeclarationFields.tsx"
    assert 'box("reputation_service")' in editor.read_text()


@pytest.mark.no_kept_reputation_service
def test_the_first_attach_of_a_fresh_deployment_already_reads_what_it_sends() -> None:
    from maljan.agents.mcp_client import MCPLangChainToolkit
    from maljan.core.declared_reading import tools_in_force
    from maljan.providers.servers import ServerHandle

    settings = Settings(_env_file=None)
    block = settings.mcp.servers["virustotal"]
    assert sd.derived("mcp:virustotal") == {}
    # The toolkit reads its listing once, before it tags its tools.
    kit = object.__new__(MCPLangChainToolkit)
    kit._server_name = lambda: "virustotal"  # type: ignore[method-assign]
    read, closed = kit._derived_readings(LISTING["tools"])
    assert read is not None
    # Nothing kept yet: what the attach tags its tools by holds the reading.
    held = tools_in_force("mcp:virustotal", block, {}, read, closed)
    assert sends_sample_bytes(held["submit_file"])
    assert sends_sample_bytes(held["submit_local_file"])
    # The handle passes the same reading to the tags it asks for.
    seen: list[Any] = []
    handle = ServerHandle("virustotal", block)
    real = tools_in_force

    def _spy(*args: Any) -> Any:
        found = real(*args)
        seen.append(found)
        return found

    import maljan.core.declared_reading as declared_reading

    original = declared_reading.tools_in_force
    declared_reading.tools_in_force = _spy  # type: ignore[assignment]
    try:
        handle._categories_with_served({}, read, closed)
    finally:
        declared_reading.tools_in_force = original  # type: ignore[assignment]
    assert seen and sends_sample_bytes(seen[0]["submit_file"])
