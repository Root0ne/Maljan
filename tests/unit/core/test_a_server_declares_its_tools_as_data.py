"""A server's declaration: its schema, paths, patterns, merge rule and read API.

The declaration is what the core will read about a tool instead of a table of
tool names (``maljan.core.tool_declarations``). These tests hold the schema to
an open vocabulary checked by shape, the field paths and the declared patterns
to linear readers, a built-in's stored block to the merge rule ``sample_open``
already follows, and the read API to the source an entry recorded when it was
written: never a bare tool name, an agent's name or today's settings.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from pydantic import ValidationError

from maljan.core.config import MCPServerConfig, Settings, StaticConfig
from maljan.core.tool_declarations import (
    PACK,
    SANDBOX,
    ErrorPattern,
    ReputationFacts,
    SourceRef,
    TechniqueField,
    ToolDeclarations,
    ToolFacts,
    fill_declaration,
    parse_path,
    select,
    strip_declaration_defaults,
)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_a_kind_nobody_wrote_down_is_accepted_by_its_shape() -> None:
    facts = ToolFacts(kind="pseudo_code")
    assert facts.kind == "pseudo_code"


@pytest.mark.parametrize("kind", ["Strings", "rule-match", "1st", "a" * 65])
def test_a_kind_that_is_not_a_lowercase_word_is_refused(kind: str) -> None:
    with pytest.raises(ValidationError, match="vocabulary word"):
        ToolFacts(kind=kind)


@pytest.mark.parametrize("kind", ["", "unclassified"])
def test_a_declaration_may_name_no_kind_and_state_kind_free_fields(kind: str) -> None:
    facts = ToolFacts(kind=kind, display_name="Sections")
    assert facts.kind == ""
    assert ToolFacts(display_name="Sections").kind == ""
    assert ToolFacts(timeout_seconds=30, arguments={"path": "path"}).kind == ""


@pytest.mark.parametrize(
    ("declared", "message"),
    [
        # The three a kindless save let through: refused again, as dev refused them.
        ({"knd": "decompile"}, "knd"),
        ({}, "names its kind or at least one of"),
        ({"rows": "/m/*", "places": {"offset": "/o"}}, "rows, places are read only through a kind"),
        ({"kind": "unclassified"}, "names its kind or at least one of"),
        ({"display_name": "Scanner", "rows": "/m/*"}, "rows are read only through a kind"),
        ({"display_name": "Scanner", "report_sections": ["commands"]}, "report_sections"),
    ],
)
def test_an_edit_a_kind_would_be_needed_to_read_is_refused(
    declared: dict[str, Any], message: str
) -> None:
    """The rules hold for what an operator types now (``strict_declarations``)."""
    from maljan.core.tool_declarations import strict_declarations

    with strict_declarations():
        with pytest.raises(ValidationError, match=message):
            ToolFacts.model_validate(declared)
        with pytest.raises(ValidationError, match=message):
            MCPServerConfig.model_validate({"command": "x", "tool_facts": {"scan": declared}})


@pytest.mark.parametrize(
    ("declared", "kept", "left_out"),
    [
        ({"kind": "decompile", "note": "a later field"}, {"kind": "decompile"}, ["note"]),
        ({"knd": "decompile"}, {}, ["knd"]),
        # No kind at all: what only a kind reads is left out.
        (
            {"kind": "", "rows": "/m/*", "places": {"offset": "/o"}},
            {"kind": ""},
            ["rows", "places"],
        ),
        (
            {"display_name": "Scanner", "rows": "/m/*"},
            {"display_name": "Scanner"},
            ["rows"],
        ),
    ],
)
def test_what_was_already_accepted_is_read_with_what_this_version_cannot_read_left_out(
    declared: dict[str, Any],
    kept: dict[str, Any],
    left_out: list[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Stored, shipped, runtime and imported declarations never fail on a key or field."""
    import logging

    from maljan.core import tool_declarations

    tool_declarations._WARNED.clear()
    other = {"kind": "strings", "rows": "/strings/*"}
    with caplog.at_level(logging.WARNING, logger="maljan"):
        block = MCPServerConfig.model_validate(
            {"command": "x", "tool_facts": {"scan": declared, "other": other}}
        )
        again = MCPServerConfig.model_validate(
            {"command": "x", "tool_facts": {"scan": declared, "other": other}}
        )
    assert block == again
    # The tool keeps everything this version reads; the other tool is untouched.
    assert block.tool_facts["scan"].model_dump(exclude_defaults=True) == {
        k: v for k, v in kept.items() if v not in ("", None)
    }
    assert block.tool_facts["other"] == ToolFacts.model_validate(other)
    warnings = [r.getMessage() for r in caplog.records if "left out" in r.getMessage()]
    # One warning, naming the fields left out, however often the block is read.
    assert len(warnings) == 1
    for name in left_out:
        assert name in warnings[0]


def test_a_key_left_out_is_logged_on_one_line(caplog: pytest.LogCaptureFixture) -> None:
    import logging

    from maljan.core import tool_declarations

    tool_declarations._WARNED.clear()
    forged = "note\nFAKE RECORD: everything is fine"
    with caplog.at_level(logging.WARNING, logger="maljan"):
        MCPServerConfig.model_validate(
            {"command": "x", "tool_facts": {"scan\rtool": {"kind": "strings", forged: 1}}}
        )
    (message,) = [r.getMessage() for r in caplog.records if "left out" in r.getMessage()]
    assert "\n" not in message and "\r" not in message
    assert "note\\nFAKE RECORD" in message


def test_a_runtime_provider_block_with_an_unknown_key_keeps_the_rest_of_its_declaration() -> None:
    from maljan.core import declared_reading
    from maljan.core.tool_declarations import (
        forget_provider_declaration,
        provider_declarations,
        register_provider_declaration,
    )

    def _reader(_cfg: Any) -> dict[str, Any]:
        return {
            "tool_facts": {
                "listing": {"kind": "decompile", "a_later_field": {"x": 1}},
                "strings_of": {"kind": "strings", "rows": "/strings/*"},
            }
        }

    register_provider_declaration("provider:invented_runtime_g10b", _reader)
    try:
        blocks = provider_declarations(Settings())
        block = blocks["provider:invented_runtime_g10b"]
        assert block.tool_facts["listing"].kind == "decompile"
        assert block.tool_facts["strings_of"].rows == "/strings/*"
    finally:
        forget_provider_declaration("provider:invented_runtime_g10b")
        declared_reading.forget()


def test_the_fields_split_once_into_kind_free_and_kind_dependent() -> None:
    from maljan.core.tool_declarations import KIND_DEPENDENT_FIELDS, KIND_FREE_FIELDS

    assert not set(KIND_FREE_FIELDS) & set(KIND_DEPENDENT_FIELDS)
    assert {*KIND_FREE_FIELDS, *KIND_DEPENDENT_FIELDS, "kind"} == set(ToolFacts.model_fields)
    # The console's declaration box reads the same split from the served
    # schema (tests/unit/api/test_the_console_reads_tool_declarations_as_the_api_does.py).


def test_every_shipped_declaration_and_stored_record_loads_as_before() -> None:
    import json

    from tests.unit.reporting.test_an_entry_without_a_source_is_read_as_before import _benchmark

    from maljan.core import declared_reading
    from maljan.core.builtin_declarations import builtin_server_names, server_declaration

    for key in builtin_server_names():
        block = server_declaration(key)
        MCPServerConfig.model_validate({"command": "x", **block})
    # A record dev stored always names its kind and reads as it did; a key a
    # later version adds is read past, never refused.
    record = {"v": 1, "kind": "strings", "rows": "/strings/*", "a_later_field": 1}
    facts = declared_reading.facts_of({"tool": "t", "source": "mcp:x", "facts": record})
    assert facts is not None and facts.kind == "strings" and facts.rows == "/strings/*"
    root = _benchmark()
    if root is None:
        pytest.skip("the stored benchmark runs are not on this machine")
    from maljan.schemas.evidence import LedgerEntry

    read = 0
    for run in ("run7", "run5", "run4", "local8"):
        path = root / run / "evidence.json"
        if not path.is_file():
            continue
        for item in json.loads(path.read_text()).get("items") or []:
            entry = LedgerEntry.model_validate({**item, "id": item.get("entry_id") or item["id"]})
            # Stored before sources and records: read by name, as it always was.
            assert entry.facts is None or entry.facts.get("kind")
            read += 1
    assert read > 0


@pytest.mark.parametrize(
    ("path", "message"),
    [
        ("rows", "must start with '/'"),
        ("/**/a/**/b", "'\\*\\*' once"),
    ],
)
def test_a_rows_path_is_checked_where_it_is_written(path: str, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        ToolFacts(kind="strings", rows=path)


def test_a_path_read_inside_a_row_may_not_descend_without_bound() -> None:
    with pytest.raises(ValidationError, match="read inside a row"):
        ToolFacts(kind="strings", rows="/strings/*", places={"offset": "/**/offset"})


def test_places_and_values_need_rows_to_be_read_in() -> None:
    with pytest.raises(ValidationError, match="declare rows"):
        ToolFacts(kind="strings", values={"text": "/text"})


def test_an_asserting_tool_names_where_its_techniques_are() -> None:
    with pytest.raises(ValidationError, match="needs techniques"):
        ToolFacts(kind="rule_match", asserts_techniques=True)
    with pytest.raises(ValidationError, match="set asserts_techniques"):
        ToolFacts(kind="rule_match", source="mine")


def test_a_technique_field_needs_a_path_and_a_format_word() -> None:
    with pytest.raises(ValidationError):
        TechniqueField(path="")
    with pytest.raises(ValidationError, match="vocabulary word"):
        TechniqueField(path="/attck", format="ATT&CK")


def test_an_argument_name_is_an_identifier() -> None:
    assert ToolFacts(kind="x", arguments={"path": "file_path"}).arguments["path"] == "file_path"
    with pytest.raises(ValidationError, match="not an argument name"):
        ToolFacts(kind="x", arguments={"path": "file path"})


def test_a_declaration_is_frozen() -> None:
    facts = ToolFacts(kind="strings", words=("a",))
    with pytest.raises(ValidationError):
        facts.kind = "other"  # type: ignore[misc]
    assert isinstance(facts.words, tuple)


def test_a_server_block_checks_its_names_mount_and_prefixes() -> None:
    with pytest.raises(ValidationError, match="server role"):
        MCPServerConfig(roles=["Reputation"])
    with pytest.raises(ValidationError, match="absolute path"):
        MCPServerConfig(sample_mount="data/samples")
    with pytest.raises(ValidationError, match="'\\.\\.' segment"):
        MCPServerConfig(sample_mount="/data/../etc")
    assert MCPServerConfig(sample_mount="/data//samples/").sample_mount == "/data/samples"
    with pytest.raises(ValidationError, match="environment variable name"):
        MCPServerConfig(required_env_allow=["NOT-A-NAME"])
    with pytest.raises(ValidationError, match="one directory name"):
        MCPServerConfig(work_dir="a/b")
    with pytest.raises(ValidationError, match="auto_name_prefixes"):
        MCPServerConfig(auto_name_prefixes=["FUN"])
    with pytest.raises(ValidationError, match="https"):
        MCPServerConfig(reference_urls=["http://example.org/{sha256}"])
    with pytest.raises(ValidationError, match="names none of"):
        MCPServerConfig(reference_urls=["https://example.org/"])


@pytest.mark.parametrize("name", ["", " capa", "capa "])
def test_a_declared_tool_name_is_a_tools_own_name(name: str) -> None:
    with pytest.raises(ValidationError, match="tool"):
        MCPServerConfig(tool_facts={name: {"kind": "strings"}})
    with pytest.raises(ValidationError, match="tool"):
        ErrorPattern(match="x", tools=(name,))


@pytest.mark.parametrize("name", ["get__thing", "a__b__c", "other__capa", "__proto__"])
def test_a_tool_whose_own_name_holds_a_double_underscore_is_declared(name: str) -> None:
    settings = Settings.model_validate(
        {"mcp": {"servers": {"mine": {"command": "x", "tool_facts": {name: {"kind": "x"}}}}}}
    )
    d = ToolDeclarations.from_settings(settings)
    assert d.declaration_for({"source": "mcp:mine", "tool": name}).kind == "x"
    # Renamed by the registry beside another server's tool of the same name.
    assert d.declaration_for({"source": "mcp:mine", "tool": f"mine__{name}"}).kind == "x"


def test_a_tool_spelled_as_its_own_servers_renamed_tool_is_refused() -> None:
    with pytest.raises(ValidationError, match="renamed tool"):
        Settings.model_validate(
            {
                "mcp": {
                    "servers": {"mine": {"command": "x", "tool_facts": {"mine__x": {"kind": "x"}}}}
                }
            }
        )
    with pytest.raises(ValidationError, match="renamed tool"):
        Settings.model_validate(
            {
                "mcp": {
                    "servers": {
                        "mine": {
                            "command": "x",
                            "error_patterns": [{"match": "x", "tools": ["mine__x"]}],
                        }
                    }
                }
            }
        )


def test_the_separator_is_read_only_after_the_known_server_key() -> None:
    from maljan.core.tool_declarations import renamed_tool

    assert renamed_tool("mine", "mine__get__thing") == "get__thing"
    assert renamed_tool("mine", "get__thing") == "get__thing"
    assert renamed_tool("mine", "minefield__x") == "minefield__x"
    assert renamed_tool("my", "mine__x") == "mine__x"


def test_a_server_block_holds_every_declaration_field() -> None:
    block = MCPServerConfig(
        roles=["reputation", "my_own_role"],
        sample_mount="/srv/in",
        work_dir="my-work",
        required_env_allow=["MY_TOKEN_DIR"],
        variable_names=["MY_SAMPLES_PATH"],
        reads_staged_sample=True,
        platform_owned=False,
        auto_name_prefixes=["fn_"],
        reference_urls=["https://example.org/sample/{sha256}"],
        prompt_fragment="Call open first.",
        tool_facts={
            "lookup": {
                "kind": "reputation",
                "arguments": {"hash": "sha256"},
                "timeout_seconds": 30,
                "discloses_sample": False,
                "display_name": "My intel",
                "category": "list",
            }
        },
    )
    assert block.tool_facts["lookup"].timeout_seconds == 30


# ---------------------------------------------------------------------------
# Patterns: RE2
# ---------------------------------------------------------------------------


def test_an_error_pattern_is_held_against_the_whole_stripped_answer() -> None:
    pattern = ErrorPattern(match=r"No file is open\..*", tools=("list_strings",))
    assert pattern.matches("list_strings", "  No file is open. Open one.  ")
    assert not pattern.matches("list_strings", "a listing\nNo file is open. Open one.")
    assert not pattern.matches("decompile", "No file is open. Open one.")
    assert not pattern.matches("list_strings", "No file is open. x", target="protocol_error")


def test_a_multiline_pattern_files_the_lines_of_its_message_group() -> None:
    pattern = ErrorPattern(
        match=r"<log>(?P<body>[\s\S]*)</log>", multiline=True, message_group="body"
    )
    assert pattern.message("t", "<log>\n  [ERROR] a \n\n [INFO] b\n</log>") == "[ERROR] a\n[INFO] b"
    with pytest.raises(ValidationError, match="not a group"):
        ErrorPattern(match="x", message_group="body")


def test_a_remediation_names_the_samples_path_where_it_has_a_form_for_it() -> None:
    pattern = ErrorPattern(
        match="x",
        remediation="open the sample",
        remediation_with_path="open {sample_path}",
    )
    assert pattern.remediation_for("/m/s.exe") == "open /m/s.exe"
    assert pattern.remediation_for(None) == "open the sample"
    with pytest.raises(ValidationError, match="sample_path"):
        ErrorPattern(match="x", remediation_with_path="open it")


@pytest.mark.parametrize("pattern", [r"(a)\1", r"(?=a)a", r"(?<!a)b", "(unclosed"])
def test_a_pattern_re2_cannot_run_is_refused_when_it_is_saved(pattern: str) -> None:
    with pytest.raises(ValidationError, match="linear time"):
        ErrorPattern(match=pattern)
    with pytest.raises(ValidationError, match="linear time"):
        ReputationFacts(text_patterns=(f"(?P<malicious>\\d+){pattern}",))


def test_a_hostile_answer_is_matched_in_linear_time() -> None:
    pattern = ErrorPattern(match=r"(a|aa)+$")
    text = ReputationFacts(text_patterns=(r"(?P<malicious>(\d+)+)x",))

    def timed(n: int) -> float:
        started = time.perf_counter()
        assert not pattern.matches("t", "a" * n + "b")
        assert text.counts_in_text("1" * n + "y") is None
        return time.perf_counter() - started

    timed(2_000)
    small, large = timed(20_000), timed(200_000)
    assert large < max(small, 0.002) * 30


def test_reputation_text_patterns_are_searched_first_match_first() -> None:
    facts = ReputationFacts(
        text_patterns=(
            r"(?P<malicious>\d+)/(?P<total>\d+) detections",
            r"(?P<malicious>\d+) bad",
        )
    )
    assert facts.counts_in_text("x 3/9 detections y") == (3, 9, None)
    assert facts.counts_in_text("found 4 bad ones") == (4, None, None)
    assert facts.counts_in_text("nothing") is None
    with pytest.raises(ValidationError, match="named 'malicious'"):
        ReputationFacts(text_patterns=(r"(\d+)/(\d+)",))


# ---------------------------------------------------------------------------
# Field paths
# ---------------------------------------------------------------------------


ANSWER = {
    "matches": [
        {"rule": "one", "strings": [{"offset": 1, "instances": [{"offset": 2}]}]},
        {"rule": "two", "strings": [{"offset": 3}], "meta": {"attck": ["T1055"]}},
    ],
    "a/b": {"c~d": 7},
    "*": {"**": 8},
    "nested": {"deep": {"attck": "T1027"}},
}


def test_a_path_names_keys_items_and_every_value() -> None:
    assert select(ANSWER, "/matches/*/rule") == ["one", "two"]
    assert select(ANSWER, "/matches/1/rule") == ["two"]
    assert select(ANSWER, "/matches/*/strings/*/offset") == [1, 3]
    assert select(ANSWER, "/a~1b/c~0d") == [7]
    assert select(ANSWER, "/~2/~2~2") == [8]
    assert select(ANSWER, "/missing/*") == []
    assert select(ANSWER, "") == []


def test_any_depth_finds_a_key_wherever_it_sits_in_document_order() -> None:
    assert select(ANSWER, "/**/attck") == [["T1055"], "T1027"]
    assert select(ANSWER, "/matches/**/offset") == [1, 2, 3]


def test_a_bounded_depth_stops_where_it_says() -> None:
    assert select(ANSWER, "/**2/attck") == ["T1027"]
    assert select(ANSWER, "/**3/attck") == [["T1055"], "T1027"]
    assert select(ANSWER, "/**0/nested") == [ANSWER["nested"]]


def test_a_rows_path_with_row_fields_reads_each_row() -> None:
    facts = ToolFacts(
        kind="rule_match",
        rows="/matches/*",
        places={"offset": "/strings/*/offset"},
        values={"rule": "/rule"},
    )
    assert facts.row_values(ANSWER) == [
        {"offset": [1], "rule": ["one"]},
        {"offset": [3], "rule": ["two"]},
    ]


def test_parse_path_says_what_is_wrong() -> None:
    assert parse_path("/a/*/b") == ("a", "*", "b")
    with pytest.raises(ValueError, match="start with"):
        parse_path("a")


def _hostile(width: int) -> dict:
    """A deep and wide answer: every level a list of objects holding the key."""
    node: dict = {"attck": "T1", "rows": []}
    for _ in range(width):
        node = {"attck": "T1", "rows": [node, {"attck": "T2", "x": list(range(10))}]}
    return node


def test_reading_any_depth_stays_linear_on_a_hostile_answer() -> None:
    small, large = _hostile(2_000), _hostile(20_000)

    def timed(doc: dict) -> float:
        started = time.perf_counter()
        found = select(doc, "/**/attck")
        assert len(found) > 0
        return time.perf_counter() - started

    timed(small)
    small_s, large_s = timed(small), timed(large)
    assert large_s < max(small_s, 0.005) * 30


# ---------------------------------------------------------------------------
# The merge rule
# ---------------------------------------------------------------------------


def test_a_stored_built_in_that_never_set_a_field_takes_the_shipped_value() -> None:
    stored = {"analysis": {"enabled": False, "command": "python", "transport": "stdio"}}
    settings = Settings.model_validate({"mcp": {"servers": stored}})
    analysis = settings.mcp.servers["analysis"]
    assert analysis.enabled is False
    assert analysis.reads_staged_sample is True
    assert analysis.platform_owned is True
    assert analysis.tool_facts["capa"].kind == "capability_rules"
    assert "tool_facts" not in analysis.model_fields_set


def test_a_field_the_operator_set_even_empty_is_kept() -> None:
    stored = {"threatintel": {"command": "python", "roles": [], "tool_facts": {}}}
    settings = Settings.model_validate({"mcp": {"servers": stored}})
    threatintel = settings.mcp.servers["threatintel"]
    assert threatintel.roles == []
    assert threatintel.tool_facts == {}


def test_a_server_of_the_operators_inherits_no_declaration() -> None:
    stored = {"mine": {"command": "my-server", "tools": ["capa", "strings"]}}
    settings = Settings.model_validate({"mcp": {"servers": stored}})
    mine = settings.mcp.servers["mine"]
    assert mine.tool_facts == {}
    assert mine.roles == []


def test_the_provider_blocks_carry_their_declarations_where_they_set_none() -> None:
    static = StaticConfig.model_validate({"ghidra": {"url": "http://g:8089"}, "r2": {}})
    assert static.ghidra.sample_open.open_tool == "load_program"
    assert static.ghidra.sample_mount == "/data/samples"
    assert static.ghidra.tool_facts["decompile_function"].kind == "decompile"
    assert static.r2.error_patterns[0].applies_to == ("protocol_error",)
    cleared = StaticConfig.model_validate({"ghidra": {"prompt_fragment": "", "sample_open": {}}})
    assert cleared.ghidra.prompt_fragment == ""
    assert cleared.ghidra.sample_open.open_tool == ""


def test_the_cape_mcp_block_carries_its_role() -> None:
    settings = Settings.model_validate({"sandbox": {"cape2": {"mcp": {"url": "http://c"}}}})
    assert settings.sandbox.cape2.mcp.roles == ["sandbox"]


def test_a_filled_block_strips_back_to_what_the_operator_wrote() -> None:
    from maljan.core.config import _builtin_servers

    default = _builtin_servers()["analysis"]
    stored = MCPServerConfig.model_validate({"command": "python", "roles": ["mine"]})
    fill_declaration(stored, default)
    dumped = strip_declaration_defaults(stored.model_dump(mode="json"), default)
    assert dumped["roles"] == ["mine"]
    assert "tool_facts" not in dumped
    assert "required_env_allow" not in dumped


def test_a_value_written_equal_to_the_shipped_one_is_not_recorded() -> None:
    from maljan.core.config import _builtin_servers

    default = _builtin_servers()["analysis"]
    stored = MCPServerConfig.model_validate({"command": "python", "sample_mount": ""})
    dumped = strip_declaration_defaults(stored.model_dump(mode="json"), default)
    assert "sample_mount" not in dumped


# ---------------------------------------------------------------------------
# The read API: by the recorded source alone
# ---------------------------------------------------------------------------


def _declarations(**overrides: object) -> ToolDeclarations:
    return ToolDeclarations.from_settings(Settings.model_validate(overrides))


def test_an_entry_resolves_by_its_recorded_source_and_its_tool_together() -> None:
    d = _declarations()
    capa = d.declaration_for({"source": "mcp:analysis", "server": "analysis", "tool": "capa"})
    assert capa is not None and capa.asserts_techniques and capa.source == "capa"
    pack = d.declaration_for({"source": "pack", "server": "pipeline", "tool": "floss"})
    assert pack is not None and pack.kind == "emulated_strings"
    assert d.declaration_for(("mcp:virustotal", "get_file_report")).kind == "reputation"
    assert d.declaration_for((PACK, "reputation")).kind == "reputation_not_asked"


def test_an_entry_with_no_recorded_source_resolves_to_nothing() -> None:
    d = _declarations()
    for entry in (
        {"server": "analysis", "agent": "static", "tool": "capa"},
        {"server": "pipeline", "agent": "pipeline", "tool": "capa"},
        {"server": None, "agent": "capa_yara", "tool": "yara_scan"},
        {"server": None, "agent": "dynamic", "tool": "sandbox_signatures"},
        {"server": None, "agent": None, "tool": "decompile_function"},
        {"source": "not a source", "tool": "capa"},
    ):
        assert d.declaration_for(entry) is None, entry


def test_a_tool_renamed_with_its_own_servers_prefix_is_read_without_it() -> None:
    d = _declarations()
    entry = {"source": "mcp:knowledge", "tool": "knowledge__capabilities"}
    assert d.declaration_for(entry).kind == "capabilities"
    assert d.declaration_for({"source": "mcp:knowledge", "tool": "analysis__capa"}) is None


def test_a_users_tool_sharing_a_built_in_name_takes_none_of_its_facts() -> None:
    servers = {
        "mine": {"command": "x", "tools": None},
        "theirs": {"command": "y", "tool_facts": {"capa": {"kind": "function_list"}}},
    }
    d = _declarations(mcp={"servers": servers})
    assert d.declaration_for({"source": "mcp:mine", "tool": "capa"}) is None
    assert d.declaration_for({"source": "mcp:mine", "tool": "strings"}) is None
    theirs = d.declaration_for({"source": "mcp:theirs", "tool": "capa"})
    assert theirs is not None and theirs.kind == "function_list"


def test_a_generic_providers_tool_named_like_a_sandbox_tool_is_its_own() -> None:
    servers = {"qk": {"command": "x"}}
    d = _declarations(
        mcp={"servers": servers}, static={"provider": "generic_mcp", "generic": {"server": "qk"}}
    )
    entry = {"source": "mcp:qk", "tool": "sandbox_signatures"}
    assert d.declaration_for(entry) is None
    assert d.declaration_for({"source": "sandbox", "tool": "sandbox_signatures"}) is not None


def test_an_operator_server_named_like_the_pack_is_its_own_server() -> None:
    d = _declarations(mcp={"servers": {"pipeline": {"command": "x"}}})
    entry = {"source": "mcp:pipeline", "server": "pipeline", "agent": "pipeline", "tool": "capa"}
    assert d.source_of(entry) == SourceRef("mcp", "pipeline")
    assert d.declaration_for(entry) is None


def test_the_generic_providers_entries_are_read_by_the_server_they_recorded() -> None:
    from maljan.providers.static.generic_mcp import GenericMCPStaticProvider

    servers = {
        "mydis": {"command": "x", "tool_facts": {"pseudo_c": {"kind": "decompile"}}},
        "other": {"command": "y", "tool_facts": {"pseudo_c": {"kind": "listing"}}},
    }
    first = Settings.model_validate(
        {
            "mcp": {"servers": servers},
            "static": {"provider": "generic_mcp", "generic": {"server": "mydis"}},
        }
    )
    provider = GenericMCPStaticProvider.from_settings(first)
    assert provider.declaration_source == "mcp:mydis"
    entry = {"source": provider.declaration_source, "tool": "pseudo_c"}
    assert ToolDeclarations.from_settings(first).declaration_for(entry).kind == "decompile"
    # The provider re-pointed at another server later: the entry keeps its server.
    later = Settings.model_validate(
        {
            "mcp": {"servers": servers},
            "static": {"provider": "generic_mcp", "generic": {"server": "other"}},
        }
    )
    assert ToolDeclarations.from_settings(later).declaration_for(entry).kind == "decompile"
    assert ToolDeclarations.from_settings(later).source("provider:generic_mcp") is None


def test_radare2_and_ghidra_record_their_own_blocks() -> None:
    from maljan.providers.static.ghidra import GhidraStaticProvider
    from maljan.providers.static.r2 import R2StaticProvider

    settings = Settings()
    assert R2StaticProvider.from_settings(settings).declaration_source == "provider:r2"
    assert GhidraStaticProvider.from_settings(settings).declaration_source == "provider:ghidra"


def test_the_provider_blocks_are_one_table() -> None:
    from maljan.core.settings_overrides import declaration_blocks
    from maljan.core.tool_declarations import block_at, provider_blocks

    settings = Settings()
    blocks = declaration_blocks(settings)
    for source, path in provider_blocks().items():
        assert blocks[source] == path
        assert isinstance(block_at(settings, path), MCPServerConfig)
    d = ToolDeclarations.from_settings(settings)
    assert {str(x.source) for x in d.sources() if x.source.kind == "provider"} >= set(
        provider_blocks()
    )


def test_tools_of_a_kind_and_servers_of_a_role_come_from_the_declarations() -> None:
    d = _declarations()
    rule_tools = {
        (str(s), t) for s, t, _ in d.tools_of_kind(["capability_rules", "signature_rules"])
    }
    assert {("mcp:analysis", "capa"), ("mcp:analysis", "yara_scan"), ("pack", "capa")} <= rule_tools
    assert ("provider:capa_yara", "yara_scan") in rule_tools
    assert d.servers_with_role("reputation") == [
        SourceRef("mcp", "threatintel"),
        SourceRef("mcp", "virustotal"),
    ]
    assert d.servers_with_role("reputation", enabled_only=True) == [SourceRef("mcp", "threatintel")]
    assert SANDBOX in d.servers_with_role("sandbox")


def test_a_role_an_operator_declares_on_their_own_server_is_found() -> None:
    servers = {"intel": {"command": "x", "enabled": True, "roles": ["reputation"]}}
    d = _declarations(mcp={"servers": servers})
    assert SourceRef("mcp", "intel") in d.servers_with_role("reputation", enabled_only=True)


def test_a_source_parses_from_its_text_and_refuses_anything_else() -> None:
    assert SourceRef.parse("mcp:analysis") == SourceRef("mcp", "analysis")
    assert SourceRef.parse("provider:r2") == SourceRef("provider", "r2")
    assert SourceRef.parse("pack") == PACK
    for bad in ("analysis", "mcp:", "pack:x", "server:x"):
        with pytest.raises(ValueError):
            SourceRef.parse(bad)


def test_a_read_cannot_change_the_shipped_data() -> None:
    d = _declarations()
    held = d.source("pack")
    assert held is not None
    held.tools["capa"].places["addresses"] = "/elsewhere"  # type: ignore[index]
    assert _declarations().source("pack").tools["capa"].places["addresses"] == "/addresses"  # type: ignore[union-attr]


def test_the_module_functions_read_the_settings_given() -> None:
    from maljan.core.tool_declarations import declaration_for, servers_with_role, tools_of_kind

    settings = Settings()
    entry = {"source": "mcp:analysis", "tool": "strings"}
    assert declaration_for(entry, settings=settings).kind == "strings"
    assert tools_of_kind("pcap", settings=settings)
    assert SourceRef("mcp", "virustotal") in servers_with_role("reputation", settings=settings)


# ---------------------------------------------------------------------------
# "unclassified": no kind only when nothing a kind reads is set
# ---------------------------------------------------------------------------

DEV_UNCLASSIFIED = {
    "kind": "unclassified",
    "rows": "/matches/*",
    "places": {"offset": "/offset"},
    "asserts_techniques": True,
    "techniques": [{"path": "/matches/*/tags", "format": "sigma_tag"}],
}
DEV_ANSWER = {"matches": [{"offset": "0x400", "tags": ["attack.t1055"]}]}


def _dev_entry(facts: dict[str, Any]) -> Any:
    from maljan.schemas.evidence import LedgerEntry

    return LedgerEntry(
        id="ev_0001",
        seq=1,
        agent="static",
        tool="scan_rules",
        source="mcp:invented",
        output="{}",
        structured=DEV_ANSWER,
        facts=facts,
    )


def test_a_dev_record_of_kind_unclassified_with_rows_reads_as_on_dev() -> None:
    from maljan.analysis.evidence_roots import reading_branch
    from maljan.core import declared_reading
    from maljan.pipeline.evidence_summary import asserted_techniques

    entry = _dev_entry({"v": 1, **DEV_UNCLASSIFIED})
    facts = declared_reading.facts_of(entry)
    assert facts is not None
    assert (facts.kind, facts.rows, facts.asserts_techniques) == (
        "unclassified",
        "/matches/*",
        True,
    )
    assert reading_branch(entry) == "declared_rows"
    assert asserted_techniques(entry) == {"T1055"}


def test_a_stored_declaration_of_kind_unclassified_with_rows_is_kept_whole() -> None:
    from maljan.core.settings_overrides import build_settings
    from maljan.core.tool_declarations import ToolFacts, strict_declarations

    built = build_settings({"static.ghidra.tool_facts": {"scan_rules": DEV_UNCLASSIFIED}})
    facts = built.static.ghidra.tool_facts["scan_rules"]
    assert facts == ToolFacts.model_validate(DEV_UNCLASSIFIED)
    assert (facts.kind, facts.rows, facts.asserts_techniques) == (
        "unclassified",
        "/matches/*",
        True,
    )
    assert facts.techniques[0].path == "/matches/*/tags"
    # The same rule holds for an edit being saved: it is an ordinary kind.
    with strict_declarations():
        assert ToolFacts.model_validate(DEV_UNCLASSIFIED).kind == "unclassified"


def test_a_bare_unclassified_still_reads_as_undeclared() -> None:
    from maljan.core import declared_reading
    from maljan.core.tool_declarations import ToolFacts, strict_declarations

    entry = _dev_entry({"v": 1, "kind": "unclassified"})
    assert declared_reading.facts_of(entry) is None
    assert ToolFacts.model_validate({"kind": "unclassified"}).kind == ""
    named = ToolFacts.model_validate({"kind": "unclassified", "display_name": "S"})
    assert (named.kind, named.display_name) == ("", "S")
    with strict_declarations(), pytest.raises(ValidationError, match="names its kind"):
        ToolFacts.model_validate({"kind": "unclassified"})


# ---------------------------------------------------------------------------
# A stored record's kind-free fields are read whatever its kind
# ---------------------------------------------------------------------------

# A value for each stored field read without a kind; a field added to both
# lists needs one here, and is then held to be read for a record of no kind.
KIND_FREE_SAMPLES: dict[str, Any] = {
    "display_name": "Section scanner",
    "words": ["sectioner"],
    "arguments": {"report": "task_report", "address": "offset_va"},
}


def _stored_kind_free_fields() -> tuple[str, ...]:
    from maljan.core.declared_reading import STORED_FACT_FIELDS
    from maljan.core.tool_declarations import KIND_FREE_FIELDS

    return tuple(name for name in STORED_FACT_FIELDS if name in KIND_FREE_FIELDS)


@pytest.mark.parametrize("kind", ["", "unclassified", None])
def test_every_stored_kind_free_field_is_read_for_a_record_of_no_kind(kind: str | None) -> None:
    from maljan.core import declared_reading
    from maljan.reporting import tool_kinds

    assert set(_stored_kind_free_fields()) == set(KIND_FREE_SAMPLES)
    for name in _stored_kind_free_fields():
        record = {"v": 1, name: KIND_FREE_SAMPLES[name]}
        if kind is not None:
            record["kind"] = kind
        entry = _dev_entry(record)
        assert declared_reading.facts_of(entry) is None
        read = declared_reading.kind_free_facts(entry).model_dump(mode="json")
        assert read[name] == KIND_FREE_SAMPLES[name], name
        assert tool_kinds.kind_free_facts(entry).model_dump(mode="json")[name] == read[name]


def test_a_kind_free_field_the_validators_refuse_costs_no_other() -> None:
    from maljan.core import declared_reading
    from maljan.core.tool_declarations import strict_declarations

    entry = _dev_entry({"v": 1, "kind": "", "display_name": "S", "arguments": {"Not A Role": "x"}})
    with strict_declarations():
        facts = declared_reading.kind_free_facts(entry)
    assert (facts.display_name, dict(facts.arguments)) == ("S", {})
    assert declared_reading.kind_free_facts(_dev_entry({"kind": "", "display_name": "S"})) == (
        ToolFacts.model_construct()
    )


@pytest.mark.parametrize("kind", ["", "unclassified"])
def test_a_report_argument_declared_without_a_kind_keeps_the_tool_off_the_file(
    kind: str,
) -> None:
    from maljan.reporting.renderers.markdown import _looked_at_the_file

    row = {
        "tool": "my_tool",
        "source": "mcp:operator",
        "facts": {"v": 1, "kind": kind, "arguments": {"report": "task_report"}},
    }
    # As on dev, where the bare word was a kind: the tool read a report.
    assert _looked_at_the_file(row) is False
    assert _looked_at_the_file({**row, "facts": {"v": 1, "kind": kind}}) is True


def test_an_address_argument_declared_without_a_kind_is_read_first() -> None:
    from maljan.core import declared_reading
    from maljan.core.undeclared_tools import ADDRESS_ARGUMENTS, address_arguments

    entry = _dev_entry({"v": 1, "kind": "unclassified", "arguments": {"address": "offset_va"}})
    assert address_arguments(declared_reading.kind_free_facts(entry))[0] == "offset_va"
    plain = _dev_entry({"v": 1})
    assert address_arguments(declared_reading.kind_free_facts(plain)) == ADDRESS_ARGUMENTS


@pytest.mark.parametrize("kind", ["", "unclassified"])
def test_an_entry_s_address_argument_declared_without_a_kind_is_read(kind: str) -> None:
    from maljan.core.undeclared_tools import ADDRESS_ARGUMENTS, entry_address_arguments

    entry = _dev_entry({"v": 1, "kind": kind, "arguments": {"address": "offset_va"}})
    assert entry_address_arguments(entry)[0] == "offset_va"
    assert entry_address_arguments(_dev_entry({"v": 1, "kind": kind})) == ADDRESS_ARGUMENTS


_KIND_GATED = {"facts_of", "entry_facts", "declared_facts", "stored_facts_by_name"}
_READERS_OF_FIELDS = {"address_arguments"}


def _kind_gated_reads(source: str, where: str = "") -> list[str]:
    """Each place ``source`` reads a stored kind-free field off a kind-gated reader's answer.

    The answer is followed wherever it can stand for the gated call: the call
    itself, an ``or``/``and`` or conditional expression holding it, a walrus,
    an ``await``, and a name bound to any of these by ``=`` (one target or
    position by position in a tuple), an annotated assignment, a walrus, a
    ``for`` or comprehension target over a literal holding it, a ``with``
    target of it (or of a call handed it first), and a lambda parameter the
    lambda is called with it for. A field is read off it as an attribute, by
    ``getattr`` with the field's name, by handing it to a reader of the
    fields, or by name (``.get("<field>")`` or ``["<field>"]``) off its
    ``model_dump()``, ``dict()``, ``vars()`` or ``__dict__``. Function bodies
    and the code outside every function (module and class bodies) are walked.

    Not followed (none is used anywhere; a reader that needs one reads
    ``declared_reading.kind_free_facts`` instead): ``functools.partial`` and
    ``operator.attrgetter`` over it, ``getattr`` with a field name held in a
    variable, star-unpacking with unequal lengths, a ``match`` capture, the
    answer stored in a container (or iterated from a name bound to one) and
    read back, a helper that returns the answer, and the answer passed
    through any other call.
    """
    import ast

    fields = set(_stored_kind_free_fields())
    mappings = {"model_dump", "dict"}

    def callee(node: ast.Call) -> str:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        return func.attr if isinstance(func, ast.Attribute) else ""

    def yields_gated(node: ast.AST | None, bound: set[str]) -> bool:
        if isinstance(node, ast.Call):
            return callee(node) in _KIND_GATED
        if isinstance(node, ast.Name):
            return node.id in bound
        if isinstance(node, ast.BoolOp):
            return any(yields_gated(value, bound) for value in node.values)
        if isinstance(node, ast.IfExp):
            return yields_gated(node.body, bound) or yields_gated(node.orelse, bound)
        if isinstance(node, ast.NamedExpr | ast.Await):
            return yields_gated(node.value, bound)
        return False

    def holds_gated(node: ast.AST | None, bound: set[str]) -> bool:
        """A literal collection with the answer in it: what a loop target takes."""
        return isinstance(node, ast.Tuple | ast.List | ast.Set) and any(
            yields_gated(element, bound) for element in node.elts
        )

    def mapping_of_gated(node: ast.AST, bound: set[str]) -> bool:
        """The answer's fields by name: ``model_dump()``, ``dict()``, ``vars()``, ``__dict__``."""
        if isinstance(node, ast.Attribute) and node.attr == "__dict__":
            return yields_gated(node.value, bound)
        if not isinstance(node, ast.Call):
            return False
        if isinstance(node.func, ast.Attribute) and node.func.attr in mappings:
            return yields_gated(node.func.value, bound)
        if isinstance(node.func, ast.Name) and node.func.id == "vars" and node.args:
            return yields_gated(node.args[0], bound)
        return False

    def names_field(node: ast.AST | None) -> bool:
        return isinstance(node, ast.Constant) and node.value in fields

    def bind(target: ast.AST, value: ast.AST | None, bound: set[str]) -> bool:
        if isinstance(target, ast.Name) and target.id not in bound:
            if yields_gated(value, bound):
                bound.add(target.id)
                return True
        if isinstance(target, ast.Tuple | ast.List) and isinstance(value, ast.Tuple | ast.List):
            if len(target.elts) == len(value.elts):
                return any(bind(t, v, bound) for t, v in zip(target.elts, value.elts, strict=True))
        return False

    def bind_name(target: ast.AST | None, bound: set[str]) -> bool:
        if isinstance(target, ast.Name) and target.id not in bound:
            bound.add(target.id)
            return True
        if isinstance(target, ast.arg) and target.arg not in bound:
            bound.add(target.arg)
            return True
        return False

    def bindings(node: ast.AST, bound: set[str]) -> bool:
        if isinstance(node, ast.Assign):
            return any(bind(t, node.value, bound) for t in node.targets)
        if isinstance(node, ast.AnnAssign | ast.NamedExpr):
            return bind(node.target, node.value, bound)
        if isinstance(node, ast.For | ast.AsyncFor | ast.comprehension):
            return holds_gated(node.iter, bound) and bind_name(node.target, bound)
        if isinstance(node, ast.withitem):
            held = node.context_expr
            handed = isinstance(held, ast.Call) and bool(held.args)
            if yields_gated(held, bound) or (
                handed and isinstance(held, ast.Call) and yields_gated(held.args[0], bound)
            ):
                return bind_name(node.optional_vars, bound)
            return False
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Lambda):
            grew = False
            for param, arg in zip(node.func.args.args, node.args, strict=False):
                if yields_gated(arg, bound):
                    grew |= bind_name(param, bound)
            return grew
        return False

    def outside_functions(tree: ast.AST) -> list[ast.AST]:
        """The nodes of the module and class bodies, without any function's body."""
        out: list[ast.AST] = []
        pending: list[ast.AST] = [tree]
        while pending:
            node = pending.pop()
            out.append(node)
            for child in ast.iter_child_nodes(node):
                if not isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                    pending.append(child)
        return out

    found: list[str] = []
    tree = ast.parse(source)
    scopes: list[tuple[str, list[ast.AST]]] = [("<module>", outside_functions(tree))]
    for fn in ast.walk(tree):
        if isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
            scopes.append((fn.name, list(ast.walk(fn))))
    for name_of_scope, nodes in scopes:
        bound: set[str] = set()
        grew = True
        while grew:  # a name bound from a name bound earlier
            grew = False
            for node in nodes:
                grew |= bindings(node, bound)
        for node in nodes:
            here = f"{where}:{getattr(node, 'lineno', 0)} {name_of_scope}"
            if isinstance(node, ast.Attribute) and node.attr in fields:
                if yields_gated(node.value, bound):
                    found.append(here)
            if isinstance(node, ast.Subscript) and names_field(node.slice):
                if mapping_of_gated(node.value, bound):
                    found.append(here)
            if not isinstance(node, ast.Call):
                continue
            name = callee(node)
            if name == "getattr" and len(node.args) >= 2:
                if names_field(node.args[1]) and yields_gated(node.args[0], bound):
                    found.append(here)
            if name in _READERS_OF_FIELDS and any(yields_gated(a, bound) for a in node.args):
                found.append(here)
            if (
                name == "get"
                and isinstance(node.func, ast.Attribute)
                and node.args
                and names_field(node.args[0])
                and mapping_of_gated(node.func.value, bound)
            ):
                found.append(here)
    return found


def test_no_kind_free_field_is_read_only_through_a_kind() -> None:
    """A stored kind-free field is never read off what a kind-gated reader returned."""
    from pathlib import Path

    repo = Path(__file__).resolve().parents[3]
    found: list[str] = []
    for root in ("src/maljan", "apps/api/app"):
        for path in sorted((repo / root).rglob("*.py")):
            found += _kind_gated_reads(
                path.read_text(encoding="utf-8"), str(path.relative_to(repo))
            )
    assert not found, found


_GATED_READ_FORMS = {
    "an assignment": "facts = tool_kinds.facts_of(row)\n    return facts.arguments",
    "an annotated assignment": "facts: Any = tool_kinds.facts_of(row)\n    return facts.arguments",
    "a walrus": "if (facts := tool_kinds.facts_of(row)) is not None:\n        return facts.words",
    "an or around the call": "return (tool_kinds.facts_of(row) or ToolFacts()).arguments",
    "a conditional around the call": (
        "return (tool_kinds.facts_of(row) if row else ToolFacts()).display_name"
    ),
    "getattr on the call": 'return getattr(tool_kinds.facts_of(row), "arguments")',
    "getattr on a bound name": (
        'facts = declared_reading.facts_of(row)\n    return getattr(facts, "words", None)'
    ),
    "a name bound from a bound name": (
        "facts = tool_kinds.facts_of(row)\n    held = facts or None\n    return held.arguments"
    ),
    "a tuple assignment": "facts, n = tool_kinds.facts_of(row), 1\n    return facts.display_name",
    "a reader of the fields": (
        "facts = tool_kinds.facts_of(row)\n    return address_arguments(facts)"
    ),
    "an awaited call": "return (await tool_kinds.facts_of(row)).arguments",
    "a list comprehension target": ("return [f.arguments for f in [tool_kinds.facts_of(row)]]"),
    "a generator target": "return next(f.words for f in (tool_kinds.facts_of(row),))",
    "a dict comprehension target": (
        "return {1: f.display_name for f in {tool_kinds.facts_of(row)}}"
    ),
    "a for target": "for facts in (tool_kinds.facts_of(row),):\n        return facts.arguments",
    "an async for target": (
        "async for facts in [tool_kinds.facts_of(row)]:\n        return facts.words"
    ),
    "a with target of the answer": (
        "with tool_kinds.facts_of(row) as facts:\n        return facts.arguments"
    ),
    "a with target of a call handed the answer": (
        "with nullcontext(tool_kinds.facts_of(row)) as facts:\n        return facts.arguments"
    ),
    "a lambda parameter": "return (lambda f: f.arguments)(tool_kinds.facts_of(row))",
    "model_dump get": 'return tool_kinds.facts_of(row).model_dump().get("arguments")',
    "model_dump subscript": 'return tool_kinds.facts_of(row).model_dump()["arguments"]',
    "model_dump on a bound name": (
        'facts = tool_kinds.facts_of(row)\n    return facts.model_dump(mode="json")["words"]'
    ),
    "vars subscript": 'return vars(tool_kinds.facts_of(row))["arguments"]',
    "vars get": 'return vars(tool_kinds.facts_of(row)).get("display_name")',
    "__dict__ get": 'facts = tool_kinds.facts_of(row)\n    return facts.__dict__.get("words")',
}


@pytest.mark.parametrize("form", sorted(_GATED_READ_FORMS))
def test_the_guard_catches_a_kind_gated_read_in_every_form(form: str) -> None:
    body = _GATED_READ_FORMS[form]
    source = f"async def reader(row):\n    {body}\n"
    assert _kind_gated_reads(source), form


@pytest.mark.parametrize(
    "source",
    [
        "x = tool_kinds.facts_of(row).arguments\n",
        "facts = tool_kinds.facts_of(row)\nx = facts.words\n",
        "class C:\n    x = tool_kinds.facts_of(row).display_name\n",
    ],
)
def test_the_guard_reads_module_and_class_bodies_too(source: str) -> None:
    assert _kind_gated_reads(source), source


def test_the_guard_passes_the_one_reader_of_kind_free_facts() -> None:
    clean = (
        "def reader(row):\n"
        "    facts = declared_reading.kind_free_facts(row)\n"
        "    kind = tool_kinds.facts_of(row)\n"
        '    return facts.arguments, getattr(facts, "words"), address_arguments(facts), kind.rows\n'
        "def other(row):\n"
        "    kind = tool_kinds.facts_of(row)\n"
        '    held = kind.model_dump()["rows"], vars(kind).get("kind")\n'
        "    return [f.arguments for f in [declared_reading.kind_free_facts(row)]], held\n"
    )
    assert _kind_gated_reads(clean) == []
