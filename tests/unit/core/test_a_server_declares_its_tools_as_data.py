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


@pytest.mark.parametrize("kind", ["", "Strings", "rule-match", "1st", "a" * 65])
def test_a_kind_that_is_not_a_lowercase_word_is_refused(kind: str) -> None:
    with pytest.raises(ValidationError, match="vocabulary word"):
        ToolFacts(kind=kind)


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


@pytest.mark.parametrize("name", ["", " capa", "analysis__capa", "__proto__"])
def test_a_declared_tool_name_is_a_tools_own_name(name: str) -> None:
    with pytest.raises(ValidationError, match="tool"):
        MCPServerConfig(tool_facts={name: {"kind": "strings"}})
    with pytest.raises(ValidationError, match="tool"):
        ErrorPattern(match="x", tools=(name,))


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
    assert facts.counts_in_text("x 3/9 detections y") == (3, 9)
    assert facts.counts_in_text("found 4 bad ones") == (4, None)
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
    assert d.declaration_for(("mcp:virustotal", "get_file_report")).kind == "file_reputation"
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
    entry = {"source": "provider:generic_mcp", "tool": "sandbox_signatures"}
    assert d.declaration_for(entry) is None
    assert d.declaration_for({"source": "sandbox", "tool": "sandbox_signatures"}) is not None


def test_an_operator_server_named_like_the_pack_is_its_own_server() -> None:
    d = _declarations(mcp={"servers": {"pipeline": {"command": "x"}}})
    entry = {"source": "mcp:pipeline", "server": "pipeline", "agent": "pipeline", "tool": "capa"}
    assert d.source_of(entry) == SourceRef("mcp", "pipeline")
    assert d.declaration_for(entry) is None


def test_the_generic_provider_reads_the_server_it_names() -> None:
    servers = {"mydis": {"command": "x", "tool_facts": {"pseudo_c": {"kind": "decompile"}}}}
    d = _declarations(
        mcp={"servers": servers},
        static={"provider": "generic_mcp", "generic": {"server": "mydis"}},
    )
    entry = {"source": "provider:generic_mcp", "tool": "pseudo_c"}
    assert d.declaration_for(entry).kind == "decompile"
    kinds = d.tools_of_kind("decompile", enabled_only=True)
    assert (SourceRef("provider", "generic_mcp"), "pseudo_c") in {(s, t) for s, t, _ in kinds}


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
