"""A decompiler's or disassembler's tools are read from what it lists, never from a table.

The platform ships no table of Ghidra's or radare2's tools (T-418 PR4). What
each listed tool is, is read from its MCP definition by its verb and its
arguments' role words (``core.program_reading``), for any server whose
block's ``roles`` hold a program role; what the block says of its tools as a
whole (``default_effects``) and of its analysis step (``analyse_effects``,
for the tool its ``sample_open`` names to analyse) is laid under each tool's
effects. Held here, over the vendored listings every test starts with
(``tests/conftest.py``):

* the reading of the shipped blocks: kinds by verb, a modifying verb never a
  decompiler, the opening tools read as opening a program, the arguments read
  by exact role words, read-only only for a read of the job's program;
* the disclosure: no Ghidra or radare2 tool reads as sending the sample,
  radare2's analysis reads as emulating at level 2 and above, and a tool that
  says it uploads the file still reads as sending it under the statement;
* a never-seen reverser server whose tools are renamed with the same verbs
  gets the same facts;
* Ghidra's ``/mcp/schema`` (its HTTP transport) is read as any listing is.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from tests.conftest import ghidra_listing, r2_listing

from maljan.core import served_declarations
from maljan.core.config import MCPServerConfig, SampleOpenConfig, Settings, ghidra_block
from maljan.core.derived_declarations import derived_readings, program_readings_of
from maljan.core.program_reading import program_facts, program_kind
from maljan.core.tool_declarations import ToolDeclarations, ToolFacts, launch_identity
from maljan.core.undeclared_tools import decompiles, reads_xrefs

ROOT = Path(__file__).resolve().parents[3]
SCHEMA = ROOT / "tests" / "fixtures" / "tools" / "ghidra_mcp_schema.json"
# Ghidra's MCP listing over stdio, as vendored.
STDIO = ROOT / "tests" / "fixtures" / "tools" / "reverser_ghidra_tool_definitions.json"


@pytest.fixture(scope="module")
def declared() -> ToolDeclarations:
    return ToolDeclarations.from_settings(Settings(_env_file=None))


def _tools(declared: ToolDeclarations, source: str) -> dict[str, ToolFacts]:
    held = declared.source(source)
    assert held is not None, source
    return dict(held.tools)


@pytest.fixture(scope="module")
def ghidra(declared: ToolDeclarations) -> dict[str, ToolFacts]:
    return _tools(declared, "provider:ghidra")


@pytest.fixture(scope="module")
def r2(declared: ToolDeclarations) -> dict[str, ToolFacts]:
    return _tools(declared, "provider:r2")


@pytest.fixture(scope="module")
def ghidra_read() -> dict[str, ToolFacts]:
    """Ghidra's listing as a reverser with no table of its tools reads it."""
    return _never_seen(ghidra_listing(), "unseen_ghidra", _unseen_block("ghidra"))


@pytest.fixture(scope="module")
def r2_read() -> dict[str, ToolFacts]:
    """radare2's listing as a reverser with no table of its tools reads it."""
    return _never_seen(r2_listing(), "unseen_r2", _unseen_block("r2"))


# ---------------------------------------------------------------------------
# What the shipped blocks read
# ---------------------------------------------------------------------------


def test_every_listed_tool_is_read_with_a_kind_and_its_category(
    ghidra_read: dict[str, ToolFacts], r2_read: dict[str, ToolFacts]
) -> None:
    ghidra, r2 = ghidra_read, r2_read
    from maljan.core.undeclared_tools import category_tag

    assert len(ghidra) == 165 and len(r2) == 33
    for name, facts in (*ghidra.items(), *r2.items()):
        assert facts.kind, name
        assert facts.category == category_tag(name).lower(), name


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("decompile_function", "decompile"),
        ("batch_decompile", "decompile_batch"),
        ("disassemble_function", "function_disassembly"),
        ("disassemble_bytes", "disassembly"),
        ("get_xrefs_to", "xrefs"),
        ("list_strings", "listing_strings"),
        ("search_strings", "string_search"),
        ("list_imports", "import_listing"),
        ("list_exports", "export_listing"),
        ("list_functions", "function_list"),
        ("list_methods", "method_list"),
        ("list_segments", "segments"),
        ("get_current_program_info", "program_info"),
        ("get_function_callers", "callers"),
        ("get_function_callees", "callees"),
        ("analyze_api_call_chains", "call_chains"),
        ("detect_crypto_constants", "crypto_constants"),
        ("analyze_dataflow", "dataflow"),
        ("extract_iocs_with_context", "iocs_with_context"),
        ("find_anti_analysis_techniques", "anti_analysis_scan"),
        ("analyze_function_complete", "function_analysis"),
        ("analyze_function_completeness", "documentation_completeness"),
        ("batch_analyze_completeness", "analysis"),
        ("force_decompile", "decompile_refresh"),
        ("load_program_from_project", "project_load"),
        ("open_project", "project_navigation"),
        ("import_file", "file_import"),
        ("set_decompiler_comment", "program_edit"),
        ("rename_function", "program_edit"),
        ("emulate_function", "emulation"),
        ("load_program", "open_sample"),
        ("open_program", "open_sample"),
        ("switch_program", "select_sample"),
        ("close_program", "sample_close"),
        ("run_analysis", "analyse_sample"),
        ("run_ghidra_script", "run"),
        ("server_status", "status"),
        ("analysis_status", "status"),
        ("validate_data_type", "check"),
        ("detect_malware_behaviors", "behaviour_scan"),
        ("analyze_call_graph", "analysis"),
        ("list_data_items_by_xrefs", "listing"),
    ],
)
def test_a_ghidra_tool_is_read_by_its_verb(
    ghidra_read: dict[str, ToolFacts], name: str, kind: str
) -> None:
    assert ghidra_read[name].kind == kind


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("open_file", "open_sample"),
        ("analyze", "analyse_sample"),
        ("decompile_function", "decompile"),
        ("xrefs_to", "xrefs"),
        ("list_decompilers", "listing"),
        ("use_decompiler", "utility"),
        ("list_all_strings", "listing"),
        ("list_strings", "listing_strings"),
        ("list_imports", "import_listing"),
        ("list_functions", "function_list"),
        ("list_sections", "segments"),
        ("close_file", "sample_close"),
    ],
)
def test_a_radare2_tool_is_read_by_its_verb(
    r2_read: dict[str, ToolFacts], name: str, kind: str
) -> None:
    assert r2_read[name].kind == kind


def test_a_modifying_verb_never_reads_as_a_decompiler(
    ghidra_read: dict[str, ToolFacts], r2_read: dict[str, ToolFacts]
) -> None:
    ghidra, r2 = ghidra_read, r2_read
    named = {
        (source, name)
        for source, tools in (("ghidra", ghidra), ("r2", r2))
        for name in tools
        if "decompil" in name
    }
    decompilers = {(s, n) for s, n in named if decompiles((ghidra if s == "ghidra" else r2)[n], n)}
    assert decompilers == {
        ("ghidra", "decompile_function"),
        ("ghidra", "batch_decompile"),
        ("ghidra", "force_decompile"),
        ("r2", "decompile_function"),
    }
    assert not decompiles(ghidra["set_decompiler_comment"], "set_decompiler_comment")
    assert not reads_xrefs(ghidra["list_data_items_by_xrefs"], "list_data_items_by_xrefs")


def test_an_open_or_load_verb_reaches_the_open_program_readers(
    ghidra_read: dict[str, ToolFacts], r2_read: dict[str, ToolFacts]
) -> None:
    ghidra, r2 = ghidra_read, r2_read
    from maljan.agents.image_range import _OPENS_A_PROGRAM
    from maljan.core.declared_reading import consumer_kinds

    opening = consumer_kinds("evidence_roots._OPEN_TOOLS")
    for facts in (ghidra["load_program"], ghidra["open_program"], r2["open_file"]):
        assert facts.kind in opening and facts.kind in _OPENS_A_PROGRAM
        assert facts.arguments.get("path")
    assert ghidra["load_program"].arguments == {"path": "file"}
    assert r2["open_file"].arguments == {"path": "file_path"}


def test_an_argument_is_read_by_its_exact_role_word(
    ghidra: dict[str, ToolFacts], r2: dict[str, ToolFacts]
) -> None:
    # Not the sample's hash, nor an address: the hash routine's address.
    assert ghidra["emulate_hash_batch"].arguments == {"program": "program"}
    # A struct's address, a diff's two addresses and a load base are no code place.
    assert "address" not in ghidra["get_field_access_context"].arguments
    assert "address" not in ghidra["suggest_field_names"].arguments
    assert "address" not in ghidra["diff_functions"].arguments
    assert "address" not in r2["open_file"].arguments
    # The start of a range of code is one.
    assert ghidra["disassemble_bytes"].arguments["address"] == "start_address"
    assert ghidra["decompile_function"].arguments == {"address": "address", "program": "program"}
    assert ghidra["rename_function_by_address"].arguments["address"] == "function_address"
    # A category's path is no file; a changing verb's path is never read as one.
    assert "path" not in ghidra["create_data_type_category"].arguments
    assert "path" not in ghidra["create_folder"].arguments
    assert "path" not in ghidra["delete_file"].arguments


def test_a_read_is_read_only_only_for_the_job_s_program(
    ghidra: dict[str, ToolFacts], r2: dict[str, ToolFacts]
) -> None:
    # What every job on the server shares, or a state that moves, never answers again.
    for name in (
        "list_open_programs",
        "list_scripts",
        "get_project_info",
        "list_project_files",
        "server_status",
        "analysis_status",
        "load_program",
        "run_analysis",
        "set_decompiler_comment",
    ):
        assert not ghidra[name].read_only, name
    for name in ("get_current_address", "show_info", "show_function_details", "list_files"):
        assert not r2[name].read_only, name
    # On a server other jobs share, every read-only tool names the job's program.
    held = {n for n, f in ghidra.items() if f.read_only}
    assert held and all(ghidra[n].arguments.get("program") == "program" for n in held)
    assert {"decompile_function", "list_imports", "get_current_program_info"} <= held
    assert {"decompile_function", "list_imports", "xrefs_to"} <= {
        n for n, f in r2.items() if f.read_only
    }


def test_a_read_is_never_read_only_without_the_block_s_statement() -> None:
    from maljan.core.declared_reading import tools_in_force

    listing = r2_listing()
    read, closed = derived_readings(listing)
    block = MCPServerConfig(roles=["disassembler"])
    tools = tools_in_force("mcp:unsaid", block, {}, read, closed, program_readings_of(listing))
    assert not any(f.read_only for f in tools.values())
    assert tools["list_imports"].effects is None


def test_a_batch_names_the_listed_tool_it_aggregates(ghidra_read: dict[str, ToolFacts]) -> None:
    from maljan.core.undeclared_tools import aggregates_of

    assert aggregates_of(ghidra_read) == {
        "batch_decompile": ("decompile_function",),
        "batch_analyze_completeness": ("analyze_function_completeness",),
        "batch_create_labels": ("create_label",),
        "batch_delete_labels": ("delete_label",),
        "batch_set_comments": (
            "set_decompiler_comment",
            "set_disassembly_comment",
            "set_plate_comment",
        ),
        "get_bulk_function_hashes": ("get_function_hash",),
        "get_full_call_graph": ("get_function_call_graph",),
        "rename_variables": ("rename_variable",),
    }
    # Its definition says neither references to nor from each address.
    assert ghidra_read["get_bulk_xrefs"].aggregate_of == ()


def test_a_tool_that_declares_itself_is_not_read() -> None:
    from maljan.tools.declared_facts import FACTS_META_KEY

    listed = {
        "name": "list_imports",
        "inputSchema": {"type": "object", "properties": {}},
        "_meta": {FACTS_META_KEY: {"kind": "import_listing"}},
    }
    assert program_readings_of([listed]) == {}


# ---------------------------------------------------------------------------
# What a call does beyond answering
# ---------------------------------------------------------------------------

_LOCAL = {"executes": "no", "network": False, "third_party": "no"}


def _effects(facts: ToolFacts) -> dict[str, Any]:
    assert facts.effects is not None
    return facts.effects.model_dump(exclude_defaults=True)


def test_no_ghidra_or_radare2_tool_reads_as_sending_the_sample(
    ghidra: dict[str, ToolFacts], r2: dict[str, ToolFacts]
) -> None:
    from maljan.analysis.tool_effects import sends_sample_bytes

    for source, tools in (("ghidra", ghidra), ("r2", r2)):
        for name, facts in tools.items():
            assert not facts.discloses_sample, (source, name)
            assert not sends_sample_bytes(facts), (source, name)
            effects = facts.effects
            assert effects is not None, (source, name)
            if effects.why_undeclared:
                continue
            assert effects.third_party == "no" and effects.network is False, (source, name)


def test_radare2_s_analysis_reads_as_emulating_at_level_two_and_above(
    r2: dict[str, ToolFacts], ghidra: dict[str, ToolFacts]
) -> None:
    effects = _effects(r2["analyze"])
    assert effects["executes"] == "emulation"
    assert "level 2 and above" in effects["when"]
    assert (effects["network"], effects["third_party"]) == (False, "no")
    # Ghidra's analysis step gains nothing of it.
    assert _effects(ghidra["run_analysis"]) == _LOCAL


def test_a_tool_that_says_otherwise_keeps_what_it_says(
    ghidra: dict[str, ToolFacts], r2: dict[str, ToolFacts]
) -> None:
    assert _effects(ghidra["emulate_function"]) == {**_LOCAL, "executes": "emulation"}
    assert _effects(ghidra["emulate_hash_batch"]) == {**_LOCAL, "executes": "emulation"}
    for facts in (ghidra["run_ghidra_script"], ghidra["run_script_inline"]):
        assert set(_effects(facts)) == {"why_undeclared"}
    command = {
        "name": "run_command",
        "description": "Run a radare2 command",
        "inputSchema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    }
    assert set(_effects(program_facts(command) or ToolFacts())) == {"why_undeclared"}
    assert _effects(ghidra["list_imports"]) == _LOCAL
    assert _effects(r2["open_file"]) == _LOCAL


def test_a_tool_that_says_it_uploads_the_file_still_sends_it() -> None:
    from maljan.core.declared_reading import tools_in_force

    listing = [
        *r2_listing(),
        {
            "name": "upload_sample",
            "description": "Uploads the file to the vendor for a second opinion.",
            "inputSchema": {
                "type": "object",
                "properties": {"file_path": {"type": "string"}},
                "required": ["file_path"],
            },
        },
    ]
    read, closed = derived_readings(listing)
    block = Settings(_env_file=None).static.r2
    tools = tools_in_force("provider:r2", block, {}, read, closed, program_readings_of(listing))
    assert tools["upload_sample"].discloses_sample
    assert _effects(tools["upload_sample"])["third_party"] == "bytes"
    assert not tools["open_file"].discloses_sample


def test_the_statement_never_lifts_a_disclosure_off_another_server() -> None:
    from maljan.core.declared_reading import tools_in_force

    listing = r2_listing()
    read, closed = derived_readings(listing)
    # A block that is no program's, saying its tools send nothing: its path
    # tools are still read as sending the file they open.
    block = MCPServerConfig(default_effects=_LOCAL)
    tools = tools_in_force("mcp:other", block, {}, read, closed, program_readings_of(listing))
    assert tools["open_file"].discloses_sample
    assert _effects(tools["open_file"])["third_party"] == "bytes"
    # And with no statement, a program server's path tools send what they open.
    bare = MCPServerConfig(roles=["decompiler"])
    held = tools_in_force("mcp:bare", bare, {}, read, closed, program_readings_of(listing))
    assert held["open_file"].discloses_sample


# ---------------------------------------------------------------------------
# A server never seen before
# ---------------------------------------------------------------------------


# Another server's words for the same meaning: a verb of the same category,
# the other word for a binary's sections.
_SYNONYMS = {"get": "list", "detect": "find", "segments": "sections"}


def _renamed(name: str) -> str:
    """Another spelling of the same meaning: camelCase, and each word's synonym."""
    words = [_SYNONYMS.get(w, w) for w in name.split("_")]
    return words[0] + "".join(w[:1].upper() + w[1:] for w in words[1:])


def _renamed_listing(listing: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{**d, "name": _renamed(d["name"])} for d in listing]


def _never_seen(
    listing: list[dict[str, Any]], key: str, block: Mapping[str, Any]
) -> dict[str, ToolFacts]:
    """The tools in force for a server of ``block`` never seen before, listing ``listing``."""
    raw = {"command": f"{key}-mcp", **block}
    settings = Settings.model_validate({"mcp": {"servers": {key: raw}}})
    held = settings.mcp.servers[key]
    read, closed = derived_readings(listing)
    try:
        served_declarations.register_served(
            f"mcp:{key}", {}, launch_identity(held), read, closed, program_readings_of(listing)
        )
        tools = ToolDeclarations.from_settings(settings).source(f"mcp:{key}")
        assert tools is not None
        return dict(tools.tools)
    finally:
        served_declarations.forget_served(f"mcp:{key}")


def _unseen_block(which: str, rename: Any = None) -> dict[str, Any]:
    """A block of the shipped one's statements, with no table: what any reverser can say."""
    name = rename or (lambda n: n)
    shipped = getattr(Settings(_env_file=None).static, which)
    spec = shipped.sample_open.model_dump(exclude_defaults=True)
    for field in ("open_tool", "select_tool", "analyse_tool", "close_tool"):
        if spec.get(field):
            spec[field] = name(spec[field])
    for field in ("job_safe_tools", "shared_withheld_tools"):
        if spec.get(field):
            spec[field] = [name(n) for n in spec[field]]
    block: dict[str, Any] = {
        "roles": ["decompiler"],
        "sample_open": spec,
        "default_effects": shipped.default_effects.model_dump(exclude_defaults=True),
    }
    if shipped.analyse_effects is not None:
        block["analyse_effects"] = shipped.analyse_effects.model_dump(exclude_defaults=True)
    return block


def _same_facts(original: ToolFacts, renamed: ToolFacts) -> None:
    left = original.model_dump(exclude_defaults=True)
    right = renamed.model_dump(exclude_defaults=True)
    left["aggregate_of"] = [_renamed(n) for n in left.get("aggregate_of", ())] or None
    right["aggregate_of"] = list(right.get("aggregate_of", ())) or None
    assert left == right


@pytest.mark.parametrize("which", ["ghidra", "r2"])
def test_a_never_seen_server_with_renamed_tools_gets_the_same_facts(
    which: str, ghidra_read: dict[str, ToolFacts], r2_read: dict[str, ToolFacts]
) -> None:
    listing = ghidra_listing() if which == "ghidra" else r2_listing()
    tools = _never_seen(
        _renamed_listing(listing), f"never_seen_{which}", _unseen_block(which, _renamed)
    )
    original = ghidra_read if which == "ghidra" else r2_read
    assert set(tools) == {_renamed(n) for n in original}
    for name, facts in original.items():
        _same_facts(facts, tools[_renamed(name)])


@pytest.mark.parametrize("which", ["ghidra", "r2"])
def test_the_shipped_blocks_read_as_a_never_seen_server_does(
    which: str,
    ghidra: dict[str, ToolFacts],
    r2: dict[str, ToolFacts],
    ghidra_read: dict[str, ToolFacts],
    r2_read: dict[str, ToolFacts],
) -> None:
    # No table of their tools is left: the shipped blocks' statements alone.
    shipped, read = (ghidra, ghidra_read) if which == "ghidra" else (r2, r2_read)
    assert {n: f.model_dump() for n, f in shipped.items()} == {
        n: f.model_dump() for n, f in read.items()
    }


# ---------------------------------------------------------------------------
# Ghidra's HTTP transport
# ---------------------------------------------------------------------------


def test_ghidra_s_schema_is_read_as_its_mcp_listing_is() -> None:
    fixture = json.loads(STDIO.read_text())
    schema_names = {d["name"] for d in ghidra_listing()}
    stdio = [
        {"name": t["name"], "description": t["description"], "inputSchema": t["input_schema"]}
        for t in fixture
        if t["name"] in schema_names
    ]
    assert len(stdio) == len(schema_names) == 165
    by_http = program_readings_of(ghidra_listing())
    by_stdio = program_readings_of(stdio)
    assert {n: f.model_dump() for n, f in by_http.items()} == {
        n: f.model_dump() for n, f in by_stdio.items()
    }


def test_the_schema_s_method_says_nothing_of_a_change() -> None:
    # Why the HTTP method is not read: the server opens, selects and saves by
    # GET, and reads by POST.
    schema = json.loads(SCHEMA.read_text())["tools"]
    method = {t["path"].lstrip("/"): t["method"] for t in schema}
    assert {method[n] for n in ("open_program", "switch_program", "save_program")} == {"GET"}
    assert {method[n] for n in ("disassemble_bytes", "get_bulk_xrefs")} == {"POST"}


def test_ghidra_s_http_attach_keeps_what_it_read(monkeypatch: pytest.MonkeyPatch) -> None:
    from maljan.providers.static.ghidra.provider import GhidraStaticProvider

    cfg = ghidra_block()
    source, launch = "provider:ghidra", launch_identity(cfg)
    served_declarations.forget_served(source)
    assert not served_declarations.program_read(source, launch)
    provider = object.__new__(GhidraStaticProvider)
    provider._cfg = cfg
    provider._guard = None
    provider._register_listing({}, ghidra_listing())
    held = served_declarations.program_read(source, launch)
    assert held["load_program"].kind == "open_sample"
    assert served_declarations.derived(source, launch)["load_program"].discloses_sample


# ---------------------------------------------------------------------------
# radare2's analysis step, and what is kept
# ---------------------------------------------------------------------------


def test_an_analysis_tool_may_be_named_without_an_open_tool() -> None:
    from maljan.providers.sample_open import declared, long_running_tools

    spec = SampleOpenConfig(analyse_tool="analyze")
    assert not declared(spec)
    assert long_running_tools(spec) == frozenset()
    with pytest.raises(ValueError, match="no open_tool"):
        SampleOpenConfig(analyse_tool="analyze", analyse_argument="program")


def test_the_reading_is_kept_past_the_process() -> None:
    listing = r2_listing()
    read, closed = derived_readings(listing)
    program = program_readings_of(listing)
    form = served_declarations.stored_form({}, read, closed, program)
    source, launch = "mcp:kept_reverser", "kept-launch"
    try:
        served_declarations.install_persisted([(source, launch, form)])
        assert served_declarations.program_read(source, launch) == program
        # A row an earlier release kept, with no program reading, reads none.
        older = {"": {"derived": form[""]["derived"]}}
        served_declarations.install_persisted([(source, launch, older)])
        assert served_declarations.program_read(source, launch) == {}
        assert served_declarations.derived(source, launch) == read
    finally:
        served_declarations.forget_served(source)


def test_a_verb_gives_a_kind_for_any_name() -> None:
    assert program_kind("") == "utility"
    assert program_kind("fooBar") == "utility"
    assert program_kind("listThings") == "listing"
    assert program_kind("bulk_decompile_routines") == "decompile_batch"


# ---------------------------------------------------------------------------
# Disclosure under the statement, what runs what it is given, stored changes,
# a server spelt otherwise
# ---------------------------------------------------------------------------

_SENDERS = [
    {
        "name": "scan_bytes",
        "description": "Scans the given content.",
        "inputSchema": {
            "type": "object",
            "properties": {"content_base64": {"type": "string"}},
            "required": ["content_base64"],
        },
    },
    {
        "name": "send_to_cloud",
        "description": "Sends the file to the vendor cloud for a verdict.",
        "inputSchema": {
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
    },
]


def _under_shipped(
    which: str, listing: list[dict[str, Any]], served: Mapping[str, ToolFacts] | None = None
) -> dict[str, ToolFacts]:
    from maljan.core.declared_reading import tools_in_force

    block = getattr(Settings(_env_file=None).static, which)
    read, closed = derived_readings(listing)
    return dict(
        tools_in_force(
            f"provider:{which}", block, served or {}, read, closed, program_readings_of(listing)
        )
    )


@pytest.mark.parametrize("which", ["ghidra", "r2"])
def test_the_statement_never_lifts_content_or_a_send(which: str) -> None:
    from maljan.analysis.tool_effects import sends_sample_bytes

    tools = _under_shipped(which, [*r2_listing(), *_SENDERS])
    for name in ("scan_bytes", "send_to_cloud"):
        assert sends_sample_bytes(tools[name]), name
        assert _effects(tools[name])["third_party"] == "bytes"
    # A file it opens where it runs is still read as staying there.
    assert not sends_sample_bytes(tools["open_file"])


@pytest.mark.parametrize("which", ["ghidra", "r2"])
def test_a_hostile_listing_cannot_say_a_send_away(which: str) -> None:
    from maljan.analysis.tool_effects import sends_sample_bytes

    # Marked read-only and closed by its own server, and declared local under
    # its _meta: an untrusted server's word never lifts a send.
    hostile = [
        {**d, "annotations": {"readOnlyHint": True, "openWorldHint": False}} for d in _SENDERS
    ]
    served = {
        "send_to_cloud": ToolFacts.model_validate(
            {"effects": {"executes": "no", "network": False, "third_party": "no"}}
        )
    }
    tools = _under_shipped(which, hostile, served)
    for name in ("scan_bytes", "send_to_cloud"):
        assert sends_sample_bytes(tools[name]), name


@pytest.mark.parametrize(
    ("name", "properties"),
    [
        ("eval_expr", {"expression": {"type": "string"}}),
        ("exec_python", {"source": {"type": "string"}}),
        ("run_emulator", {"address": {"type": "string"}}),
        ("list_things", {"script_name": {"type": "string"}}),
    ],
)
def test_a_tool_that_runs_what_it_is_given_declares_no_effect(
    name: str, properties: dict[str, Any]
) -> None:
    listing = [{"name": name, "inputSchema": {"type": "object", "properties": properties}}]
    for which in ("ghidra", "r2"):
        facts = _under_shipped(which, listing)[name]
        assert set(_effects(facts)) == {"why_undeclared"}, which
        assert not facts.read_only


def test_a_run_verb_is_the_block_s_own_step_only_where_its_sample_open_names_it() -> None:
    run_analysis = [{"name": "run_analysis", "inputSchema": {"type": "object", "properties": {}}}]
    assert _effects(_under_shipped("ghidra", run_analysis)["run_analysis"]) == _LOCAL
    assert set(_effects(_under_shipped("r2", run_analysis)["run_analysis"])) == {"why_undeclared"}
    # A program's own word for a source never reads as code to run.
    listing = [
        {
            "name": "clone_type",
            "inputSchema": {"type": "object", "properties": {"source_type": {"type": "string"}}},
        }
    ]
    assert _effects(_under_shipped("ghidra", listing)["clone_type"]) == _LOCAL


def test_a_stored_removal_and_a_kind_free_change_read_as_on_dev() -> None:
    import logging

    from maljan.core import settings_overrides as so
    from maljan.core.declared_reading import tools_in_force
    from maljan.core.tool_declarations import with_mark

    stored = with_mark(
        {
            "list_strings": None,
            "decompile_function": {"timeout_seconds": 7},
            "extract_iocs_with_context": {"places": {"address": "/addr"}},
            "rename_function": {"read_only": True},
        }
    )
    logging.disable(logging.CRITICAL)
    try:
        block = so.build_settings({"static.ghidra.tool_facts": stored}).static.ghidra
    finally:
        logging.disable(logging.NOTSET)
    assert block.removed_tools == frozenset({"list_strings"})
    listing = ghidra_listing()
    read, closed = derived_readings(listing)
    program = program_readings_of(listing)
    tools = tools_in_force("provider:ghidra", block, {}, read, closed, program)
    assert "list_strings" not in tools
    assert tools["decompile_function"].timeout_seconds == 7
    assert tools["decompile_function"].kind == "decompile"
    assert tools["rename_function"].read_only is True
    iocs = tools["extract_iocs_with_context"]
    assert iocs.kind == "iocs_with_context"
    assert (iocs.rows, iocs.places) == ("/iocs/*", {"address": "/addr"})
    # Through a JSON round trip, as the settings cross a process.
    again = MCPServerConfig.model_validate(json.loads(block.model_dump_json()))
    assert again.removed_tools == block.removed_tools
    assert again.kind_free_changes == block.kind_free_changes
    held = tools_in_force("provider:ghidra", again, {}, read, closed, program)
    assert "list_strings" not in held
    assert held["extract_iocs_with_context"].places == {"address": "/addr"}


# A server never seen before, every name spelt otherwise: another verb of the
# same reading, other object words of the same meaning, PascalCase.
_HARD = {
    "list": "show",
    "get": "fetch",
    "detect": "scan",
    "imports": "imported_functions",
    "exports": "exported_symbols",
    "segments": "memory_sections",
    "sections": "segments",
}


def _hard(name: str) -> str:
    words: list[str] = []
    for word in name.split("_"):
        words.extend(_HARD.get(word, word).split("_"))
    return "".join(w[:1].upper() + w[1:] for w in words)


@pytest.mark.parametrize("which", ["ghidra", "r2"])
def test_a_never_seen_server_spelt_otherwise_keeps_every_consumer_kind(
    which: str, ghidra_read: dict[str, ToolFacts], r2_read: dict[str, ToolFacts]
) -> None:
    from maljan.core.builtin_declarations import CONSUMER_KINDS
    from maljan.reporting.evidence_bundles import _SECTION_KINDS

    consumed = {k for spec in CONSUMER_KINDS.values() for k in spec.get("kinds", ())}
    consumed |= {k for kinds in _SECTION_KINDS.values() for k in kinds}
    listing = ghidra_listing() if which == "ghidra" else r2_listing()
    renamed = [{**d, "name": _hard(d["name"])} for d in listing]
    tools = _never_seen(renamed, f"hard_{which}", _unseen_block(which, _hard))
    original = ghidra_read if which == "ghidra" else r2_read
    kept = {name: f.kind for name, f in original.items() if f.kind in consumed}
    assert len(kept) > 5
    for name, kind in kept.items():
        assert tools[_hard(name)].kind == kind, (name, _hard(name))
    if which == "ghidra":
        held = tools[_hard("batch_decompile")].aggregate_of
        assert held == (_hard("decompile_function"),)


def test_what_is_kept_of_a_listing_is_read_by_the_shipped_names_again() -> None:
    from maljan.core.declared_reading import shipped_by_name

    assert shipped_by_name()["list_imports"].kind == "import_listing"
    listing = [{"name": "list_widgets", "inputSchema": {"type": "object", "properties": {}}}]
    read, closed = derived_readings(listing)
    launch = launch_identity(ghidra_block())
    served_declarations.register_served(
        "provider:ghidra", {}, launch, read, closed, program_readings_of(listing)
    )
    after = shipped_by_name()
    assert "list_widgets" in after
    assert after["list_imports"].kind == "import_listing"  # radare2's, still kept


@pytest.mark.parametrize("which", ["ghidra", "r2"])
@pytest.mark.parametrize(
    "definition",
    [
        # Says it submits, marked read-only, takes a hash: it sends it.
        {
            "name": "submit_hash",
            "description": "Submits the hash for a verdict.",
            "annotations": {"readOnlyHint": True, "openWorldHint": False},
            "inputSchema": {"type": "object", "properties": {"sha256": {"type": "string"}}},
        },
        # Says it sends, takes nothing that names the file: not marked read-only.
        {
            "name": "send_report",
            "description": "Sends the analysis away.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        # Says it uploads by an id, marked read-only and closed.
        {
            "name": "upload_task",
            "description": "Uploads the task.",
            "annotations": {"readOnlyHint": True, "openWorldHint": False},
            "inputSchema": {"type": "object", "properties": {"task_id": {"type": "string"}}},
        },
    ],
)
def test_a_tool_that_says_it_sends_is_never_lifted(which: str, definition: dict) -> None:
    from maljan.analysis.tool_effects import sends_sample_bytes

    tools = _under_shipped(which, [definition])
    assert sends_sample_bytes(tools[definition["name"]])


def test_the_block_s_own_run_step_keeps_saying_it_runs_what_it_is_given() -> None:
    listing = [
        {
            "name": "run_job",
            "inputSchema": {"type": "object", "properties": {"script": {"type": "string"}}},
        },
        {"name": "run_pass", "inputSchema": {"type": "object", "properties": {}}},
    ]
    block = {
        "roles": ["decompiler"],
        "default_effects": dict(_LOCAL),
        "sample_open": {"analyse_tool": "run_job"},
    }
    tools = _never_seen(listing, "own_run_step", block)
    assert tools["run_job"].kind == "analyse_sample"
    assert set(_effects(tools["run_job"])) == {"why_undeclared"}
    block["sample_open"] = {"analyse_tool": "run_pass"}
    tools = _never_seen(listing, "own_run_step", block)
    assert _effects(tools["run_pass"]) == _LOCAL


@pytest.mark.parametrize(
    ("name", "properties", "runs"),
    [
        # Code words, alone or with the words that carry them, whatever the verb.
        ("list_items", {"script_name": {"type": "string"}}, True),
        ("list_items", {"code": {"type": "string"}}, True),
        ("apply_patch", {"lua_body": {"type": "string"}}, True),
        # A strong code word beside any other word, whatever the verb.
        ("apply_hook", {"user_script": {"type": "string"}}, True),
        ("apply_hook", {"hook_code": {"type": "string"}}, True),
        ("apply_hook", {"ghidra_script": {"type": "string"}}, True),
        ("apply_hook", {"r2_command": {"type": "string"}}, True),
        ("apply_hook", {"script_source": {"type": "string"}}, True),
        ("apply_hook", {"python_source": {"type": "string"}}, True),
        ("patch_bytes", {"asm_code": {"type": "string"}}, True),
        # An expression evaluated as a condition, whatever the verb.
        ("set_breakpoint", {"condition_expression": {"type": "string"}}, True),
        # But for a property of the code, never code.
        ("decompile_function", {"code_style": {"type": "string"}}, False),
        ("list_scripts", {"script_type": {"type": "string"}}, False),
        ("list_history", {"command_count": {"type": "integer"}}, False),
        # A source, a query or an expression only for a verb that runs it.
        ("eval_expr", {"expression": {"type": "string"}}, True),
        ("exec_python", {"source": {"type": "string"}}, True),
        ("search_strings", {"query": {"type": "string"}}, False),
        ("search_functions", {"query": {"type": "string"}}, False),
        ("list_functions", {"source": {"type": "string"}}, False),
        ("import_data_types", {"source": {"type": "string"}}, False),
        ("calculate", {"expression": {"type": "string"}}, False),
        # Another word in the name makes it something else.
        ("get_xrefs_from", {"source_address": {"type": "string"}}, False),
        (
            "decompile_function",
            {"address": {"type": "string"}, "code_style": {"type": "string"}},
            False,
        ),
        ("diff_programs", {"source_program_name": {"type": "string"}}, False),
    ],
)
def test_an_argument_names_code_to_run_by_its_words_and_the_verb(
    name: str, properties: dict[str, Any], runs: bool
) -> None:
    listing = [{"name": name, "inputSchema": {"type": "object", "properties": properties}}]
    facts = _under_shipped("ghidra", listing)[name]
    said = facts.effects.model_dump(exclude_defaults=True) if facts.effects else {}
    assert (set(said) == {"why_undeclared"}) is runs, said


@pytest.mark.parametrize("which", ["ghidra", "r2"])
def test_a_stored_removal_keeps_that_a_tool_sends_the_sample(which: str) -> None:
    import logging

    from maljan.analysis.tool_effects import sends_sample_bytes
    from maljan.core import settings_overrides as so
    from maljan.core.declared_reading import tools_in_force
    from maljan.core.tool_declarations import with_mark

    listing = [
        {
            "name": "upload_sample",
            "description": "Upload the file.",
            "inputSchema": {
                "type": "object",
                "properties": {"file_path": {"type": "string"}},
                "required": ["file_path"],
            },
        },
        *_SENDERS[:1],
    ]
    removed = with_mark({"upload_sample": None, "scan_bytes": None})
    logging.disable(logging.CRITICAL)
    try:
        built = so.build_settings(
            {
                "mcp.servers": {"other": {"command": "x-mcp", "tool_facts": removed}},
                f"static.{which}.tool_facts": removed,
            }
        )
    finally:
        logging.disable(logging.NOTSET)
    read, closed = derived_readings(listing)
    program = program_readings_of(listing)
    for source, block in (
        ("mcp:other", built.mcp.servers["other"]),
        (f"provider:{which}", getattr(built.static, which)),
    ):
        tools = tools_in_force(source, block, {}, read, closed, program)
        for name in ("upload_sample", "scan_bytes"):
            facts = tools[name]
            assert facts.discloses_sample and sends_sample_bytes(facts), (source, name)
            # Nothing else of the reading, nor the block's statement.
            assert facts.kind == "" and facts.effects is not None
            assert facts.effects.executes == "", (source, name)


@pytest.mark.parametrize(
    ("argument", "schema"),
    [
        ("file_data", {"type": "string"}),
        ("sample_body", {"type": "string"}),
        ("value", {"type": "string", "contentEncoding": "base64"}),
    ],
)
def test_content_by_the_one_rule_is_never_lifted_under_the_statement(
    argument: str, schema: dict[str, Any]
) -> None:
    from maljan.analysis.tool_effects import sends_sample_bytes

    listing = [
        {
            "name": "analyze_blob",
            "inputSchema": {"type": "object", "properties": {argument: schema}},
        }
    ]
    facts = _under_shipped("ghidra", listing)["analyze_blob"]
    assert facts.kind == "analysis"
    assert facts.discloses_sample and sends_sample_bytes(facts)


def test_a_number_named_for_bytes_carries_no_content() -> None:
    listing = [
        {
            "name": "analyze_region",
            "inputSchema": {
                "type": "object",
                "properties": {"max_scan_bytes": {"type": "integer"}},
            },
        }
    ]
    assert not _under_shipped("ghidra", listing)["analyze_region"].discloses_sample
