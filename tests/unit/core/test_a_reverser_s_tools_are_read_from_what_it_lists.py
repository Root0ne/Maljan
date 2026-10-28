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
        ("list_imports", "listing"),
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
        ("detect_malware_behaviors", "analysis"),
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
        ("list_all_strings", "listing_strings"),
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
        ("r2", "decompile_function"),
    }
    assert not decompiles(ghidra["set_decompiler_comment"], "set_decompiler_comment")
    assert not decompiles(ghidra["force_decompile"], "force_decompile")
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
        "batch_create_labels": ("create_label",),
        "batch_delete_labels": ("delete_label",),
        "get_bulk_function_hashes": ("get_function_hash",),
    }


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


def _renamed(name: str) -> str:
    """The same verb, another name: ``my`` after the verb (after a batch word's verb)."""
    words = name.split("_")
    at = 2 if words[0] in ("batch", "bulk") and len(words) > 1 else 1
    return "_".join([*words[:at], "my", *words[at:]])


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
def test_the_shipped_blocks_read_as_a_never_seen_server_but_for_their_kinds(
    which: str,
    ghidra: dict[str, ToolFacts],
    r2: dict[str, ToolFacts],
    ghidra_read: dict[str, ToolFacts],
    r2_read: dict[str, ToolFacts],
) -> None:
    # The kinds alone are still the leftover table's (``builtin_reverser_kinds``).
    shipped, read = (ghidra, ghidra_read) if which == "ghidra" else (r2, r2_read)
    kind_read = {"kind", "aggregate_of", "report_sections", "rows", "places", "values"}
    for name, facts in read.items():
        left = {k: v for k, v in shipped[name].model_dump(exclude_defaults=True).items()}
        right = {k: v for k, v in facts.model_dump(exclude_defaults=True).items()}
        left = {k: v for k, v in left.items() if k not in kind_read | {"holds_strings"}}
        right = {k: v for k, v in right.items() if k not in kind_read | {"holds_strings"}}
        assert left == right, (which, name)


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
