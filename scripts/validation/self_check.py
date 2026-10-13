"""The validation harness's own checks: offline, no run, no server, a second or two.

``python scripts/validation/run.py --self-check`` runs them. They hold the
harness pieces to what the plan says they do — the stub's argument filling
(H3), the report hand-over and the static paths (H1, H2), the reach reading
(H5), the registered memory backend (H7) and the result directory rule — so a
validation run that misses a gate misses it for the product, not for the
harness. A script rather than test cases: the suite's live count stays put.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

CHECKS: list[tuple[str, Callable[[], None]]] = []


def check(fn: Callable[[], None]) -> Callable[[], None]:
    CHECKS.append((fn.__name__, fn))
    return fn


def _tool(name: str, required: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "name": name,
        "description": "",
        "schema": {"type": "object", "properties": required, "required": list(required)},
    }


def _facts() -> Any:
    from scripts.rehearsal.roles import _Facts

    return _Facts(ids=[], lines=[], urls=[], sample_path="/s/sample_1.exe", sha256="a" * 64)


LISTING = json.dumps(
    {"functions": [{"name": "entry0", "address": "0x00401000"}, {"name": "FUN_00401200"}]}
)
IMPORTED = json.dumps({"binary_name": "sample_1.exe-1a2b3c", "status": "imported"})


@check
def an_address_argument_is_given_up_without_answers() -> None:
    from scripts.rehearsal.roles import _fillable

    tool = _tool("any_decompiler", {"address": {"type": "string"}})
    assert _fillable(tool, _facts()) is None
    assert _fillable(tool, _facts(), []) is None


@check
def an_address_argument_takes_the_latest_answers_first_place() -> None:
    from scripts.rehearsal.roles import _fillable

    tool = _tool("any_decompiler", {"address": {"type": "string"}})
    args = _fillable(tool, _facts(), [LISTING])
    assert args == {"address": "0x00401000"}, args
    older = json.dumps({"seen": "sub_00409999"})
    assert _fillable(tool, _facts(), [LISTING, older]) == {"address": "0x00401000"}
    named = _tool("x", {"name_or_address": {"type": "string"}})
    assert _fillable(named, _facts(), [older, LISTING]) == {"name_or_address": "sub_00409999"}


@check
def a_required_string_takes_the_value_under_its_key() -> None:
    from scripts.rehearsal.roles import _fillable

    tool = _tool("x", {"binary_name": {"type": "string"}, "name_or_address": {"type": "string"}})
    args = _fillable(tool, _facts(), [LISTING, IMPORTED])
    assert args == {"binary_name": "sample_1.exe-1a2b3c", "name_or_address": "0x00401000"}, args
    by_last_word = _tool("x", {"program_status": {"type": "string"}})
    assert _fillable(by_last_word, _facts(), [IMPORTED]) == {"program_status": "imported"}
    prose = _tool("x", {"session": {"type": "string"}})
    assert _fillable(prose, _facts(), ["opened\nsession: s-42\n"]) == {"session": "s-42"}
    missing = _tool("x", {"unheard_of": {"type": "string"}})
    assert _fillable(missing, _facts(), [IMPORTED]) is None


@check
def a_described_place_is_filled_only_when_no_key_holds_it() -> None:
    from scripts.rehearsal.roles import _fillable

    described = _tool("x", {"target": {"type": "string", "description": "the function to read"}})
    assert _fillable(described, _facts(), [LISTING]) == {"target": "0x00401000"}
    held = _tool("x", {"target": {"type": "string", "description": "the function to read"}})
    assert _fillable(held, _facts(), [json.dumps({"target": "t1"})]) == {"target": "t1"}


@check
def every_rule_that_filled_before_fills_the_same() -> None:
    from scripts.rehearsal.roles import _fillable

    tool = _tool(
        "x",
        {
            "file_path": {"type": "string"},
            "section": {"type": "string"},
            "technique_id": {"type": "string"},
            "api": {"type": "string"},
            "sha256": {"type": "string"},
            "limit": {"type": "integer"},
        },
    )
    before = _fillable(tool, _facts())
    assert before == _fillable(tool, _facts(), [LISTING, IMPORTED]), before
    pcap = _tool("x", {"pcap_path": {"type": "string"}})
    assert _fillable(pcap, _facts(), [LISTING]) is None


@check
def a_tool_answer_is_read_without_the_products_frame() -> None:
    from scripts.rehearsal.roles import _answer_text

    framed = '[ev_0042]\n{"a": 1}\n\n=== RUN STATE (derived) ===\n[ev_0001] 0x1234'
    assert _answer_text(framed) == '{"a": 1}'


@check
def the_stub_fills_from_answers_only_when_asked() -> None:
    from scripts.rehearsal import wire
    from scripts.rehearsal.roles import _next_call

    tools = [_tool("any_decompiler", {"address": {"type": "string"}})]
    turns = [
        wire.Turn(role="user", text="go"),
        wire.Turn(role="assistant", tool_calls=[wire.ToolCall("lister", {}, "c1")]),
        wire.Turn(role="user", tool_results=[wire.ToolResult("c1", "[ev_0001]\n" + LISTING)]),
    ]
    request = wire.Request("openai", "m", "sys", turns, tools, None, False, {})
    assert _next_call(request, _facts(), 1) is None
    call = _next_call(request, _facts(), 1, fill_from_results=True)
    assert call is not None and call.args == {"address": "0x00401000"}, call


@check
def the_stub_follows_a_remediation_then_the_answers_leads() -> None:
    from scripts.rehearsal import wire
    from scripts.rehearsal.roles import _next_call

    tools = [
        _tool("aaa_listing", {}),
        _tool("any_decompiler", {"address": {"type": "string"}}),
        _tool("open_it", {"file_path": {"type": "string"}}),
    ]
    refusal = json.dumps(
        {"error": {"code": "tool_failed", "remediation": "call open_it with the path, then again"}}
    )

    def request(*answers: tuple[str, str, dict[str, Any]]) -> Any:
        turns = [wire.Turn(role="user", text="go")]
        for i, (name, text, args) in enumerate(answers):
            turns.append(
                wire.Turn(role="assistant", tool_calls=[wire.ToolCall(name, args, f"c{i}")])
            )
            turns.append(wire.Turn(role="user", tool_results=[wire.ToolResult(f"c{i}", text)]))
        return wire.Request("openai", "m", "sys", turns, tools, None, False, {})

    first = request(("aaa_listing", refusal, {}))
    call = _next_call(first, _facts(), 1, fill_from_results=True)
    assert call is not None and call.name == "open_it", call
    assert call.args == {"file_path": "/s/sample_1.exe"}
    opened = request(
        ("aaa_listing", refusal, {}), ("open_it", LISTING, {"file_path": "/s/sample_1.exe"})
    )
    call = _next_call(opened, _facts(), 2, fill_from_results=True)
    assert call is not None and call.name == "any_decompiler", call
    again = request(
        ("open_it", LISTING, {"file_path": "/s/sample_1.exe"}),
        ("any_decompiler", "int f(void);", {"address": "0x00401000"}),
    )
    call = _next_call(again, _facts(), 2, fill_from_results=True)
    assert call is None or call.args != {"address": "0x00401000"}, call
    # Off, the rotation is what it always was: the answers lead nowhere.
    rotated = {getattr(_next_call(first, _facts(), step), "name", "") for step in range(4)}
    assert rotated == {"aaa_listing", "open_it"}, rotated


@check
def a_report_is_refused_by_a_provider_that_takes_none() -> None:
    from scripts.rehearsal.inprocess import attach_report

    handed: list[Any] = []

    def provider(accepts: bool) -> Any:
        return SimpleNamespace(
            id="p",
            capabilities=SimpleNamespace(accepts_uploaded_report=accepts),
            set_pending_blob=lambda blob, **kw: handed.append((blob, kw)),
        )

    path = _ROOT / "tests" / "fixtures" / "sandbox" / "cape2_report.json"
    refusing = SimpleNamespace(
        container=SimpleNamespace(get_sandbox_provider=lambda: provider(False))
    )
    try:
        attach_report(refusing, path, None)
    except ValueError:
        pass
    else:
        raise AssertionError("a provider that accepts no report took one")
    taking = SimpleNamespace(container=SimpleNamespace(get_sandbox_provider=lambda: provider(True)))
    attach_report(taking, path, "cape2")
    assert handed and handed[0][1] == {"filename": path.name, "report_format": "cape2"}
    assert handed[0][0] == path.read_bytes()


@check
def static_paths_are_passed_as_the_worker_passes_them() -> None:
    from scripts.rehearsal.inprocess import Rehearsal, _static_paths

    settings = SimpleNamespace(static=SimpleNamespace(provider="r2"))
    sample = Path("/s/sample_1.exe")
    assert _static_paths(Rehearsal(), settings, sample) == {}
    got = _static_paths(Rehearsal(static_sample_paths={"r2": ""}), settings, sample)
    assert got == {"static_sample_path": str(sample), "static_sample_paths": {"r2": str(sample)}}


def _record(**over: Any) -> Any:
    base = {
        "malware_report": {
            "evidence_index": [
                {"id": "ev_0001", "server": "pipeline", "tool": "t", "ok": True, "source": "pack"},
                {
                    "id": "ev_0002",
                    "server": "newcomer",
                    "tool": "look",
                    "ok": True,
                    "source": "mcp:newcomer",
                    "facts": {},
                },
            ],
            "sections": [{"key": "tool_look", "evidence_ids": ["ev_0002"]}],
            "flagged_statements": [],
            "degradation_reasons": [],
            "figures": [],
            "technical_evidence": {"a": [{"seq": 1, "output": "the newcomer answered this"}]},
        },
        "events": [
            {
                "type": "agent_message",
                "role": "analyst",
                "speaker": "a",
                "claims": [{"claim": "It looks.", "evidence_ref": "[ev_0002] look: ..."}],
            },
        ],
        "run_summary": {"corroboration": {}},
        "markdown": "Appendix A. Evidence index\n\n| ID |\n|---|\n| ev_0002 | a | newcomer |\n",
        "stix_bundle": {},
        "stix_extended": {},
    }
    base.update(over)
    return SimpleNamespace(**base)


@check
def reach_reads_the_six_rows_of_one_source() -> None:
    import tempfile

    from scripts.validation.reach import reach

    with tempfile.TemporaryDirectory() as tmp:
        dump = Path(tmp)
        body = {
            "model": "m",
            "messages": [
                {"role": "system", "content": "sys"},
                {
                    "role": "user",
                    "content": "Section: x. Evidence: [ev_0002] the newcomer answered this",
                },
            ],
        }
        (dump / "0001-composer.json").write_text(json.dumps(body), encoding="utf-8")
        row = reach(_record(), dump, "newcomer", absent=("Elsewhere",))
    for e in ("E1", "E2", "E3", "E4", "E5", "E6"):
        assert row[e]["ok"], (e, row[e])
    assert row["E3"]["undeclared"] == ["ev_0002"]
    named = reach(_record(markdown="Elsewhere said so"), None, "newcomer", absent=("Elsewhere",))
    assert not named["E6"]["ok"] and not named["E4"]["ok"]
    failed = _record()
    failed.malware_report["technical_evidence"]["a"][0]["output"] = "Error: binary not found"
    assert reach(failed, None, "newcomer")["E6"]["ok_but_reads_as_error"] == ["ev_0002"]


@check
def the_registered_backend_is_built_by_the_products_factory() -> None:
    from scripts.validation import memory_backend

    from maljan.core.settings_overrides import build_settings
    from maljan.memory.store_factory import build_memory_store, registered_backends

    store = memory_backend.register()
    try:
        built = build_memory_store(build_settings({"memory.backend": memory_backend.BACKEND_ID}))
        assert built is store and built.function_hash_store() is None
        case = SimpleNamespace(sample_id="s1", summary_text="beacon over http")
        built.store(case)
        assert built.retrieve("http beacon") == [case]
        assert built.retrieve("http beacon", exclude_sample_id="s1") == []
        built.clear()
        built.writes.clear()
    finally:
        memory_backend.unregister()
    assert memory_backend.BACKEND_ID not in registered_backends()


@check
def a_results_directory_under_a_dot_segment_is_refused() -> None:
    from scripts.validation.run import no_hidden_segment

    try:
        no_hidden_segment(Path("/tmp/x/.hidden/out"))
    except SystemExit:
        pass
    else:
        raise AssertionError("a dot segment was accepted")
    assert no_hidden_segment(Path("/tmp/x/out")) == Path("/tmp/x/out").resolve()


def _request(tools: list[dict[str, Any]], *answers: tuple[str, str, dict[str, Any]]) -> Any:
    from scripts.rehearsal import wire

    turns = [wire.Turn(role="user", text="go")]
    for i, (name, text, args) in enumerate(answers):
        turns.append(wire.Turn(role="assistant", tool_calls=[wire.ToolCall(name, args, f"c{i}")]))
        turns.append(wire.Turn(role="user", tool_results=[wire.ToolResult(f"c{i}", text)]))
    return wire.Request("openai", "m", "sys", turns, tools, None, False, {})


SECTIONS = json.dumps({"sections": [{"name": ".text", "virtual_address": "0x00001000"}]})


@check
def a_place_is_read_where_a_function_listing_says_a_function_starts() -> None:
    from scripts.rehearsal.roles import _next_call

    lister = {**_tool("enumerate", {}), "description": "Lists all functions found"}
    reader = _tool("reader", {"address": {"type": "string"}})
    header = _tool("header", {})
    index = {**_tool("index", {}), "description": "Join every reading by the functions found."}
    tools = [header, index, lister, reader]
    # A section address seen first: the functions are listed before any place is read.
    seen = _request(tools, ("header", SECTIONS, {}))
    call = _next_call(seen, _facts(), 1, fill_from_results=True)
    assert call is not None and call.name == "enumerate", call
    # A listing that gives only a base is no list of starts: the next lister is asked.
    based = {**_tool("bases", {}), "description": "Lists the functions known"}
    only_base = _request(
        [header, based, lister, reader],
        ("header", SECTIONS, {}),
        ("bases", json.dumps({"image_base": "0x140000000"}), {}),
    )
    call = _next_call(only_base, _facts(), 2, fill_from_results=True)
    assert call is not None and call.name == "enumerate", call
    listed = _request(tools, ("header", SECTIONS, {}), ("enumerate", "0x140001000  entry0\n", {}))
    call = _next_call(listed, _facts(), 2, fill_from_results=True)
    assert call is not None and call.args == {"address": "0x140001000"}, call


@check
def a_place_one_tool_failed_at_is_still_tried_by_another() -> None:
    from scripts.rehearsal.roles import _next_call

    lister = {**_tool("enumerate", {}), "description": "Lists all functions found"}
    first = _tool("decompile_it", {"address": {"type": "string"}})
    second = _tool("disassemble_it", {"address": {"type": "string"}})
    failed = json.dumps({"error": {"code": "tool_failed", "message": "no function here"}})
    request = _request(
        [lister, first, second],
        ("enumerate", "0x140001000  entry0\n", {}),
        ("decompile_it", failed, {"address": "0x140001000"}),
    )
    call = _next_call(request, _facts(), 2, fill_from_results=True)
    assert call is not None and call.name == "disassemble_it", call
    assert call.args == {"address": "0x140001000"}, call


@check
def a_tool_that_changes_state_is_left_alone() -> None:
    from scripts.rehearsal.roles import _changes_state

    assert _changes_state({"description": "[MODIFY] Renames the function"})
    assert _changes_state({"description": "This tool renames a variable"})
    assert _changes_state({"description": "Reads", "annotations": {"destructiveHint": True}})
    assert _changes_state({"description": "Reads", "annotations": {"readOnlyHint": False}})
    assert not _changes_state(
        {"description": "Sets nothing", "annotations": {"readOnlyHint": True}}
    )
    assert not _changes_state({"description": "[LIST] Lists all functions"})


@check
def code_is_credited_only_when_read_at_a_listed_function_start() -> None:
    import tempfile

    from scripts.validation.reach import code_evidence, holds_code

    assert not holds_code("0x00003000      invalid\n0x00003001      invalid\n")
    assert not holds_code('{"error": {"code": "tool_failed"}}')
    assert holds_code("0x140001000      sub rsp, 0x28\n")
    assert holds_code("int entry0(void) {\n    return 0;\n}")
    entries = [
        {"id": "ev_0001", "ok": True, "tool": "fl", "facts": {"kind": "function_list"}},
        {"id": "ev_0002", "ok": True, "tool": "da", "facts": {"kind": "disassembly"}},
        {"id": "ev_0003", "ok": True, "tool": "da", "facts": {"kind": "disassembly"}},
        {"id": "ev_0004", "ok": True, "tool": "da", "facts": {"kind": "disassembly"}},
    ]
    outputs = {
        1: "0x140001000  entry0",
        2: "0x140001000      sub rsp, 0x28",
        3: "0x00003000      invalid",
        4: "0x00001000      push rbp",
    }
    record = _record()
    record.malware_report["technical_evidence"] = {
        "s": [{"seq": n - 1, "output": text} for n, text in outputs.items()]
    }
    calls = {1: ("fl", {}), 2: ("da", {"address": "0x140001000"})}
    calls |= {3: ("da", {"address": "0x00003000"}), 4: ("da", {"address": "0x00001000"})}
    with tempfile.TemporaryDirectory() as tmp:
        messages: list[dict[str, Any]] = [{"role": "user", "content": "go"}]
        for n, (tool, args) in calls.items():
            messages.append(
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": f"c{n}",
                            "function": {"name": tool, "arguments": json.dumps(args)},
                        }
                    ],
                }
            )
            text = f"[ev_{n:04d}]\n{outputs[n]}"
            messages.append({"role": "tool", "tool_call_id": f"c{n}", "content": text})
        body = {"model": "m", "messages": messages}
        (Path(tmp) / "0001-analyst.json").write_text(json.dumps(body), encoding="utf-8")
        code = code_evidence(record, Path(tmp), entries)
    assert code["credited"] == ["ev_0002"], code
    assert code["refused"]["ev_0003"] == "its answer holds no code", code
    assert code["refused"]["ev_0004"].startswith("its place is not"), code


@check
def e3_misses_when_nothing_cites_or_a_declared_entry_never_reaches_corroboration() -> None:
    from scripts.validation.reach import reach

    uncited = _record(events=[])
    assert not reach(uncited, None, "newcomer")["E3"]["ok"]
    assert reach(uncited, None, "newcomer", expect_cited=False)["E3"]["ok"]
    # A kind that asserts no technique is held to citation and flags only.
    plain = _record()
    plain.malware_report["evidence_index"][1]["facts"] = {"kind": "strings"}
    row = reach(plain, None, "newcomer")["E3"]
    assert row["ok"] and row["corroboration"] == "n/a (kind asserts no technique)", row
    # An asserting kind cited for a technique must reach corroboration and be placed there.
    asserting = _record()
    asserting.malware_report["evidence_index"][1]["facts"] = {
        "kind": "signatures",
        "asserts_techniques": True,
        "techniques": "/t",
    }
    claim = {"claim": "It looks.", "evidence_ref": "[ev_0002] look", "technique_id": "T1071"}
    asserting.events[0]["claims"] = [claim]
    row = reach(asserting, None, "newcomer")["E3"]
    assert not row["ok"] and "never reaches corroboration" in row["why"], row
    asserting.run_summary = {"corroboration": {"T1": {"sources": ["ev_0002"]}}}
    assert reach(asserting, None, "newcomer")["E3"]["corroboration"] == "reached"
    asserting.run_summary = {
        "corroboration": {"T1": {"sources": ["ev_0002"], "roots_not_read": ["ev_0002: no: x"]}}
    }
    assert not reach(asserting, None, "newcomer")["E3"]["ok"]
    asserting.events[0]["claims"] = [{**claim, "technique_id": "NONE"}]
    asserting.run_summary = {"corroboration": {}}
    row = reach(asserting, None, "newcomer")["E3"]
    assert row["ok"] and row["corroboration"].startswith("n/a (no claim"), row


@check
def a_process_started_for_the_project_is_ended_by_pid_and_a_decoy_is_not() -> None:
    import subprocess
    import tempfile
    import time

    from scripts.validation.run import end_survivors, processes_naming

    project = tempfile.mkdtemp(prefix="validation-project-")
    # $0 and $1 of the shell: the project given after the flag, exactly.
    child = subprocess.Popen(["/bin/sh", "-c", "sleep 30", "--project-path", project])
    # Decoys: one only mentions the path, one gives another path after the flag.
    decoys = [
        subprocess.Popen(["/bin/sh", "-c", "sleep 30", "decoy", f"{project}/sub"]),
        subprocess.Popen(["/bin/sh", "-c", "sleep 30", "--project-path", f"{project}-other"]),
    ]
    try:
        time.sleep(0.3)
        found = processes_naming(project)
        assert child.pid in found, found
        assert not {d.pid for d in decoys} & set(found), found
        left = end_survivors(project, grace_s=0.5)
        assert child.pid in left, left
        child.wait(timeout=10)
        assert not processes_naming(project)
        assert all(d.poll() is None for d in decoys), "a decoy was signalled"
    finally:
        for proc in (child, *decoys):
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        Path(project).rmdir()


@check
def an_entry_point_kind_is_matched_as_a_whole_word() -> None:
    from scripts.validation.reach import _LISTS_FUNCTIONS

    for kind in ("function_list", "function_tree", "entrypoints", "entry_points", "list_functions"):
        assert _LISTS_FUNCTIONS.search(kind), kind
    for kind in ("entropy", "section_entropy", "disfunctional", "entry"):
        assert not _LISTS_FUNCTIONS.search(kind), kind


@check
def a_gap_pin_excuses_only_its_exact_miss_and_a_skip_is_no_pass() -> None:
    from unittest import mock

    from scripts.validation import run

    def result(detail: str) -> Any:
        return run.RunResult(
            "z", "r1", "openai", "completed", {}, {}, [], {}, {"g": (False, detail)}
        )

    pins = {("z", "r1", "openai", "g"): ("exact words", "G0")}
    with mock.patch.object(run, "gap_pins", return_value=pins):
        held = result("exact words")
        run.apply_pins(held)
        other = result("exact words, and more")
        run.apply_pins(other)
    assert held.ok and held.pinned == {"g": "G0"}, held.summary()
    assert not other.ok and not other.pinned
    skipped = run._skipped("z", "no tool")
    assert not skipped.ok and skipped.label == "SKIPPED"
    assert run._pending("z", "later").label == "PENDING"


@check
def a_built_in_renamed_or_hidden_by_a_newcomers_name_is_found() -> None:
    from scripts.validation.run import offered_name_findings

    own = {"pe_info": "Describe as the kit records it.", "dec": "Answer the kit's listing."}
    builtins = {"analysis": {"pe_info", "hashes"}, "prov": {"dec", "open"}}
    fine = [
        {
            "pe_info": "PE header reader",
            "kit__pe_info": "Describe as the kit records it.",
            "hashes": "h",
            "dec": "real decompiler",
            "kit__dec": "Answer the kit's listing.",
            "open": "o",
        }
    ]
    assert offered_name_findings(fine, "kit", own, builtins) == []
    renamed = [
        {
            "analysis__pe_info": "PE header reader",
            "pe_info": "Describe as the kit records it.",
            "hashes": "h",
            "dec": "[ANALYZE] Answer the kit's listing.",
            "open": "o",
        }
    ]
    assert offered_name_findings(renamed, "kit", own, builtins) == [
        "built-in analysis pe_info renamed analysis__pe_info",
        "built-in prov dec hidden behind the kit copy",
    ]
    alone = [{"pe_info": "Describe as the kit records it."}]
    assert offered_name_findings(alone, "kit", own, builtins) == []


@check
def a_new_run_clears_only_the_named_scenarios_earlier_outputs() -> None:
    import tempfile

    from scripts.validation.run import clean_outputs

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        (out / "e" / "an-old-name").mkdir(parents=True)
        (out / "e.json").write_text("{}")
        (out / "d").mkdir()
        (out / "notes.txt").write_text("kept")
        assert sorted(clean_outputs(out, ["e"])) == ["e", "e.json"]
        assert sorted(p.name for p in out.iterdir()) == ["d", "notes.txt"]


def _program_tools() -> list[dict[str, Any]]:
    """A server whose readers take the name of a program it opened from a path."""
    name = {"binary_name": {"type": "string"}}
    return [
        {**_tool("attck_lookup", {"technique_id": {"type": "string"}}), "description": "Look up"},
        {**_tool("import_it", {"binary_path": {"type": "string"}}), "description": "[IMPORT] It"},
        {**_tool("list_programs", {}), "description": "[LIST] List all programs."},
        {**_tool("list_exports", name), "description": "[LIST] List exported symbols."},
        {**_tool("list_imports", name), "description": "[LIST] List imported symbols."},
        {
            **_tool("decompile_it", {**name, "name_or_address": {"type": "string"}}),
            "description": "[ANALYZE] Decompile a function.",
        },
    ]


ATTCK = json.dumps({"valid": True, "technique_id": "T1071.001", "name": "Web Protocols"})
QUEUED = json.dumps({"queued_count": 1, "message": "Queued 1 import(s) in the background."})
PROGRAM = {"name": "/sample_1.exe-1a2b3c", "file_path": "/s/sample_1.exe"}


def _programs(*items: dict[str, Any]) -> str:
    return json.dumps({"programs": list(items)})


@check
def the_products_tool_error_marker_reads_as_failed() -> None:
    from scripts.rehearsal.roles import _FAILED

    assert _FAILED.match('{"tool_error": "tool_returned_error", "tool": "x", "detail": "no"}')
    assert _FAILED.match('{"error": {"code": "tool_failed"}}')
    assert not _FAILED.match('{"name": "entry", "code": "void entry(void) {}"}')


@check
def the_sample_is_opened_before_a_tool_needing_what_it_opened() -> None:
    from scripts.rehearsal.roles import _next_call

    tools = _program_tools()
    first = _next_call(_request(tools), _facts(), 0, fill_from_results=True)
    assert first is not None and first.name == "import_it", first
    assert first.args == {"binary_path": "/s/sample_1.exe"}, first
    # Off, the rotation is what it always was.
    plain = _next_call(_request(tools), _facts(), 0)
    assert plain is not None and plain.name == "attck_lookup", plain
    # Once opened, it is not opened again: the listing says what was opened.
    opened = _request(tools, ("import_it", QUEUED, {"binary_path": "/s/sample_1.exe"}))
    call = _next_call(opened, _facts(), 1, fill_from_results=True)
    assert call is not None and call.name == "list_programs" and call.args == {}, call


@check
def a_name_is_read_from_a_listing_never_from_an_unrelated_record() -> None:
    from scripts.rehearsal.roles import _fillable

    reader = _tool("list_exports", {"binary_name": {"type": "string"}})
    assert _fillable(reader, _facts(), [ATTCK]) is None
    listed = _programs({**PROGRAM, "analysis_complete": True})
    assert _fillable(reader, _facts(), [ATTCK, listed]) == {"binary_name": PROGRAM["name"]}
    # A listing from a call that took the argument lists what is inside the thing.
    exports = json.dumps({"exports": [{"name": "entry", "address": "140001000"}]})
    asked = (frozenset({"binary_name"}), frozenset())
    args = _fillable(reader, _facts(), [exports, listed], asked=asked)
    assert args == {"binary_name": PROGRAM["name"]}, args
    # The argument's own key is still read wherever it stands.
    assert _fillable(reader, _facts(), [IMPORTED]) == {"binary_name": "sample_1.exe-1a2b3c"}


@check
def a_listing_is_asked_again_while_what_was_opened_is_not_done() -> None:
    import contextlib
    import io

    from scripts.rehearsal import roles

    tools = _program_tools()
    opened = ("import_it", QUEUED, {"binary_path": "/s/sample_1.exe"})
    pause, roles.POLL_PAUSE_S = roles.POLL_PAUSE_S, 0.0

    def opening(request: Any) -> Any:
        offered = {str(t["name"]): t for t in tools}
        answers = [roles._answer_text(r.text) for r in reversed(request.tool_results)]
        return roles._opening(request, offered, _facts(), answers, sorted(offered))

    try:
        for listing in (_programs(), _programs({**PROGRAM, "analysis_complete": False})):
            request = _request(tools, opened, ("list_programs", listing, {}))
            call = roles._next_call(request, _facts(), 2, fill_from_results=True)
            assert call is not None and call.name == "list_programs", (listing, call)
        # An empty listing after an open that said nothing goes on is not waited for.
        done_open = ("import_it", json.dumps({"imported": 1}), opened[2])
        request = _request(tools, done_open, ("list_programs", _programs(), {}))
        assert opening(request) is None
        # The bound is explicit and logged when it is hit.
        waiting = ("list_programs", _programs(), {})
        bounded = _request(tools, opened, *([waiting] * roles.POLL_ROUNDS))
        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            assert opening(bounded) is None
        assert "still lists what was opened as not done" in log.getvalue(), log.getvalue()
    finally:
        roles.POLL_PAUSE_S = pause


@check
def an_opened_program_is_listed_then_decompiled_at_an_exported_start() -> None:
    from scripts.rehearsal.roles import _next_call

    tools = _program_tools()
    opened = ("import_it", QUEUED, {"binary_path": "/s/sample_1.exe"})
    listed = ("list_programs", _programs({**PROGRAM, "analysis_complete": True}), {})
    looked_up = ("attck_lookup", ATTCK, {"technique_id": "T1071.001"})
    request = _request(tools, looked_up, opened, listed)
    call = _next_call(request, _facts(), 3, fill_from_results=True)
    assert call is not None and call.name == "list_exports", call
    assert call.args == {"binary_name": PROGRAM["name"]}, call
    exports = json.dumps({"exports": [{"name": "entry", "address": "140001000"}]})
    request = _request(
        tools, opened, listed, ("list_exports", exports, {"binary_name": PROGRAM["name"]})
    )
    call = _next_call(request, _facts(), 3, fill_from_results=True)
    assert call is not None and call.name == "decompile_it", call
    assert call.args == {"binary_name": PROGRAM["name"], "name_or_address": "140001000"}, call
    # A decompile answer names the function, not a program: the name stays the listed one.
    code = json.dumps({"name": "entry-140001000", "code": "\nvoid entry(void)\n{\n}\n"})
    request = _request(
        tools,
        opened,
        listed,
        ("list_exports", exports, {"binary_name": PROGRAM["name"]}),
        ("decompile_it", code, {"binary_name": PROGRAM["name"], "name_or_address": "140001000"}),
    )
    call = _next_call(request, _facts(), 4, fill_from_results=True)
    assert call is None or call.args.get("binary_name", PROGRAM["name"]) == PROGRAM["name"], call


@check
def an_api_list_argument_asks_about_every_api_an_answer_listed() -> None:
    from scripts.rehearsal.roles import _fillable

    tool = _tool("catalogue", {"api_names": {"type": "array"}})
    called = json.dumps({"apis": [{"api": "HttpSendRequestW"}, {"api": "CryptAcquireContextW"}]})
    args = _fillable(tool, _facts(), [called])
    assert args == {"api_names": ["HttpSendRequestW", "CryptAcquireContextW"]}, args
    # Without such an answer, the fixed name it always took.
    assert _fillable(tool, _facts(), [LISTING]) == {"api_names": ["InternetOpenW"]}
    assert _fillable(tool, _facts()) == {"api_names": ["InternetOpenW"]}


def run_self_checks() -> int:
    failed = 0
    for name, fn in CHECKS:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — every check is reported
            failed += 1
            print(f"FAIL {name}: {type(exc).__name__}: {exc}")
        else:
            print(f"ok   {name}")
    print(f"{len(CHECKS) - failed}/{len(CHECKS)} harness self-checks pass")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run_self_checks())
