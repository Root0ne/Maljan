"""Every function a batch decompiled reaches the report writer, once, with its citation.

A batch decompile (kind ``decompile_batch``) answers ``{address: code, ...}``.
The composer's sections read only ``decompile`` and ``function_disassembly``,
so on a stored run 34 of 51 decompiled functions, the command switch and the
beacon loop among them, never reached the report, which then said decompile
results were obtained for three functions only.

Decompiled code is now read as ``decompile`` whichever tool gave it, and the
functions a batch lists form one run-wide table: each function once, in one
spelling of its address, with the citation of every entry that listed it
(``ev_0008 (function 0x401000)``, the ledger's form for a part of an entry).
Its code is shown whole in the sections whose claims cite its entry or name
it, else in ``commands``; every other section that reads code gets one line
for it. The claims and the tool answers keep the share of the window they
had. A tool that declares nothing is read the same way only when each
function of its answer names the function it stands under: a string table,
a cross-reference map or a rule's matches keyed by address is not code. A
declared single decompile is one listing whatever its answer's shape.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from maljan.core.undeclared_tools import (
    ANSWER_CUT_NOTE,
    CodePart,
    code_parts,
    function_key,
    names_itself,
)
from maljan.reporting import tool_kinds
from maljan.reporting.composer import FUNCTION_CODE_HEADING, FUNCTION_INDEX_HEADING, _bundle_text
from maljan.reporting.evidence_bundles import (
    CODE_HOME_SECTION,
    SECTIONS,
    bundle_for,
    function_table,
)
from maljan.reporting.figures import ANSWER_CUT_AFTER_LISTING, build_code_listings
from maljan.reporting.ledger_report import build_sections
from maljan.reporting.models import EvidenceIndexRow, FileHashes, MalwareReport, SampleIdentity
from maljan.schemas.evidence import LedgerEntry, entry_ids_in

SWITCH = (
    "\nint FUN_00401000(int cmd)\n\n{\n  switch(cmd) {\n  case 1:\n    run(cmd);\n  }\n"
    "  return 0;\n}\n"
)
BEACON = "\nvoid FUN_00402000(void)\n\n{\n  do {\n    send_beacon(0x4380);\n  } while (true);\n}\n"
ENCODE = "\nchar * FUN_00403000(char *in)\n\n{\n  return b64(in);\n}\n"
BATCH = json.dumps(
    {
        "0x401000": SWITCH,
        "0x402000": BEACON,
        "0x403000": ENCODE,
        "0x404000": "Error: no function at 0x404000",
    }
)
BATCH_FACTS = {"v": 1, "kind": "decompile_batch", "arguments": {"program": "program"}}
SINGLE_FACTS = {
    "v": 1,
    "kind": "decompile",
    "arguments": {"address": "address"},
    "report_sections": ["commands", "command_and_control"],
}
CODE_SECTIONS = (
    "string_resolution",
    "discovery",
    "persistence_detail",
    "evasion_antiforensics",
    "command_and_control",
    "configuration",
    "commands",
    "cli_flags",
    "payloads",
)
# A part of an entry as the ledger cites it: the id, then what in it.
PART_CITATION = re.compile(r"^ev_\d{4} \((function \S+|item \d+)\)$")


def _capture(tool: str, output: str, seq: int, facts: Any = None, **over: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "agent_id": "reverser",
        "tool_name": tool,
        "args": {"program": "sample.exe"},
        "output": output,
        "seq": seq,
        "source": "provider:ghidra",
        **over,
    }
    if facts is not None:
        row["facts"] = facts
    return row


def _report(*rows: dict[str, Any], indexed: bool = True) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        technical_evidence={"reverser": list(rows)},
        evidence_index=[
            EvidenceIndexRow(
                id=f"ev_{int(r['seq']) + 1:04d}", agent=str(r["agent_id"]), tool=r["tool_name"]
            )
            for r in rows
        ]
        if indexed
        else [],
    )


class _Claim:
    def __init__(self, claim: str, evidence_ref: str) -> None:
        self.claim, self.evidence_ref, self.confidence = claim, evidence_ref, 0.9


class _Isr:
    def __init__(self, *claims: _Claim) -> None:
        self.agent_id, self.claims = "reverser", list(claims)


# ---------------------------------------------------------------------------
# The composer's sections
# ---------------------------------------------------------------------------


def test_a_batch_is_shown_once_function_by_function_with_its_citations() -> None:
    report = _report(_capture("batch_decompile", BATCH, 7, BATCH_FACTS))
    home = bundle_for(CODE_HOME_SECTION, report)
    assert home["tool_outputs"] == []
    shown = home["function_code"]
    assert [row["symbol"] for row in shown] == ["0x401000", "0x402000", "0x403000"]
    assert [row["output"] for row in shown] == [
        SWITCH.strip("\n"),
        BEACON.strip("\n"),
        ENCODE.strip("\n"),
    ]
    assert [row["cites"] for row in shown] == [
        ["ev_0008 (function 0x401000)"],
        ["ev_0008 (function 0x402000)"],
        ["ev_0008 (function 0x403000)"],
    ]
    for section in CODE_SECTIONS:
        if section == CODE_HOME_SECTION:
            continue
        bundle = bundle_for(section, report)
        assert "function_code" not in bundle, section
        assert [row["symbol"] for row in bundle["function_index"]] == [
            "0x401000",
            "0x402000",
            "0x403000",
        ]
        assert all(row["shown_in"] == [CODE_HOME_SECTION] for row in bundle["function_index"])
    for section in set(SECTIONS) - set(CODE_SECTIONS):
        bundle = bundle_for(section, report)
        assert "function_code" not in bundle and "function_index" not in bundle, section


def test_a_function_goes_to_the_sections_whose_claims_cite_or_name_it() -> None:
    report = _report(_capture("batch_decompile", BATCH, 7, BATCH_FACTS))
    isrs = {
        "reverser": _Isr(
            _Claim("The beacon loop at 0x402000 sends a keep-alive over HTTP.", "decompiled"),
            _Claim("The command switch dispatches each command handler.", "ev_0008"),
        )
    }
    table = {row.where: row for row in function_table(report, None, isrs)}
    # Named by its address in a C2 claim, and in the commands claim's entry.
    assert "command_and_control" in table["0x402000"].shown_in
    assert "commands" in table["0x402000"].shown_in
    # The commands claim cites the batch's entry: all of its functions are there.
    assert "commands" in table["0x401000"].shown_in
    assert "command_and_control" not in table["0x401000"].shown_in


def _discovery(report: MalwareReport, claim: _Claim) -> tuple[list[str], list[str]]:
    bundle = bundle_for("discovery", report, None, {"reverser": _Isr(claim)})
    return (
        [row["symbol"] for row in bundle.get("function_code", [])],
        [row["symbol"] for row in bundle.get("function_index", [])],
    )


def test_a_claim_naming_functions_of_a_cited_batch_is_shown_only_those() -> None:
    report = _report(_capture("batch_decompile", BATCH, 7, BATCH_FACTS))
    claim = _Claim("FUN_00402000 enumerates the drives.", "ev_0008")
    assert _discovery(report, claim) == (["0x402000"], ["0x401000", "0x403000"])
    # By an offset from an image base the run states, too.
    based = _report(
        _capture("batch_decompile", BATCH, 7, BATCH_FACTS),
        _capture("program_info", json.dumps({"image_base": "0x400000"}), 2),
    )
    claim = _Claim("The routine at 0x3000 enumerates the drives.", "ev_0008")
    assert _discovery(based, claim) == (["0x403000"], ["0x401000", "0x402000"])


def test_a_claim_citing_a_batch_and_naming_none_of_it_is_shown_all_of_it() -> None:
    report = _report(_capture("batch_decompile", BATCH, 7, BATCH_FACTS))
    claim = _Claim("The sample enumerates the drives.", "ev_0008")
    assert _discovery(report, claim) == (["0x401000", "0x402000", "0x403000"], [])


def test_each_function_s_citation_resolves_to_its_entry() -> None:
    report = _report(_capture("batch_decompile", BATCH, 7, BATCH_FACTS))
    index = {row.id for row in report.evidence_index}
    for row in function_table(report):
        (cite,) = row.cites
        assert PART_CITATION.fullmatch(cite)
        # A citation resolves by the entry id it writes, which the index holds.
        assert entry_ids_in(cite) == {"ev_0008"}
        assert entry_ids_in(cite) <= index
        assert row.where in cite


def test_an_entry_the_index_does_not_name_for_the_tool_and_agent_is_not_cited() -> None:
    wrong_agent = _report(_capture("batch_decompile", BATCH, 7, BATCH_FACTS))
    wrong_agent.evidence_index[0].agent = "someone_else"
    assert all(row.cites == [] for row in function_table(wrong_agent))
    unindexed = _report(_capture("batch_decompile", BATCH, 7, BATCH_FACTS), indexed=False)
    assert all(row.cites == [] for row in function_table(unindexed))


def test_the_composer_shows_each_function_whole_and_keeps_the_answers_share() -> None:
    report = _report(_capture("batch_decompile", BATCH, 7, BATCH_FACTS))
    home = bundle_for(CODE_HOME_SECTION, report)
    text = _bundle_text(CODE_HOME_SECTION, home)
    assert FUNCTION_CODE_HEADING in text
    assert '"0x402000"] (cite as "ev_0008 (function 0x402000)"):' in text
    assert "send_beacon(0x4380);" in text
    assert "Error: no function" not in text
    elsewhere = _bundle_text("discovery", bundle_for("discovery", report))
    assert FUNCTION_INDEX_HEADING in elsewhere
    assert "send_beacon" not in elsewhere
    assert f'"0x402000" — "ev_0008 (function 0x402000)" — {len(BEACON.strip())} characters' in (
        elsewhere
    )
    # The measuring pass the window's share is reckoned on leaves the block out.
    assert FUNCTION_CODE_HEADING not in _bundle_text(CODE_HOME_SECTION, home, None, -1)


def test_a_function_in_two_batches_and_two_spellings_is_one_body_with_both_cites() -> None:
    again = json.dumps({"401000": SWITCH, "FUN_00405000": SWITCH.replace("401000", "405000")})
    report = _report(
        _capture("batch_decompile", BATCH, 7, BATCH_FACTS),
        _capture("batch_decompile", again, 9, BATCH_FACTS),
    )
    table = function_table(report)
    assert [row.key for row in table] == ["401000", "402000", "403000", "405000"]
    assert table[0].cites == ["ev_0008 (function 0x401000)", "ev_0010 (function 401000)"]
    assert function_key("0x1360bc03868") == function_key("1360bc03868")
    assert function_key("FUN_1360bc03868") == "1360bc03868"


def test_a_body_a_single_decompile_shows_is_not_repeated() -> None:
    report = _report(
        _capture("decompile_function", SWITCH, 3, SINGLE_FACTS, symbol="0x401000"),
        _capture("batch_decompile", BATCH, 7, BATCH_FACTS),
    )
    assert [row.key for row in function_table(report)] == ["402000", "403000"]


def test_a_single_decompile_is_shown_unchanged() -> None:
    report = _report(_capture("decompile_function", SWITCH, 3, SINGLE_FACTS, symbol="0x401000"))
    bundle = bundle_for("commands", report)
    assert bundle["tool_outputs"] == [
        {"tool": "decompile_function", "symbol": "0x401000", "output": SWITCH}
    ]
    assert "function_code" not in bundle and "function_index" not in bundle
    (figure,) = build_code_listings(report)
    assert figure.caption == "Decompiled 0x401000"


def test_a_declared_single_decompile_is_never_split_whatever_its_shape() -> None:
    keyed = json.dumps({"FUN_00401000": SWITCH, "FUN_00402000": BEACON})
    blocks = json.dumps(
        {
            "code": SWITCH,
            "blocks": [
                {"disasm": "0x00401000 push ebp\n0x00401001 mov ebp, esp"},
                {"disasm": "0x00401003 call 0x402000\n0x00401008 ret 0"},
            ],
        }
    )
    for answer in (keyed, blocks):
        single = _capture("decompile_function", answer, 3, SINGLE_FACTS, symbol="0x401000")
        assert tool_kinds.function_parts(single) == []
        (item,) = bundle_for("commands", _report(single))["tool_outputs"]
        assert item == {"tool": "decompile_function", "symbol": "0x401000", "output": answer}
    # The answer holds its function's code beside the list: it is one listing.
    assert code_parts(blocks) == []
    # One function under its key is one listing too.
    assert code_parts(json.dumps({"FUN_00401000": SWITCH})) == []


# ---------------------------------------------------------------------------
# A tool that declares nothing
# ---------------------------------------------------------------------------


def test_an_undeclared_tool_whose_functions_name_themselves_is_read_the_same_way() -> None:
    # No declaration and no code word in its name: its answer's shape decides.
    keyed = _capture("bulk_lift", BATCH, 7)
    rows = _capture(
        "bulk_lift",
        json.dumps(
            {
                "program": "sample.exe",
                "results": [
                    {"address": "0x406000", "pseudocode": SWITCH.replace("401000", "406000")},
                    {"address": "0x407000", "pseudocode": BEACON.replace("402000", "407000")},
                    {"error": "timed out"},
                ],
            }
        ),
        9,
    )
    listing = _capture(
        "bulk_lift",
        json.dumps(
            {
                "0x408000": "0x00408000  push rbp\n0x00408001  mov rbp, rsp\n0x00408004  ret",
                "0x409000": "0x00409000  xor eax, eax\n0x00409002  mov ecx, eax\n0x00409004  ret",
            }
        ),
        11,
    )
    for output in (keyed, rows, listing):
        assert tool_kinds.code_family_kind(output) == "decompile"
    table = function_table(_report(keyed, rows, listing))
    assert [row.where for row in table] == [
        "0x401000",
        "0x402000",
        "0x403000",
        "0x406000",
        "0x407000",
        "0x408000",
        "0x409000",
    ]
    assert table[3].cites == ["ev_0010 (function 0x406000)"]


# Answers keyed or listed by address that hold no function's code, each from a
# tool that declares nothing: none is read as decompiled code.
NOT_CODE = {
    "strings keyed": {"0x401000": "kernel32.dll", "0x401010": "http://evil/x"},
    "script strings keyed": {"0x401000": "function a(){eval(b);}", "0x402000": "if(x){run(y);}"},
    "script string rows": [
        {"address": "0x401000", "string": "function a(){eval(b);}"},
        {"address": "0x402000", "string": "try{WScript.Run(c);}"},
    ],
    "import rows": [{"name": "CreateFileA", "dll": "kernel32"}, {"name": "WriteFile", "dll": "k"}],
    "xrefs keyed, several lines": {
        "0x401000": "0x00401010  call  0x402000\n0x00401020  jmp  0x403000",
        "0x402000": "0x00402010 call 0x404000\n0x00402020 call 0x405000",
    },
    "xrefs naming their key": {
        "0x402000": "0x00401010 call 0x402000\n0x00401500 call 0x402000",
        "0x403000": "0x00401020 jmp 0x403000\n0x00401600 call 0x403000",
    },
    "xref lists": {
        "0x401000": ["0x00401010 call 0x402000", "0x00401020 jmp 0x403000"],
        "0x402000": ["0x00402010 call 0x404000"],
    },
    "numbers keyed": {"0x401000": 12, "0x402000": 34},
    "hex dump keyed": {"00401000": "55 8b ec 83 ec 10 ; push ebp; mov(ebp);}", "00401010": "x"},
    "rule string rows": [
        {"rule": "a", "strings": [{"offset": "0x10", "data": "push ebp\nmov ebp, esp\ncall eax"}]},
        {"rule": "b", "strings": [{"offset": "0x20", "data": "0x00401000 push ebp\n0x0040 ret"}]},
    ],
    "capability rows": [
        {"rule": "x", "matches": {"0x401000": "0x00401000 call eax\n0x00401002 jmp ebx"}},
        {"rule": "y", "matches": {"0x402000": "0x00402000 call eax\n0x00402002 jmp ebx"}},
    ],
    "year keys": {"2024": "for(i=0;i<n;i++){f(i);}", "2025": "while(x){g(y);}"},
    "decimal keys": {"1000": "for(i=0;i<n;i++){f(i);}", "2000": "while(x){g(y);}"},
}


@pytest.mark.parametrize("case", sorted(NOT_CODE))
def test_an_undeclared_answer_that_holds_no_function_s_code_is_not_read_as_code(
    case: str,
) -> None:
    output = _capture("lookup_things", json.dumps(NOT_CODE[case]), 4)
    assert tool_kinds.code_family_kind(output) == ""
    assert tool_kinds.function_parts(output) == []
    report = _report(output)
    for section in CODE_SECTIONS:
        bundle = bundle_for(section, report)
        assert bundle["tool_outputs"] == [] and "function_code" not in bundle, section
    assert build_code_listings(report) == []


def test_a_function_names_itself_by_its_decompiler_name_or_first_address() -> None:
    assert names_itself(CodePart("0x401000", SWITCH, False))
    assert names_itself(CodePart("0x408000", "0x00408000  push rbp\n0x00408001  ret", False))
    assert not names_itself(CodePart("0x402000", SWITCH, False))
    assert not names_itself(CodePart("item 1", SWITCH, False))


def test_a_row_s_name_never_becomes_a_citation() -> None:
    rows = json.dumps([{"name": "ev_0003", "code": SWITCH}, {"name": "b", "code": BEACON}])
    (first, _second) = code_parts(rows)
    assert entry_ids_in(first.where) == set()
    unnamed = json.dumps([SWITCH, BEACON])
    assert [p.where for p in code_parts(unnamed)] == ["item 1", "item 2"]
    assert tool_kinds.part_citation("ev_0003", code_parts(unnamed)[1]) == "ev_0003 (item 2)"


# ---------------------------------------------------------------------------
# A batch cut for storage
# ---------------------------------------------------------------------------


def test_a_cut_that_falls_between_functions_is_said() -> None:
    cut = BATCH[: BATCH.index('"0x403000"')] + "[OUTPUT TRUNCATED]"
    parts = code_parts(cut)
    assert [(p.where, p.cut, p.answer_cut) for p in parts] == [
        ("0x401000", False, False),
        ("0x402000", False, True),
    ]
    assert parts[1].code == BEACON.strip("\n")


def test_a_cut_inside_a_function_marks_it() -> None:
    cut = BATCH[: BATCH.index("while")]
    parts = code_parts(cut)
    assert [(p.where, p.cut, p.answer_cut) for p in parts] == [
        ("0x401000", False, False),
        ("0x402000", True, True),
    ]


def test_a_cut_list_shaped_batch_keeps_the_functions_it_shows() -> None:
    rows = [{"address": f"0x40{i}000", "code": c} for i, c in enumerate((SWITCH, BEACON, ENCODE))]
    for answer in (rows, {"functions": rows, "errors": []}):
        text = json.dumps(answer)
        parts = code_parts(text[: text.index("b64")] + "[OUTPUT TRUNCATED]")
        assert [p.where for p in parts] == ["0x400000", "0x401000"]
        assert parts[-1].answer_cut


def test_a_cut_batch_says_so_in_the_report_and_the_composer_and_the_figures() -> None:
    cut = BATCH[: BATCH.index('"0x403000"')] + "[OUTPUT TRUNCATED]"
    sections = build_sections([_entry("batch_decompile", cut, 8, BATCH_FACTS, "provider:ghidra")])
    assert _items(sections, "functions_examined") == [
        "0x401000 (batch_decompile)",
        f"0x402000 (batch_decompile; {ANSWER_CUT_NOTE})",
    ]
    report = _report(_capture("batch_decompile", cut, 7, BATCH_FACTS))
    shown = bundle_for(CODE_HOME_SECTION, report)["function_code"]
    assert [row["notes"] for row in shown] == [[], [ANSWER_CUT_NOTE]]
    figures = build_code_listings(report)
    assert figures[1].legend == ANSWER_CUT_AFTER_LISTING


# ---------------------------------------------------------------------------
# Figures and "Functions examined"
# ---------------------------------------------------------------------------


def test_a_batch_draws_one_listing_per_function_once() -> None:
    again = json.dumps({"401000": SWITCH, "0x405000": SWITCH.replace("401000", "405000")})
    figures = build_code_listings(
        _report(
            _capture("batch_decompile", BATCH, 7, BATCH_FACTS),
            _capture("batch_decompile", again, 9, BATCH_FACTS),
        )
    )
    assert [f.caption for f in figures] == [
        "Decompiled 0x401000",
        "Decompiled 0x402000",
        "Decompiled 0x403000",
        "Decompiled 0x405000",
    ]
    assert "send_beacon" in figures[1].content


def _entry(tool: str, output: str, seq: int, facts: Any, source: str | None, **over: Any) -> Any:
    return LedgerEntry(
        id=f"ev_{seq:04d}",
        agent="reverser",
        tool=tool,
        args={"program": "sample.exe"},
        output=output,
        structured=json.loads(output) if output.startswith("{") and output.endswith("}") else None,
        seq=seq,
        source=source,
        facts=facts,
        **over,
    )


def _items(sections: list[Any], key: str) -> list[str]:
    section = next((s for s in sections if s.key == key), None)
    return list(section.items) if section is not None else []


def test_a_batch_lists_each_function_under_functions_examined_once() -> None:
    again = json.dumps({"401000": SWITCH, "0x405000": SWITCH.replace("401000", "405000")})
    sections = build_sections(
        [
            _entry(
                "decompile_function", SWITCH, 2, SINGLE_FACTS, "provider:ghidra", symbol="403000"
            ),
            _entry("batch_decompile", BATCH, 8, BATCH_FACTS, "provider:ghidra"),
            _entry("batch_decompile", again, 10, BATCH_FACTS, "provider:ghidra"),
        ]
    )
    assert _items(sections, "functions_examined") == [
        "403000 (decompile_function)",
        "0x401000 (batch_decompile)",
        "0x402000 (batch_decompile)",
        "0x405000 (batch_decompile)",
    ]
    examined = next(s for s in sections if s.key == "functions_examined")
    assert examined.evidence_ids == ["ev_0002", "ev_0008", "ev_0010"]
    # Its answer is still drawn as its own block, as before.
    assert any(s.key == "tool_batch_decompile" for s in sections)


def test_a_function_no_claim_points_at_is_shown_in_commands() -> None:
    report = _report(_capture("batch_decompile", BATCH, 7, BATCH_FACTS))
    assert CODE_HOME_SECTION == "commands"
    assert all(row.shown_in == ["commands"] for row in function_table(report))


def test_a_function_no_claim_points_at_falls_to_the_first_section_it_reaches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.reporting import evidence_bundles

    # A configuration whose commands section reads no code.
    reads = tuple(k for k in evidence_bundles._SECTION_KINDS["commands"] if k != "decompile")
    monkeypatch.setitem(evidence_bundles._SECTION_KINDS, "commands", reads)
    report = _report(_capture("batch_decompile", BATCH, 7, BATCH_FACTS))
    first = next(s for s in SECTIONS if s in CODE_SECTIONS and s != "commands")
    for row in function_table(report):
        assert "commands" not in row.reaches
        assert row.shown_in == [row.reaches[0]] == [first]


def test_code_that_takes_a_prompt_past_the_window_is_stated() -> None:
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import patch

    from maljan.reporting.composer import ReportComposer

    long = "\n".join(f"  v{i} = f(v{i - 1});" for i in range(1, 2000))
    big = json.dumps(
        {
            f"0x40{n}000": f"\nint FUN_0040{n}000(int v0)\n{{\n{long}\n  return v0;\n}}\n"
            for n in range(1, 4)
        }
    )
    report = _report(_capture("batch_decompile", big, 7, BATCH_FACTS))
    report.verdict = "Malware"

    class _Answers:
        def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
            raise RuntimeError("structured output is unavailable")

        async def ainvoke(self, messages: Any, **_: Any) -> Any:
            return SimpleNamespace(content=json.dumps({"text": "An example."}))

    composer = ReportComposer(
        llm=_Answers(),  # type: ignore[arg-type]
        per_section_timeout=5,
        window_tokens=40_000,
        output_cap=1000,
    )
    with patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=False):
        asyncio.run(composer.compose(report, isr_reports={}))
    said = "\n".join(composer.degradations)
    assert "The commands section's prompt with the code of the functions it is shown" in said


def test_an_answer_nested_past_the_decoder_never_costs_the_report() -> None:
    deep = "[" * 50_000 + "]" * 50_000
    cut_deep = '{"0x401000": ' + "[" * 50_000
    for answer in (deep, cut_deep):
        assert code_parts(answer) == []
        output = _capture("lookup_things", answer, 4)
        for section in SECTIONS:
            from maljan.reporting.evidence_bundles import shown_to_section

            assert not shown_to_section(section, output)
        bundle_for("commands", _report(output))
        sections = build_sections([_entry("lookup_things", answer, 5, None, "mcp:things")])
        assert not _items(sections, "functions_examined")


def test_a_source_less_batch_is_read_as_it_always_was() -> None:
    sections = build_sections([_entry("batch_decompile", BATCH, 8, None, None)])
    assert _items(sections, "functions_examined") == []
    report = _report(_capture("batch_decompile", BATCH, 7, source=None))
    assert function_table(report) == []


# ---------------------------------------------------------------------------
# The stored run the defect was read off
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parents[3]
HAIKU5 = Path(".superpowers") / "sdd" / "mandate-2026-09-17" / "benchmark" / "deepseek" / "haiku5"


def _haiku5() -> Path | None:
    for base in (ROOT, *(p for p in ROOT.parents if (p / ".claude" / "worktrees").is_dir())):
        if (base / HAIKU5 / "report.json").is_file():
            return base / HAIKU5
    return None


def test_the_stored_run_s_batch_functions_now_reach_the_composer() -> None:
    root = _haiku5()
    if root is None:
        pytest.skip("the stored benchmark runs are not on this machine")
    report = MalwareReport.model_validate(json.loads((root / "report.json").read_text()))
    table = function_table(report)
    # The run's nine batches listed 47 functions: 46 distinct, 0x1360bc0c2c4 twice.
    assert len(table) == len({row.key for row in table}) == 46
    cites = {cite for row in table for cite in row.cites}
    # A function of each batch the run's score names, the install routine 0x33ac among them.
    for cited in (
        "ev_0063 (function 0x1360bc05750)",
        "ev_0066 (function 0x1360bc06370)",
        "ev_0068 (function 0x1360bc03868)",
        "ev_0068 (function 0x1360bc033ac)",
        "ev_0070 (function 0x1360bc03074)",
    ):
        assert cited in cites, cited
    (twice,) = [row for row in table if row.key == "1360bc0c2c4"]
    assert twice.cites == ["ev_0070 (function 0x1360bc0c2c4)", "ev_0074 (function 0x1360bc0c2c4)"]
    # Every function's code is shown in a section, and every other code section lists it.
    shown = {
        row["symbol"]
        for s in CODE_SECTIONS
        for row in bundle_for(s, report).get("function_code", [])
    }
    assert len(shown) == 46
