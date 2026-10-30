"""A decompile answer is drawn as the code it holds, captioned with what was decompiled.

A decompiler answering ``{"name": ..., "code": "\\n/* ... */\\nvoid entry(void)..."}``
was drawn as that raw JSON, escaped line breaks and all, under the caption
"Decompiled function". The figure now draws the answer's code field (at the
declared ``values.code`` path, or its one string field that reads as code)
with its own line breaks, captioned with the call's symbol or address
argument (declared, or named for an address). A JSON answer holding no code (a
search's hits, a refusal) is not drawn; a plain text answer is drawn as before.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.core.undeclared_tools import code_listing, code_text, holds_code
from maljan.reporting.figures import LISTING_CUT_FOR_STORAGE, build_code_listings
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from tests.linear_cost import assert_scales

CODE = (
    "\n/* WARNING: bad instruction */\n\nvoid entry(void)\n\n{\n  char c;\n  *(char *)p = c;\n}\n"
)
WRAPPED = json.dumps({"name": "entry-140001000", "code": CODE}, indent=2)


def _capture(output: str, args: dict[str, Any], facts: Any = None, **over: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "agent_id": "reverser",
        "tool_name": "decompile_function",
        "args": args,
        "output": output,
        "seq": 1,
        "source": "mcp:programs",
        **over,
    }
    if facts is not None:
        row["facts"] = facts
    return row


def _report(*rows: dict[str, Any]) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        technical_evidence={"reverser": list(rows)},
    )


DECLARED = {
    "v": 1,
    "kind": "decompile",
    "arguments": {"address": "name_or_address", "program": "binary_name"},
}
ARGS = {"binary_name": "/sample_1.exe-1a2b3c", "name_or_address": "140001000"}


def test_a_json_answer_draws_its_code_field_with_its_line_breaks() -> None:
    for facts in (DECLARED, None):
        (figure,) = build_code_listings(_report(_capture(WRAPPED, ARGS, facts)))
        assert figure.caption == "Decompiled 140001000"
        assert "void entry(void)\n\n{" in figure.content
        assert "&quot;code&quot;" not in figure.content and "\\n" not in figure.content


def test_a_declared_code_path_is_read() -> None:
    nested = json.dumps({"result": {"listing": CODE, "notes": "int f(x); {"}})
    facts = {**DECLARED, "rows": "/result", "values": {"code": "/listing"}}
    (figure,) = build_code_listings(_report(_capture(nested, ARGS, facts)))
    assert "void entry(void)" in figure.content


def test_a_json_answer_holding_no_code_is_not_drawn() -> None:
    hits = json.dumps({"results": [{"function": "entry", "score": 0.9}], "total": 1})
    refused = json.dumps({"message": "Binary not found"})
    assert build_code_listings(_report(_capture(hits, ARGS), _capture(refused, ARGS))) == []


def test_a_plain_text_answer_is_drawn_as_before_and_a_symbol_still_leads() -> None:
    (figure,) = build_code_listings(
        _report(_capture("int f(void) { return 0; }", {"address": "0x401000"}, symbol="f"))
    )
    assert figure.caption == "Decompiled f"
    assert "int f(void) { return 0; }" in figure.content
    (bare,) = build_code_listings(_report(_capture("int g(void);", {})))
    assert bare.caption == "Decompiled function"


def test_an_answer_cut_for_storage_still_draws_its_code() -> None:
    cut = WRAPPED[:130] + "…"
    assert "void entry(void)" in code_text(cut)


def test_code_is_read_by_its_shape() -> None:
    assert holds_code(CODE)
    assert holds_code("1360bc06aa4: MOV dword ptr [RSP + 0x10],EDX\n1360bc06aa8: SUB RSP,0x18\n")
    assert holds_code("│ 0x00401000  55  push rbp\n│ 0x00401001  4889e5  mov rbp, rsp\n")
    assert not holds_code("Binary Web Protocols not found. Available binaries: []")
    assert not holds_code("")


def test_reading_code_stays_linear() -> None:
    def hostile(size: int) -> str:
        return json.dumps({"a": "x(" * size, "b": "{" * size, "c": "0x1234 " * size})

    def read(text: str) -> None:
        code_text(text)
        code_text(text[: len(text) // 2])

    assert_scales(hostile, 20_000, read, factor=10, repeats=5)


def test_prose_holding_numbers_is_not_read_as_code() -> None:
    assert not holds_code("Found 1234 matches in 4096 files total")
    assert not holds_code("Error 1234 was raised; retry 5678 has failed")
    assert not holds_code("1234 matches in 4096 files\n5678 errors in 1024 runs\n")
    assert holds_code("00401000  add eax, 1\n00401003  ret near ptr\n")
    assert holds_code(".text:00401000 push ebp\n.text:00401001 mov ebp, esp\n")


def test_a_decompile_with_other_fields_or_nesting_is_still_drawn() -> None:
    numbered = json.dumps(
        {
            "name": "entry",
            "code": "void entry(void)\n{\n f();\n}",
            "comment": "Seen 1234 times in 4096 runs here",
        }
    )
    nested = json.dumps({"result": {"code": "void f(void){ g(); }", "lines": 1}})
    several = json.dumps({"source": CODE, "callers": "int h(void) { return k(); }"})
    one_line = json.dumps({"code": "int f(int a) { return g(a); }"})
    figures = build_code_listings(
        _report(*(_capture(text, ARGS) for text in (numbered, nested, several, one_line)))
    )
    bodies = [figure.content for figure in figures]
    assert "void entry(void)" in bodies[0] and "Seen 1234" not in bodies[0]
    assert "void f(void){ g(); }" in bodies[1]
    # Among several code strings, the one under a code-ish key.
    assert "void entry(void)" in bodies[2] and "int h(void)" not in bodies[2]
    assert "return g(a);" in bodies[3]


def test_a_json_answer_holding_code_no_string_carries_alone_is_drawn_whole() -> None:
    split = json.dumps(
        {"lines": {"a": "0x00401000  55  push rbp", "b": "0x00401001  89e5  mov rbp, rsp"}}
    )
    (figure,) = build_code_listings(_report(_capture(split, ARGS)))
    assert "push rbp" in figure.content and "mov rbp, rsp" in figure.content


def test_a_cut_answer_reads_its_escapes_keeps_the_mark_out_and_says_it_was_cut() -> None:
    whole = json.dumps({"name": "e", "code": 'void entry(void)\n{\n  puts("\u00e9");\n  f();\n}\n'})
    at = whole.index("u00e9")
    # Cut inside the escape: the split escape is left out, never read as text.
    body, cut = code_listing(whole[: at + 2] + "\n\n[OUTPUT TRUNCATED]")
    assert cut and body.endswith('puts("') and "u0" not in body.split("puts")[-1]
    # Cut after it: the escape is undone, and no storage mark is in the listing.
    body, cut = code_listing(whole[: at + 14] + "\u2026")
    assert cut and 'puts("\u00e9");' in body and "\u2026" not in body
    body, cut = code_listing(whole[: at + 20] + "\n\n[OUTPUT TRUNCATED]")
    assert cut and "[OUTPUT TRUNCATED]" not in body
    (figure,) = build_code_listings(_report(_capture(whole[: at + 20] + "\u2026", ARGS)))
    assert figure.legend is not None and LISTING_CUT_FOR_STORAGE in figure.legend
    # A whole answer is not said to be cut.
    assert code_listing(whole) == ('void entry(void)\n{\n  puts("\u00e9");\n  f();\n}', False)


BARE = "push ebp\nmov ebp, esp\nsub esp, 10h\ncall sub_401000\nmov dword ptr [ebp-4], eax\nretn"


def test_a_listing_without_addresses_under_a_code_key_is_drawn() -> None:
    for key in ("disassembly", "listing", "asm", "code"):
        answer = json.dumps({key: BARE, "address": "0x401000"})
        (figure,) = build_code_listings(_report(_capture(answer, ARGS)))
        assert "mov ebp, esp" in figure.content and "retn" in figure.content, key


def test_short_prose_lines_under_a_code_key_are_not_drawn() -> None:
    for prose in (
        "Hello world\nGood bye\nSee you",
        "Status ok\nRetry 3\nDone",
        "Found 1234 matches\nin 4096 files\nsee the log",
        "The function loads the config, then patches it.\nIt calls 3 helpers.\nNothing else.",
    ):
        assert build_code_listings(_report(_capture(json.dumps({"code": prose}), ARGS))) == []


def test_a_bare_listing_is_read_in_linear_time() -> None:
    def hostile(size: int) -> str:
        return json.dumps({"disassembly": ("mov eax, " + "a " * 40 + "\n") * size})

    assert_scales(hostile, 2_000, code_text, factor=10, repeats=5)
