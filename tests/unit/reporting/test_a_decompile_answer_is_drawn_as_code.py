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
import time
from typing import Any

from maljan.core.undeclared_tools import code_text, holds_code
from maljan.reporting.figures import build_code_listings
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity

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
    def took(size: int) -> float:
        hostile = json.dumps({"a": "x(" * size, "b": "{" * size, "c": "0x1234 " * size})
        start = time.perf_counter()
        code_text(hostile)
        code_text(hostile[: len(hostile) // 2])
        return time.perf_counter() - start

    small, large = took(20_000), took(200_000)
    assert large < small * 30, (small, large)
