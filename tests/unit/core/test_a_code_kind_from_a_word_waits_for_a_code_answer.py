"""A code-listing kind read from a description word waits for an answer that holds code.

A probe proposed ``search_code`` as a decompiler from the word "decompiled" in
its description; accepted, its search hits would be drawn as decompiled
functions and listed as functions examined. A code kind read from the
description's words alone (the name says no such thing) is now proposed only
when the probe answer it read holds code; a tool whose name says it
decompiles is read by its name, as before.
"""

from __future__ import annotations

from maljan.core.declaration_proposals import propose_tool

CODE = "\nvoid entry(void)\n\n{\n  char c;\n  *(char *)p = c;\n}\n"


SEARCH = {
    "name": "search_code",
    "description": "[LIST] Search decompiled pseudo-C code by similarity.",
    "inputSchema": {
        "type": "object",
        "properties": {"binary_name": {"type": "string"}, "query": {"type": "string"}},
        "required": ["binary_name", "query"],
    },
}


def test_a_code_kind_from_a_description_word_waits_for_a_code_answer() -> None:
    unanswered = propose_tool(SEARCH)
    assert unanswered is not None and unanswered.facts.get("kind") != "decompile"
    hits = propose_tool(SEARCH, answer={"results": [{"function": "entry", "score": 0.9}]})
    assert hits is not None and hits.facts.get("kind") != "decompile"
    code = propose_tool(SEARCH, answer={"code": CODE})
    assert code is not None and code.facts.get("kind") == "decompile"
    # A tool whose name says it decompiles is read by its name, as before.
    named = propose_tool({**SEARCH, "name": "decompile_function"})
    assert named is not None and named.facts.get("kind") == "decompile"


def test_prose_holding_numbers_is_no_code_answer() -> None:
    for prose in (
        "Found 1234 matches in 4096 files total",
        "Error 1234 was raised; retry 5678 has failed",
        "1234 matches in 4096 files\n5678 errors in 1024 runs",
    ):
        proposed = propose_tool(SEARCH, answer=prose)
        assert proposed is not None and proposed.facts.get("kind") != "decompile", prose
    # A code string nested in the answer still confirms code.
    nested = propose_tool(SEARCH, answer={"result": {"code": CODE}})
    assert nested is not None and nested.facts.get("kind") == "decompile"
