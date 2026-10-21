"""A sample_open read from schemas is marked incomplete for a server other jobs share."""

from __future__ import annotations

from maljan.core.declaration_proposals import SHARED_OPEN_NOTE, propose

_DEFINITIONS = [
    {
        "name": "open_binary",
        "description": "Open a binary for analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {"binary_path": {"type": "string"}},
            "required": ["binary_path"],
        },
    },
    *(
        {
            "name": name,
            "description": f"{name} of an opened binary.",
            "inputSchema": {
                "type": "object",
                "properties": {"binary_name": {"type": "string"}},
                "required": ["binary_name"],
            },
        }
        for name in ("list_functions", "decompile", "list_imports")
    ),
]


def test_a_local_server_is_offered_the_open_tool() -> None:
    server = propose(_DEFINITIONS)["server"]

    assert "incomplete" not in server["sample_open"]
    assert server["sample_open"]["value"] == {
        "open_tool": "open_binary",
        "path_argument": "binary_path",
    }


def test_a_server_at_an_address_is_offered_it_incomplete_and_told_what_to_declare() -> None:
    out = propose(_DEFINITIONS, remote=True)

    offered = out["server"]["sample_open"]
    assert offered["value"] == {"open_tool": "open_binary", "path_argument": "binary_path"}
    assert offered["incomplete"] == ["program_arguments", "job_safe_tools"]
    assert out["notes"] == [SHARED_OPEN_NOTE.format(tool="open_binary")]
    assert "program_arguments" in out["notes"][0] and "job_safe_tools" in out["notes"][0]
