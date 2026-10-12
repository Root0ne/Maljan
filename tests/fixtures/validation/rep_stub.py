"""A reputation lookup server for the validation runs: one tool, canned answers, stdio.

``lookup_hash(sha256)`` answers the same record for any well-formed SHA-256
and ``not found`` for anything else. It reaches no network, reads no file and
holds no sample bytes; it stands in for a reputation service an operator
plugs in, under a tool name no built-in uses.
"""

from __future__ import annotations

import json
import re

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

SERVER = "validation reputation stub"
RECORD = {
    "data": {
        "attributes": {
            "stats": {"malicious": 3, "total": 60},
            "label": "stub.family",
            "first_seen": "2026-01-01",
        }
    }
}
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")

server = FastMCP(SERVER, instructions="Look a file hash up in the stub reputation service.")
# Every tool only reads, so a connection test may call it to propose its declaration.
READ_ONLY = ToolAnnotations(readOnlyHint=True)


@server.tool(annotations=READ_ONLY)
def lookup_hash(sha256: str) -> str:
    """Look up a file by its SHA-256 and answer the service's record for it."""
    if not _SHA256.match(str(sha256 or "").strip()):
        return "not found"
    return json.dumps(RECORD)


if __name__ == "__main__":
    server.run()
