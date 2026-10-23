"""webcrack over MCP: a JavaScript dropper unminified, unpacked and deobfuscated, never run.

One tool around ``deobfuscate.mjs`` (webcrack on Node.js), in an image of its
own (``Dockerfile``); see ``README.md``. The script runs as a program of its
own through the shared plumbing: in a process group of its own, under
``TOOL_TIMEOUT_SECONDS``, with only the variables it needs. webcrack parses
the file and rewrites its syntax tree; the sandbox it would evaluate an
obfuscator's string decoders in is never handed to it, so nothing of the
script runs and those decoder calls stay as written.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

try:  # The image copies the shared module beside this file.
    import cli_sidecar as sidecar
except ModuleNotFoundError:  # A checkout keeps it in a directory of its own.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli-sidecar"))
    import cli_sidecar as sidecar

SERVER = "webcrack"
# The release the image pins (``package.json``, ``package-lock.json``); the
# install hint names it.
WEBCRACK_VERSION = "2.16.0"
HERE = Path(__file__).resolve().parent
SCRIPT = str(HERE / "deobfuscate.mjs")
# Where Node.js finds webcrack: the packages installed beside the script.
WEBCRACK_PACKAGE = HERE / "node_modules" / "webcrack" / "package.json"


@dataclass(frozen=True)
class _Webcrack(sidecar.Program):
    """``node`` on the script beside this file, with webcrack installed beside it."""

    def absent(self) -> str | None:
        missing = super().absent()
        if missing:
            return missing
        if not WEBCRACK_PACKAGE.is_file():
            return "webcrack is not installed beside deobfuscate.mjs"
        return None


PROGRAM = _Webcrack(
    name="webcrack",
    command=("node", SCRIPT),
    files=(SCRIPT,),
    install=(
        f"install Node.js 22 or 24 on this server's PATH and webcrack {WEBCRACK_VERSION} beside "
        "deobfuscate.mjs (npm ci --ignore-scripts in services/webcrack-mcp), or run the "
        "webcrack-mcp image, which carries both"
    ),
)
DEOBFUSCATE_TOOL = "js_deobfuscate"
TOOLS = (DEOBFUSCATE_TOOL,)

mcp = FastMCP("WebcrackMCP", stateless_http=True)


@mcp.tool()
async def js_deobfuscate(
    path: str,
    deobfuscate: bool = True,
    unminify: bool = True,
    unpack: bool = True,
    mangle: bool = False,
) -> dict[str, Any]:
    """A JavaScript file (or the scripts of an HTA or WSF) as webcrack rewrites it.

    Each row of ``scripts`` is one script: the whole file for JavaScript, or
    each ``<script>`` block of a file that opens with markup (an HTA, a
    Windows Script File), with its ``language`` and the ``start`` offset of
    its text. A JavaScript or JScript block is rewritten (``deobfuscated``,
    ``changed``, ``code``); a block in another language (VBScript) is listed
    as it is; a block webcrack cannot parse says why (``error``). ``bundle``
    lists the modules of a webpack or browserify bundle (``unpack``).
    ``deobfuscate`` removes self-defending and debugger traps, merges object
    assignments and decodes literal ``atob``/``unescape`` calls;
    ``unminify`` restores readable syntax (strings, numbers, sequences,
    blocks); ``mangle`` renames variables. An obfuscator's string-decoder
    calls stay as written: decoding them would run the script's code. With no
    sandbox, a script guarded by an obfuscator-style string array also keeps
    its control-flow flattening and dead code, which webcrack removes only in
    that step. ``start`` and ``end`` are byte offsets in the file.
    """

    async def work() -> dict[str, Any]:
        sample = sidecar.sample_file(path)
        flags = [
            f"--{'' if on else 'no-'}{name}"
            for name, on in (
                ("deobfuscate", deobfuscate),
                ("unminify", unminify),
                ("unpack", unpack),
                ("mangle", mangle),
            )
        ]
        ran = await sidecar.run_ok(PROGRAM, [*flags, "--", sample])
        document = sidecar.json_document(ran.stdout.decode("utf-8", "replace"), PROGRAM.name)
        if not isinstance(document, dict):
            raise sidecar.ToolFailure(sidecar.TOOL_FAILED, "webcrack wrote no document")
        failed = document.get("error")
        if isinstance(failed, dict):
            code = str(failed.get("code") or sidecar.TOOL_FAILED)
            raise sidecar.ToolFailure(code, f"webcrack: {failed.get('message') or 'failed'}")
        scripts = [row for row in document.get("scripts") or () if isinstance(row, dict)]
        return {
            "tool": DEOBFUSCATE_TOOL,
            "scripts": scripts,
            "script_count": len(scripts),
            "deobfuscated_count": sum(1 for row in scripts if row.get("deobfuscated")),
        }

    return await sidecar.answering(DEOBFUSCATE_TOOL, work)


@mcp.tool()
def capabilities() -> dict[str, Any]:
    """Which of this server's tools this host can run, and how to install what is missing."""
    return sidecar.capabilities(SERVER, PROGRAM, TOOLS, version=WEBCRACK_VERSION)


if __name__ == "__main__":
    sidecar.serve(mcp)
