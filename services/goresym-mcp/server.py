"""GoReSym over MCP: a Go binary's functions, build facts, types and strings.

Tools around ``GoReSym`` in an image of its own (``Dockerfile``); see
``README.md``. GoReSym reads the Go runtime's own tables in the file (its
pclntab, its moduledata and build info) for PE, ELF and Mach-O, stripped or
not; nothing of the sample runs.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

try:  # The image copies the shared module beside this file.
    import cli_sidecar as sidecar
except ModuleNotFoundError:  # A checkout keeps it in a directory of its own.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli-sidecar"))
    import cli_sidecar as sidecar

SERVER = "goresym"
# The release the image pins (``Dockerfile``); the install hint names it.
GORESYM_VERSION = "3.4.1"
PROGRAM = sidecar.Program(
    name="GoReSym",
    command=("GoReSym",),
    install=(
        f"install GoReSym {GORESYM_VERSION} on this server's PATH, or run the goresym-mcp "
        "image, which carries it"
    ),
)

SYMBOLS_TOOL = "go_symbols"
TYPES_TOOL = "go_types"
STRINGS_TOOL = "go_strings"
TOOLS = (SYMBOLS_TOOL, TYPES_TOOL, STRINGS_TOOL)

# What GoReSym says when the file holds no Go runtime table it can read.
_NOT_GO = ("no valid pclntab", "no valid moduledata")

mcp = FastMCP("GoReSymMCP", stateless_http=True)

# What each tool declares of itself (``cli_sidecar.reading_tool``).
_EXECUTABLE_FORMATS = ["pe", "elf", "mach-o"]
# The runtime every tool here reads, in the words an identification answer
# names it by (``ToolFacts.runtimes``): a Go binary.
_RUNTIMES = ["go"]
_DECLARED: dict[str, dict[str, Any]] = {
    SYMBOLS_TOOL: sidecar.reading_tool(
        "Go symbols",
        {
            "kind": "function_list",
            "long_running": True,
            "rows": "/functions/*",
            "places": {"address": "/start"},
            "values": {"name": "/name", "package": "/package"},
            "arguments": {"path": "path"},
            "routed_formats": _EXECUTABLE_FORMATS,
            "runtimes": _RUNTIMES,
            "display_name": "GoReSym",
            "shows": (
                "the Go version, build id and build info, and each function's name, package and "
                "address range, read from the Go runtime's own tables in the file"
            ),
            "does_not_show": "what a function does, or code that is not Go",
        },
    ),
    TYPES_TOOL: sidecar.reading_tool(
        "Go types",
        {
            "kind": "type_list",
            "long_running": True,
            "rows": "/types/*",
            "values": {"name": "/Str", "type_kind": "/Kind"},
            "arguments": {"path": "path"},
            "routed_formats": _EXECUTABLE_FORMATS,
            "runtimes": _RUNTIMES,
            "display_name": "GoReSym",
            "shows": "the Go type structures and interfaces the binary's moduledata lists",
            "does_not_show": "how the types are used, or types of a Go version it misreads",
        },
    ),
    STRINGS_TOOL: sidecar.reading_tool(
        "Go strings",
        {
            "kind": "embedded_strings",
            "long_running": True,
            "holds_strings": True,
            "rows": "/strings/*",
            "values": {"text": "/Str"},
            "arguments": {"path": "path"},
            "routed_formats": _EXECUTABLE_FORMATS,
            "runtimes": _RUNTIMES,
            "display_name": "GoReSym",
            "shows": "the strings the binary's Go string table holds, each cut where Go cuts it",
            "does_not_show": "strings built, decoded or decrypted at run time",
        },
    ),
    "capabilities": sidecar.reading_tool("Tool availability", sidecar.CAPABILITIES_FACTS),
}


async def _goresym(path: str, flags: list[str], go_version: str) -> dict[str, Any]:
    """GoReSym's JSON document over the sample, or its failure as a :class:`ToolFailure`."""
    sample = sidecar.sample_file(path)
    if go_version:
        flags = [*flags, "-v", sidecar.option_value("go_version", go_version)]
    ran = await sidecar.run(PROGRAM, [*flags, sample])
    document = sidecar.json_document(ran.stdout.decode("utf-8", "replace"), PROGRAM.name)
    if not isinstance(document, dict):
        raise sidecar.ToolFailure(sidecar.TOOL_FAILED, "GoReSym wrote no metadata document")
    said = str(document.get("error") or "")
    if said or ran.returncode != 0:
        said = said or ran.said or f"exited with {ran.returncode}"
        code = (
            sidecar.UNSUPPORTED_FORMAT
            if any(marker in said for marker in _NOT_GO)
            else sidecar.TOOL_FAILED
        )
        raise sidecar.ToolFailure(code, f"GoReSym: {said}")
    return document


def _build_facts(document: dict[str, Any]) -> dict[str, Any]:
    return {
        "go_version": document.get("Version") or "",
        "build_id": document.get("BuildId") or "",
        "arch": document.get("Arch") or "",
        "os": document.get("OS") or "",
        "pclntab": document.get("TabMeta") or {},
        "build_info": document.get("BuildInfo") or {},
    }


def function_rows(document: dict[str, Any]) -> list[dict[str, Any]]:
    """The user functions, then the standard library's, each with its start and end address."""
    rows: list[dict[str, Any]] = []
    for key, standard in (("UserFunctions", False), ("StdFunctions", True)):
        for func in document.get(key) or ():
            if not isinstance(func, dict):
                continue
            start, end = func.get("Start"), func.get("End")
            rows.append(
                {
                    "name": func.get("FullName") or "",
                    "package": func.get("PackageName") or "",
                    "start": f"0x{start:x}" if isinstance(start, int) else start,
                    "end": f"0x{end:x}" if isinstance(end, int) else end,
                    "standard_library": standard,
                }
            )
    return rows


@mcp.tool(**_DECLARED["go_symbols"])
async def go_symbols(
    path: str,
    standard_library: bool = False,
    file_paths: bool = False,
    go_version: str = "",
) -> dict[str, Any]:
    """Recover a Go binary's functions and build facts, stripped or not.

    The Go version, build id, architecture, OS, the pclntab's header and the
    build info (main module, dependencies, build settings), and each
    function with its package, full name and start and end address (virtual
    addresses). ``standard_library`` adds the standard library's functions
    after the program's own; ``file_paths`` adds the source file paths the
    pclntab names; ``go_version`` overrides the detected Go version, which a
    stripped binary may need.
    """

    async def work() -> dict[str, Any]:
        flags = [*(["-d"] if standard_library else []), *(["-p"] if file_paths else [])]
        document = await _goresym(path, flags, go_version)
        rows = function_rows(document)
        answer = {"tool": SYMBOLS_TOOL, **_build_facts(document), "functions": rows}
        answer["function_count"] = len(rows)
        if file_paths:
            answer["files"] = document.get("Files") or []
        return answer

    return await sidecar.answering(SYMBOLS_TOOL, work)


@mcp.tool(**_DECLARED["go_types"])
async def go_types(path: str, go_version: str = "") -> dict[str, Any]:
    """Recover a Go binary's type structures and interfaces from its moduledata typelinks.

    Each type as GoReSym reconstructs it: its address, name, kind and, where
    it could, its Go declaration. ``go_version`` overrides the detected Go
    version, which type parsing depends on.
    """

    async def work() -> dict[str, Any]:
        document = await _goresym(path, ["-t", "-nofuncs"], go_version)
        types = list(document.get("Types") or [])
        interfaces = list(document.get("Interfaces") or [])
        return {
            "tool": TYPES_TOOL,
            **_build_facts(document),
            "types": types,
            "interfaces": interfaces,
            "type_count": len(types),
            "interface_count": len(interfaces),
        }

    return await sidecar.answering(TYPES_TOOL, work)


@mcp.tool(**_DECLARED["go_strings"])
async def go_strings(path: str, go_version: str = "") -> dict[str, Any]:
    """Recover the strings a Go binary embeds, from its string internment table.

    Go strings are not NUL-terminated, so a plain strings pass runs them
    together; these are cut where Go itself cuts them.
    """

    async def work() -> dict[str, Any]:
        document = await _goresym(path, ["-strings", "-nofuncs"], go_version)
        strings = list(document.get("Strings") or [])
        return {
            "tool": STRINGS_TOOL,
            **_build_facts(document),
            "strings": strings,
            "string_count": len(strings),
        }

    return await sidecar.answering(STRINGS_TOOL, work)


@mcp.tool(**_DECLARED["capabilities"])
def capabilities() -> dict[str, Any]:
    """Which of this server's tools this host can run, and how to install what is missing."""
    return sidecar.capabilities(SERVER, PROGRAM, TOOLS, version=GORESYM_VERSION)


if __name__ == "__main__":
    sidecar.serve(mcp)
