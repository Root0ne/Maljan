"""Detect It Easy over MCP: the packer, compiler, linker and protector of any file.

One tool around ``diec --json`` (Detect It Easy's console program), in an
image of its own (``Dockerfile``); see ``README.md``. The answer's rows are
Detect It Easy's detections, one per detected item, each with the file type it
was found in, its type (Compiler, Linker, Packer, Protector, Library …), its
name and version as Detect It Easy wrote them: the platform's declaration
(``core.builtin_declarations``) reads ``name``, ``type``, ``version`` and
``file_type`` from each, and a pack step may run on one of them.
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

SERVER = "die"
# The release the image pins (``Dockerfile``); the install hint names it.
DIE_VERSION = "3.21"
PROGRAM = sidecar.Program(
    name="diec",
    command=("diec",),
    install=(
        f"install Detect It Easy {DIE_VERSION} (its console program diec) on this server's "
        "PATH, or run the die-mcp image, which carries it"
    ),
)
SCAN_TOOL = "die_scan"
TOOLS = (SCAN_TOOL,)

mcp = FastMCP("DetectItEasyMCP", stateless_http=True)


def detections(document: Any) -> tuple[list[str], list[dict[str, Any]]]:
    """The file types and the detection rows of a ``diec --json`` document, in its order.

    Each row is one detected item as Detect It Easy wrote it, with the file
    type and the part of the file it was found in beside it; every key
    Detect It Easy wrote is kept.
    """
    if not isinstance(document, dict):
        raise sidecar.ToolFailure(sidecar.TOOL_FAILED, "diec wrote no detection document")
    file_types: list[str] = []
    rows: list[dict[str, Any]] = []
    for detect in document.get("detects") or ():
        if not isinstance(detect, dict):
            continue
        file_type = str(detect.get("filetype") or "")
        if file_type and file_type not in file_types:
            file_types.append(file_type)
        part = str(detect.get("parentfilepart") or "")
        for value in detect.get("values") or ():
            if isinstance(value, dict):
                rows.append({"file_type": file_type, "part": part, **value})
    return file_types, rows


@mcp.tool()
async def die_scan(
    path: str,
    deep_scan: bool = True,
    heuristic_scan: bool = False,
    recursive_scan: bool = False,
    all_types: bool = False,
) -> dict[str, Any]:
    """Name the packer, compiler, linker, protector, installer and libraries of a file.

    Detect It Easy's signatures over any format it reads (PE, ELF, Mach-O,
    APK, DEX, archives, installers …). Each row of ``detections`` is one
    detected item: ``file_type`` (the format it was found in), ``type``
    (Compiler, Linker, Packer, Protector, Library, Installer …), ``name``,
    ``version``, ``info`` and Detect It Easy's own ``string``.
    ``deep_scan`` reads the whole file rather than its headers;
    ``heuristic_scan`` adds Detect It Easy's heuristics, which may name a
    packer no signature names; ``recursive_scan`` also scans the files and
    overlays found inside; ``all_types`` scans the file as every type it
    could be, not only the first.
    """

    async def work() -> dict[str, Any]:
        sample = sidecar.sample_file(path)
        arguments = ["--json"]
        for flag, on in (
            ("--deepscan", deep_scan),
            ("--heuristicscan", heuristic_scan),
            ("--recursivescan", recursive_scan),
            ("--alltypes", all_types),
        ):
            if on:
                arguments.append(flag)
        ran = await sidecar.run_ok(PROGRAM, [*arguments, sample])
        document = sidecar.json_document(ran.stdout.decode("utf-8", "replace"), PROGRAM.name)
        file_types, rows = detections(document)
        return {
            "tool": SCAN_TOOL,
            "file_types": file_types,
            "detections": rows,
            "detection_count": len(rows),
        }

    return await sidecar.answering(SCAN_TOOL, work)


@mcp.tool()
def capabilities() -> dict[str, Any]:
    """Which of this server's tools this host can run, and how to install what is missing."""
    return sidecar.capabilities(SERVER, PROGRAM, TOOLS, version=DIE_VERSION)


if __name__ == "__main__":
    sidecar.serve(mcp)
