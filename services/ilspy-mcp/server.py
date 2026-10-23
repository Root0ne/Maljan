"""ILSpy over MCP: a .NET assembly's types, resources, metadata and C# source.

Tools around ``ilspycmd`` (ILSpy's command-line decompiler), in an image of
its own with the .NET runtime it needs (``Dockerfile``); see ``README.md``.
ilspycmd reads the assembly's metadata and IL and decompiles it; it never
loads the assembly into a runtime, so nothing of the sample runs.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

try:  # The image copies the shared module beside this file.
    import cli_sidecar as sidecar
except ModuleNotFoundError:  # A checkout keeps it in a directory of its own.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli-sidecar"))
    import cli_sidecar as sidecar

SERVER = "ilspy"
# The release the image pins (``Dockerfile``); the install hint names it.
ILSPYCMD_VERSION = "11.1.0.9782"
_INSTALL = (
    f"install ilspycmd {ILSPYCMD_VERSION} (dotnet tool install --global ilspycmd --version "
    f"{ILSPYCMD_VERSION}, with the .NET 10 runtime), or run the ilspy-mcp image, which "
    "carries it"
)
# The image runs the tool's own assembly on the runtime; a host that installed
# it as a global tool runs the ``ilspycmd`` command on its PATH instead.
_ASSEMBLY = os.environ.get("ILSPYCMD_DLL", "")
# No telemetry, no first-run work and no diagnostics socket: the runtime's
# only writable place is the run's scratch directory.
_DOTNET_ENV = {
    "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
    "DOTNET_EnableDiagnostics": "0",
    "DOTNET_NOLOGO": "1",
    "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
}
PROGRAM = (
    sidecar.Program(
        name="ilspycmd",
        command=("dotnet", _ASSEMBLY),
        files=(_ASSEMBLY,),
        install=_INSTALL,
        env=_DOTNET_ENV,
    )
    if _ASSEMBLY
    else sidecar.Program(name="ilspycmd", command=("ilspycmd",), install=_INSTALL, env=_DOTNET_ENV)
)

TYPES_TOOL = "dotnet_types"
DECOMPILE_TYPE_TOOL = "dotnet_decompile_type"
DECOMPILE_MEMBER_TOOL = "dotnet_decompile_member"
DECOMPILE_ASSEMBLY_TOOL = "dotnet_decompile_assembly"
RESOURCES_TOOL = "dotnet_resources"
METADATA_TABLE_TOOL = "dotnet_metadata_table"
TOOLS = (
    TYPES_TOOL,
    DECOMPILE_TYPE_TOOL,
    DECOMPILE_MEMBER_TOOL,
    DECOMPILE_ASSEMBLY_TOOL,
    RESOURCES_TOOL,
    METADATA_TABLE_TOOL,
)

# ilspycmd's ``--list`` letters, each with the word its listing writes.
ENTITY_LETTERS = "cisde"

mcp = FastMCP("ILSpyMCP", stateless_http=True)


def _common(sample: str, bundle_entry: str) -> list[str]:
    arguments = ["--disable-updatecheck"]
    if bundle_entry:
        arguments += ["--bundle-entry", sidecar.option_value("bundle_entry", bundle_entry)]
    return [*arguments, sample]


def _lines(data: bytes) -> list[str]:
    return [line.strip() for line in data.decode("utf-8", "replace").splitlines() if line.strip()]


def type_rows(data: bytes) -> list[dict[str, str]]:
    """ilspycmd's ``--list`` output as rows: each line ``<Kind> <full name>``, in its order."""
    rows: list[dict[str, str]] = []
    for line in _lines(data):
        kind, _, name = line.partition(" ")
        rows.append({"type_kind": kind, "name": name.strip()} if name else {"name": kind})
    return rows


async def _decompile(
    tool: str, path: str, selection: list[str], il: bool, bundle_entry: str
) -> dict[str, Any]:
    sample = sidecar.sample_file(path)
    arguments = [*selection, "--ignore-decompilation-errors"]
    if il:
        arguments.append("--ilcode")
    ran = await sidecar.run_ok(PROGRAM, [*arguments, *_common(sample, bundle_entry)])
    return {
        "tool": tool,
        "language": "IL" if il else "C#",
        "source": ran.stdout.decode("utf-8", "replace"),
        # What ilspycmd could not decompile; the code carries the error text there.
        "decompilation_errors": _lines(ran.stderr),
    }


@mcp.tool()
async def dotnet_types(
    path: str, kinds: str = ENTITY_LETTERS, bundle_entry: str = ""
) -> dict[str, Any]:
    """List the types a .NET assembly defines, each with its kind and full name.

    ``kinds`` holds the letters of the kinds to list: c(lass), i(nterface),
    s(truct), d(elegate), e(num); all by default. ``bundle_entry`` names the
    assembly inside a single-file bundle, as an answer without it lists them.
    """

    async def work() -> dict[str, Any]:
        letters = "".join(ch for ch in str(kinds or "").lower() if ch in ENTITY_LETTERS)
        if not letters:
            raise sidecar.ToolFailure(
                sidecar.BAD_ARGUMENT, f"kinds holds none of the letters {ENTITY_LETTERS}"
            )
        sample = sidecar.sample_file(path)
        ran = await sidecar.run_ok(PROGRAM, ["--list", letters, *_common(sample, bundle_entry)])
        rows = type_rows(ran.stdout)
        return {"tool": TYPES_TOOL, "types": rows, "type_count": len(rows)}

    return await sidecar.answering(TYPES_TOOL, work)


@mcp.tool()
async def dotnet_decompile_type(
    path: str, type_name: str, il: bool = False, bundle_entry: str = ""
) -> dict[str, Any]:
    """Decompile one type of a .NET assembly to C# (or its IL, with ``il``).

    ``type_name`` is the type's full name as ``dotnet_types`` lists it.
    """

    async def work() -> dict[str, Any]:
        selection = ["--type", sidecar.option_value("type_name", type_name)]
        answer = await _decompile(DECOMPILE_TYPE_TOOL, path, selection, il, bundle_entry)
        return {**answer, "type_name": type_name.strip()}

    return await sidecar.answering(DECOMPILE_TYPE_TOOL, work)


@mcp.tool()
async def dotnet_decompile_member(
    path: str, member: str, il: bool = False, bundle_entry: str = ""
) -> dict[str, Any]:
    """Decompile one member (method, property, field, event) of a .NET assembly.

    ``member`` is an XML documentation id (``M:Namespace.Type.Method(System.String)``)
    or a metadata token (``0x06000005``).
    """

    async def work() -> dict[str, Any]:
        selection = ["--member", sidecar.option_value("member", member)]
        answer = await _decompile(DECOMPILE_MEMBER_TOOL, path, selection, il, bundle_entry)
        return {**answer, "member": member.strip()}

    return await sidecar.answering(DECOMPILE_MEMBER_TOOL, work)


@mcp.tool()
async def dotnet_decompile_assembly(
    path: str, il: bool = False, bundle_entry: str = ""
) -> dict[str, Any]:
    """Decompile a whole .NET assembly to C# (or its IL, with ``il``) in one answer.

    One call in place of ``dotnet_decompile_type`` over every type.
    """

    async def work() -> dict[str, Any]:
        return await _decompile(DECOMPILE_ASSEMBLY_TOOL, path, [], il, bundle_entry)

    return await sidecar.answering(DECOMPILE_ASSEMBLY_TOOL, work)


@mcp.tool()
async def dotnet_resources(path: str, bundle_entry: str = "") -> dict[str, Any]:
    """List the resources a .NET assembly embeds, each entry of a .resources container apart."""

    async def work() -> dict[str, Any]:
        sample = sidecar.sample_file(path)
        ran = await sidecar.run_ok(PROGRAM, ["--list-resources", *_common(sample, bundle_entry)])
        names = [{"name": line} for line in _lines(ran.stdout)]
        return {"tool": RESOURCES_TOOL, "resources": names, "resource_count": len(names)}

    return await sidecar.answering(RESOURCES_TOOL, work)


@mcp.tool()
async def dotnet_metadata_table(path: str, table: str, bundle_entry: str = "") -> dict[str, Any]:
    """Dump one ECMA-335 metadata table of a .NET assembly, every row, as JSON.

    ``table`` is the table's name (``TypeDef``, ``MethodDef``, ``MemberRef``,
    ``ImplMap``, ``ManifestResource`` …) or number (``0x06``). Each row gives
    its RID, token, names, heap offsets and coded indexes as ilspycmd dumps
    them.
    """

    async def work() -> dict[str, Any]:
        sample = sidecar.sample_file(path)
        name = sidecar.option_value("table", table)
        ran = await sidecar.run_ok(
            PROGRAM, ["--dump-table", name, "--json", *_common(sample, bundle_entry)]
        )
        document = sidecar.json_document(ran.stdout.decode("utf-8", "replace"), PROGRAM.name)
        rows = document if isinstance(document, list) else None
        return {
            "tool": METADATA_TABLE_TOOL,
            "table": name,
            **({"rows": rows, "row_count": len(rows)} if rows is not None else {"dump": document}),
        }

    return await sidecar.answering(METADATA_TABLE_TOOL, work)


@mcp.tool()
def capabilities() -> dict[str, Any]:
    """Which of this server's tools this host can run, and how to install what is missing."""
    return sidecar.capabilities(SERVER, PROGRAM, TOOLS, version=ILSPYCMD_VERSION)


if __name__ == "__main__":
    sidecar.serve(mcp)
