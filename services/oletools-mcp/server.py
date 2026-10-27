"""oletools over MCP: the macros, indicators, embedded objects and DDE links of Office documents.

Five tools, each one report of ``ole_report.py`` (olevba, MacroRaptor, oleid,
rtfobj, msodde), in an image of its own (``Dockerfile``); see ``README.md``.
Each report runs as a program of its own through the shared plumbing: in a
process group of its own, under ``TOOL_TIMEOUT_SECONDS``, with only the
variables it needs, so a document that sends a parser into a loop is killed
with its run. oletools reads the document; no macro runs, and the XLM emulator
olevba would call where it is installed is switched off.
"""

from __future__ import annotations

import importlib.util
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

SERVER = "oletools"
# The release the image pins (``requirements.txt``); the install hint names it.
OLETOOLS_VERSION = "0.60.2"
REPORT = str(Path(__file__).resolve().with_name("ole_report.py"))


@dataclass(frozen=True)
class _Oletools(sidecar.Program):
    """``ole_report.py`` on this interpreter, which must import oletools."""

    def absent(self) -> str | None:
        missing = super().absent()
        if missing:
            return missing
        if importlib.util.find_spec("oletools") is None:
            return "oletools is not installed"
        return None


PROGRAM = _Oletools(
    name="oletools",
    # This interpreter, isolated from the working directory and the user's
    # site packages, on the report beside this file.
    command=(sys.executable, "-I", REPORT),
    files=(REPORT,),
    install=(
        f"install oletools {OLETOOLS_VERSION} for this server's Python "
        "(pip install --require-hashes -r services/oletools-mcp/requirements.txt), or run the "
        "oletools-mcp image, which carries it"
    ),
)

VBA_TOOL = "ole_vba"
RISK_TOOL = "ole_macro_risk"
INDICATORS_TOOL = "ole_indicators"
RTF_TOOL = "rtf_objects"
DDE_TOOL = "office_dde"
TOOLS = (VBA_TOOL, RISK_TOOL, INDICATORS_TOOL, RTF_TOOL, DDE_TOOL)

# msodde's field filters, as ``office_dde`` takes them.
FIELD_FILTERS = ("only_dde", "exclude_blacklisted", "keep_all")

mcp = FastMCP("OletoolsMCP", stateless_http=True)


async def _report(tool: str, report: str, path: str, options: list[str]) -> dict[str, Any]:
    """One report's document over the sample, with the tool's name; a failure raised."""
    sample = sidecar.sample_file(path)
    ran = await sidecar.run_ok(PROGRAM, [report, *options, "--", sample])
    document = sidecar.json_document(ran.stdout.decode("utf-8", "replace"), "ole_report")
    if not isinstance(document, dict):
        raise sidecar.ToolFailure(sidecar.TOOL_FAILED, f"{report} wrote no report document")
    failed = document.get("error")
    if isinstance(failed, dict):
        code = str(failed.get("code") or sidecar.TOOL_FAILED)
        raise sidecar.ToolFailure(code, f"{report}: {failed.get('message') or 'failed'}")
    return {"tool": tool, **document}


@mcp.tool()
async def ole_vba(path: str, deobfuscate: bool = False) -> dict[str, Any]:
    """The VBA macros of an Office document (OLE, OOXML, Word 2003 XML, MHT) and olevba's analysis.

    ``macros``: each module's ``container`` (the OLE file inside an OOXML
    package), ``stream``, ``module`` and its ``source``, decompressed from
    the VBA project. ``indicators``: olevba's keyword analysis over all of it,
    each with its ``type`` (AutoExec, Suspicious, IOC, Hex String, Base64
    String, Dridex String, VBA string), ``keyword`` and ``description``;
    decoded strings included. ``deobfuscate`` adds olevba's evaluation of VBA
    string expressions (Chr, concatenation), a text grammar: no macro runs.
    ``has_xlm`` and ``xlm_macros``: Excel 4 macro sheets, read by olevba's
    BIFF parser. ``vba_stomping``: the P-code and the source disagree. A
    document encrypted with an Office default password is read decrypted
    (``encrypted``). An RTF is ``unsupported_format``: ``rtf_objects`` reads it.
    """

    async def work() -> dict[str, Any]:
        options = ["--deobfuscate"] if deobfuscate else []
        answer = await _report(VBA_TOOL, "vba", path, options)
        answer["macro_count"] = len(answer.get("macros") or ())
        answer["indicator_count"] = len(answer.get("indicators") or ())
        return answer

    return await sidecar.answering(VBA_TOOL, work)


@mcp.tool()
async def ole_macro_risk(path: str) -> dict[str, Any]:
    """MacroRaptor's verdict on an Office document's VBA macros: auto-run, write, execute.

    ``flags`` is MacroRaptor's ``AWX`` string: ``autoexec`` (a macro runs on
    open or close), ``write`` (it writes to the file system or memory) and
    ``execute`` (it runs a program or a library call); ``suspicious`` is
    auto-run with write or execute. ``matches`` names the keyword behind each
    flag. A keyword match on the source text, not a trace of a run.
    """

    async def work() -> dict[str, Any]:
        return await _report(RISK_TOOL, "macro_risk", path, [])

    return await sidecar.answering(RISK_TOOL, work)


@mcp.tool()
async def ole_indicators(path: str) -> dict[str, Any]:
    """oleid's indicators of a document: format, encryption, macros, external links, objects.

    Each row of ``indicators`` has ``id``, ``name``, ``value``, ``risk``
    (none, info, low, medium, HIGH, as oleid rates it) and ``description``.
    """

    async def work() -> dict[str, Any]:
        answer = await _report(INDICATORS_TOOL, "indicators", path, [])
        answer["indicator_count"] = len(answer.get("indicators") or ())
        return answer

    return await sidecar.answering(INDICATORS_TOOL, work)


@mcp.tool()
async def rtf_objects(path: str) -> dict[str, Any]:
    """The objects embedded in an RTF document, as rtfobj finds them.

    Each row of ``objects``: its ``index``, the ``start`` and ``end`` offsets
    of its data in the RTF, whether it is an OLE 1.0 object (``is_ole``) with
    its ``format_id``, ``class_name`` (Package, Equation.3, OLE2Link …) and
    ``data_size``; for a Package, the ``filename``, ``source_path`` and
    ``temp_path`` it names; the ``clsid`` of an embedded OLE file and its
    known description; and ``payload_sha256``, the digest of the payload
    (the package's file, else the OLE data, else the raw bytes). Nothing is
    written out. A file that is not RTF is ``unsupported_format``.
    """

    async def work() -> dict[str, Any]:
        answer = await _report(RTF_TOOL, "rtf_objects", path, [])
        answer["object_count"] = len(answer.get("objects") or ())
        return answer

    return await sidecar.answering(RTF_TOOL, work)


@mcp.tool()
async def office_dde(path: str, field_filter: str = "exclude_blacklisted") -> dict[str, Any]:
    """The DDE links and fields of a Word, Excel or RTF document, as msodde extracts them.

    Each row of ``links`` holds one link or field instruction (``text``),
    such as a ``DDEAUTO`` command line. ``field_filter`` is msodde's:
    ``only_dde`` keeps DDE fields alone, ``exclude_blacklisted`` (the
    default) leaves out fields known to be harmless, ``keep_all`` keeps every
    field. An encrypted document is answered ``encrypted`` with no links.
    """

    async def work() -> dict[str, Any]:
        if field_filter not in FIELD_FILTERS:
            raise sidecar.ToolFailure(
                sidecar.BAD_ARGUMENT, "field_filter is one of " + ", ".join(FIELD_FILTERS)
            )
        answer = await _report(DDE_TOOL, "dde", path, ["--field-filter", field_filter])
        answer["link_count"] = len(answer.get("links") or ())
        return answer

    return await sidecar.answering(DDE_TOOL, work)


@mcp.tool()
def capabilities() -> dict[str, Any]:
    """Which of this server's tools this host can run, and how to install what is missing."""
    return sidecar.capabilities(SERVER, PROGRAM, TOOLS, version=OLETOOLS_VERSION)


if __name__ == "__main__":
    sidecar.serve(mcp)
