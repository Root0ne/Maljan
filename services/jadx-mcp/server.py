"""JADX over MCP: an Android package's or dex file's classes, and Java source decompiled from them.

Tools around JADX's command-line decompiler (``jadx.cli.JadxCLI``), in an
image of its own with the Java runtime it needs (``Dockerfile``); see
``README.md``. JADX reads the dex bytecode and writes Java source; it never
loads a class into a virtual machine of its own, so nothing of the sample
runs. The manifest, permissions, components and certificates of an APK are
the analysis server's ``apk_info`` (androguard); this server adds the code.

What JADX is handed is held to that: the file is given to it under a name of
this server's choosing (``input.apk`` or ``input.dex``, a link in the call's
scratch directory, chosen by the file's own first bytes), so no name the
sample's uploader wrote decides which of JADX's inputs reads it; every input
plugin but the dex reader is switched off (no smali assembler, no Java class
or XAPK, APKS, APKM or AAB loader), no configuration file is read, resources
are not decoded, and the run's only writable place is its scratch directory.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

try:  # The image copies the shared module beside this file.
    import cli_sidecar as sidecar
except ModuleNotFoundError:  # A checkout keeps it in a directory of its own.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli-sidecar"))
    import cli_sidecar as sidecar

SERVER = "jadx"
# The release the image pins (``Dockerfile``); the install hint names it.
JADX_VERSION = "1.5.6"
_INSTALL = (
    f"install JADX {JADX_VERSION} (its jadx command, with a Java 11 or later runtime) on this "
    "server's PATH, or run the jadx-mcp image, which carries both"
)
# The image runs JADX's own jar on the runtime; a host that installed the
# release runs the ``jadx`` command on its PATH instead.
_JAR = os.environ.get("JADX_JAR", "")
# The Java options JADX's own launcher passes (a share of the container's
# memory, half of it here so the container's sized tmpfs fits beside the heap,
# a few collector threads, zip64 archives read as they are), and the run's
# temporary files and home in its working directory, the call's own scratch.
_JVM_OPTIONS = (
    "-XX:+IgnoreUnrecognizedVMOptions",
    "-XX:MaxRAMPercentage=50.0",
    "-Djava.io.tmpdir=.",
    "-Duser.home=.",
    "-XX:ParallelGCThreads=3",
    "-XX:-UsePerfData",
    "-Djdk.util.zip.disableZip64ExtraFieldValidation=true",
)
PROGRAM = (
    sidecar.Program(
        name="jadx",
        command=("java", *_JVM_OPTIONS, "-cp", _JAR, "jadx.cli.JadxCLI"),
        files=(_JAR,),
        install=_INSTALL,
    )
    if _JAR
    # JADX's launcher adds what JAVA_OPTS holds to its own options.
    else sidecar.Program(
        name="jadx",
        command=("jadx",),
        install=_INSTALL,
        env={"JAVA_OPTS": " ".join(_JVM_OPTIONS[1:4])},
    )
)

CLASSES_TOOL = "android_classes"
DECOMPILE_CLASS_TOOL = "android_decompile_class"
TOOLS = (CLASSES_TOOL, DECOMPILE_CLASS_TOOL)

# JADX's input plugins other than the dex reader, each switched off.
DISABLED_PLUGINS = (
    "smali-input",
    "java-input",
    "java-convert",
    "xapk-input",
    "apks-input",
    "jadx-apks-input",
    "apkm-input",
    "jadx-apkm-input",
    "aab-input",
    "rename-mappings",
)
# What a file's first bytes make it, as JADX's dex reader takes it.
_DEX_MAGIC = b"dex\n"
_ZIP_MAGIC = b"PK\x03\x04"
# The line JADX ends a run with when some code did not decompile.
_ERRORS_RE = re.compile(r"finished with errors, count: (\d+)")

mcp = FastMCP("JadxMCP", stateless_http=True)

# What each tool declares of itself (``cli_sidecar.reading_tool``).
# The report sections a decompiled function's writer is shown, for decompiled
# code.
_DECOMPILED_CODE_SECTIONS = [
    "cli_flags",
    "discovery",
    "persistence_detail",
    "evasion_antiforensics",
    "command_and_control",
    "string_resolution",
    "configuration",
    "commands",
    "payloads",
]
# JADX decompiles dex bytecode to Java and loads no class; an APK's
# manifest, permissions and certificates are another tool's.
_ANDROID_FORMATS = ["apk", "dex"]
_DECLARED: dict[str, dict[str, Any]] = {
    CLASSES_TOOL: sidecar.reading_tool(
        "Android classes",
        {
            "kind": "type_list",
            "long_running": True,
            "rows": "/classes/*",
            "values": {"name": "/name"},
            "arguments": {"path": "path"},
            "routed_formats": _ANDROID_FORMATS,
            "display_name": "JADX",
            "shows": (
                "the classes the APK's or dex file's bytecode defines, each with its methods and "
                "their signatures, as JADX reads them"
            ),
            "does_not_show": (
                "what any of them does; classes loaded, decrypted or downloaded at run time (no "
                "code is run); the manifest, permissions and certificates, which apk_info reads"
            ),
        },
    ),
    DECOMPILE_CLASS_TOOL: sidecar.reading_tool(
        "Decompile an Android class",
        {
            "kind": "decompile",
            "arguments": {"path": "path"},
            "routed_formats": _ANDROID_FORMATS,
            "report_sections": _DECOMPILED_CODE_SECTIONS,
            "display_name": "JADX",
            "shows": "Java source JADX decompiled from one class's dex bytecode, inner classes too",
            "does_not_show": (
                "what runs at run time: code loaded, decrypted or downloaded while the app runs, "
                "or native libraries beside the bytecode; no code is run"
            ),
        },
    ),
    "capabilities": sidecar.reading_tool("Tool availability", sidecar.CAPABILITIES_FACTS),
}


def input_name(sample: str) -> str:
    """The name the sample is handed to JADX under: ``input.apk`` or ``input.dex``, by its bytes."""
    with open(sample, "rb") as handle:
        head = handle.read(4)
    if head == _DEX_MAGIC:
        return "input.dex"
    if head == _ZIP_MAGIC:
        return "input.apk"
    raise sidecar.ToolFailure(
        sidecar.UNSUPPORTED_FORMAT, "the file is neither an Android package (a zip) nor a dex file"
    )


def _common() -> list[str]:
    return [
        "--log-level",
        "error",
        "--config",
        "none",
        "--no-res",
        # No comment of JADX's own in the code: none names the scratch path
        # the file was loaded from, so one file answers the same each time.
        "--comments-level",
        "none",
        "--disable-plugins",
        ",".join(DISABLED_PLUGINS),
        # A dex file whose checksum does not match its bytes (a common
        # tampering) is read as it is.
        "-Pdex-input.verify-checksum=no",
    ]


def _handed(sample: str, scratch: Path) -> str:
    """The sample, linked into ``scratch`` under the name JADX reads it by.

    An absolute path of this server's making: JADX's argument parser has no
    ``--`` to end its options, and a path that starts with ``/`` is never
    read as one.
    """
    linked = scratch / input_name(sample)
    os.symlink(sample, linked)
    return str(linked)


def errors_count(ran: sidecar.Ran) -> int:
    """How many classes or methods JADX said it could not decompile."""
    said = f"{ran.stdout.decode('utf-8', 'replace')}\n{ran.stderr.decode('utf-8', 'replace')}"
    found = _ERRORS_RE.findall(said)
    return int(found[-1]) if found else 0


def class_rows(mapping: Any, package: str) -> list[dict[str, Any]]:
    """The classes JADX's ``mapping.json`` lists, those under ``package`` when one is named.

    Each row is the class's full name, whether it is an inner class, its
    field count and its methods (name, signature, and the method's offset in
    the dex file as JADX gives it).
    """
    if not isinstance(mapping, dict):
        raise sidecar.ToolFailure(sidecar.TOOL_FAILED, "jadx wrote no class index")
    prefix = f"{package}." if package else ""
    rows: list[dict[str, Any]] = []
    for held in mapping.get("classes") or ():
        if not isinstance(held, dict):
            continue
        name = str(held.get("name") or "")
        if prefix and not name.startswith(prefix):
            continue
        methods = [
            {
                "name": str(method.get("name") or ""),
                "signature": str(method.get("signature") or ""),
                "dex_offset": str(method.get("offset") or ""),
            }
            for method in held.get("methods") or ()
            if isinstance(method, dict)
        ]
        row: dict[str, Any] = {
            "name": name,
            "inner": bool(held.get("inner")),
            "field_count": len([f for f in held.get("fields") or () if isinstance(f, dict)]),
            "methods": methods,
        }
        alias = str(held.get("alias") or "")
        if alias and alias != name:
            row["alias"] = alias
        rows.append(row)
    return rows


def _package(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "\0" in text or not re.fullmatch(r"[\w$]+(?:\.[\w$]+)*", text):
        raise sidecar.ToolFailure(
            sidecar.BAD_ARGUMENT, "package is not a dotted Java package name (com.example.app)"
        )
    return text


@mcp.tool(**_DECLARED["android_classes"])
async def android_classes(path: str, package: str = "") -> dict[str, Any]:
    """List the classes an APK or dex file defines, each with its methods, as JADX reads them.

    ``package`` (``com.example.app``) keeps the classes under that package;
    all of them otherwise. JADX decompiles the whole package to index it, so
    a large APK takes a while.
    """

    async def work() -> dict[str, Any]:
        sample = sidecar.sample_file(path)
        prefix = _package(package)
        with tempfile.TemporaryDirectory(prefix="jadx-") as scratch:
            where = Path(scratch)
            handed = _handed(sample, where)
            out = where / "out"
            arguments = [*_common(), "--output-format", "json", "--output-dir-src", str(out)]
            ran = await sidecar.run(PROGRAM, [*arguments, handed], workdir=scratch)
            index = out / "mapping.json"
            if not index.is_file():
                said = ran.said or f"exit status {ran.returncode}"
                raise sidecar.ToolFailure(
                    sidecar.TOOL_FAILED, f"jadx exited with {ran.returncode}: {said}"
                )
            try:
                mapping = json.loads(index.read_text(encoding="utf-8", errors="replace"))
            except ValueError as exc:
                raise sidecar.ToolFailure(
                    sidecar.TOOL_FAILED, f"jadx's class index does not parse: {exc}"
                ) from exc
        rows = class_rows(mapping, prefix)
        return {
            "tool": CLASSES_TOOL,
            "engine": "jadx",
            "engine_version": JADX_VERSION,
            "classes": rows,
            "class_count": len(rows),
            "decompilation_errors": errors_count(ran),
        }

    return await sidecar.answering(CLASSES_TOOL, work)


@mcp.tool(**_DECLARED["android_decompile_class"])
async def android_decompile_class(path: str, class_name: str) -> dict[str, Any]:
    """Decompile one class of an APK or dex file to Java, with JADX.

    ``class_name`` is the class's full name as ``android_classes`` lists it
    (``com.example.app.MainActivity``); its inner classes come with it.
    """

    async def work() -> dict[str, Any]:
        sample = sidecar.sample_file(path)
        name = sidecar.option_value("class_name", class_name)
        with tempfile.TemporaryDirectory(prefix="jadx-") as scratch:
            where = Path(scratch)
            handed = _handed(sample, where)
            out = where / "class.java"
            arguments = [*_common(), "--single-class", name, "--single-class-output", str(out)]
            ran = await sidecar.run(PROGRAM, [*arguments, handed], workdir=scratch)
            if not out.is_file():
                said = ran.said or f"exit status {ran.returncode}"
                raise sidecar.ToolFailure(
                    sidecar.TOOL_FAILED, f"jadx exited with {ran.returncode}: {said}"
                )
            source = out.read_text(encoding="utf-8", errors="replace")
        return {
            "tool": DECOMPILE_CLASS_TOOL,
            "language": "Java",
            "class_name": name,
            "source": source,
            "decompilation_errors": errors_count(ran),
        }

    return await sidecar.answering(DECOMPILE_CLASS_TOOL, work)


@mcp.tool(**_DECLARED["capabilities"])
def capabilities() -> dict[str, Any]:
    """Which of this server's tools this host can run, and how to install what is missing."""
    return sidecar.capabilities(SERVER, PROGRAM, TOOLS, version=JADX_VERSION)


if __name__ == "__main__":
    sidecar.serve(mcp)
