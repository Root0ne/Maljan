"""YARA-X over MCP: the operator's own YARA rule files, matched against any file.

One tool around ``yr scan`` (YARA-X's command-line program), in an image of
its own (``Dockerfile``); see ``README.md``. The rules are the operator's:
every ``*.yar`` and ``*.yara`` file under the directories ``YARA_X_RULES``
lists (the image mounts one read-only at ``/data/rules``), compiled by YARA-X
on each call, so a rule file changed on the host is read by the next call.
The platform's shipped rule corpus stays with its own ``yara_scan``; this
server adds the operator's native rule sets beside it.

The answer's rows are the rules that matched, each with its metadata, tags and
every matching string's offset, in the row shape the platform's ``yara_scan``
answers, so the declaration (``core.builtin_declarations``) reads both alike.
"""

from __future__ import annotations

import os
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

SERVER = "yarax"
# The release the image pins (``Dockerfile``); the install hint names it.
YARA_X_VERSION = "1.21.0"
# The directories the rule files are read from, separated as PATH is.
RULES_ENV = "YARA_X_RULES"
RULE_SUFFIXES = (".yar", ".yara")
# How much of each matching string yr prints when the caller asks for no
# other length: yr's own default.
STRING_CHARS = 120


def rule_roots() -> list[Path]:
    """The rule directories (or files) ``YARA_X_RULES`` names; empty when it is unset."""
    raw = os.environ.get(RULES_ENV, "")
    return [Path(part) for part in raw.split(os.pathsep) if part.strip()]


def rule_files() -> list[Path]:
    """Every rule file yr reads from the rule roots, as it walks them: ``*.yar``, ``*.yara``."""
    found: list[Path] = []
    for root in rule_roots():
        if root.is_file():
            found.append(root)
        elif root.is_dir():
            found.extend(
                path
                for path in sorted(root.rglob("*"))
                if path.suffix.lower() in RULE_SUFFIXES and path.is_file()
            )
    return found


@dataclass(frozen=True)
class _YaraX(sidecar.Program):
    """``yr``, and the rule files it needs: without either, every call is an absence."""

    def absent(self) -> str | None:
        missing = super().absent()
        if missing:
            return missing
        if not rule_files():
            places = ", ".join(str(root) for root in rule_roots()) or f"{RULES_ENV} (unset)"
            return f"no YARA rule file (*.yar, *.yara) under {places}"
        return None


PROGRAM = _YaraX(
    name="yr",
    command=("yr",),
    install=(
        f"install YARA-X {YARA_X_VERSION} (its command-line program yr) on this server's PATH "
        f"and put rule files (*.yar, *.yara) under the directories {RULES_ENV} names, or run "
        "the yarax-mcp image, which carries yr, with the rules directory mounted at /data/rules"
    ),
)
SCAN_TOOL = "yarax_scan"
TOOLS = (SCAN_TOOL,)

mcp = FastMCP("YaraXMCP", stateless_http=True)


def match_rows(document: Any) -> list[dict[str, Any]]:
    """The rules a ``yr scan --output-format json`` document says matched, in its order.

    Each row keeps the rule's name, metadata and tags and its matching
    strings (``identifier``, ``offset``, ``match`` as yr escaped it); the
    file's path, which is the call's own argument, is left out.
    """
    if not isinstance(document, dict):
        raise sidecar.ToolFailure(sidecar.TOOL_FAILED, "yr wrote no scan document")
    rows: list[dict[str, Any]] = []
    for match in document.get("matches") or ():
        if not isinstance(match, dict):
            continue
        rows.append(
            {
                "rule": str(match.get("rule") or ""),
                "meta": match.get("meta") or {},
                "tags": list(match.get("tags") or ()),
                "strings": [s for s in match.get("strings") or () if isinstance(s, dict)],
            }
        )
    return rows


def compile_errors(said: str) -> list[str]:
    """Each error yr's standard error names, with the rule file and line it points at."""
    errors: list[str] = []
    for line in said.splitlines():
        if line.startswith("error"):
            errors.append(line.strip())
        elif errors and line.strip().startswith("--> ") and not errors[-1].endswith(")"):
            errors[-1] += f" ({line.strip()[4:]})"
    return errors


@mcp.tool()
async def yarax_scan(
    path: str,
    ignore_invalid_rules: bool = True,
    string_chars: int = STRING_CHARS,
) -> dict[str, Any]:
    """Match the operator's YARA rule files against a file, with YARA-X.

    Every ``*.yar`` and ``*.yara`` file under the server's rule directories is
    compiled and matched against the file. Each row of ``matches`` is one rule
    that matched: ``rule``, its ``meta`` and ``tags``, and ``strings``, each
    matching string's ``identifier``, ``offset`` and the bytes it matched
    (``match``, escaped as yr prints them, at most ``string_chars``
    characters each). ``ignore_invalid_rules`` skips a rule YARA-X cannot
    compile and lists it in ``rules_not_compiled``; off, one such rule fails
    the call.
    """

    async def work() -> dict[str, Any]:
        sample = sidecar.sample_file(path)
        if not isinstance(string_chars, int) or isinstance(string_chars, bool):
            raise sidecar.ToolFailure(sidecar.BAD_ARGUMENT, "string_chars is not a whole number")
        if string_chars < 1:
            raise sidecar.ToolFailure(sidecar.BAD_ARGUMENT, "string_chars must be at least 1")
        files = rule_files()
        arguments = [
            "scan",
            "--output-format=json",
            f"--print-strings={string_chars}",
            "--print-meta",
            "--print-tags",
            # One file is scanned: one thread, which a container's pids
            # limit always has room for.
            "--threads=1",
            "--disable-console-logs",
            "--disable-warnings",
        ]
        if ignore_invalid_rules:
            arguments.append("--ignore-invalid-rules")
        roots = [str(root) for root in rule_roots()]
        # ``--`` ends the options: a rule directory or sample path that
        # starts with '-' is a path, never a flag.
        ran = await sidecar.run_ok(PROGRAM, [*arguments, "--", *roots, sample])
        document = sidecar.json_document(ran.stdout.decode("utf-8", "replace"), PROGRAM.name)
        rows = match_rows(document)
        return {
            "tool": SCAN_TOOL,
            "engine": "yara-x",
            "engine_version": str(document.get("version") or YARA_X_VERSION),
            "rule_files": len(files),
            "rules_not_compiled": compile_errors(ran.stderr.decode("utf-8", "replace")),
            "matches": rows,
            "match_count": len(rows),
        }

    return await sidecar.answering(SCAN_TOOL, work)


@mcp.tool()
def capabilities() -> dict[str, Any]:
    """Which of this server's tools this host can run, and how to install what is missing."""
    return sidecar.capabilities(SERVER, PROGRAM, TOOLS, version=YARA_X_VERSION)


if __name__ == "__main__":
    sidecar.serve(mcp)
