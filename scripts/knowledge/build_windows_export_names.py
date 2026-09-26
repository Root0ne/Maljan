#!/usr/bin/env python3
"""Build the vendored Windows export-name lists from the Wine project's DLL spec files.

Offline, operator-run, never imported by the pipeline and never run by a test.
It writes ``data/windows_export_names_v1.json``, the name lists the analysis
server's ``resolve_api_hashes`` tool hashes (``maljan.tools.api_hashes``).

Why Wine's spec files. A hash resolver needs the names a Windows DLL exports,
and the DLLs themselves are Microsoft's binaries: they cannot be shipped in this
repository and differ between Windows builds. The Wine project reimplements the
same DLLs under the LGPL, and each of its DLLs declares its export table in a
plain-text ``<dll>.spec`` file, one export per line, written to match the
Windows DLL of the same name. Those files are public, versioned by release tag
and readable without building anything, so the lists are reproducible: run
this script against the same tag and the same file comes out.

What is kept: every export that has a name, in the order the spec declares it,
once per DLL. An ordinal-only export (``-noname``) has no name to hash and is
left out; a name declared for one architecture only (``-arch=win64``) is kept,
because the resolver does not know which build of the DLL a sample walks. What
the spec calls the implementation (a forward such as ``ntdll.RtlAllocateHeap``)
is not the exported name and is ignored.

The output records the tag, the URL each spec was read from and its sha256, so
a reader can check the lists against their source.

Usage::

    uv run python scripts/knowledge/build_windows_export_names.py
    uv run python scripts/knowledge/build_windows_export_names.py --tag wine-9.0
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "data" / "windows_export_names_v1.json"

# The release the vendored file was generated from.
DEFAULT_TAG = "wine-9.0"
SPEC_URL = "https://gitlab.winehq.org/wine/wine/-/raw/{tag}/dlls/{dll}/{dll}.spec"

# The DLLs whose exports a Windows program most often resolves at run time:
# the core system libraries, the networking and HTTP libraries, the shell and
# registry libraries, the cryptography libraries and the C runtime.
DLLS: tuple[str, ...] = (
    "kernel32",
    "kernelbase",
    "ntdll",
    "user32",
    "gdi32",
    "advapi32",
    "shell32",
    "shlwapi",
    "ole32",
    "oleaut32",
    "wininet",
    "winhttp",
    "ws2_32",
    "iphlpapi",
    "urlmon",
    "crypt32",
    "bcrypt",
    "psapi",
    "secur32",
    "netapi32",
    "dnsapi",
    "mpr",
    "version",
    "userenv",
    "wtsapi32",
    "rpcrt4",
    "msvcrt",
)

# The words a spec line may carry between its ordinal and the exported name.
_CONVENTIONS = frozenset(
    {"stdcall", "cdecl", "varargs", "thiscall", "fastcall", "pascal", "stub", "extern", "equate"}
)
_NAME = re.compile(r"^[A-Za-z_?@$][A-Za-z0-9_?@$.]*")


# What the file holds, said beside where it came from.
LICENSE = (
    "names extracted from LGPL-2.1-or-later spec files; the file holds only the exported "
    "names, which the Windows ABI fixes, and no code or comment of the spec files"
)

# The module names a resolver that walks the loaded-module list hashes: the
# file name of each DLL above as the loader records it, with and without its
# extension, in lower and in upper case.
MODULES_SOURCE = (
    "the file names of the DLLs whose exports are listed above, each with and without its "
    ".dll extension, in lower and in upper case"
)


def module_names(dlls: list[str]) -> list[str]:
    """Every spelling of each DLL's file name the module set carries, once each."""
    names: list[str] = []
    for dll in dlls:
        stem = dll[: -len(".dll")] if dll.lower().endswith(".dll") else dll
        for name in (dll.lower(), stem.lower(), dll.upper(), stem.upper()):
            if name not in names:
                names.append(name)
    return names


def exported_names(spec: str) -> list[str]:
    """The named exports one spec file declares, once each, in declaration order."""
    names: list[str] = []
    seen: set[str] = set()
    for raw in spec.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = line.split()
        if len(tokens) < 3 or tokens[1] not in _CONVENTIONS:
            continue
        flags = []
        index = 2
        while index < len(tokens) and tokens[index].startswith("-"):
            flags.append(tokens[index])
            index += 1
        if index >= len(tokens) or "-noname" in flags:
            continue
        match = _NAME.match(tokens[index])
        if not match:
            continue
        name = match.group(0)
        if name not in seen:
            seen.add(name)
            names.append(name)
    return names


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tag", default=DEFAULT_TAG)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)

    dlls: dict[str, list[str]] = {}
    sources: dict[str, dict[str, str]] = {}
    for dll in DLLS:
        url = SPEC_URL.format(tag=args.tag, dll=dll)
        # The URL is the module's constant with a tag and a module name filled in; any scheme
        # other than https is refused so urllib is never pointed at a local file.
        if urlparse(url).scheme != "https":
            raise SystemExit(f"refusing a non-https spec URL: {url!r}")
        # nosemgrep: dynamic-urllib-use-detected — scheme validated; constant https URL
        with urllib.request.urlopen(url, timeout=60) as response:  # noqa: S310
            body = response.read()
        dlls[f"{dll}.dll"] = exported_names(body.decode("utf-8", errors="replace"))
        sources[f"{dll}.dll"] = {"url": url, "sha256": hashlib.sha256(body).hexdigest()}
        print(f"{dll}: {len(dlls[f'{dll}.dll'])} names", file=sys.stderr)

    document = {
        "version": 1,
        "source": (
            "Named exports declared in the Wine project's DLL spec files (dlls/<dll>/<dll>.spec) "
            f"at release tag {args.tag}, generated by scripts/knowledge/"
            "build_windows_export_names.py; no DLL binary was read"
        ),
        "license": LICENSE,
        "tag": args.tag,
        "sources": sources,
        "dlls": dlls,
        "modules": {"source": MODULES_SOURCE, "names": module_names(list(dlls))},
    }
    args.output.write_text(json.dumps(document, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
