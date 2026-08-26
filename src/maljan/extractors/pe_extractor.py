"""Extract the StaticAnalysis section of the report from binary bytes.

Despite the name, this module handles **PE, ELF and unknown binaries** —
the entry point is ``build_static_analysis()`` which dispatches to the right
parser based on the file's magic bytes. PE samples get the richest output
(sections, imports, exports, embedded resources); other formats currently
fall back to a strings + magic header extraction so the report still
surfaces some signal.

Suspicious flagging is rule-based (no LLM) — see ``_SUSPICIOUS_IMPORTS`` and
``_HIGH_ENTROPY_THRESHOLD``. The flags are advisory; the narrative agent
later expands on them, and the heatmap aggregates them into capability
cells.

Reuses ``maljan.loaders.pe_loader.PELoader`` for low-level parsing —
extending rather than rewriting.
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from maljan.core.logger import logger
from maljan.reporting.models import (
    ImportRow,
    PESection,
    StaticAnalysis,
    StringIOC,
)

# ---------------------------------------------------------------------------
# Heuristics — suspicious-import classifier
# ---------------------------------------------------------------------------

_HIGH_ENTROPY_THRESHOLD = 7.0
# Below this many named imports, a LoadLibrary/GetProcAddress pair reads as
# dynamic-API-resolution / API-hiding rather than ordinary delay-loading.
_SPARSE_IMPORT_THRESHOLD = 15
_MIN_STRING_LENGTH = 6
# How many printable runs the scan will look at before giving up. A runaway
# guard, not an output budget — see ``_iter_strings``. Real PEs routinely carry
# tens of thousands of runs and the interesting ones are rarely at the front.
_MAX_STRINGS_SCANNED = 200_000
_MAX_IOC_STRINGS = 120

# Memo for ``build_static_analysis`` — see its docstring for why the key is a
# (path, mtime, size) triple rather than the path alone.
_MEMO_LOCK = threading.Lock()
_MEMO: dict[tuple[str, int, int], StaticAnalysis | None] = {}
_MEMO_MAX_ENTRIES = 4

# DLL→function classifier — extend rather than replace.
_SUSPICIOUS_IMPORTS: dict[str, str] = {
    # Process injection
    "VirtualAlloc": "process_injection",
    "VirtualAllocEx": "process_injection",
    "WriteProcessMemory": "process_injection",
    "CreateRemoteThread": "process_injection",
    "NtCreateThreadEx": "process_injection",
    "RtlCreateUserThread": "process_injection",
    "QueueUserAPC": "process_injection",
    "SetWindowsHookEx": "process_injection",
    # Anti-analysis / anti-debug
    "IsDebuggerPresent": "anti_debug",
    "CheckRemoteDebuggerPresent": "anti_debug",
    "NtQueryInformationProcess": "anti_debug",
    "GetTickCount": "anti_debug",
    "QueryPerformanceCounter": "anti_debug",
    "OutputDebugStringA": "anti_debug",
    # Network / C2
    "WSAStartup": "network",
    "WSASocketA": "network",
    "connect": "network",
    "InternetOpenA": "network",
    "InternetOpenUrlA": "network",
    "HttpSendRequestA": "network",
    "URLDownloadToFileA": "network",
    "WinHttpConnect": "network",
    "WinHttpOpen": "network",
    "WinHttpSendRequest": "network",
    "send": "network",
    "recv": "network",
    # Crypto
    "CryptAcquireContextA": "crypto",
    "CryptEncrypt": "crypto",
    "CryptDecrypt": "crypto",
    "BCryptEncrypt": "crypto",
    "BCryptDecrypt": "crypto",
    "CryptGenKey": "crypto",
    # File & persistence
    "CreateFileA": "filesystem",
    "WriteFile": "filesystem",
    "DeleteFileA": "filesystem",
    "MoveFileExA": "filesystem",
    "CopyFileA": "filesystem",
    "SetFileAttributesA": "filesystem",
    "RegCreateKeyExA": "registry",
    "RegSetValueExA": "registry",
    "RegOpenKeyExA": "registry",
    # Privilege / token
    "AdjustTokenPrivileges": "privilege",
    "OpenProcessToken": "privilege",
    "LookupPrivilegeValueA": "privilege",
    "ImpersonateLoggedOnUser": "privilege",
    "CreateProcessAsUserA": "privilege",
    # Execution
    "WinExec": "execution",
    "ShellExecuteA": "execution",
    "CreateProcessA": "execution",
    "LoadLibraryA": "execution",
    "GetProcAddress": "execution",
}


def classify_import(function: str) -> tuple[str | None, bool]:
    """Return ``(behaviour_category, is_suspicious)`` for one imported symbol.

    ``category`` and ``is_suspicious`` used to be the same fact —
    ``is_suspicious=bool(category)`` — which was correct while the table held
    51 hand-picked names that a human had already decided were interesting.

    They are separated here because the table is about to get an order of
    magnitude larger. Categorising ``RegOpenKeyExA`` is useful (it tells the
    prompt and the ATT&CK mapper what the binary touches); calling it
    *suspicious* is not, and if every import in a benign PE is flagged then
    four consumers quietly stop working: the report's "Suspicious Imports"
    table becomes the whole import table, the suspicious-first sort that
    decides which rows survive the prompt's row cap becomes a no-op, the
    family-RAG profile text saturates, and the import-capability layer's
    ``is_suspicious`` gate stops filtering anything.

    So a category is assigned to everything recognised, while suspicion is
    reserved for the ``high``/``medium`` tiers. The hardcoded table below is
    the fallback used when no data asset is present; every one of its entries
    is suspicious by construction, which is the invariant the tests pin.
    """
    legacy = _SUSPICIOUS_IMPORTS.get(function)
    db = _behaviour_db()
    if db is not None:
        category, suspicious = db.classify(function)
        if category is not None:
            # Suspicion is the *union* of the two sources, not the catalog's
            # verdict alone. The catalog tiers whole categories, and
            # ``filesystem``/``registry`` are informational because every
            # Windows program reads files and opens keys — but six specific
            # filesystem calls and three registry calls were hand-picked into
            # the legacy table by someone who decided they mattered, and the
            # vendored family fingerprints were built against that decision.
            # Demoting them here would change the family-RAG profile text
            # without changing the catalog it is matched against: a silent
            # retrieval regression with no exception to notice it by.
            #
            # The result is admittedly uneven — CreateFileA is flagged and
            # ReadFile is not — but that unevenness is inherited, not
            # introduced, and preserving it costs nothing.
            return category, suspicious or bool(legacy)
        # Fall through: an API the catalog has not heard of may still be in the
        # curated table, and losing a known-bad name to a catalog gap would be a
        # silent regression.
    return legacy, bool(legacy)


def _behaviour_db() -> Any:
    """Return the loaded behaviour catalog, or ``None`` to use the built-in table.

    Config is read per call rather than captured at import: the settings object
    is memoised anyway, and reading it lazily keeps this module importable
    without a configured environment — which several tests and the offline
    scripts rely on.
    """
    try:
        from maljan.analysis.api_capability_db import load_api_behaviour_db
        from maljan.core.config import get_settings
        from maljan.core.paths import resolve_data

        cfg = get_settings().preprocessing
        if not getattr(cfg, "use_api_behaviour_map", False):
            return None
        return load_api_behaviour_db(str(resolve_data(cfg.api_behaviour_map_path)))
    except Exception as exc:  # noqa: BLE001 — classification must never break a parse
        logger.debug("pe_extractor: behaviour catalog unavailable (%s)", exc)
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_static_analysis(
    *,
    sample_path: str | None,
) -> StaticAnalysis | None:
    """Return ``StaticAnalysis`` for ``sample_path`` or ``None`` if unreadable.

    Memoized. One analysis calls this **nine** times — three inside the judge
    node alone (import-capability Layer 0, the family-feature RAG hint and the
    ATT&CK-case RAG hint), plus the analyst node, the report builder and three
    sites in the static analyst. Each call used to re-read the file from disk
    and re-run ``pefile`` from scratch, which was merely wasteful when this
    module only classified 51 imports and became a real latency cliff once
    carving and per-string IOC classification were added on top.

    The key is ``(resolved_path, st_mtime_ns, st_size)`` rather than the path
    alone, for two reasons: the Ghidra container mirror means one logical
    sample is visible at two different paths, and a stale entry for a path
    whose contents changed would be worse than no cache at all.
    """
    if not sample_path:
        return None
    path = Path(sample_path)
    if not (path.exists() and path.is_file()):
        logger.warning("pe_extractor: %s does not exist", sample_path)
        return None
    try:
        stat = path.stat()
        key = (str(path.resolve()), stat.st_mtime_ns, stat.st_size)
    except OSError as exc:
        logger.warning("pe_extractor: stat failed (%s)", exc)
        return None

    with _MEMO_LOCK:
        if key in _MEMO:
            return _MEMO[key]

    result = _build_static_analysis_uncached(path)

    with _MEMO_LOCK:
        # Bounded to a handful of entries: an analysis only ever works on one
        # sample, and the extra slots exist for the container-mirror path and
        # for carved children, not for a long history.
        if len(_MEMO) >= _MEMO_MAX_ENTRIES:
            _MEMO.clear()
        _MEMO[key] = result
    return result


def reset_static_analysis_cache() -> None:
    """Clear the memo (test hook; also called on worker recycle)."""
    with _MEMO_LOCK:
        _MEMO.clear()


def _build_static_analysis_uncached(path: Path) -> StaticAnalysis | None:
    try:
        blob = path.read_bytes()
    except OSError as exc:
        logger.warning("pe_extractor: read failed (%s)", exc)
        return None

    parsed = _PEParse()

    if blob[:2] == b"MZ":
        parsed = _parse_pe(blob)
        parsed.embedded = parsed.embedded + _carve_embedded(blob, parsed.sections)
    elif blob[:4] == b"\x7fELF":
        parsed.sections = _parse_elf_sections(blob)
        parsed.imports = _parse_elf_imports(blob)
        parsed.exports = _parse_elf_exports(blob)

    sections = parsed.sections
    imports = parsed.imports
    exports = parsed.exports
    embedded = parsed.embedded
    packer_hint = parsed.packer_hint
    obfuscation = parsed.obfuscation

    strings = _extract_string_iocs(blob)

    if not packer_hint and any(s.entropy >= _HIGH_ENTROPY_THRESHOLD for s in sections):
        packer_hint = "high-entropy sections (possibly packed/encrypted)"

    capabilities = Counter(imp.category for imp in imports if imp.category)

    return StaticAnalysis(
        sections=sections,
        imports=imports,
        exports=exports,
        interesting_strings=strings,
        embedded_resources=embedded,
        packer_hint=packer_hint,
        obfuscation_indicators=obfuscation,
        api_capabilities=dict(capabilities),
        packer_matches=parsed.packer_matches,
        pdb_path=parsed.pdb_path,
    )


# ---------------------------------------------------------------------------
# PE parsing
# ---------------------------------------------------------------------------


@dataclass
class _PEParse:
    """What one PE parse yields.

    Was a six-tuple, which was already at the limit of what a positional return
    can carry legibly; the packer catalog needed a seventh element and that is
    where a tuple stops being readable at the call site. One unpack point, so
    the conversion is contained.
    """

    sections: list[PESection] = field(default_factory=list)
    imports: list[ImportRow] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    embedded: list[dict[str, Any]] = field(default_factory=list)
    packer_hint: str | None = None
    obfuscation: list[str] = field(default_factory=list)
    packer_matches: list[dict[str, Any]] = field(default_factory=list)
    pdb_path: str | None = None


def _parse_pe(blob: bytes) -> _PEParse:
    """Parse a PE into the report's static section. Never raises."""
    try:
        import pefile  # type: ignore[import-not-found]
    except ImportError:
        logger.warning("pe_extractor: pefile unavailable, skipping PE parse")
        return _PEParse()

    try:
        pe = pefile.PE(data=blob, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                # DEBUG carries the PDB path — see _pe_pdb_path.
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
            ]
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("pe_extractor: PE parse failed (%s)", exc)
        return _PEParse()

    sections = _pe_sections(pe)
    imports = _pe_imports(pe)
    packer_matches = _pe_packer_matches(pe, sections, blob)
    # Prefer the catalog's top hit for the display string, but keep the built-in
    # check as the fallback so removing the data file degrades to the previous
    # behaviour rather than to nothing.
    packer_hint = (
        f"{packer_matches[0]['name']} ({packer_matches[0]['kind']})"
        if packer_matches
        else _pe_packer_hint(pe, sections)
    )
    return _PEParse(
        sections=sections,
        imports=imports,
        exports=_pe_exports(pe),
        embedded=_pe_resources(pe),
        packer_hint=packer_hint,
        obfuscation=_pe_obfuscation_indicators(sections, imports),
        packer_matches=packer_matches,
        pdb_path=_pe_pdb_path(pe),
    )


def _pe_sections(pe: Any) -> list[PESection]:
    out: list[PESection] = []
    for sect in getattr(pe, "sections", []):
        raw_name = sect.Name or b""
        try:
            name = raw_name.decode("utf-8", errors="replace").strip("\x00 ")
        except Exception:  # noqa: BLE001
            name = repr(raw_name)
        entropy = float(sect.get_entropy() or 0.0)
        char = int(getattr(sect, "Characteristics", 0))
        is_writable = bool(char & 0x80000000)
        is_executable = bool(char & 0x20000000)
        rwx = is_writable and is_executable
        out.append(
            PESection(
                name=name or "(unnamed)",
                virtual_address=f"0x{int(sect.VirtualAddress):08x}",
                virtual_size=int(sect.Misc_VirtualSize or 0),
                raw_size=int(sect.SizeOfRawData or 0),
                raw_offset=int(getattr(sect, "PointerToRawData", 0) or 0),
                entropy=round(entropy, 3),
                characteristics=_format_characteristics(char),
                is_suspicious=(entropy >= _HIGH_ENTROPY_THRESHOLD or rwx),
            )
        )
    return out


def _format_characteristics(char: int) -> str:
    flags: list[str] = []
    if char & 0x20000000:
        flags.append("EXECUTE")
    if char & 0x40000000:
        flags.append("READ")
    if char & 0x80000000:
        flags.append("WRITE")
    if char & 0x00000020:
        flags.append("CODE")
    if char & 0x00000040:
        flags.append("INITIALIZED_DATA")
    if char & 0x00000080:
        flags.append("UNINITIALIZED_DATA")
    return "|".join(flags) or f"0x{char:08x}"


def _pe_imports(pe: Any) -> list[ImportRow]:
    rows: list[ImportRow] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        try:
            dll = (entry.dll or b"").decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            dll = "(unknown)"
        for imp in entry.imports or []:
            fn = (imp.name or b"").decode("utf-8", errors="replace") if imp.name else None
            if not fn:
                fn = f"Ordinal_{getattr(imp, 'ordinal', '?')}"
            category, suspicious = classify_import(fn)
            rows.append(
                ImportRow(
                    dll=dll,
                    function=fn,
                    is_suspicious=suspicious,
                    category=category,
                )
            )
    return rows


def _pe_exports(pe: Any) -> list[str]:
    out: list[str] = []
    export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_dir is None:
        return out
    for sym in getattr(export_dir, "symbols", []) or []:
        if sym.name:
            try:
                out.append(sym.name.decode("utf-8", errors="replace"))
            except Exception:  # noqa: BLE001
                continue
    return out


# Standard Win32 resource-type IDs (RT_*). 2026-07 audit (Bulgu #16): the
# report showed raw "TYPE_3 / TYPE_5" which carry no meaning; map the well-known
# ids to their symbolic names so the STATIC tab reads "RT_ICON (…)" etc.
_RT_NAMES: dict[int, str] = {
    1: "RT_CURSOR",
    2: "RT_BITMAP",
    3: "RT_ICON",
    4: "RT_MENU",
    5: "RT_DIALOG",
    6: "RT_STRING",
    7: "RT_FONTDIR",
    8: "RT_FONT",
    9: "RT_ACCELERATOR",
    10: "RT_RCDATA",
    11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    17: "RT_DLGINCLUDE",
    19: "RT_PLUGPLAY",
    20: "RT_VXD",
    21: "RT_ANICURSOR",
    22: "RT_ANIICON",
    23: "RT_HTML",
    24: "RT_MANIFEST",
}


def _resource_type_name(resource_type: Any) -> str:
    """Human-readable resource type: custom string name, RT_* symbol, or id."""
    name_obj = getattr(resource_type, "name", None)
    if name_obj and getattr(name_obj, "string", None):
        return str(name_obj.string.decode("utf-8", errors="replace"))
    rid = getattr(resource_type, "id", None)
    if isinstance(rid, int) and rid in _RT_NAMES:
        return _RT_NAMES[rid]
    return f"TYPE_{rid if rid is not None else '?'}"


def _pe_resources(pe: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    rsrc_dir = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if rsrc_dir is None:
        return out
    for resource_type in getattr(rsrc_dir, "entries", []) or []:
        type_name = _resource_type_name(resource_type)
        directory = getattr(resource_type, "directory", None)
        for resource_id in getattr(directory, "entries", []) or []:
            entry_id = (
                resource_id.name.string.decode("utf-8", errors="replace")
                if getattr(resource_id, "name", None) and resource_id.name
                else getattr(resource_id, "id", None)
            )
            sub_dir = getattr(resource_id, "directory", None)
            for lang in getattr(sub_dir, "entries", []) or []:
                data = getattr(lang, "data", None)
                if data is not None:
                    out.append(
                        {
                            "type": type_name,
                            "id": entry_id,
                            "size": int(getattr(data.struct, "Size", 0) or 0),
                        }
                    )
    return out


def _pe_pdb_path(pe: Any) -> str | None:
    """The debug PDB path the linker left in the binary.

    One of the highest-value single strings in a PE and Maljan was not reading
    it. A real example from the audited sample:

        E:\\xml-data\\build-dir\\CODRU-CL23M-SOURCES\\bin\\Win32\\Release\\BdUserHost.pdb

    That is the build machine's drive layout, the internal project name, the
    target architecture and the build configuration — from one field. Malware
    authors leave it in constantly, and the internal name is frequently the
    family's own name before anyone in the industry chose one for it.

    Read from the CodeView (RSDS/NB10) debug entry. Absent in stripped or
    release-hardened binaries, which is itself mildly informative.
    """
    for entry in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
        data = getattr(entry, "entry", None)
        raw = getattr(data, "PdbFileName", None)
        if not raw:
            continue
        try:
            decoded = bytes(raw).decode("utf-8", errors="replace").strip("\x00").strip()
        except Exception:  # noqa: BLE001
            continue
        if decoded:
            return decoded
    return None


def _packer_signatures() -> list[dict[str, Any]]:
    """Load the packer catalog, or ``[]`` to fall back to the built-in checks."""
    try:
        import json as _json

        from maljan.core.config import get_settings
        from maljan.core.paths import resolve_data

        cfg = get_settings().preprocessing
        if not getattr(cfg, "use_packer_signatures", False):
            return []
        path = resolve_data(cfg.packer_signatures_path)
        if not path.is_file():
            return []
        doc = _json.loads(path.read_text(encoding="utf-8"))
        rows = doc.get("packers") if isinstance(doc, dict) else None
        return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
    except Exception as exc:  # noqa: BLE001 — a missing catalog costs depth, not the parse
        logger.debug("pe_extractor: packer catalog unavailable (%s)", exc)
        return []


def _pe_packer_matches(pe: Any, sections: list[PESection], blob: bytes) -> list[dict[str, Any]]:
    """Identify packers/protectors, ranked by how much the evidence is worth.

    Four methods, deliberately not weighted equally:

    * **Section name** — strongest. ``UPX0`` in a section header is not an
      accident.
    * **Entry-point section** — strong. Execution starting anywhere but the
      first code section is what an unpacking stub looks like.
    * **String** — weakest, and the reason ranking matters at all. ``UPX!``
      appears in every scanner's signature table, including Maljan's own data
      files; a string-only match must never reach the confidence of a
      structural one.

    Returns rows sorted most-confident first, so ``packer_hint`` can be derived
    from ``[0]`` without re-deciding anything.
    """
    signatures = _packer_signatures()
    if not signatures:
        return []

    section_names = {s.name.lower() for s in sections}
    ep_section = ""
    try:
        ep = int(getattr(getattr(pe, "OPTIONAL_HEADER", None), "AddressOfEntryPoint", 0) or 0)
        for sect in getattr(pe, "sections", []) or []:
            start = int(getattr(sect, "VirtualAddress", 0) or 0)
            size = int(getattr(sect, "Misc_VirtualSize", 0) or 0)
            if start <= ep < start + max(size, 1):
                ep_section = (sect.Name or b"").decode("utf-8", errors="replace").strip("\x00 ")
                break
    except Exception:  # noqa: BLE001
        ep_section = ""

    head = blob[: 2 * 1024 * 1024]
    out: list[dict[str, Any]] = []
    for row in signatures:
        name = str(row.get("name") or "")
        if not name:
            continue
        sect_hits = [
            s
            for s in (row.get("sections") or [])
            if isinstance(s, str) and s.lower() in section_names
        ]
        ep_hits = [
            s
            for s in (row.get("ep_sections") or [])
            if isinstance(s, str) and ep_section and s.lower() == ep_section.lower()
        ]
        str_hits = [
            s
            for s in (row.get("strings") or [])
            if isinstance(s, str) and s.encode("utf-8", errors="ignore") in head
        ]
        if not (sect_hits or ep_hits or str_hits):
            continue

        confidence = min(
            0.95,
            0.25 * len(sect_hits) + 0.20 * len(ep_hits) + 0.10 * len(str_hits),
        )
        # A lone string is a hint, not an identification.
        if sect_hits or ep_hits:
            confidence = max(confidence, 0.60)
        else:
            confidence = min(confidence, 0.45)

        methods = []
        if sect_hits:
            methods.append("section")
        if ep_hits:
            methods.append("entry_point")
        if str_hits:
            methods.append("string")
        out.append(
            {
                "name": name,
                "kind": str(row.get("kind") or "packer"),
                "confidence": round(confidence, 3),
                "method": "+".join(methods),
                "evidence": (sect_hits + ep_hits + str_hits)[:5],
            }
        )

    out.sort(key=lambda r: float(r["confidence"]), reverse=True)
    return out


def _pe_packer_hint(pe: Any, sections: list[PESection]) -> str | None:
    """Built-in fallback used when no packer catalog is loaded."""
    for sect in sections:
        if sect.name.lower().startswith("upx"):
            return "UPX"
    section_names = {s.name.lower() for s in sections}
    if section_names & {".aspack", ".adata"}:
        return "ASPack"
    if section_names & {".themida", ".winlice"}:
        return "Themida"
    if section_names & {".vmp0", ".vmp1", ".vmp2"}:
        return "VMProtect"
    return None


def _pe_obfuscation_indicators(sections: list[PESection], imports: list[ImportRow]) -> list[str]:
    out: list[str] = []
    rwx = [
        s.name for s in sections if "WRITE" in s.characteristics and "EXECUTE" in s.characteristics
    ]
    if rwx:
        out.append(f"RWX sections present: {', '.join(rwx)}")
    high_entropy = [s.name for s in sections if s.entropy >= _HIGH_ENTROPY_THRESHOLD]
    if high_entropy:
        out.append(
            f"High-entropy sections (>= {_HIGH_ENTROPY_THRESHOLD}): {', '.join(high_entropy)}"
        )
    # LoadLibrary + GetProcAddress alone is NOT obfuscation — it is the standard
    # Windows idiom for optional / delay-loaded DLLs and is present in nearly
    # every non-trivial PE (2026-07: an ordinary 164-import MFC app was flagged,
    # which the LLM then inflated to T1027 "obfuscation" at conf 0.90). The
    # genuine dynamic-API-resolution / packing signature is this idiom combined
    # with a SPARSE import table — a packed binary hides its real APIs and
    # imports only a handful of functions plus LoadLibrary/GetProcAddress.
    api_resolution = {row.function for row in imports} & {
        "GetProcAddress",
        "LoadLibraryA",
        "LoadLibraryW",
    }
    if len(api_resolution) >= 2 and len(imports) < _SPARSE_IMPORT_THRESHOLD:
        out.append(
            "Dynamic API resolution with a sparse import table "
            f"({len(imports)} named imports + LoadLibrary/GetProcAddress) "
            "— possible API hiding / packing"
        )
    return out


# ---------------------------------------------------------------------------
# Minimal ELF section parser
# ---------------------------------------------------------------------------


def _parse_elf_sections(blob: bytes) -> list[PESection]:
    """Compute entropy per ELF section. Falls back to whole-binary stats."""
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore[import-not-found]
    except ImportError:
        # pyelftools is not a hard dep; report a single synthetic section so
        # the UI still shows something instead of an empty table.
        return [
            PESection(
                name="(binary)",
                virtual_address="0x0",
                virtual_size=len(blob),
                raw_size=len(blob),
                entropy=round(_shannon_entropy(blob), 3),
                characteristics="ELF",
                is_suspicious=False,
            )
        ]

    out: list[PESection] = []
    try:
        from io import BytesIO

        elf = ELFFile(BytesIO(blob))
        for section in elf.iter_sections():
            data = section.data() if section.data_size else b""
            entropy = _shannon_entropy(data) if data else 0.0
            flags = []
            sh_flags = int(getattr(section.header, "sh_flags", 0))
            if sh_flags & 0x4:
                flags.append("EXECUTE")
            if sh_flags & 0x1:
                flags.append("WRITE")
            if sh_flags & 0x2:
                flags.append("ALLOC")
            out.append(
                PESection(
                    name=section.name or "(unnamed)",
                    virtual_address=f"0x{int(section.header.sh_addr):08x}",
                    virtual_size=int(section.header.sh_size or 0),
                    raw_size=int(section.header.sh_size or 0),
                    entropy=round(entropy, 3),
                    characteristics="|".join(flags) or f"0x{sh_flags:08x}",
                    is_suspicious=(entropy >= _HIGH_ENTROPY_THRESHOLD),
                )
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("pe_extractor: ELF parse failed (%s)", exc)
    return out


# ELF API surface that's most useful to call out for malware triage:
# native execution, anti-debug, code injection, persistence, network.
_ELF_SUSPICIOUS_FUNCTIONS: frozenset[str] = frozenset(
    {
        "execve",
        "execv",
        "execvp",
        "execvpe",
        "execl",
        "execle",
        "execlp",
        "fork",
        "vfork",
        "clone",
        "system",
        "popen",
        "ptrace",
        "syscall",
        "mmap",
        "mmap64",
        "mprotect",
        "memfd_create",
        "dlopen",
        "dlsym",
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "recv",
        "send",
        "recvfrom",
        "sendto",
        "inet_pton",
        "inet_ntop",
        "getaddrinfo",
        "gethostbyname",
        "setuid",
        "setgid",
        "seteuid",
        "setegid",
        "chroot",
        "unshare",
    }
)


def _parse_elf_imports(blob: bytes) -> list[ImportRow]:
    """Return DT_NEEDED libraries paired with undefined .dynsym symbols.

    Each ``(library, function)`` pair becomes one :class:`ImportRow`. The
    library column lists every DT_NEEDED entry once for the first import
    and then ``""`` to keep tables compact. Set ``is_suspicious=True``
    when the function name matches :data:`_ELF_SUSPICIOUS_FUNCTIONS`.
    """
    try:
        from elftools.elf.dynamic import DynamicSection  # type: ignore[import-not-found]
        from elftools.elf.elffile import ELFFile  # type: ignore[import-not-found]
        from elftools.elf.sections import SymbolTableSection  # type: ignore[import-not-found]
    except ImportError:
        return []

    out: list[ImportRow] = []
    try:
        from io import BytesIO

        elf = ELFFile(BytesIO(blob))
        # DT_NEEDED libraries
        libraries: list[str] = []
        for section in elf.iter_sections():
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        libraries.append(tag.needed)

        # Imported (undefined) symbols
        dynsym = elf.get_section_by_name(".dynsym")
        if not isinstance(dynsym, SymbolTableSection):
            return []
        functions: list[str] = []
        for symbol in dynsym.iter_symbols():
            if not symbol.name:
                continue
            info = symbol.entry.st_info
            if info.type != "STT_FUNC" and info.type != "STT_NOTYPE":
                continue
            # Undefined section index → imported by the dynamic linker.
            if symbol.entry.st_shndx == "SHN_UNDEF":
                functions.append(symbol.name)

        # Combine: emit each function once with its library hint, or "" if
        # we cannot map it to a specific DT_NEEDED entry.
        lib_label = libraries[0] if libraries else ""
        for fn in functions:
            out.append(
                ImportRow(
                    dll=lib_label,
                    function=fn,
                    is_suspicious=fn in _ELF_SUSPICIOUS_FUNCTIONS,
                )
            )
            lib_label = ""  # compact: only the first row shows the lib
    except Exception as exc:  # noqa: BLE001
        logger.warning("pe_extractor: ELF imports parse failed (%s)", exc)
    return out


def _parse_elf_exports(blob: bytes) -> list[str]:
    """Return defined (exported) function symbol names from .dynsym."""
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore[import-not-found]
        from elftools.elf.sections import SymbolTableSection  # type: ignore[import-not-found]
    except ImportError:
        return []

    out: list[str] = []
    try:
        from io import BytesIO

        elf = ELFFile(BytesIO(blob))
        dynsym = elf.get_section_by_name(".dynsym")
        if not isinstance(dynsym, SymbolTableSection):
            return []
        for symbol in dynsym.iter_symbols():
            if not symbol.name:
                continue
            info = symbol.entry.st_info
            if info.type != "STT_FUNC":
                continue
            if symbol.entry.st_shndx != "SHN_UNDEF":
                out.append(symbol.name)
    except Exception as exc:  # noqa: BLE001
        logger.warning("pe_extractor: ELF exports parse failed (%s)", exc)
    return out


# ---------------------------------------------------------------------------
# Embedded-payload carving
# ---------------------------------------------------------------------------

# Magic bytes worth carving on. Kept small on purpose: every entry is a promise
# that finding these bytes at a non-zero offset means something, and a generous
# list produces confident-looking noise from ordinary compressed data.
_CARVE_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"MZ\x90\x00", "PE"),
    (b"\x7fELF", "ELF"),
    (b"PK\x03\x04", "ZIP"),
    (b"%PDF-", "PDF"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
)

_MAX_CARVED_CHILDREN = 8
_MAX_CARVE_BYTES = 32 * 1024 * 1024
_MAX_CARVE_INPUT = 128 * 1024 * 1024
# Below this a "carved payload" is a coincidence — four magic bytes and some
# padding, not a second stage.
_MIN_CARVE_BYTES = 1024


def _overlay_offset(sections: list[PESection]) -> int:
    """Where the last section's raw data ends — the start of any overlay.

    Appended data past the final section is the classic place a dropper keeps
    its payload: it is not covered by any section header, so it is invisible to
    section-based analysis, and it survives naive unpacking.
    """
    end = 0
    for sect in sections:
        try:
            raw_end = int(sect.raw_size or 0) + int(getattr(sect, "raw_offset", 0) or 0)
        except (TypeError, ValueError):
            continue
        end = max(end, raw_end)
    return end


def _carve_embedded(blob: bytes, sections: list[PESection]) -> list[dict[str, Any]]:
    """Report nested executables and archives hiding inside the sample.

    Maljan enumerated PE resources by type, id and size and never looked at the
    bytes, so a second-stage PE inside ``.rsrc`` — or appended past the last
    section — was invisible. It is still invisible to the *analysts*, which is
    a separate and larger problem, but at least the report now says it is there,
    and the judge's YARA layer gets to scan it (see ``nodes._read_sample_bytes``).

    Deliberately reports rather than recurses. A carved child would need its own
    ``sample_path``, its own Ghidra container mirror and its own memory upsert;
    ``AnalysisState`` carries exactly one of each, and faking a second run
    inside the first is how you get two analyses that each think they own the
    job row.
    """
    if len(blob) > _MAX_CARVE_INPUT:
        return []

    out: list[dict[str, Any]] = []
    seen_offsets: set[int] = set()
    overlay_start = _overlay_offset(sections)

    for magic, kind in _CARVE_SIGNATURES:
        start = 1  # never offset 0 — that is the sample itself
        while len(out) < _MAX_CARVED_CHILDREN:
            offset = blob.find(magic, start)
            if offset == -1:
                break
            start = offset + 1
            if offset in seen_offsets:
                continue
            payload = blob[offset : offset + _MAX_CARVE_BYTES]
            if len(payload) < _MIN_CARVE_BYTES:
                continue
            seen_offsets.add(offset)
            source = "overlay" if overlay_start and offset >= overlay_start else "body"
            out.append(
                {
                    "type": f"carved:{kind}",
                    "id": f"{source}+0x{offset:x}",
                    "size": len(payload),
                    "offset": offset,
                    "source": source,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "entropy": round(_shannon_entropy(payload[:65536]), 2),
                    "carved": True,
                }
            )
        if len(out) >= _MAX_CARVED_CHILDREN:
            break
    return out


def carve_payloads(blob: bytes) -> list[tuple[str, bytes]]:
    """Return ``[(label, bytes)]`` for each embedded payload found in ``blob``.

    The judge node scans these alongside the parent. Until it did, a packed
    dropper's real payload was invisible to every YARA rule in the corpus —
    the rules only ever saw the packed outer shell, which by construction
    matches nothing.
    """
    if not blob or len(blob) > _MAX_CARVE_INPUT:
        return []
    sections: list[PESection] = []
    if blob[:2] == b"MZ":
        try:
            sections = _parse_pe(blob).sections
        except Exception:  # noqa: BLE001 — carving must never break the judge
            sections = []
    out: list[tuple[str, bytes]] = []
    for row in _carve_embedded(blob, sections):
        offset = int(row["offset"])
        out.append((str(row["id"]), blob[offset : offset + _MAX_CARVE_BYTES]))
    return out


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# String / IOC extraction
# ---------------------------------------------------------------------------

_URL_RE = re.compile(rb"https?://[A-Za-z0-9._\-/?=&%:#~+]+")
_IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_REG_RE = re.compile(rb"HK(?:LM|CU|CR|U|CC)[\\\\][A-Za-z0-9_\-\\\\ ./]+")
# NB the single backslashes. This pattern used to read ``[A-Za-z]:\\\\`` and
# ``[...\\\\ ]``, which in a raw bytes literal is an escaped backslash *pair* —
# so it only ever matched paths written with doubled separators, i.e. paths that
# had already been JSON- or C-escaped. A plain ``C:\Users\victim\svchost.exe``,
# which is how a path actually appears in a binary, matched nothing. On a
# Windows-focused analyzer that meant filesystem IOCs were quietly missing from
# every report unless the sample happened to embed escaped text.
_PATH_RE = re.compile(rb"(?:[A-Za-z]:[\\/]|/)[A-Za-z0-9_\-./\\ ]+")
_EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_DOMAIN_RE = re.compile(
    rb"(?<![A-Za-z0-9.])(?:[A-Za-z0-9-]{1,63}\.){1,3}[A-Za-z]{2,24}(?![A-Za-z0-9.])"
)
_MUTEX_RE = re.compile(rb"\\BaseNamedObjects\\[A-Za-z0-9_\-]+")
_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_STRING_LENGTH)
# UTF-16LE runs. Windows binaries are full of wide strings — every ...W API call
# site, every resource string — and the ASCII scan above cannot see them,
# because the interleaved NULs break every run at the first character. Matching
# the pattern and dropping the NULs recovers a whole class of C2 hosts and file
# paths that were previously invisible.
_WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % _MIN_STRING_LENGTH)

# Credentials and wallets. These are the highest-value strings in a stealer and
# were not extracted at all.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("telegram_bot_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")),
    ("discord_webhook", re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+")),
    ("private_key_header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)
_WALLET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("bitcoin", re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")),
    ("ethereum", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("monero", re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")),
)
_ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b")

# Per-kind budgets, replacing a single global cap.
#
# The old code kept one 80-slot budget and filled it in extraction order — url,
# ip, registry, path, email, mutex, and domain *last*. A binary with a few dozen
# embedded file paths therefore exhausted the budget before a single domain was
# considered, and the C2 host — the thing an analyst actually wants — was
# dropped in favour of `C:\Windows\System32\...`. Quotas make the failure mode
# per-kind and survivable instead of global and silent.
_IOC_QUOTAS: dict[str, int] = {
    "url": 25,
    "domain": 25,
    "ip": 20,
    "secret": 15,
    "crypto_wallet": 10,
    "registry": 20,
    "mutex": 10,
    "email": 10,
    "path": 20,
}


def _iter_strings(blob: bytes) -> Iterator[str]:
    """Yield printable ASCII then UTF-16LE runs, in one pass each.

    This replaces seven independent full-blob regex passes. The old shape was
    workable at seven patterns; at the dozen below it would have meant scanning
    the whole binary a dozen times over, at every one of this module's call
    sites.

    A generator rather than a list, and bounded by ``_MAX_STRINGS_SCANNED``
    rather than by ``_MAX_STRINGS_KEPT``. Those two are not the same number and
    conflating them is a real bug: a mid-size PE holds tens of thousands of
    printable runs, so a scan that stops after the first couple of hundred sees
    only the beginning of the file. The C2 host is rarely in the first two
    hundred strings — the import thunks and the CRT banner are. The scan bound
    exists to stop a pathological input, not to shape the output; the per-kind
    quotas do that, and the caller stops early once they are all full.
    """
    scanned = 0
    for match in _PRINTABLE_RE.finditer(blob):
        yield match.group().decode("ascii", errors="ignore")
        scanned += 1
        if scanned >= _MAX_STRINGS_SCANNED:
            return
    for match in _WIDE_RE.finditer(blob):
        yield match.group()[::2].decode("ascii", errors="ignore")
        scanned += 1
        if scanned >= _MAX_STRINGS_SCANNED:
            return


def _extract_string_iocs(blob: bytes) -> list[StringIOC]:
    """Scan binary strings for typed indicators of compromise."""
    iocs: list[StringIOC] = []
    seen: set[tuple[str, str]] = set()
    per_kind: Counter[str] = Counter()

    def _add(kind: str, decoded: str, notes: str | None = None) -> None:
        decoded = decoded.strip("\x00").strip()
        if len(decoded) < _MIN_STRING_LENGTH:
            return
        key = (kind, decoded.lower())
        if key in seen:
            return
        if per_kind[kind] >= _IOC_QUOTAS.get(kind, 10):
            return
        seen.add(key)
        per_kind[kind] += 1
        iocs.append(StringIOC(value=decoded, kind=kind, notes=notes))  # type: ignore[arg-type]

    def _all_quotas_full() -> bool:
        return all(per_kind[kind] >= quota for kind, quota in _IOC_QUOTAS.items())

    for text in _iter_strings(blob):
        # Nothing left to learn — stop walking the binary.
        if _all_quotas_full():
            break
        for match in _URL_RE.findall(text.encode("ascii", errors="ignore")):
            _add("url", match.decode("ascii", errors="ignore"))
        for match in _IP_RE.findall(text.encode("ascii", errors="ignore")):
            ip = match.decode("ascii", errors="ignore")
            # 127.0.0.1 / 0.0.0.0 / RFC1918 filtered as noise
            if _is_meaningful_ip(ip):
                _add("ip", ip)
        for match in _REG_RE.findall(text.encode("ascii", errors="ignore")):
            _add("registry", match.decode("ascii", errors="ignore"))
        for match in _PATH_RE.findall(text.encode("ascii", errors="ignore")):
            candidate = match.decode("ascii", errors="ignore")
            if _looks_like_path(candidate):
                _add("path", candidate)
        for match in _EMAIL_RE.findall(text.encode("ascii", errors="ignore")):
            _add("email", match.decode("ascii", errors="ignore"))
        for match in _MUTEX_RE.findall(text.encode("ascii", errors="ignore")):
            _add("mutex", match.decode("ascii", errors="ignore"))
        for match in _DOMAIN_RE.findall(text.encode("ascii", errors="ignore")):
            candidate = match.decode("ascii", errors="ignore")
            if _looks_like_domain(candidate):
                _add("domain", candidate)
        for label, pattern in _SECRET_PATTERNS:
            for hit in pattern.findall(text):
                _add("secret", hit, notes=label)
        for label, pattern in _WALLET_PATTERNS:
            for hit in pattern.findall(text):
                _add("crypto_wallet", hit, notes=label)
        for hit in _ONION_RE.findall(text):
            _add("domain", hit, notes="tor_hidden_service")

    return iocs[:_MAX_IOC_STRINGS]


def _is_meaningful_ip(ip: str) -> bool:
    """Heuristic filter: only keep IPs that *look like* real public hosts.

    Audit 2026-05-17 (IOC-01) tightened this from the original RFC1918 +
    loopback filter — the IPv4 regex matched a flood of false positives
    on Go binaries (X.509 ASN.1 OIDs ``2.5.4.62``, the well-known
    ``1.1.1.1`` test constant, etc.). The full picture:

    * Reject any octet > 255 (already enforced).
    * Reject the canonical reserved blocks (loopback, broadcast,
      RFC1918, link-local, multicast, documentation, IETF reserved).
    * Reject ``1.x.x.x`` — Cloudflare's 1.1.1.1 / 1.0.0.1 are real, but
      every Go runtime + IETF doc string also pulls ``1.1.1.1`` /
      ``1.2.3.4`` out, so we drop the whole /8 rather than chase
      false-positives one at a time. Operators who *really* need to
      keep public 1.x.x.x can disable this filter at the caller.
    * Reject any IP whose first octet is in 0..5 — overlaps with X.509
      OID prefixes (``2.5.4.X``, ``5.4.X.X``) and reserved IETF blocks.
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False

    a, b, c, d = nums

    # X.509 OID overlap + IETF reserved ranges
    if a <= 5:
        return False
    # RFC1122 loopback
    if a == 127:
        return False
    # RFC1918 private
    if a == 10:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    # RFC3927 link-local
    if a == 169 and b == 254:
        return False
    # RFC5737 documentation blocks
    if (
        (a == 192 and b == 0 and c == 2)
        or (a == 198 and b == 51 and c == 100)
        or (a == 203 and b == 0 and c == 113)
    ):
        return False
    # Multicast + reserved
    if a >= 224:
        return False
    # Limited broadcast
    if a == 255 and b == 255 and c == 255 and d == 255:
        return False
    return True


_NON_DOMAIN_SUFFIXES: tuple[str, ...] = (
    # Native binaries
    ".exe",
    ".dll",
    ".sys",
    ".so",
    ".dylib",
    # Source / scripts
    ".py",
    ".js",
    ".c",
    ".h",
    ".cpp",
    ".cxx",
    ".cc",
    ".hpp",
    ".java",
    # Bundled bytecode / archive build artefacts that otherwise surface as
    # bogus DOMAIN matches (resources.arsc, classes.dex, etc.) — deny them.
    ".apk",
    ".aab",
    ".arsc",
    ".dex",
    ".smali",
    ".kotlin_module",
    # Bundled assets shipped inside archives
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".xml",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".html",
    ".htm",
    ".css",
    ".txt",
    ".md",
    ".csv",
    # Java / .NET / Office formats
    ".jar",
    ".class",
    ".war",
    ".ear",
    ".docx",
    ".xlsx",
    ".pptx",
    ".doc",
    ".xls",
    ".ppt",
    ".pdf",
)


# Framework namespace roots. Deliberately excludes every word that is also a
# plausible registrable name — no "com", "net", "org", "google", "android",
# "core", "base" — because this set is used to *reject*, and a false entry here
# silently discards a real C2 host. `System.Net` must go; `google.com` must not.
_NAMESPACE_TOKENS = frozenset(
    {
        "system",
        "microsoft",
        "windows",
        "runtime",
        "collections",
        "generic",
        "reflection",
        "diagnostics",
        "threading",
        "interopservices",
        "componentmodel",
        "globalization",
        "serialization",
        "regularexpressions",
        "javax",
        "mscorlib",
        "winforms",
        "presentationframework",
    }
)

# Second-level labels of multi-part public suffixes. `example.co.uk` is a real
# hostname whose second-level label is two characters, so the minimum-length
# check below has to know about them.
_MULTIPART_TLD_SECOND_LEVELS = frozenset(
    {"co", "com", "net", "org", "ac", "gov", "edu", "mil", "or", "ne", "in", "web"}
)

# A positive TLD check, complementing the negative suffix list. Without one,
# every dotted identifier whose last label happens to be alphabetic reads as a
# hostname — the concrete example being `System.Collections.Generic`, which was
# emitted as a `domain` IOC on every .NET sample.
#
# Deliberately not the full IANA list: the goal is to reject compile artefacts,
# and a curated set of TLDs that actually appear in malware C2 does that with a
# far smaller false-negative surface than trying to be exhaustive would create
# false positives.
_KNOWN_TLDS = frozenset(
    {
        # generic
        "com",
        "net",
        "org",
        "info",
        "biz",
        "io",
        "co",
        "app",
        "dev",
        "xyz",
        "site",
        "online",
        "store",
        "shop",
        "club",
        "space",
        "website",
        "tech",
        "live",
        "life",
        "world",
        "today",
        "top",
        "icu",
        "cyou",
        "monster",
        "click",
        "link",
        "fun",
        "pw",
        "cc",
        "tv",
        "me",
        "ws",
        "su",
        "sbs",
        "digital",
        "cloud",
        "email",
        "network",
        "systems",
        "services",
        "host",
        "press",
        "wiki",
        "art",
        "blog",
        "page",
        "rest",
        "zone",
        "run",
        "bar",
        # ccTLDs that show up in real C2
        "ru",
        "cn",
        "br",
        "in",
        "ir",
        "ua",
        "pl",
        "de",
        "fr",
        "uk",
        "nl",
        "it",
        "es",
        "tr",
        "jp",
        "kr",
        "vn",
        "id",
        "th",
        "my",
        "ph",
        "hk",
        "tw",
        "sg",
        "za",
        "ng",
        "ke",
        "eg",
        "sa",
        "ae",
        "il",
        "gr",
        "pt",
        "ro",
        "cz",
        "sk",
        "hu",
        "bg",
        "rs",
        "hr",
        "si",
        "lt",
        "lv",
        "ee",
        "fi",
        "se",
        "no",
        "dk",
        "be",
        "at",
        "ch",
        "ie",
        "us",
        "ca",
        "mx",
        "ar",
        "cl",
        "pe",
        "ve",
        "au",
        "nz",
        "kz",
        "by",
        "md",
        "ge",
        "am",
        "az",
        "uz",
        "pk",
        "bd",
        "lk",
        "np",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "to",
        "st",
        "cx",
        "nu",
        "im",
        "gg",
        "je",
        # ".onion" is deliberately absent. Hidden services have a fixed address
        # shape that a dedicated pattern validates, and routing them through the
        # generic domain path would accept any `word.onion` while losing the
        # note that says what it is.
    }
)


def _looks_like_path(text: str) -> bool:
    """Reject path *fragments*, which the regex produces in bulk.

    Found by reading real output rather than by reasoning about it. A scan of
    one sample returned ``/Users``, ``/rd_lee``, ``/.vscode``, ``/extensions``,
    ``/plugin``, ``/const``, ``/errors`` — and ``/Vundo.gen``, ``/Ryuk.P``,
    ``/Obfuse.VAL``, which are AV signature names lifted out of an embedded
    definition database. All of them are what ``/[A-Za-z0-9_...]+`` matches when
    it meets ordinary text containing a slash.

    They were not merely ugly. ``path`` has a 20-slot quota, and filling it with
    single-segment fragments is exactly the starvation the quotas were added to
    prevent — one noisy kind crowding out the useful ones.

    A path earns its slot by having structure: a Windows drive letter, or at
    least two separators. ``/Users`` has neither; ``C:\\Users\\x`` and
    ``/etc/cron.d/persistence`` each have one.

    A file extension deliberately does *not* qualify a single-separator string.
    That exemption was tried and admitted ``/Vundo.gen`` and ``/Obfuse.VAL`` —
    AV signature names, which are ``/Word.ext`` shaped and were being reported
    as filesystem IOCs. A genuinely interesting path essentially always has a
    directory in it.
    """
    stripped = text.strip()
    if len(stripped) < 6:
        return False
    # A slice of a URL is not a path. The regex happily starts matching in the
    # middle of `https://host/x` and yields `s://host/x`, which was appearing in
    # reports beside the URL it was carved out of — the same indicator twice,
    # once mangled.
    if "://" in stripped:
        return False
    # A drive letter is unambiguous.
    if len(stripped) > 2 and stripped[1] == ":" and stripped[0].isalpha():
        return True
    return (stripped.count("/") + stripped.count("\\")) >= 2


# Second-level labels that are code, not hostnames. `self.id` was reported as a
# C2 domain: `.id` is Indonesia's ccTLD and `self` clears every structural check
# there is. No rule about shape can separate `self.id` from `evil.id`, so the
# only honest fix is a short list of the identifiers that actually collide.
_CODE_IDENTIFIER_LABELS = frozenset(
    {
        "self",
        "this",
        "cls",
        "obj",
        "item",
        "items",
        "data",
        "value",
        "values",
        "result",
        "results",
        "config",
        "options",
        "props",
        "state",
        "error",
        "errors",
        "args",
        "kwargs",
        "ctx",
        "req",
        "res",
        "response",
        "request",
        "index",
        "length",
        "name",
        "type",
        "target",
        "source",
        "parent",
        "child",
        "node",
        "root",
        "next",
        "prev",
        "key",
        "keys",
        "attr",
        "attrs",
        "meta",
    }
)


def _looks_like_domain(text: str) -> bool:
    """Filter out obvious non-domain matches (filenames, version strings)."""
    if text.startswith(".") or text.endswith("."):
        return False
    lower = text.lower()
    if any(lower.endswith(suffix) for suffix in _NON_DOMAIN_SUFFIXES):
        return False
    if text.count(".") > 4:
        return False
    if len(text) < 5:
        return False

    labels = lower.split(".")
    if len(labels) < 2:
        return False

    # Positive TLD check. A hostname ends in a real TLD; `Collections.Generic`
    # does not.
    if labels[-1] not in _KNOWN_TLDS:
        return False

    # Namespace shape. Most .NET identifiers die on the TLD check already
    # (`System.Collections.Generic` — "generic" is not a TLD), but the ones
    # whose last segment happens to be a real TLD survive it: `System.Net`,
    # `System.IO`, `Microsoft.Web`. Two signals together catch those without
    # touching real hostnames — a framework root among the non-TLD labels, and
    # PascalCase, which dotted identifiers use and hostnames in binaries
    # essentially never do.
    if any(label in _NAMESPACE_TOKENS for label in labels[:-1]) and text[:1].isupper():
        return False

    # A one-character second-level label is a version fragment, not a
    # registrable name. Two characters are allowed only for the second level of
    # a multi-part public suffix such as `example.co.uk`.
    sld = labels[-2]
    if len(sld) < 2 or (len(sld) == 2 and sld not in _MULTIPART_TLD_SECOND_LEVELS):
        return False

    # `self.id`, `data.io`, `result.co` — a code identifier followed by a short
    # ccTLD. Only applied to two-label candidates: `self.example.com` is a
    # perfectly ordinary hostname and must survive.
    if len(labels) == 2 and sld in _CODE_IDENTIFIER_LABELS:
        return False

    # `MyApplication.app`, `DataContract.io` — a CamelCase identifier wearing a
    # real TLD. Hostnames embedded in binaries are written lowercase; an
    # internal capital is the mark of a type or assembly name. Checked on the
    # original text because the comparison above is lowercased, and only for
    # two-label candidates, so `cdn.MyCorp.com` is left alone.
    if len(labels) == 2:
        original_sld = text.split(".")[0]
        if any(ch.isupper() for ch in original_sld[1:]):
            return False

    return True
