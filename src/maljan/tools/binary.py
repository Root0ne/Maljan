"""Structure, per format: PE, ELF, Mach-O, APK, archives and documents.

Facts only. A section's entropy is reported, never called "packed"; a packer
catalog's section-name hit is reported as a match, never as an identification;
a document's macro stream is reported as present, never as malicious. The
agent weighs them — that is the whole reason these are tools and not a
pipeline stage with an opinion.

The PE and ELF parsers are ``extractors/pe_extractor``'s own, reused rather
than reimplemented: the report and the tool must not be able to disagree about
what a section is. Mach-O, APK, archive and document support is new here and
each rests on an optional library that is allowed to be missing — the tool
still exists and answers ``{"error": "<module> is not installed"}``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from maljan.core.logger import logger
from maljan.core.paths import resolve_data

# The default packer catalog. Passed explicitly so this module never reads
# ``Settings``; an operator pointing the pipeline at a different catalog hands
# the same path to the tool.
DEFAULT_PACKER_CATALOG = "data/packer_signatures_v1.json"

_MACHO_THIN_MAGICS = (
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
)
_MACHO_FAT_MAGIC = b"\xca\xfe\xba\xbe"

# PDF keywords that say a document can act rather than only be read.
_PDF_MARKERS: tuple[str, ...] = (
    "/JS",
    "/JavaScript",
    "/OpenAction",
    "/AA",
    "/Launch",
    "/EmbeddedFile",
    "/RichMedia",
    "/URI",
)
_PDF_OBJECT_RE = re.compile(rb"\b\d+\s+\d+\s+obj\b")

# OLE2 streams whose mere presence means the document carries VBA.
_OLE_MACRO_STREAMS = ("vba", "macros", "_vba_project", "dir")


def _missing(module: str, tool: str) -> dict[str, Any]:
    return {"error": f"{module} is not installed", "tool": tool}


def _no_file(path: str, tool: str) -> dict[str, Any]:
    return {"error": f"no such file: {path}", "tool": tool}


# ---------------------------------------------------------------------------
# PE
# ---------------------------------------------------------------------------


def pe_info(
    path: str,
    sections: bool = True,
    imports: bool = True,
    exports: bool = True,
    resources: bool = True,
    overlay: bool = True,
    pdb: bool = True,
    packer_catalog: str = DEFAULT_PACKER_CATALOG,
) -> dict[str, Any]:
    """The PE header's structural facts, each part switchable off.

    The flags matter for a real sample: a PE with tens of thousands of imports
    produces a payload no context window wants, and an agent that only needs
    the section table should be able to ask for the section table.

    Imports are listed without interpretation: each row is ``dll``, ``function``
    (the name, or ``Ordinal_N``), ``ordinal``, ``hint`` and ``address``, and no
    capability label. See :func:`_import_rows`.
    """
    target = Path(path)
    if not target.is_file():
        return _no_file(path, "pe_info")
    blob = target.read_bytes()
    if blob[:2] != b"MZ":
        return {"error": "not a PE file (no MZ magic)", "tool": "pe_info"}
    try:
        import pefile  # type: ignore[import-not-found]
    except ImportError:
        return _missing("pefile", "pe_info")

    try:
        pe = pefile.PE(data=blob, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            ]
        )
    except Exception as exc:  # noqa: BLE001 — a malformed PE is an answer
        return {"error": f"PE parse failed: {type(exc).__name__}: {exc}", "tool": "pe_info"}

    from maljan.extractors.pe_extractor import (
        _overlay_offset,
        _pe_exports,
        _pe_pdb_path,
        _pe_resources,
        _pe_sections,
    )

    parsed_sections = _pe_sections(pe)
    out: dict[str, Any] = {
        "machine": int(getattr(pe.FILE_HEADER, "Machine", 0) or 0),
        "timestamp": int(getattr(pe.FILE_HEADER, "TimeDateStamp", 0) or 0),
        "subsystem": int(getattr(pe.OPTIONAL_HEADER, "Subsystem", 0) or 0),
        "entry_point": int(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0) or 0),
        "is_dll": bool(getattr(pe, "is_dll", lambda: False)()),
        "size": len(blob),
    }
    if sections:
        out["sections"] = [
            {
                "name": s.name,
                "virtual_address": s.virtual_address,
                "virtual_size": s.virtual_size,
                "raw_size": s.raw_size,
                "entropy": round(float(s.entropy), 4),
                "raw_offset": s.raw_offset,
                "characteristics": s.characteristics,
            }
            for s in parsed_sections
        ]
    warnings = _pe_warnings(pe)
    out["warnings"] = warnings
    # A sample whose import directory is deliberately corrupt reads as a
    # binary that imports nothing, which is a very different claim. pefile
    # says so in its warnings and said it only there until now.
    out["import_table_damaged"] = _import_table_damaged(warnings)
    out["characteristics"] = _flag_names(
        pefile,
        "IMAGE_CHARACTERISTICS",
        "IMAGE_FILE_",
        getattr(pe.FILE_HEADER, "Characteristics", 0),
    )
    out["dll_characteristics"] = _flag_names(
        pefile,
        "DLL_CHARACTERISTICS",
        "IMAGE_DLLCHARACTERISTICS_",
        getattr(pe.OPTIONAL_HEADER, "DllCharacteristics", 0),
    )
    out["linker_version"] = (
        f"{int(getattr(pe.OPTIONAL_HEADER, 'MajorLinkerVersion', 0) or 0)}."
        f"{int(getattr(pe.OPTIONAL_HEADER, 'MinorLinkerVersion', 0) or 0)}"
    )
    out["rich_header_present"] = _has_rich_header(pe)
    if imports:
        out["imports"] = _import_rows(getattr(pe, "DIRECTORY_ENTRY_IMPORT", None))
        # A binary that resolves its interesting APIs through ``.didat`` looked
        # import-free here, which is the same false picture a damaged import
        # table gives.
        out["delay_imports"] = _import_rows(getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", None))
    if exports:
        out["exports"] = list(_pe_exports(pe))
        # The same symbols with their ordinal and address, and the name the
        # export directory gives the library. Several exports sharing one
        # address, or a DLL whose own name differs from the one it was
        # submitted under, are header facts a reader should see.
        out["export_rows"] = _pe_export_rows(pe)
        export_name = _pe_export_name(pe)
        if export_name:
            out["export_name"] = export_name
    if resources:
        out["resources"] = list(_pe_resources(pe))
        version_info = _pe_version_strings(pe)
        if version_info:
            out["version_info"] = version_info
    if pdb:
        out["pdb_path"] = _pe_pdb_path(pe)
    if overlay:
        start = _overlay_offset(parsed_sections)
        out["overlay"] = {
            "offset": start,
            "size": max(0, len(blob) - start) if start else 0,
            "present": bool(start and len(blob) > start),
        }
    out["packer_signatures"] = packer_section_matches(
        [s.name for s in parsed_sections], packer_catalog
    )
    return out


def _decoded(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip("\x00").strip()
    return str(value or "").strip()


def _pe_export_rows(pe: Any) -> list[dict[str, Any]]:
    """One row per exported symbol: its name, ordinal and RVA, as the directory states them."""
    export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    rows: list[dict[str, Any]] = []
    for sym in getattr(export_dir, "symbols", None) or []:
        try:
            address = getattr(sym, "address", None)
            rows.append(
                {
                    "name": _decoded(getattr(sym, "name", None)),
                    "ordinal": getattr(sym, "ordinal", None),
                    "rva": f"0x{int(address):x}" if address is not None else None,
                }
            )
        except Exception:  # noqa: BLE001 — one unreadable symbol costs one row
            continue
    return rows


def _pe_export_name(pe: Any) -> str:
    """The library name the export directory records, or ``""``."""
    try:
        return _decoded(getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "name", None))
    except Exception:  # noqa: BLE001 — an unreadable name is no name
        return ""


# The version-resource strings that name the binary itself.
_VERSION_NAME_KEYS = ("InternalName", "OriginalFilename", "ProductName", "FileDescription")


def _pe_version_strings(pe: Any) -> dict[str, str]:
    """The naming strings of the version resource, as the resource states them."""
    found: dict[str, str] = {}
    try:
        for group in getattr(pe, "FileInfo", None) or []:
            for info in group if isinstance(group, list) else [group]:
                for table in getattr(info, "StringTable", None) or []:
                    for key, value in (getattr(table, "entries", None) or {}).items():
                        name = _decoded(key)
                        if name in _VERSION_NAME_KEYS and name not in found:
                            text = _decoded(value)
                            if text:
                                found[name] = text
    except Exception:  # noqa: BLE001 — a malformed resource names nothing
        return found
    return found


def _pe_warnings(pe: Any) -> list[str]:
    """Everything pefile complained about while parsing, as plain strings."""
    try:
        return [str(w) for w in (pe.get_warnings() or [])]
    except Exception:  # noqa: BLE001 — a warning list is never worth an error
        return []


# What pefile says when the import table cannot be walked, as opposed to when
# one entry in it could not be read. The difference is whether the parser
# stopped: each of these either fails the directory outright or breaks out of a
# walk, so what came back is a truncated import list presented as a complete
# one — the claim worth flagging.
_IMPORT_TABLE_DAMAGE = (
    # The directory's own RVA points nowhere.
    "error parsing the import directory at rva",
    # Six bad descriptors and pefile gives up on the rest of the directory.
    "too many errors parsing the import directory",
    # A descriptor whose ILT and IAT are both unreadable.
    "damaged import table",
    # Both of these break the thunk walk, truncating that library's imports.
    "error parsing the import table. entries go beyond bounds",
    "error parsing the import table. addressofdata overlaps",
)

# One thunk pefile could not read. The walk goes on and the rest of the table
# is fine, so a single occurrence is not a damaged table — a healthy binary
# produces one. Enough of them and nothing useful came back either way.
_IMPORT_ENTRY_DAMAGE = "error parsing the import table. invalid data at rva"
_REPEATED_ENTRY_DAMAGE = 3


def _import_table_damaged(warnings: list[str]) -> bool:
    """Whether pefile could not walk the import table, rather than one entry.

    Matching the bare word "import" called every per-symbol and delay-load
    complaint a damaged table; matching "directory" against "table" got the
    rule backwards, because pefile writes "Error parsing the import table" for
    a broken walk *and* for a single unreadable thunk. The sentences are
    therefore listed one by one, against what each of them does to the parse.
    """
    lowered = [w.lower() for w in warnings]
    if any(phrase in w for w in lowered for phrase in _IMPORT_TABLE_DAMAGE):
        return True
    return sum(_IMPORT_ENTRY_DAMAGE in w for w in lowered) >= _REPEATED_ENTRY_DAMAGE


def _flag_names(pefile: Any, table: str, prefix: str, value: Any) -> list[str]:
    """The names of the flags set in ``value``, from one of pefile's tables."""
    try:
        bits = int(value or 0)
        flags = pefile.retrieve_flags(getattr(pefile, table), prefix)
        return [name for name, bit in flags if bits & bit]
    except Exception:  # noqa: BLE001 — an unreadable header field names no flags
        return []


def _has_rich_header(pe: Any) -> bool:
    """Whether the sample carries a Rich header (a Microsoft toolchain left it)."""
    try:
        return bool(pe.parse_rich_header())
    except Exception:  # noqa: BLE001 — an absent or malformed Rich header is "no"
        return False


def _import_rows(entries: Any) -> list[dict[str, Any]]:
    """One row per imported symbol, as the import directory states it.

    The table's own facts and nothing else: which library, which name or
    ordinal, the hint and the thunk address. What an API is used for is a
    question for the knowledge server's ``api_capability`` tool, asked by the
    model when it decides the answer matters. A row that labelled ``BitBlt``
    "keylogging" was this tool doing the analysis, and an analyst read the
    label as a finding on a signed binary.
    """
    rows: list[dict[str, Any]] = []
    for entry in entries or []:
        try:
            dll = (entry.dll or b"").decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            dll = "(unknown)"
        for imp in getattr(entry, "imports", None) or []:
            name = getattr(imp, "name", None)
            function = name.decode("utf-8", errors="replace") if name else ""
            ordinal = getattr(imp, "ordinal", None)
            if not function:
                function = f"Ordinal_{ordinal if ordinal is not None else '?'}"
            rows.append(
                {
                    "dll": dll,
                    "function": function,
                    "ordinal": ordinal,
                    "hint": getattr(imp, "hint", None),
                    "address": getattr(imp, "address", None),
                }
            )
    return rows


def packer_section_matches(
    section_names: list[str], catalog_path: str = DEFAULT_PACKER_CATALOG
) -> list[dict[str, Any]]:
    """Catalog entries whose declared section names this binary actually has.

    Section names only — not the entry-point or string heuristics the report's
    packer hint also weighs, and no confidence number. A tool reporting
    ``{"name": "UPX", "sections": ["UPX0", "UPX1"]}`` states what is in the
    header; whether that means the sample is packed is the agent's call.
    """
    names = {str(n).lower() for n in section_names}
    if not names:
        return []
    try:
        catalog = resolve_data(catalog_path)
        if not catalog.is_file():
            return []
        doc = json.loads(catalog.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — a missing catalog costs depth only
        logger.debug("packer catalog unavailable (%s)", exc)
        return []
    rows = doc.get("packers") if isinstance(doc, dict) else None
    if not isinstance(rows, list):
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        hits = [s for s in (row.get("sections") or []) if isinstance(s, str) and s.lower() in names]
        if hits:
            out.append(
                {
                    "name": str(row.get("name") or ""),
                    "kind": str(row.get("kind") or "packer"),
                    "sections": sorted(hits),
                }
            )
    out.sort(key=lambda r: r["name"])
    return out


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------


def elf_info(path: str) -> dict[str, Any]:
    """Sections, imports, exports, and the segment/dynamic view pyelftools adds.

    The interpreter path and the ``DT_NEEDED`` list are the two facts that most
    often decide what a Linux sample is: a static binary with no interpreter
    and a binary linked against ``libcurl`` are different animals, and neither
    shows up in a section table.

    Imports are listed without interpretation: each row is ``dll`` and
    ``function``, and no capability label, as in :func:`pe_info`. What a libc
    symbol is used for is the knowledge server's ``api_capability`` question,
    asked with ``platform="linux"`` so the answer comes from the catalogue's
    ELF vocabulary rather than its Win32 one.
    """
    target = Path(path)
    if not target.is_file():
        return _no_file(path, "elf_info")
    blob = target.read_bytes()
    if blob[:4] != b"\x7fELF":
        return {"error": "not an ELF file (no \\x7fELF magic)", "tool": "elf_info"}

    from maljan.extractors.pe_extractor import (
        _parse_elf_exports,
        _parse_elf_imports,
        _parse_elf_sections,
    )

    out: dict[str, Any] = {
        "bitness": 64 if blob[4:5] == b"\x02" else 32,
        "endianness": "little" if blob[5:6] == b"\x01" else "big",
        "size": len(blob),
        "sections": [
            {
                "name": s.name,
                "virtual_address": s.virtual_address,
                "virtual_size": s.virtual_size,
                "raw_size": s.raw_size,
                "entropy": round(float(s.entropy), 4),
                "characteristics": s.characteristics,
            }
            for s in _parse_elf_sections(blob)
        ],
        "imports": [{"dll": row.dll, "function": row.function} for row in _parse_elf_imports(blob)],
        "exports": list(_parse_elf_exports(blob)),
    }
    out.update(_elf_dynamic_view(blob))
    return out


def _elf_dynamic_view(blob: bytes) -> dict[str, Any]:
    """Program headers, the interpreter and the dynamic tags, when available."""
    try:
        import io

        from elftools.elf.dynamic import DynamicSection  # type: ignore[import-not-found]
        from elftools.elf.elffile import ELFFile  # type: ignore[import-not-found]
    except ImportError:
        return {"segments": [], "dynamic": [], "interp": None, "needed": []}
    try:
        elf = ELFFile(io.BytesIO(blob))
        segments = [
            {
                "type": str(seg.header.p_type),
                "vaddr": int(seg.header.p_vaddr),
                "filesz": int(seg.header.p_filesz),
                "memsz": int(seg.header.p_memsz),
                "flags": int(seg.header.p_flags),
            }
            for seg in elf.iter_segments()
        ]
        interp = None
        for seg in elf.iter_segments():
            if str(seg.header.p_type) != "PT_INTERP":
                continue
            read_interp = getattr(seg, "get_interp_name", None)
            interp = str(read_interp()) if callable(read_interp) else None
            break
        dynamic: list[dict[str, Any]] = []
        needed: list[str] = []
        for section in elf.iter_sections():
            if not isinstance(section, DynamicSection):
                continue
            for tag in section.iter_tags():
                entry: dict[str, Any] = {"tag": str(tag.entry.d_tag)}
                value = getattr(tag, "needed", None) or getattr(tag, "soname", None)
                if value:
                    entry["value"] = str(value)
                if str(tag.entry.d_tag) == "DT_NEEDED" and value:
                    needed.append(str(value))
                dynamic.append(entry)
        return {
            "segments": segments,
            "dynamic": dynamic,
            "interp": interp,
            "needed": needed,
        }
    except Exception as exc:  # noqa: BLE001 — a malformed ELF still reports its sections
        logger.debug("elf_info: dynamic view unavailable (%s)", exc)
        return {"segments": [], "dynamic": [], "interp": None, "needed": []}


# ---------------------------------------------------------------------------
# Mach-O
# ---------------------------------------------------------------------------


def macho_info(path: str) -> dict[str, Any]:
    """Headers, load commands, linked dylibs and whether entitlements are present.

    Needs ``macholib``; without it the tool answers that rather than guessing
    at a format whose fat headers, slices and load-command chain are exactly
    the part a hand-rolled parser gets wrong.
    """
    target = Path(path)
    if not target.is_file():
        return _no_file(path, "macho_info")
    blob = target.read_bytes()
    if blob[:4] not in _MACHO_THIN_MAGICS and blob[:4] != _MACHO_FAT_MAGIC:
        return {"error": "not a Mach-O file", "tool": "macho_info"}
    try:
        from macholib.mach_o import LC_CODE_SIGNATURE  # type: ignore[import-not-found]
        from macholib.MachO import MachO  # type: ignore[import-not-found]
    except ImportError:
        return _missing("macholib", "macho_info")

    try:
        binary = MachO(str(target))
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Mach-O parse failed: {type(exc).__name__}: {exc}", "tool": "macho_info"}

    slices: list[dict[str, Any]] = []
    for header in binary.headers:
        commands: list[str] = []
        dylibs: list[str] = []
        signed = False
        for load_command, _cmd, data in header.commands:
            describe = getattr(load_command, "get_cmd_name", None)
            name = str(describe()) if callable(describe) else str(load_command.cmd)
            commands.append(name)
            if int(load_command.cmd) == int(LC_CODE_SIGNATURE):
                signed = True
            if isinstance(data, bytes) and name.startswith("LC_LOAD"):
                text = data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                if text:
                    dylibs.append(text)
        slices.append(
            {
                "cputype": int(header.header.cputype),
                "cpusubtype": int(header.header.cpusubtype),
                "filetype": int(header.header.filetype),
                "load_commands": commands,
                "dylibs": sorted(set(dylibs)),
                "code_signature": signed,
            }
        )
    return {
        "fat": blob[:4] == _MACHO_FAT_MAGIC,
        "slices": slices,
        "entitlements_present": b"<key>com.apple." in blob or b"entitlements" in blob.lower(),
        "size": len(blob),
    }


# ---------------------------------------------------------------------------
# APK
# ---------------------------------------------------------------------------


def _degraded(
    facts: dict[str, Any],
    why: str,
    *,
    still: str = "the zip-level facts",
    remediation: str | None = None,
) -> dict[str, Any]:
    """Facts a tool did produce, with what it could not add said beside them.

    Not an ``error``. A degraded answer used to carry one, and every consumer
    reads ``error`` as "this call produced nothing": the ledger recorded the
    call as failed and the pack printed none of the facts in the same dict.
    An Android run therefore had no container channel at all, although the
    archive had been read and the dex files counted. What is missing is a
    ``degraded`` note and, when there is one, a remediation.

    The remedy is the caller's to name, because it is about the reason: a
    library that is not installed can be installed, and a file the installed
    library refused to parse cannot be fixed by installing it again.
    """
    facts["degraded"] = f"{why}; answered {still}"
    if remediation:
        facts["remediation"] = remediation
    return facts


def _missing_library_remedy() -> str:
    from maljan.tools.errors import MISSING_DEPENDENCY, REMEDIATIONS

    return REMEDIATIONS[MISSING_DEPENDENCY]


def apk_info(
    path: str,
    manifest: bool = True,
    permissions: bool = True,
    certs: bool = True,
    components: bool = True,
    native_libs: bool = True,
    dex_strings: bool = False,
    limit: int = 500,
) -> dict[str, Any]:
    """The manifest's declared surface, or the zip-level facts without androguard.

    androguard is what decodes the binary AndroidManifest, so permissions,
    components and the certificate subjects need it. Without it the archive is
    still a zip and the zip still says how many dex files there are, which ABIs
    the native libraries target and which certificate files are present — so
    the tool degrades to those facts and says which ones it could not add.
    """
    target = Path(path)
    if not target.is_file():
        return _no_file(path, "apk_info")
    if not zipfile.is_zipfile(target):
        return {"error": "not a zip-based APK", "tool": "apk_info"}
    limit = max(0, int(limit))

    out: dict[str, Any] = _apk_zip_facts(target, limit, native_libs=native_libs, certs=certs)
    try:
        from androguard.core.apk import APK  # type: ignore[import-not-found]
    except ImportError:
        return _degraded(out, "androguard is not installed", remediation=_missing_library_remedy())

    try:
        apk = APK(str(target))
    except Exception as exc:  # noqa: BLE001
        # The library is installed and refused the file, so installing it
        # again is not the remedy and saying so would send the operator after
        # the wrong thing.
        return _degraded(out, f"androguard parse failed: {type(exc).__name__}: {exc}")

    if manifest:
        out["package"] = apk.get_package()
        out["version_name"] = apk.get_androidversion_name()
        out["version_code"] = apk.get_androidversion_code()
        out["min_sdk"] = apk.get_min_sdk_version()
        out["target_sdk"] = apk.get_target_sdk_version()
    if permissions:
        out["permissions"] = _within_limit(out, "permissions", apk.get_permissions(), limit)
    if components:
        out["activities"] = _within_limit(out, "activities", apk.get_activities(), limit)
        out["services"] = _within_limit(out, "services", apk.get_services(), limit)
        out["receivers"] = _within_limit(out, "receivers", apk.get_receivers(), limit)
        out["providers"] = _within_limit(out, "providers", apk.get_providers(), limit)
    if certs:
        out["signing_schemes"] = {
            "v1": bool(apk.is_signed_v1()),
            "v2": bool(apk.is_signed_v2()),
            "v3": bool(apk.is_signed_v3()),
        }
        every_cert = [
            {"subject": str(cert.subject), "issuer": str(cert.issuer), "sha256": cert.sha256.hex()}
            for cert in apk.get_certificates()
        ]
        out["certificates"] = every_cert[:limit]
        if len(every_cert) > limit:
            out.setdefault("totals", {})["certificates"] = len(every_cert)
    if dex_strings:
        out["dex_strings"] = _apk_dex_strings(apk, limit)
    return out


def _within_limit(out: dict[str, Any], name: str, values: Any, limit: int) -> list[Any]:
    """The first ``limit`` of ``values``, sorted; the full count under ``totals`` when cut.

    ``limit`` is the caller's own argument, and a list it cut says so: the
    answer's ``totals`` holds how many there were, so a model reads a page as
    a page and can ask again with a larger ``limit``.
    """
    ordered = sorted(values or [])
    if len(ordered) > limit:
        out.setdefault("totals", {})[name] = len(ordered)
    return ordered[:limit]


def _apk_zip_facts(target: Path, limit: int, *, native_libs: bool, certs: bool) -> dict[str, Any]:
    """What the archive alone says: dex count, ABIs, cert files, manifest presence."""
    out: dict[str, Any] = {"dex_files": [], "native_libs": [], "cert_files": []}
    try:
        with zipfile.ZipFile(target) as archive:
            names = archive.namelist()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"zip read failed: {type(exc).__name__}: {exc}", "tool": "apk_info"}
    abis: set[str] = set()
    for name in names:
        lowered = name.lower()
        if lowered.endswith(".dex"):
            out["dex_files"].append(name)
        if lowered.startswith("lib/") and lowered.endswith(".so"):
            parts = name.split("/")
            if len(parts) >= 3:
                abis.add(parts[1])
            if native_libs:
                out["native_libs"].append(name)
        if certs and lowered.startswith("meta-inf/") and lowered.endswith((".rsa", ".dsa", ".ec")):
            out["cert_files"].append(name)
    out["manifest_present"] = "AndroidManifest.xml" in names
    out["dex_count"] = len(out["dex_files"])
    out["abis"] = sorted(abis)
    out["entry_count"] = len(names)
    out["dex_files"] = _within_limit(out, "dex_files", out["dex_files"], limit)
    out["native_libs"] = _within_limit(out, "native_libs", out["native_libs"], limit)
    out["cert_files"] = sorted(out["cert_files"])
    return out


def _apk_dex_strings(apk: Any, limit: int) -> list[str]:
    """Distinct dex string-table entries, best effort and always bounded."""
    try:
        from androguard.core.dex import DEX  # type: ignore[import-not-found]
    except ImportError:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for raw in apk.get_all_dex():
        try:
            for value in DEX(raw).get_strings():
                text = value if isinstance(value, str) else str(value)
                if text and text not in seen:
                    seen.add(text)
                    found.append(text)
                if len(found) >= limit:
                    return found
        except Exception:  # noqa: BLE001 — a malformed dex costs its own strings only
            continue
    return found


# ---------------------------------------------------------------------------
# Carving
# ---------------------------------------------------------------------------


# How a carved payload's display label becomes the name of the file it is
# written under. Named once, here, because two readers depend on it: this
# writer, and the sidecar's ``carved_path``, which has to find the file again
# from the ``name`` a model read off the answer. A model that passes the label
# back instead of the path is not wrong about which payload it means.
def carved_name_prefix(label: str) -> str:
    """The part of a carved file's name that its display label decides."""
    return f"{str(label).replace('+', '_').replace(':', '_')}_"


def carved_file_name(label: str, digest: str) -> str:
    """The file name one carved payload is written under."""
    return f"{carved_name_prefix(label)}{digest[:12]}"


def _write_carved(child: Path, blob: bytes) -> str | None:
    """Write one carved payload, or say why it was not written.

    ``O_CREAT|O_EXCL|O_NOFOLLOW`` at 0o600, the same discipline the upload path
    uses and for the same reason: the plain write followed a symlink planted at
    the destination, and the two-step create-then-chmod leaves the file
    readable at the process umask for as long as the write takes.

    Exclusive means a second run of the same sample finds its own payload
    already there. That is the common case and not a failure: the name carries
    the digest of the bytes, so a regular file of the same size holding the
    same content is the payload this call would have written, and it is reused.
    Anything else at that name — a link, a directory, a file whose bytes differ
    — is refused, because this call did not put it there.
    """
    try:
        fd = os.open(child, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        try:
            info = child.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_size == len(blob):
                if child.read_bytes() == blob:
                    return None
        except OSError as exc:
            return f"cannot read what is already at {child.name}: {type(exc).__name__}"
        return f"{child.name} is already taken by something this run did not write"
    except OSError as exc:
        return f"cannot write {child.name}: {type(exc).__name__}"
    try:
        os.write(fd, blob)
    except OSError as exc:
        return f"cannot write {child.name}: {type(exc).__name__}"
    finally:
        os.close(fd)
    return None


def _carve_into(path: str, destination: str | Path) -> dict[str, Any]:
    """Write each embedded payload found in the file under ``destination``.

    A packed dropper's real payload is invisible to every rule in the corpus
    until it is carved out — the rules only ever see the outer shell, which by
    construction matches nothing. The carved children are written with 0o600
    and the directory with 0o700, so a staging directory shared with a tool
    server does not widen who can read the sample.

    Private: the destination is the caller's to decide, and the one caller
    that faces a model, the analysis sidecar's ``carve_payloads``, decides it
    from the sample's hash under its own staging directory. A live run passed
    a model-chosen directory through here and live malware was written to the
    sidecar's cwd; nothing a model writes reaches this argument any more.

    One payload that cannot be written is that payload's error and not the
    call's: the others are still carved, and the entry says what happened to
    the one that was not.
    """
    target = Path(path)
    if not target.is_file():
        return _no_file(path, "carve_payloads")
    where = Path(destination)
    try:
        where.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        return {"error": f"cannot create {where}: {exc}", "tool": "carve_payloads"}

    from maljan.extractors.pe_extractor import carve_payloads as _carve

    payloads: list[dict[str, Any]] = []
    for label, blob in _carve(target.read_bytes()):
        digest = hashlib.sha256(blob).hexdigest()
        child = where / carved_file_name(label, digest)
        written = _write_carved(child, blob)
        offset = 0
        if "+0x" in label:
            try:
                offset = int(label.split("+0x", 1)[1], 16)
            except ValueError:
                offset = 0
        if written is not None:
            # The name is taken; the payload is reported with the reason
            # rather than silently missing from the list.
            payloads.append({"name": label, "offset": offset, "sha256": digest, "error": written})
            continue
        payloads.append(
            {
                "name": label,
                "offset": offset,
                "sha256": digest,
                "size": len(blob),
                "path": str(child),
                # The same value under the name of the argument that reads it,
                # so a caller copying the field whose name matches the argument
                # is right by construction. A live model passed ``name`` back,
                # and passed ``path`` back wrapped in the quotes it had read it
                # between.
                "carved_path": str(child),
            }
        )
    return {"payloads": payloads, "count": len(payloads)}


# ---------------------------------------------------------------------------
# Archives
# ---------------------------------------------------------------------------


def archive_list(path: str, limit: int = 500) -> dict[str, Any]:
    """Members of a zip, 7z, tar or gzip archive, without extracting anything.

    Listing is not extraction: nothing is written and no member is decompressed,
    so a zip bomb costs a directory read. ``compressed`` and ``crc`` are absent
    for the formats whose directory does not carry them.
    """
    target = Path(path)
    if not target.is_file():
        return _no_file(path, "archive_list")
    limit = max(0, int(limit))

    if zipfile.is_zipfile(target):
        return _zip_members(target, limit)
    if tarfile.is_tarfile(target):
        return _tar_members(target, limit)
    blob_head = target.open("rb").read(6)
    if blob_head[:6] == b"7z\xbc\xaf\x27\x1c":
        return _sevenzip_members(target, limit)
    if blob_head[:2] == b"\x1f\x8b":
        return _gzip_member(target)
    return {"error": "unsupported archive format", "tool": "archive_list"}


def _zip_members(target: Path, limit: int) -> dict[str, Any]:
    with zipfile.ZipFile(target) as archive:
        infos = archive.infolist()
        members = [
            {
                "name": info.filename,
                "size": int(info.file_size),
                "compressed": int(info.compress_size),
                "crc": f"{info.CRC:08x}",
                "is_dir": info.is_dir(),
            }
            for info in infos[:limit]
        ]
    return {
        "format": "zip",
        "members": members,
        "total": len(infos),
        "truncated": len(infos) > limit,
    }


def _tar_members(target: Path, limit: int) -> dict[str, Any]:
    with tarfile.open(target) as archive:
        infos = archive.getmembers()
        members = [
            {"name": info.name, "size": int(info.size), "is_dir": info.isdir()}
            for info in infos[:limit]
        ]
    return {
        "format": "tar",
        "members": members,
        "total": len(infos),
        "truncated": len(infos) > limit,
    }


def _sevenzip_members(target: Path, limit: int) -> dict[str, Any]:
    try:
        import py7zr  # type: ignore[import-not-found]
    except ImportError:
        return _missing("py7zr", "archive_list")
    try:
        with py7zr.SevenZipFile(target, mode="r") as archive:
            infos = archive.list()
    except Exception as exc:  # noqa: BLE001 — an encrypted header is an answer
        return {"error": f"7z read failed: {type(exc).__name__}: {exc}", "tool": "archive_list"}
    members = [
        {
            "name": info.filename,
            "size": int(info.uncompressed or 0),
            "compressed": int(info.compressed or 0),
            "crc": f"{info.crc32:08x}" if info.crc32 else "",
            "is_dir": bool(info.is_directory),
        }
        for info in infos[:limit]
    ]
    return {
        "format": "7z",
        "members": members,
        "total": len(infos),
        "truncated": len(infos) > limit,
    }


def _gzip_member(target: Path) -> dict[str, Any]:
    """A gzip stream carries one member and, usually, its original name."""
    with target.open("rb") as fh:
        header = fh.read(10)
        name = ""
        if len(header) == 10 and header[3] & 0x08:
            chunks: list[bytes] = []
            while (byte := fh.read(1)) not in (b"", b"\x00"):
                chunks.append(byte)
            name = b"".join(chunks).decode("utf-8", errors="replace")
    return {
        "format": "gzip",
        "members": [{"name": name or target.stem, "compressed": target.stat().st_size}],
        "total": 1,
        "truncated": False,
    }


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------


def document_info(path: str) -> dict[str, Any]:
    """OLE2 streams, OOXML parts or PDF action markers, whichever the file is.

    All three formats answer one question — can this document run something —
    with different evidence: an OLE2 macro storage, an OOXML ``vbaProject.bin``
    part, a PDF ``/OpenAction``. Each is reported as a count or a presence
    flag, never as a verdict.
    """
    target = Path(path)
    if not target.is_file():
        return _no_file(path, "document_info")
    with target.open("rb") as fh:
        head = fh.read(8)
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return _ole_info(target)
    if zipfile.is_zipfile(target):
        return _ooxml_info(target)
    if head[:5] == b"%PDF-":
        return _pdf_info(target)
    return {"error": "not an OLE2, OOXML or PDF document", "tool": "document_info"}


def _ole_info(target: Path) -> dict[str, Any]:
    try:
        import olefile  # type: ignore[import-not-found]
    except ImportError:
        # Without olefile the compound-document directory cannot be walked, but
        # the macro storage name is a literal in the raw bytes, so presence is
        # still answerable.
        blob = target.read_bytes()
        return _degraded(
            {
                "format": "ole2",
                "macros_present": b"VBA" in blob or b"Macros" in blob,
            },
            "olefile is not installed",
            still="the macro storage name read out of the raw bytes",
            remediation=_missing_library_remedy(),
        )
    try:
        with olefile.OleFileIO(str(target)) as ole:
            streams = ["/".join(parts) for parts in ole.listdir()]
    except Exception as exc:  # noqa: BLE001
        return {"error": f"OLE2 read failed: {type(exc).__name__}: {exc}", "tool": "document_info"}
    lowered = [s.lower() for s in streams]
    return {
        "format": "ole2",
        "streams": sorted(streams),
        "macros_present": any(
            any(marker in name for marker in _OLE_MACRO_STREAMS) for name in lowered
        ),
    }


def _ooxml_info(target: Path) -> dict[str, Any]:
    with zipfile.ZipFile(target) as archive:
        parts = archive.namelist()
    lowered = [p.lower() for p in parts]
    return {
        "format": "ooxml",
        "parts": sorted(parts),
        "vba_project_present": any(p.endswith("vbaproject.bin") for p in lowered),
        "external_relationships": sum(1 for p in lowered if p.endswith(".rels")),
    }


def _pdf_info(target: Path) -> dict[str, Any]:
    blob = target.read_bytes()
    markers = {marker: blob.count(marker.encode("ascii")) for marker in _PDF_MARKERS}
    return {
        "format": "pdf",
        "markers": {name: count for name, count in markers.items() if count},
        "object_count": len(_PDF_OBJECT_RE.findall(blob)),
        "encrypted": b"/Encrypt" in blob,
        "size": len(blob),
    }
