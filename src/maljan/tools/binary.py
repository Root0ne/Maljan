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
import re
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
            ]
        )
    except Exception as exc:  # noqa: BLE001 — a malformed PE is an answer
        return {"error": f"PE parse failed: {type(exc).__name__}: {exc}", "tool": "pe_info"}

    from maljan.extractors.pe_extractor import (
        _overlay_offset,
        _pe_exports,
        _pe_imports,
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
    if imports:
        out["imports"] = [
            {"dll": row.dll, "function": row.function, "category": row.category}
            for row in _pe_imports(pe)
        ]
    if exports:
        out["exports"] = list(_pe_exports(pe))
    if resources:
        out["resources"] = list(_pe_resources(pe))
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
        "imports": [
            {"dll": row.dll, "function": row.function, "category": row.category}
            for row in _parse_elf_imports(blob)
        ],
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
        out["error"] = "androguard is not installed"
        out["degraded"] = "zip-level facts only"
        return out

    try:
        apk = APK(str(target))
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"androguard parse failed: {type(exc).__name__}: {exc}"
        out["degraded"] = "zip-level facts only"
        return out

    if manifest:
        out["package"] = apk.get_package()
        out["version_name"] = apk.get_androidversion_name()
        out["version_code"] = apk.get_androidversion_code()
        out["min_sdk"] = apk.get_min_sdk_version()
        out["target_sdk"] = apk.get_target_sdk_version()
    if permissions:
        out["permissions"] = sorted(apk.get_permissions())[:limit]
    if components:
        out["activities"] = sorted(apk.get_activities())[:limit]
        out["services"] = sorted(apk.get_services())[:limit]
        out["receivers"] = sorted(apk.get_receivers())[:limit]
        out["providers"] = sorted(apk.get_providers())[:limit]
    if certs:
        out["signing_schemes"] = {
            "v1": bool(apk.is_signed_v1()),
            "v2": bool(apk.is_signed_v2()),
            "v3": bool(apk.is_signed_v3()),
        }
        out["certificates"] = [
            {"subject": str(cert.subject), "issuer": str(cert.issuer), "sha256": cert.sha256.hex()}
            for cert in apk.get_certificates()
        ][:limit]
    if dex_strings:
        out["dex_strings"] = _apk_dex_strings(apk, limit)
    return out


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
    out["dex_files"] = sorted(out["dex_files"])[:limit]
    out["native_libs"] = sorted(out["native_libs"])[:limit]
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


def carve_payloads(path: str, out_dir: str) -> dict[str, Any]:
    """Write each embedded payload found in the file to ``out_dir``.

    A packed dropper's real payload is invisible to every rule in the corpus
    until it is carved out — the rules only ever see the outer shell, which by
    construction matches nothing. The carved children are written with 0o600
    so a staging directory shared with a tool server does not widen who can
    read the sample.
    """
    target = Path(path)
    if not target.is_file():
        return _no_file(path, "carve_payloads")
    destination = Path(out_dir)
    try:
        destination.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"error": f"cannot create {out_dir}: {exc}", "tool": "carve_payloads"}

    from maljan.extractors.pe_extractor import carve_payloads as _carve

    payloads: list[dict[str, Any]] = []
    for label, blob in _carve(target.read_bytes()):
        digest = hashlib.sha256(blob).hexdigest()
        name = f"{label.replace('+', '_').replace(':', '_')}_{digest[:12]}"
        child = destination / name
        child.write_bytes(blob)
        child.chmod(0o600)
        offset = 0
        if "+0x" in label:
            try:
                offset = int(label.split("+0x", 1)[1], 16)
            except ValueError:
                offset = 0
        payloads.append(
            {
                "name": label,
                "offset": offset,
                "sha256": digest,
                "size": len(blob),
                "path": str(child),
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
        return {
            "format": "ole2",
            "error": "olefile is not installed",
            "degraded": "magic-level facts only",
            "macros_present": b"VBA" in blob or b"Macros" in blob,
        }
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
