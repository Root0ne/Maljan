"""Extract the SampleIdentity block of the MalwareReport.

Inputs that may be available:

- Sample bytes on disk (``sample_path``) — exact hashes, magic bytes, size.
- Sandbox report (CAPEv2 ``target`` block) — file_name, hashes pre-
  computed by the sandbox.

The extractor merges both, preferring locally computed hashes when the
bytes are reachable (cheap & deterministic) and falling back to the
sandbox-reported values otherwise. Optional fuzzy hashes (``ssdeep``,
``tlsh``) are computed when the corresponding library is installed; the
fields are ``None`` otherwise — never crash.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from maljan.core.logger import logger
from maljan.reporting.models import FileHashes, Platform, SampleIdentity, SignatureInfo


def build_sample_identity(
    *,
    sample_path: str | None,
    sandbox_report: dict[str, Any] | None,
    file_hash: str | None,
    file_name: str | None,
) -> SampleIdentity:
    """Assemble a ``SampleIdentity`` from whatever inputs are available.

    ``file_hash`` is the canonical sha256 the pipeline runs under; we treat
    it as authoritative when present and skip recomputing it from disk.
    """
    target = (sandbox_report or {}).get("target", {})
    sandbox_file = target.get("file") if isinstance(target, dict) else {}
    if not isinstance(sandbox_file, dict):
        sandbox_file = {}

    name = (
        file_name or sandbox_file.get("name") or (Path(sample_path).name if sample_path else None)
    )

    bytes_blob: bytes | None = None
    file_size = int(sandbox_file.get("size") or 0)
    magic_bytes = ""
    file_type = "unknown"
    mime_type: str | None = (
        sandbox_file.get("type") if isinstance(sandbox_file.get("type"), str) else None
    )

    if sample_path:
        try:
            path = Path(sample_path)
            if path.exists() and path.is_file():
                bytes_blob = path.read_bytes()
                if not file_size:
                    file_size = len(bytes_blob)
                magic_bytes = bytes_blob[:16].hex()
                file_type = _detect_file_type(path, bytes_blob)
                mime_type = mime_type or _guess_mime(path)
        except OSError as exc:
            logger.warning("sample_identity: could not read %s (%s)", sample_path, exc)

    hashes = _compute_hashes(
        bytes_blob=bytes_blob,
        sha256_override=file_hash or sandbox_file.get("sha256"),
        sandbox_file=sandbox_file,
    )

    compile_ts = _extract_compile_timestamp(bytes_blob)
    language = _detect_language_or_compiler(bytes_blob)
    signing = _extract_signing(bytes_blob)
    platform = _infer_platform(file_type, mime_type, sandbox_report)

    return SampleIdentity(
        hashes=hashes,
        file_name=name,
        file_size_bytes=file_size,
        file_type=file_type,
        platform=platform,
        mime_type=mime_type,
        magic_bytes=magic_bytes,
        compile_timestamp=compile_ts,
        language_or_compiler=language,
        signing=signing,
    )


def _infer_platform(
    file_type: str,
    mime_type: str | None,
    sandbox_report: dict[str, Any] | None,
) -> Platform:
    """Map file_type / sandbox hints to the canonical Platform taxonomy.

    Strategy: file_type FIRST (magic-byte-derived, deterministic), then a
    best-effort sandbox-hint fallback when file_type didn't disambiguate.
    A misrouted sandbox therefore can't poison the inference — magic bytes win.

    OS-support scope (2026-06-02): only ``windows`` and ``linux`` are recognized;
    every other executable format resolves to ``unknown`` — the pipeline does
    not support those platforms.
    """
    ft = (file_type or "").lower()
    if ft == "pe":
        return "windows"
    if ft == "elf":
        return "linux"

    # Sandbox fallback when file_type is "unknown" or generic "zip".
    target = (sandbox_report or {}).get("target", {})
    if isinstance(target, dict):
        sandbox_os = str(target.get("os") or target.get("platform") or "").lower()
        if "windows" in sandbox_os or sandbox_os.startswith("win"):
            return "windows"
        if "linux" in sandbox_os or "ubuntu" in sandbox_os or "debian" in sandbox_os:
            return "linux"

    # MIME hint as last resort.
    mime = (mime_type or "").lower()
    if "msdownload" in mime or "x-msdos-program" in mime:
        return "windows"

    return "unknown"


def _compute_hashes(
    *,
    bytes_blob: bytes | None,
    sha256_override: str | None,
    sandbox_file: dict[str, Any],
) -> FileHashes:
    """Compute hashes from bytes when available, otherwise trust the sandbox."""
    if bytes_blob is not None:
        # MD5 and SHA1 below are sample fingerprints (VirusTotal, MalwareBazaar,
        # MISP all index by them); they are NOT used as cryptographic
        # signatures. ``usedforsecurity=False`` is the canonical Python opt-out
        # but Semgrep's default rule doesn't recognise it — we suppress here
        # rather than weaken the fingerprint set.
        return FileHashes(
            md5=hashlib.md5(
                bytes_blob, usedforsecurity=False
            ).hexdigest(),  # nosemgrep: insecure-hash-algorithm-md5
            sha1=hashlib.sha1(
                bytes_blob, usedforsecurity=False
            ).hexdigest(),  # nosemgrep: insecure-hash-algorithm-sha1
            sha256=(sha256_override or hashlib.sha256(bytes_blob).hexdigest()),
            sha512=hashlib.sha512(bytes_blob).hexdigest(),
            imphash=_safe_imphash(bytes_blob),
            ssdeep=_safe_ssdeep(bytes_blob),
            tlsh=_safe_tlsh(bytes_blob),
        )

    return FileHashes(
        md5=sandbox_file.get("md5"),
        sha1=sandbox_file.get("sha1"),
        sha256=sha256_override or sandbox_file.get("sha256") or "unknown",
        sha512=sandbox_file.get("sha512"),
        imphash=sandbox_file.get("imphash"),
        ssdeep=sandbox_file.get("ssdeep"),
        tlsh=sandbox_file.get("tlsh"),
    )


def _detect_file_type(path: Path, blob: bytes) -> str:
    """Return a short label such as ``PE32``, ``ELF``, ``Mach-O``, ``ZIP``."""
    if len(blob) >= 2 and blob[:2] == b"MZ":
        return "PE"
    if len(blob) >= 4 and blob[:4] == b"\x7fELF":
        return "ELF"
    if len(blob) >= 4 and blob[:4] in (
        b"\xca\xfe\xba\xbe",
        b"\xfe\xed\xfa\xce",
        b"\xcf\xfa\xed\xfe",
    ):
        return "Mach-O"
    if len(blob) >= 4 and blob[:4] == b"PK\x03\x04":
        suffix = path.suffix.lower()
        if suffix in {".apk", ".jar", ".ipa", ".zip"}:
            return f"ZIP/{suffix.lstrip('.').upper()}"
        return "ZIP"
    if len(blob) >= 4 and blob[:4] == b"%PDF":
        return "PDF"
    return "unknown"


# OS-support scope (2026-06-02): Windows + Linux only. A sample whose magic bytes
# or extension identify a foreign (non-Win/Linux) executable format is rejected at
# the pipeline entry (see ``app.arun`` / ``UnsupportedSampleError``) rather than
# routed to an unsupported sandbox. Magic bytes are authoritative; the extension
# set is the fallback for foreign formats without a distinctive header. Reasons
# name the file FORMAT, not the OS, so the rejection stays diagnostic.
_FOREIGN_FILE_TYPES: dict[str, str] = {
    "mach-o": "unsupported format (Mach-O)",
    "zip/apk": "unsupported format (APK)",
    "zip/ipa": "unsupported format (IPA)",
}
_FOREIGN_EXTENSIONS: dict[str, str] = {
    ".apk": "unsupported format (.apk)",
    ".dex": "unsupported format (.dex)",
    ".ipa": "unsupported format (.ipa)",
    ".dmg": "unsupported format (.dmg)",
    ".pkg": "unsupported format (.pkg)",
    ".app": "unsupported format (.app)",
    ".scpt": "unsupported format (.scpt)",
}


def unsupported_os_reason(sample_path: str | Path | None) -> str | None:
    """Return a human reason when the sample targets an unsupported OS, else None.

    Windows + Linux are the only supported targets. Magic bytes are checked first
    (authoritative — only the 16-byte header is read, never the whole file); the
    extension set is a fallback for foreign types that lack a distinctive header
    (.dex/.dmg/.pkg/.app/.scpt). Only *definitely-foreign* samples trip this — a
    renamed or obscure Windows file (unknown magic + non-foreign extension) is
    NOT rejected, so legitimate Win/Linux analysis is never blocked.
    """
    if not sample_path:
        return None
    path = Path(sample_path)
    try:
        if not path.is_file():
            return None  # phantom path -> nothing to reject; metadata-only path handles it
        with path.open("rb") as fh:
            header = fh.read(16)
    except OSError:
        return None
    reason = _FOREIGN_FILE_TYPES.get(_detect_file_type(path, header).lower())
    if reason:
        return reason
    return _FOREIGN_EXTENSIONS.get(path.suffix.lower())


def _guess_mime(path: Path) -> str | None:
    """Use ``filetype`` if available, otherwise rough suffix-based mapping."""
    try:
        import filetype  # type: ignore[import-not-found]

        kind = filetype.guess(str(path))
        if kind is not None:
            mime = kind.mime
            return str(mime) if mime is not None else None
    except Exception:  # noqa: BLE001
        pass
    return None


def _extract_compile_timestamp(blob: bytes | None) -> datetime | None:
    """Read the PE ``TimeDateStamp`` field (when applicable) as aware UTC."""
    if blob is None or len(blob) < 64 or blob[:2] != b"MZ":
        return None
    try:
        import pefile  # type: ignore[import-not-found]

        pe = pefile.PE(data=blob, fast_load=True)
        ts = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)
        if ts and 946684800 <= ts < 4102444800:  # plausibility window 2000-2100
            return datetime.fromtimestamp(int(ts), tz=UTC)
    except Exception:  # noqa: BLE001
        return None
    return None


# MSVC MajorLinkerVersion → Visual Studio product family.
_MSVC_LINKER: dict[int, str] = {
    6: "6.0",
    7: "2002/2003",
    8: "2005",
    9: "2008",
    10: "2010",
    11: "2012",
    12: "2013",
    14: "2015-2022",
}


def _detect_language_or_compiler(blob: bytes | None) -> str | None:
    """Compiler / runtime fingerprint.

    2026-07 round 2: the previous version only matched six literal byte markers
    and returned "unknown" for ordinary MSVC PEs (the toolchain evidence lives in
    the PE Rich header + linker version + import DLLs, none of which it read).
    We keep the fast byte-signature path for packers/scripting runtimes, then
    fall back to a real PE fingerprint (Rich header, linker version, MFC/MSVCP/
    MinGW/Python import heuristics).
    """
    if not blob:
        return None
    # Fast path — packer / scripting-runtime markers.
    head = blob[: 4 * 1024]
    if b"Go build ID" in head or b"GoStringer" in blob[: 64 * 1024]:
        return "Go"
    if b".pyz" in head or b"PYZ-00.pyz" in blob[: 64 * 1024]:
        return "Python (PyInstaller)"
    if b"UPX!" in blob[: 64 * 1024]:
        return "C/C++ (UPX packed)"
    if b"rustc" in blob[: 64 * 1024]:
        return "Rust"
    # PE-format fingerprint (MSVC/MFC/MinGW).
    pe_guess = _pe_compiler_fingerprint(blob)
    if pe_guess:
        return pe_guess
    # Legacy literal fallbacks.
    if b"Microsoft Visual C++" in blob[: 64 * 1024]:
        return "Microsoft Visual C++"
    if b"GCC: (" in blob[: 64 * 1024]:
        return "GCC"
    return None


def _pe_compiler_fingerprint(blob: bytes) -> str | None:
    """Derive a compiler string from PE Rich header / linker version / imports."""
    if len(blob) < 64 or blob[:2] != b"MZ":
        return None
    try:
        import pefile  # type: ignore[import-not-found]

        pe = pefile.PE(data=blob, fast_load=False)
    except Exception:  # noqa: BLE001
        return None

    dlls: set[str] = set()
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            try:
                dlls.add(entry.dll.decode("latin1").lower())
            except Exception:  # noqa: BLE001
                continue

    if any("libgcc" in d or "mingw" in d or "cygwin" in d for d in dlls):
        return "MinGW / GCC"
    py_dll = next((d for d in dlls if d.startswith("python") and d.endswith(".dll")), None)
    if py_dll:
        return f"Python (embedded {py_dll})"

    is_mfc = any(d.startswith("mfc") for d in dlls)
    is_cpp = is_mfc or any(d.startswith("msvcp") for d in dlls)
    has_rich = False
    try:
        has_rich = bool(pe.parse_rich_header())
    except Exception:  # noqa: BLE001
        has_rich = False
    major = int(getattr(pe.OPTIONAL_HEADER, "MajorLinkerVersion", 0) or 0)

    if is_mfc or is_cpp or has_rich or major >= 6:
        ver = _MSVC_LINKER.get(major)
        base = f"Microsoft Visual C++ {ver}" if ver else "Microsoft Visual C++"
        lang = "C++" if is_cpp else "C/C++"
        suffix = " (MFC)" if is_mfc else ""
        return f"{base} ({lang}){suffix}"
    return None


def _extract_signing(blob: bytes | None) -> SignatureInfo:
    """Best-effort PE Authenticode probe — no verification, just metadata."""
    info = SignatureInfo()
    if blob is None or len(blob) < 1024 or blob[:2] != b"MZ":
        return info
    try:
        import pefile  # type: ignore[import-not-found]

        pe = pefile.PE(data=blob, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        )
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        if security_dir.Size and security_dir.VirtualAddress:
            info.is_signed = True
            # Subject / issuer extraction needs ASN.1 parsing; surface the
            # presence flag here and let an enrichment step fill the names.
    except Exception:  # noqa: BLE001
        pass
    return info


def _safe_imphash(blob: bytes) -> str | None:
    if blob[:2] != b"MZ":
        return None
    try:
        import pefile  # type: ignore[import-not-found]

        pe = pefile.PE(data=blob, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        digest = pe.get_imphash()
        return str(digest) if digest else None
    except Exception:  # noqa: BLE001
        return None


def _safe_ssdeep(blob: bytes) -> str | None:
    try:
        import ssdeep  # type: ignore[import-not-found]

        digest = ssdeep.hash(blob)
        return str(digest) if digest else None
    except Exception:  # noqa: BLE001
        return None


def _safe_tlsh(blob: bytes) -> str | None:
    if len(blob) < 256:  # tlsh requires at least 256 bytes of input
        return None
    try:
        import tlsh  # type: ignore[import-not-found]

        digest = tlsh.hash(blob)
        return str(digest) if digest else None
    except Exception:  # noqa: BLE001
        return None
