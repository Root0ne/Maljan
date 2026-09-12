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
import io
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
    platform = _infer_platform(file_type, mime_type, sandbox_report, language)

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
    language_or_compiler: str | None = None,
) -> Platform:
    """Map file_type / sandbox hints to the canonical platform vocabulary.

    Strategy: file_type FIRST (magic-byte-derived, deterministic), then a
    best-effort sandbox-hint fallback when file_type didn't disambiguate.
    A misrouted sandbox therefore can't poison the inference — magic bytes win.

    No format resolves to a rejection: a type this table does not name simply
    stays ``unknown``, which the rule layers treat as fall-open.
    """
    ft = (file_type or "").lower()
    mapped = PLATFORM_BY_FILE_TYPE.get(ft)
    # A format that binds to one OS is the end of the question. ``multi`` is
    # not: a macro document or a JAR runs anywhere, and the guest it was
    # detonated on is real information about which one it ran on here. So a
    # ``multi`` mapping falls through to the hints below and is only the answer
    # when nothing else says otherwise.
    if mapped and mapped != "multi":
        return mapped

    # Sandbox fallback when file_type is "unknown", cross-platform, or a
    # generic container.
    target = (sandbox_report or {}).get("target", {})
    if isinstance(target, dict):
        sandbox_os = str(target.get("os") or target.get("platform") or "").lower()
        for needle, platform in _SANDBOX_OS_HINTS:
            if needle in sandbox_os:
                return platform
        if sandbox_os.startswith("win"):
            return "windows"

    # MIME hint as last resort.
    mime = (mime_type or "").lower()
    for needle, platform in _MIME_HINTS:
        if needle in mime:
            return platform

    if mapped:
        return mapped

    # Toolchain hint, last of all, and only over an ``unknown`` platform. This
    # matters more than its position suggests: ``unknown`` is not a neutral
    # answer downstream — ``_yara_rule_compatible`` drops *every*
    # platform-specific rule for an unknown platform, and Sigma does the same,
    # so an unidentified blob is scanned by a fraction of the corpus. A
    # confident Windows-only toolchain fingerprint is enough to restore that
    # coverage, and only Windows-exclusive runtimes are listed — Go and Rust
    # are cross-platform and say nothing about the target.
    lang = (language_or_compiler or "").lower()
    if any(
        marker in lang
        for marker in ("autoit", ".net", "c#", "delphi", "visual c++", "py2exe", "mfc")
    ):
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
            # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
            sha1=hashlib.sha1(bytes_blob, usedforsecurity=False).hexdigest(),
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


# Magic-byte prefixes that identify a format on their own, longest first so a
# prefix never shadows a longer one that starts with the same bytes.
_MAGIC_PREFIXES: tuple[tuple[bytes, str], ...] = (
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\x7fELF", "elf"),
    (b"%PDF", "pdf"),
    (b"dex\n", "dex"),
    (b"BZh", "bz2"),
    (b"MZ", "pe"),
    (b"\x1f\x8b", "gz"),
)

# Mach-O thin headers: 32/64-bit, big- and little-endian.
_MACHO_THIN_MAGICS: frozenset[bytes] = frozenset(
    {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}
)

# A Mach-O fat binary and a Java class file share the 0xCAFEBABE magic. The
# next four bytes tell them apart: a fat header counts its architectures (a
# handful), a class file carries its minor/major version, which as a 32-bit
# big-endian integer is at least 45.
_MACHO_FAT_MAGIC = b"\xca\xfe\xba\xbe"
_MACHO_FAT_MAX_ARCHS = 16

# A Windows shortcut: the 76-byte header length followed by the LNK class id.
_LNK_MAGIC = b"\x4c\x00\x00\x00\x01\x14\x02\x00"

# ZIP local file header, plus the empty and spanned central-directory variants.
_ZIP_MAGICS: frozenset[bytes] = frozenset({b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"})

# ISO 9660 writes its volume descriptor identifier at this fixed offset.
_ISO_MAGIC_OFFSET = 32769
_ISO_MAGIC = b"CD001"

# Interpreters named on a shebang line, and the type each one gives the file.
_SHEBANG_TYPES: tuple[tuple[str, str], ...] = (
    ("python", "py"),
    ("perl", "pl"),
    ("pwsh", "ps1"),
    ("powershell", "ps1"),
    ("bash", "sh"),
    ("zsh", "sh"),
    ("dash", "sh"),
    ("ksh", "sh"),
    ("/sh", "sh"),
    ("env sh", "sh"),
)

# Formats with no distinctive header, recognised by their extension alone.
_EXTENSION_TYPES: dict[str, str] = {
    ".ps1": "ps1",
    ".psm1": "ps1",
    ".bat": "bat",
    ".cmd": "cmd",
    ".vbs": "vbs",
    ".vbe": "vbs",
    ".js": "js",
    ".jse": "js",
    ".hta": "hta",
    ".wsf": "wsf",
    ".sh": "sh",
    ".py": "py",
    ".pl": "pl",
    ".iso": "iso",
}

# Entries that identify what a ZIP container really is, in the order they are
# looked for: an APK also carries META-INF/MANIFEST.MF, so ``jar`` must lose to
# ``apk`` rather than win by arriving first.
_ZIP_SIGNATURE_ENTRIES: tuple[tuple[str, str], ...] = (
    ("AndroidManifest.xml", "apk"),
    ("classes.dex", "apk"),
    ("[Content_Types].xml", "ooxml"),
    ("META-INF/MANIFEST.MF", "jar"),
)

# Every container format, grouped under the one word an operator routes on.
ARCHIVE_FILE_TYPES: frozenset[str] = frozenset({"zip", "7z", "rar", "gz", "bz2", "xz", "iso"})
DOCUMENT_FILE_TYPES: frozenset[str] = frozenset({"ole2", "ooxml", "pdf"})
SCRIPT_FILE_TYPES: frozenset[str] = frozenset(
    {"ps1", "bat", "cmd", "vbs", "js", "hta", "wsf", "sh", "py", "pl"}
)

# The platform each recognised file type binds the sample to. A format that
# runs anywhere (a JAR, a macro document, a PDF) is "multi"; a container that
# says nothing about its payload stays "unknown".
PLATFORM_BY_FILE_TYPE: dict[str, Platform] = {
    "pe": "windows",
    "lnk": "windows",
    "ps1": "windows",
    "bat": "windows",
    "cmd": "windows",
    "vbs": "windows",
    "js": "windows",
    "hta": "windows",
    "wsf": "windows",
    "elf": "linux",
    "sh": "linux",
    "mach-o": "macos",
    "apk": "android",
    "dex": "android",
    "ipa": "ios",
    "jar": "multi",
    "ole2": "multi",
    "ooxml": "multi",
    "pdf": "multi",
    "py": "multi",
    "pl": "multi",
}

# Sandbox ``target.os`` / ``target.platform`` substrings. Every entry here is a
# word no other platform's name contains; the bare ``win`` prefix is checked
# separately, after these, because ``"win" in "darwin"`` is true and a macOS
# guest must not read as a Windows one.
_SANDBOX_OS_HINTS: tuple[tuple[str, Platform], ...] = (
    ("windows", "windows"),
    ("darwin", "macos"),
    ("macos", "macos"),
    ("mac os", "macos"),
    ("osx", "macos"),
    ("android", "android"),
    ("ios", "ios"),
    ("iphone", "ios"),
    ("linux", "linux"),
    ("ubuntu", "linux"),
    ("debian", "linux"),
)

_MIME_HINTS: tuple[tuple[str, Platform], ...] = (
    ("msdownload", "windows"),
    ("x-msdos-program", "windows"),
    ("x-dosexec", "windows"),
    ("vnd.android.package-archive", "android"),
    ("x-mach-binary", "macos"),
    ("x-executable", "linux"),
    ("x-sharedlib", "linux"),
)


def file_type_category(file_type: str) -> str:
    """The routing category of a file type: executable, document, script, archive."""
    ft = (file_type or "").lower()
    if ft in ARCHIVE_FILE_TYPES:
        return "archive"
    if ft in DOCUMENT_FILE_TYPES:
        return "document"
    if ft in SCRIPT_FILE_TYPES:
        return "script"
    if ft in {"pe", "elf", "mach-o", "apk", "dex", "ipa", "jar"}:
        return "executable"
    return "unknown"


def _zip_container_type(path: Path, blob: bytes) -> str:
    """What a ZIP container actually is, read from its entry names.

    Falls back to the plain ``zip`` label whenever the archive cannot be
    opened — a truncated header (this function is also called with the first
    sixteen bytes of a file), an encrypted or corrupt archive. Never raises:
    an unreadable container is still a sample worth routing.
    """
    import zipfile

    names: list[str] = []
    try:
        if len(blob) >= 22 and path.is_file() and path.stat().st_size == len(blob):
            with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                names = archive.namelist()
        elif path.is_file():
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
    except (OSError, zipfile.BadZipFile, ValueError, RuntimeError):
        return "zip"

    if not names:
        return "zip"
    lowered = {name.lower() for name in names}
    for entry, label in _ZIP_SIGNATURE_ENTRIES:
        if entry.lower() in lowered:
            return label
    if any(name.startswith("payload/") and ".app/" in name for name in lowered):
        return "ipa"
    return "zip"


def _shebang_type(blob: bytes) -> str | None:
    """The script type named on a shebang line, when the file opens with one."""
    if not blob.startswith(b"#!"):
        return None
    line = blob[:256].split(b"\n", 1)[0].decode("utf-8", "replace").lower()
    for needle, label in _SHEBANG_TYPES:
        if needle in line:
            return label
    # An interpreter this table does not name says nothing about the format —
    # ``#!/usr/bin/env node`` is not a shell script — so the extension table
    # answers instead, and ``unknown`` is better than a wrong label.
    return None


def _detect_file_type(path: Path, blob: bytes) -> str:
    """Return the lowercase routing label for a sample: ``pe``, ``apk``, ``pdf``...

    Magic bytes are authoritative and are read first; the extension table is
    the fallback for the script and image formats that have no distinctive
    header. ``unknown`` is the honest answer for anything else — it routes the
    sample to the neutral analysis path rather than refusing it.
    """
    if len(blob) >= 4:
        head4 = blob[:4]
        if head4 in _MACHO_THIN_MAGICS:
            return "mach-o"
        if head4 == _MACHO_FAT_MAGIC and len(blob) >= 8:
            nfat = int.from_bytes(blob[4:8], "big")
            if 1 <= nfat <= _MACHO_FAT_MAX_ARCHS:
                return "mach-o"
        if head4 in _ZIP_MAGICS:
            return _zip_container_type(path, blob)
    if blob.startswith(_LNK_MAGIC):
        return "lnk"
    for prefix, label in _MAGIC_PREFIXES:
        if blob.startswith(prefix):
            return label
    if len(blob) >= _ISO_MAGIC_OFFSET + len(_ISO_MAGIC) and (
        blob[_ISO_MAGIC_OFFSET : _ISO_MAGIC_OFFSET + len(_ISO_MAGIC)] == _ISO_MAGIC
    ):
        return "iso"
    shebang = _shebang_type(blob)
    if shebang:
        return shebang
    return _EXTENSION_TYPES.get(path.suffix.lower(), "unknown")


# The public name. ``_detect_file_type`` stays for the callers that grew up
# around it; new code across package boundaries reads this one.
def detect_file_type(path: Path, blob: bytes) -> str:
    """Return the lowercase routing label for a sample: ``pe``, ``apk``, ``pdf``..."""
    return _detect_file_type(path, blob)


def infer_platform(
    file_type: str,
    mime_type: str | None = None,
    sandbox_report: dict[str, Any] | None = None,
    language_or_compiler: str | None = None,
) -> Platform:
    """Return the platform a detected file type binds the sample to."""
    return _infer_platform(file_type, mime_type, sandbox_report, language_or_compiler)


# Formats the pipeline accepts but has no format-aware extractor for. No sample
# is refused for its format; the analysis these receive is a raw-byte string
# sweep and nothing else, and saying so is the difference between a thin report
# and a dishonest one.
_UNPARSED_CONTAINER_EXTENSIONS: dict[str, str] = {
    ".doc": "OLE2 document",
    ".docm": "Office macro document",
    ".dotm": "Office macro template",
    ".xls": "OLE2 spreadsheet",
    ".xlsm": "Office macro spreadsheet",
    ".xlsb": "Office binary spreadsheet",
    ".ppt": "OLE2 presentation",
    ".pptm": "Office macro presentation",
    ".rtf": "RTF document",
    ".pdf": "PDF document",
    ".one": "OneNote notebook",
    ".ps1": "PowerShell script",
    ".vbs": "VBScript",
    ".vbe": "encoded VBScript",
    ".js": "JScript",
    ".jse": "encoded JScript",
    ".hta": "HTML application",
    ".wsf": "Windows Script File",
    ".bat": "batch script",
    ".cmd": "batch script",
    ".lnk": "Windows shortcut",
    ".chm": "compiled HTML help",
    ".msi": "Windows Installer package",
    ".jar": "Java archive",
    ".zip": "ZIP archive",
    ".7z": "7-Zip archive",
    ".rar": "RAR archive",
    ".iso": "disc image",
    ".img": "disc image",
    ".vhd": "virtual disk",
}

_UNPARSED_CONTAINER_TYPES: dict[str, str] = {
    "pdf": "PDF document",
    "ole2": "OLE2 document",
    "ooxml": "Office Open XML document",
    "zip": "ZIP archive",
    "jar": "Java archive",
    "apk": "Android package",
    "ipa": "iOS application archive",
    "dex": "Dalvik executable",
    "7z": "7-Zip archive",
    "rar": "RAR archive",
    "gz": "gzip archive",
    "bz2": "bzip2 archive",
    "xz": "xz archive",
    "iso": "disc image",
}


def unparsed_container_reason(sample_path: str | Path | None) -> str | None:
    """Say so when the sample's container was never opened.

    A ``.docm`` is accepted by the upload allow-list — correctly, since macro
    documents are among the most common malware carriers. But
    ``build_static_analysis`` returns
    empty sections, imports and exports for it, and only the raw-byte IOC sweep
    runs. The analysis completes, the report renders, and nothing anywhere says
    that the macro stream — the entire payload — was never read.

    That is the gap this closes. Not by refusing the sample, which would be
    worse, but by returning a degradation reason so the report caps its own
    confidence and states plainly what it did not look at.
    """
    if not sample_path:
        return None
    path = Path(sample_path)
    try:
        if not path.is_file():
            return None
        with path.open("rb") as fh:
            header = fh.read(16)
    except OSError:
        return None

    # A real PE, ELF or Mach-O was parsed properly; nothing to declare.
    detected = _detect_file_type(path, header).lower()
    if detected in {"pe", "elf", "mach-o"}:
        return None

    label = _UNPARSED_CONTAINER_TYPES.get(detected) or _UNPARSED_CONTAINER_EXTENSIONS.get(
        path.suffix.lower()
    )
    if not label:
        return None
    return (
        f"{label} container was not parsed — no format-aware extraction exists for it; "
        "findings come from a raw-byte string sweep only"
    )


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

    The previous version only matched six literal byte markers
    and returned "unknown" for ordinary MSVC PEs (the toolchain evidence lives in
    the PE Rich header + linker version + import DLLs, none of which it read).
    We keep the fast byte-signature path for packers/scripting runtimes, then
    fall back to a real PE fingerprint (Rich header, linker version, MFC/MSVCP/
    MinGW/Python import heuristics).
    """
    if not blob:
        return None

    # Scored signature table. Replaces the six literal checks below, which
    # covered four languages and answered "Rust" to any binary containing the
    # string "rustc" — including, for instance, a scanner carrying Rust
    # signatures. Scoring makes a single suggestive marker insufficient.
    catalog_available, scored = _score_language_signatures(blob)
    if scored:
        return scored

    # PE-format fingerprint (MSVC/MFC/MinGW). Kept ahead of the literal
    # fallbacks and never replaced: the Rich header and linker version identify
    # a toolchain far more precisely than any string table can, and no signature
    # list in this repo has an equivalent.
    pe_guess = _pe_compiler_fingerprint(blob)
    if pe_guess:
        return pe_guess

    # Legacy literal fallbacks — only when there is no catalog to have an
    # opinion. "The catalog scored nothing" is a decision, not a gap, and
    # falling through to a one-substring check would quietly undo the scoring:
    # `rustc` alone scores 1 against a minimum of 3, and then the literal below
    # would call it Rust anyway.
    if catalog_available:
        return None

    head = blob[: 4 * 1024]
    if b"Go build ID" in head or b"GoStringer" in blob[: 64 * 1024]:
        return "Go"
    if b".pyz" in head or b"PYZ-00.pyz" in blob[: 64 * 1024]:
        return "Python (PyInstaller)"
    if b"UPX!" in blob[: 64 * 1024]:
        return "C/C++ (UPX packed)"
    if b"rustc" in blob[: 64 * 1024]:
        return "Rust"
    if b"Microsoft Visual C++" in blob[: 64 * 1024]:
        return "Microsoft Visual C++"
    if b"GCC: (" in blob[: 64 * 1024]:
        return "GCC"
    return None


def _score_language_signatures(blob: bytes) -> tuple[bool, str | None]:
    """Score the sample against the language catalog; highest total wins.

    Returns ``(catalog_available, name)``. The first element matters: the caller
    must distinguish "no catalog to consult" from "the catalog looked and
    declined to name it", because only the first is a reason to fall back to the
    cruder literal checks.

    Strong markers are worth three, weak ones one, and a language must clear its
    own ``min_score`` to be named. That threshold is the difference between
    "this binary mentions Rust" and "this binary is Rust".

    Scans a bounded prefix rather than the whole file: toolchain markers live in
    the runtime stub and the metadata, both near the front, and scanning a
    100 MB installer for them would cost far more than the answer is worth.
    """
    try:
        import json as _json

        from maljan.core.config import get_settings
        from maljan.core.paths import resolve_data

        cfg = get_settings().preprocessing
        if not getattr(cfg, "use_language_signatures", False):
            return False, None
        path = resolve_data(cfg.language_signatures_path)
        if not path.is_file():
            return False, None
        doc = _json.loads(path.read_text(encoding="utf-8"))
        rows = doc.get("languages") if isinstance(doc, dict) else None
        if not isinstance(rows, list) or not rows:
            return False, None
    except Exception:  # noqa: BLE001 — identity must never fail over a catalog
        return False, None

    window = blob[: 4 * 1024 * 1024]
    best_name: str | None = None
    best_score = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        if not isinstance(name, str) or not name:
            continue
        strong = [s for s in (row.get("strong") or []) if isinstance(s, str)]
        weak = [s for s in (row.get("weak") or []) if isinstance(s, str)]
        score = 3 * sum(1 for s in strong if s.encode("utf-8", errors="ignore") in window)
        score += sum(1 for s in weak if s.encode("utf-8", errors="ignore") in window)
        try:
            minimum = int(row.get("min_score", 3))
        except (TypeError, ValueError):
            minimum = 3
        # Strictly greater: ties go to the earlier entry, which is why the
        # catalog is ordered most-specific first.
        if score >= minimum and score > best_score:
            best_score = score
            best_name = name
    return True, best_name


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
