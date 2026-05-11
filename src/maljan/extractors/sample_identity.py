"""Extract the SampleIdentity block of the MalwareReport.

Inputs that may be available:

- Sample bytes on disk (``sample_path``) — exact hashes, magic bytes, size.
- Sandbox report (Triage / CAPE normalised dict) — file_name, hashes pre-
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
from maljan.reporting.models import FileHashes, SampleIdentity, SignatureInfo


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

    return SampleIdentity(
        hashes=hashes,
        file_name=name,
        file_size_bytes=file_size,
        file_type=file_type,
        mime_type=mime_type,
        magic_bytes=magic_bytes,
        compile_timestamp=compile_ts,
        language_or_compiler=language,
        signing=signing,
    )


def _compute_hashes(
    *,
    bytes_blob: bytes | None,
    sha256_override: str | None,
    sandbox_file: dict[str, Any],
) -> FileHashes:
    """Compute hashes from bytes when available, otherwise trust the sandbox."""
    if bytes_blob is not None:
        # MD5 and SHA1 below are sample fingerprints (VirusTotal, MalwareBazaar,
        # Triage, MISP all index by them); they are NOT used as cryptographic
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


def _detect_language_or_compiler(blob: bytes | None) -> str | None:
    """Lightweight compiler / runtime fingerprint from binary signatures."""
    if not blob:
        return None
    # Look at the first 4 KB for common toolchain markers.
    head = blob[: 4 * 1024]
    if b"Go build ID" in head or b"GoStringer" in blob[: 64 * 1024]:
        return "Go"
    if b".pyz" in head or b"PYZ-00.pyz" in blob[: 64 * 1024]:
        return "Python (PyInstaller)"
    if b"UPX!" in blob[: 64 * 1024]:
        return "C/C++ (UPX packed)"
    if b"Microsoft Visual C++" in blob[: 64 * 1024]:
        return "Microsoft Visual C++"
    if b"GCC: (" in blob[: 64 * 1024]:
        return "GCC"
    if b"rustc" in blob[: 64 * 1024]:
        return "Rust"
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
