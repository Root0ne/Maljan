"""What a file is, what it hashes to, and whether anything signed it.

The three cheapest questions about a sample, and the three an agent asks
first. The detection tables themselves stay in
``extractors/sample_identity`` — that module is the report's own identity
extractor and owns the magic prefixes, the zip-container probe and the
platform inference — so this is the tool-shaped view over them rather than a
second copy that could disagree about what a ``.jar`` is.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path
from typing import Any

from maljan.extractors.sample_identity import (
    _extract_signing,
    _guess_mime,
    _safe_imphash,
    _safe_ssdeep,
    _safe_tlsh,
    detect_file_type,
    file_type_category,
    infer_platform,
)

# How much of a file the magic-byte probes need. The ISO probe reads at
# offset 32769, which is the deepest of them.
_HEADER_BYTES = 40960

# APK signature-scheme block ids, as they appear in the APK Signing Block that
# sits between the last zip entry and the central directory.
_APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
_APK_SCHEME_IDS: dict[int, str] = {
    0x7109871A: "v2",
    0xF05368C0: "v3",
    0x1B93AD61: "v3.1",
}

_MACHO_THIN_MAGICS = (
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
)
_MACHO_FAT_MAGIC = b"\xca\xfe\xba\xbe"
# LC_CODE_SIGNATURE. The presence of the load command is the fact this tool
# reports; validating the blob is a different job and needs the whole chain.
_LC_CODE_SIGNATURE = 0x1D


def identify_file(path: str) -> dict[str, Any]:
    """The format, platform, mime type, size and leading magic bytes.

    ``category`` is the coarse family the routing layer uses (``executable``,
    ``document``, ``archive``, ...), so an agent can branch on it without
    having to know every value ``file_type`` can take.
    """
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {path}", "tool": "identify_file"}
    with target.open("rb") as fh:
        header = fh.read(_HEADER_BYTES)
    size = target.stat().st_size
    mime = _guess_mime(target)
    file_type = detect_file_type(target, header)
    return {
        "file_type": file_type,
        "platform": infer_platform(file_type, mime, None),
        "mime": mime,
        "size": size,
        "magic_hex": header[:16].hex(),
        "category": file_type_category(file_type),
    }


def hashes(path: str) -> dict[str, Any]:
    """Every fingerprint this environment can compute for the file.

    The cryptographic three are always present. ``ssdeep``, ``tlsh``,
    ``imphash`` and ``telfhash`` need an optional library or a matching
    format, and each is simply absent from the result when it is unavailable —
    a missing key is "could not compute", never "computed as nothing".
    """
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {path}", "tool": "hashes"}
    blob = target.read_bytes()
    # MD5 and SHA1 here are sample fingerprints — VirusTotal, MalwareBazaar
    # and MISP all index by them — never signatures.
    out: dict[str, Any] = {
        "md5": hashlib.md5(  # nosemgrep: insecure-hash-algorithm-md5
            blob, usedforsecurity=False
        ).hexdigest(),
        # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
        "sha1": hashlib.sha1(blob, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(blob).hexdigest(),
    }
    for key, value in (
        ("ssdeep", _safe_ssdeep(blob)),
        ("tlsh", _safe_tlsh(blob)),
        ("imphash", _safe_imphash(blob)),
        ("telfhash", _safe_telfhash(str(target), blob)),
    ):
        if value:
            out[key] = value
    return out


def _safe_telfhash(path: str, blob: bytes) -> str | None:
    """telfhash for an ELF, when the library is installed. Never raises."""
    if blob[:4] != b"\x7fELF":
        return None
    try:
        import telfhash  # type: ignore[import-not-found]

        rows = telfhash.telfhash(path)
    except Exception:  # noqa: BLE001 — an optional hash never costs a result
        return None
    if not rows:
        return None
    digest = rows[0].get("telfhash") if isinstance(rows[0], dict) else None
    return str(digest) if digest else None


# The one code-signing scheme each routed format has, by the routing label
# the pipeline uses. A format that is not here has none that this tool looks
# for, which is a fact about the format rather than about the sample.
_SIGNING_SCHEMES: dict[str, str] = {
    "pe": "authenticode",
    "apk": "apk",
    "mach-o": "macho",
    "macho": "macho",
}


def _routed_scheme(file_type: str | None, target: Path, blob: bytes) -> tuple[str, str | None]:
    """The format this sample was routed as, and the scheme it is signed under.

    The caller's routing answer decides, because it is the answer the rest of
    the run is built on. Only when there is none does the tool read the bytes
    itself — an agent may call this directly, with nothing but a path.
    """
    routed = (file_type or "").strip().lower()
    if routed:
        return routed, _SIGNING_SCHEMES.get(routed)
    if blob[:2] == b"MZ":
        return "pe", "authenticode"
    if blob[:4] in _MACHO_THIN_MAGICS or blob[:4] == _MACHO_FAT_MAGIC:
        return "mach-o", "macho"
    if _looks_like_an_apk(target):
        return "apk", "apk"
    return "unknown", None


def _looks_like_an_apk(target: Path) -> bool:
    """A zip is not an APK. A zip holding an Android manifest is."""
    if not zipfile.is_zipfile(target):
        return False
    try:
        with zipfile.ZipFile(target) as archive:
            names = {name.lower() for name in archive.namelist()}
    except Exception:  # noqa: BLE001 — a broken zip is a fact, not a failure
        return False
    return "androidmanifest.xml" in names or "classes.dex" in names


def signing_info(path: str, file_type: str | None = None) -> dict[str, Any]:
    """Whether the file carries a code signature, for the format it was routed as.

    One answer, about this sample. The three schemes used to be reported
    together, so a PE carried "apk present=no" and "macho present=no" beside
    the one row that was about it — two statements about what this tool
    looks for, read by every consumer as two findings about the sample. A
    format with no signing scheme this tool checks says so with
    ``applicable: False`` rather than with three absences.

    Presence only, and deliberately so. Verifying an Authenticode chain, an
    APK v2 block or a Mach-O signature each needs a trust store this process
    does not have, and a tool that reported "signed" when it means "carries a
    signature blob" would be reporting a verdict it never checked.
    """
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {path}", "tool": "signing_info"}
    blob = target.read_bytes()
    routed, scheme = _routed_scheme(file_type, target, blob)
    out: dict[str, Any] = {"format": routed}
    if scheme == "authenticode":
        info = _extract_signing(blob)
        out["authenticode"] = {
            "present": bool(info.is_signed),
            "subject": info.signer_subject,
            "issuer": info.signer_issuer,
        }
    elif scheme == "apk":
        out["apk"] = _apk_signing(target, blob)
    elif scheme == "macho":
        out["macho"] = _macho_signing(blob)
    else:
        out["applicable"] = False
    return out


def _apk_signing(target: Path, blob: bytes) -> dict[str, Any]:
    """v1 cert files from the zip directory, v2/v3 from the signing block."""
    schemes: list[str] = []
    certs: list[str] = []
    try:
        with zipfile.ZipFile(target) as archive:
            names = archive.namelist()
    except Exception:  # noqa: BLE001 — a broken zip is a fact, not a failure
        names = []
    for name in names:
        lowered = name.lower()
        if lowered.startswith("meta-inf/") and lowered.endswith((".rsa", ".dsa", ".ec")):
            certs.append(name)
    if certs:
        schemes.append("v1")
    schemes.extend(_apk_block_schemes(blob))
    return {"present": bool(schemes), "schemes": schemes, "cert_files": sorted(certs)}


def _apk_block_schemes(blob: bytes) -> list[str]:
    """Scheme ids inside the APK Signing Block, if there is one.

    The block opens with its own size, then the id-value pairs, then that same
    size again and the 16-byte magic, immediately before the zip central
    directory. Finding the magic from the tail is enough to locate it without
    parsing the whole archive.

    The size counts everything after the leading size field, so the first pair
    begins eight bytes past the block's start. Reading it at the start instead
    means the leading size field is taken for a pair length, the walk falls out
    of step and no scheme id is ever recognised — which reports every APK
    signed only with v2/v3, that is to say every modern APK, as unsigned.
    """
    marker = blob.rfind(_APK_SIG_BLOCK_MAGIC)
    if marker < 24:
        return []
    try:
        block_size = struct.unpack_from("<Q", blob, marker - 8)[0]
    except struct.error:
        return []
    start = marker + len(_APK_SIG_BLOCK_MAGIC) - 8 - int(block_size)
    if start < 8 or start >= marker:
        return []
    try:
        declared = struct.unpack_from("<Q", blob, start)[0]
    except struct.error:
        return []
    if declared != block_size:
        # The two size fields are one number written twice. When they
        # disagree, the magic was not a block footer and there is nothing
        # here to read.
        return []
    pairs_end = marker - 8
    found: list[str] = []
    cursor = start + 8
    while cursor + 12 <= pairs_end:
        try:
            pair_len, pair_id = struct.unpack_from("<QI", blob, cursor)
        except struct.error:
            break
        if pair_len < 4 or cursor + 8 + pair_len > pairs_end:
            break
        name = _APK_SCHEME_IDS.get(int(pair_id))
        if name and name not in found:
            found.append(name)
        cursor += 8 + int(pair_len)
    return found


def _macho_signing(blob: bytes) -> dict[str, Any]:
    """Walk the thin header's load commands looking for LC_CODE_SIGNATURE."""
    if blob[:4] == _MACHO_FAT_MAGIC:
        # A fat binary's slices each carry their own header; reporting the
        # container as unknown is honest, and ``macho_info`` is the tool that
        # actually walks the slices.
        return {"present": False, "reason": "fat binary; inspect each slice"}
    little = blob[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
    sixty_four = blob[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    endian = "<" if little else ">"
    header_size = 32 if sixty_four else 28
    if len(blob) < header_size:
        return {"present": False}
    try:
        ncmds = struct.unpack_from(endian + "I", blob, 16)[0]
    except struct.error:
        return {"present": False}
    cursor = header_size
    for _ in range(min(int(ncmds), 4096)):
        if cursor + 8 > len(blob):
            break
        try:
            cmd, cmd_size = struct.unpack_from(endian + "II", blob, cursor)
        except struct.error:
            break
        if cmd_size < 8:
            break
        if int(cmd) == _LC_CODE_SIGNATURE:
            return {"present": True, "load_command": "LC_CODE_SIGNATURE"}
        cursor += int(cmd_size)
    return {"present": False}
