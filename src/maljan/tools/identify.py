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
_MACHO_FAT64_MAGIC = b"\xca\xfe\xba\xbf"
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
    if blob[:4] in (*_MACHO_THIN_MAGICS, _MACHO_FAT_MAGIC, _MACHO_FAT64_MAGIC):
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
            "thumbprint": info.signer_thumbprint,
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
    """Whether the Mach-O carries LC_CODE_SIGNATURE: the thin header, or each slice of a fat one.

    ``present`` is ``True`` when a header (one slice of a fat binary is
    enough) carries the load command, ``False`` only when every header was
    walked to its end without one, and ``None`` with a ``reason`` when a
    header could not be walked whole: a header this tool did not read is not
    reported unsigned. A fat binary also lists each slice's answer.
    """
    if blob[:4] in (_MACHO_FAT_MAGIC, _MACHO_FAT64_MAGIC):
        return _fat_macho_signing(blob)
    return _thin_macho_signing(blob, 0, len(blob))


def _fat_macho_signing(blob: bytes) -> dict[str, Any]:
    """Each slice's answer, and the container's from them.

    Linear by construction, with no cap: the slices are sorted by offset and
    a fat header whose slices overlap (two at one offset included) or run
    past the file's end is malformed and nothing is walked. Each walk is then
    held inside its own slice (``_thin_macho_signing``), so the bytes walked
    over all slices are at most the file's size.
    """
    wide = blob[:4] == _MACHO_FAT64_MAGIC
    entry, layout = (32, ">iiQQI") if wide else (20, ">iiIII")
    if len(blob) < 8:
        return _not_a_fat_header("the header is cut short")
    count = int.from_bytes(blob[4:8], "big")
    if 8 + count * entry > len(blob):
        return _not_a_fat_header(f"it lists {count} slices past the file's end")
    if not count:
        return _not_a_fat_header("it lists no slice")
    listed: list[tuple[int, int, int]] = []
    for index in range(count):
        cpu, _sub, offset, size, _align = struct.unpack_from(layout, blob, 8 + index * entry)
        listed.append((int(offset), int(size), int(cpu)))
    ordered = sorted(listed)
    for offset, size, _cpu in ordered:
        if offset + size > len(blob):
            return _not_a_fat_header(f"a slice at {offset} runs past the file's end")
    for (before, size, _cpu), (after, _size, _next) in zip(ordered, ordered[1:], strict=False):
        if after < before + size or after == before:
            return _not_a_fat_header(f"the slices at {before} and {after} overlap")
    slices: list[dict[str, Any]] = []
    for offset, size, cpu in listed:
        answer = _thin_macho_signing(blob, offset, offset + size)
        slices.append({"cputype": cpu, "offset": offset, **answer})
    states = [row["present"] for row in slices]
    if any(state is True for state in states):
        present: bool | None = True
    elif states and all(state is False for state in states):
        present = False
    else:
        present = None
    # ``present`` and ``reason`` before the slices: an answer cut from its
    # end to fit its reader keeps them however many slices follow.
    out: dict[str, Any] = {"present": present}
    if present is None:
        out["reason"] = "a slice's header could not be walked whole"
    out["slices"] = slices
    return out


# What a CAFEBABE file whose fat header does not hold is: it may not be a fat
# Mach-O at all (a Java class file starts with the same four bytes).
NOT_A_FAT_HEADER = "not a fat Mach-O header, or a malformed one"


def _not_a_fat_header(why: str) -> dict[str, Any]:
    return {"present": None, "reason": f"{NOT_A_FAT_HEADER}: {why}"}


# Why a walk stopped before the load commands' end: not "unsigned".
LOAD_COMMANDS_UNREAD = "load commands unread: {why}"


def _thin_macho_signing(blob: bytes, start: int, end: int) -> dict[str, Any]:
    """Walk one thin header's load commands, at ``start`` and inside ``end``, for LC_CODE_SIGNATURE.

    Every command read advances at least 8 bytes and ends inside the slice,
    so the walk reads no more than the slice whatever ``ncmds`` says. The
    first command whose size is under 8 or whose end runs past the slice
    stops it, and that is stated with ``present: None``.
    """
    magic = blob[start : start + 4]
    if magic not in _MACHO_THIN_MAGICS:
        return {"present": None, "reason": "no thin Mach-O header at this offset"}
    little = magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
    sixty_four = magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    endian = "<" if little else ">"
    header_size = 32 if sixty_four else 28
    if end - start < header_size:
        return {"present": None, "reason": "header cut short"}
    ncmds = struct.unpack_from(endian + "I", blob, start + 16)[0]
    cursor = start + header_size
    for _ in range(int(ncmds)):
        if cursor + 8 > end:
            why = "the next command runs past the slice's end"
            return {"present": None, "reason": LOAD_COMMANDS_UNREAD.format(why=why)}
        cmd, cmd_size = struct.unpack_from(endian + "II", blob, cursor)
        if cmd_size < 8:
            why = "a command's size is under 8 bytes"
            return {"present": None, "reason": LOAD_COMMANDS_UNREAD.format(why=why)}
        if cursor + int(cmd_size) > end:
            why = "a command's end runs past the slice's end"
            return {"present": None, "reason": LOAD_COMMANDS_UNREAD.format(why=why)}
        if int(cmd) == _LC_CODE_SIGNATURE:
            return {"present": True, "load_command": "LC_CODE_SIGNATURE"}
        cursor += int(cmd_size)
    return {"present": False}
