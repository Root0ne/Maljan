"""Static analysis over stdio MCP: identify, strings, structure, rules.

Every tool is a one-line delegation to ``maljan.tools`` — the sidecar runs in
the same uv environment as the pipeline, so it imports the implementation
rather than carrying a copy of it. What this file adds is the two things a
tool server owes a model: an error is *returned*, never raised (an exception
across the MCP boundary ends the call with a stack trace the model cannot act
on), and a tool whose optional library is missing still appears on the
manifest so the model learns why it is empty instead of never seeing the
capability at all.

``put_sample`` implements the remote-delivery convention (see
``maljan.agents.sample_staging``): a caller on another host uploads the bytes
and gets back the path to pass to every other tool here.
"""

from __future__ import annotations

import base64
import hashlib
import os
import stat
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from maljan.tools import binary as binary_tools
from maljan.tools import identify as identify_tools
from maljan.tools import rules as rule_tools
from maljan.tools import strings as string_tools

mcp = FastMCP("AnalysisMCP")

# Chunked uploads in flight, keyed by upload id. Bounded by the number of
# concurrent stagers, which is the number of agents in a profile — but a
# ``put_sample_begin`` whose caller vanished would otherwise hold its chunks
# for the process lifetime, so they are evicted by age as well.
_UPLOADS: dict[str, dict[str, Any]] = {}
_UPLOAD_TTL_SECONDS = 15 * 60

# A chunk larger than this is refused rather than buffered: the convention
# splits at 8 MiB and a caller sending more is not speaking it.
_MAX_CHUNK_BYTES = 16 * 1024 * 1024
# The largest sample this server will accept by either route. A tool server
# reachable over HTTP is a place to post arbitrary bytes, and an unbounded
# accept is an unbounded write.
_MAX_SAMPLE_BYTES = 2 * 1024 * 1024 * 1024

# How long a staged sample is kept. Every ``put_sample*`` call prunes, so a
# long-lived server does not accumulate malware bytes without bound.
_DEFAULT_STAGING_TTL_HOURS = 24.0


def _guard(tool: str, call: Any, **kwargs: Any) -> dict[str, Any]:
    """Run one tool call, turning any exception into a returned error.

    A raised exception reaches the model as a transport-level failure with no
    structure; a returned ``{"error": ...}`` is something it can read and route
    around, which is the difference between an agent that tries another tool
    and one that retries the same broken call until its step budget is gone.
    """
    try:
        return dict(call(**kwargs))
    except Exception as exc:  # noqa: BLE001 — a tool server answers, it does not raise
        return {"error": f"{type(exc).__name__}: {exc}", "tool": tool}


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


@mcp.tool()
def identify_file(path: str) -> dict[str, Any]:
    """Detect a file's format, platform, mime type, size and magic bytes."""
    return _guard("identify_file", identify_tools.identify_file, path=path)


@mcp.tool()
def hashes(path: str) -> dict[str, Any]:
    """Compute md5, sha1, sha256 and any available fuzzy or import hash."""
    return _guard("hashes", identify_tools.hashes, path=path)


@mcp.tool()
def signing_info(path: str) -> dict[str, Any]:
    """Report whether the file carries an Authenticode, APK or Mach-O signature."""
    return _guard("signing_info", identify_tools.signing_info, path=path)


# ---------------------------------------------------------------------------
# Strings
# ---------------------------------------------------------------------------


@mcp.tool()
def strings(
    path: str,
    min_len: int = 6,
    encodings: list[str] | None = None,
    limit: int = 2000,
    offset: int = 0,
) -> dict[str, Any]:
    """List printable ASCII and UTF-16LE runs with their byte offsets."""
    return _guard(
        "strings",
        string_tools.strings,
        path=path,
        min_len=min_len,
        encodings=tuple(encodings or ("ascii", "utf16le")),
        limit=limit,
        offset=offset,
    )


@mcp.tool()
def iocs_from_text(text: str, kinds: list[str] | None = None) -> dict[str, Any]:
    """Extract typed indicators (url, domain, ip, path, secret, ...) from text."""
    return _guard("iocs_from_text", string_tools.iocs_from_text, text=text, kinds=kinds)


@mcp.tool()
def iocs_from_file(path: str, kinds: list[str] | None = None) -> dict[str, Any]:
    """Extract typed indicators from a file's ASCII and wide strings."""
    return _guard("iocs_from_file", string_tools.iocs_from_file, path=path, kinds=kinds)


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


@mcp.tool()
def pe_info(
    path: str,
    sections: bool = True,
    imports: bool = True,
    exports: bool = True,
    resources: bool = True,
    overlay: bool = True,
    pdb: bool = True,
) -> dict[str, Any]:
    """Parse a PE: sections with entropy, imports, exports, resources, overlay, PDB path."""
    return _guard(
        "pe_info",
        binary_tools.pe_info,
        path=path,
        sections=sections,
        imports=imports,
        exports=exports,
        resources=resources,
        overlay=overlay,
        pdb=pdb,
    )


@mcp.tool()
def elf_info(path: str) -> dict[str, Any]:
    """Parse an ELF: sections, imports, exports, segments, interpreter, DT_NEEDED."""
    return _guard("elf_info", binary_tools.elf_info, path=path)


@mcp.tool()
def macho_info(path: str) -> dict[str, Any]:
    """Parse a Mach-O: headers, load commands, dylibs, code-signature presence."""
    return _guard("macho_info", binary_tools.macho_info, path=path)


@mcp.tool()
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
    """Read an APK's manifest, permissions, components, certificates and native libs."""
    return _guard(
        "apk_info",
        binary_tools.apk_info,
        path=path,
        manifest=manifest,
        permissions=permissions,
        certs=certs,
        components=components,
        native_libs=native_libs,
        dex_strings=dex_strings,
        limit=limit,
    )


@mcp.tool()
def carve_payloads(path: str, out_dir: str = "") -> dict[str, Any]:
    """Extract embedded payloads from a file and write them to a directory."""
    destination = out_dir or str(_staging_dir() / "carved")
    return _guard("carve_payloads", binary_tools.carve_payloads, path=path, out_dir=destination)


@mcp.tool()
def archive_list(path: str, limit: int = 500) -> dict[str, Any]:
    """List a zip, 7z, tar or gzip archive's members without extracting them."""
    return _guard("archive_list", binary_tools.archive_list, path=path, limit=limit)


@mcp.tool()
def document_info(path: str) -> dict[str, Any]:
    """Inspect an OLE2, OOXML or PDF document for macros, parts and action markers."""
    return _guard("document_info", binary_tools.document_info, path=path)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@mcp.tool()
def yara_scan(
    path: str = "",
    text: str = "",
    ruleset: str = "default",
    timeout_s: int = 60,
) -> dict[str, Any]:
    """Scan a file or a block of text against a YARA rule corpus."""
    return _guard(
        "yara_scan",
        rule_tools.yara_scan,
        path=path or None,
        text=text or None,
        ruleset=ruleset,
        timeout_s=timeout_s,
    )


@mcp.tool()
def sigma_match(events: list[dict[str, Any]], ruleset: str = "default") -> dict[str, Any]:
    """Match structured events against a Sigma rule corpus."""
    return _guard("sigma_match", rule_tools.sigma_match, events=events, ruleset=ruleset)


@mcp.tool()
def sigma_match_sandbox(report: dict[str, Any], ruleset: str = "default") -> dict[str, Any]:
    """Derive Sysmon-shaped events from a sandbox report and match Sigma rules."""
    return _guard(
        "sigma_match_sandbox", rule_tools.sigma_match_sandbox, report=report, ruleset=ruleset
    )


@mcp.tool()
def capa(path: str, timeout_s: int = 300, backend: str = "auto") -> dict[str, Any]:
    """Run capa and report the capabilities it finds, with ATT&CK and MBC metadata."""
    return _guard("capa", rule_tools.capa, path=path, timeout_s=timeout_s, backend=backend)


# ---------------------------------------------------------------------------
# Sample delivery
# ---------------------------------------------------------------------------


def _staging_ttl_seconds() -> float:
    """``MALJAN_STAGING_TTL_HOURS``, or a day. Zero or less disables pruning."""
    raw = os.environ.get("MALJAN_STAGING_TTL_HOURS", "").strip()
    try:
        hours = float(raw) if raw else _DEFAULT_STAGING_TTL_HOURS
    except ValueError:
        hours = _DEFAULT_STAGING_TTL_HOURS
    return hours * 3600.0


def _staging_dir() -> Path:
    """Where uploaded samples land: ``MALJAN_STAGING_DIR`` or a private temp dir.

    Created with ``mkdir(mode=0o700)`` rather than created-then-chmodded, and
    refused if what is already there is a symlink or belongs to somebody else.
    The default name is predictable and the system temp directory is shared, so
    without those checks another local user could plant a directory or a link
    at that path and receive live malware into a location of their choosing —
    and the chmod would then be applied to their target.
    """
    configured = os.environ.get("MALJAN_STAGING_DIR", "").strip()
    base = Path(configured) if configured else Path(tempfile.gettempdir()) / "maljan-analysis-mcp"
    try:
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
    except FileExistsError as exc:  # a non-directory already sits at that path
        raise RuntimeError(f"staging path {base} is not a directory") from exc
    if base.is_symlink():
        raise RuntimeError(f"staging path {base} is a symlink")
    info = base.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"staging path {base} is not a directory")
    if info.st_uid != os.getuid():
        raise RuntimeError(f"staging path {base} is owned by another user")
    if info.st_mode & 0o077:
        base.chmod(0o700)
    return base


def _prune_staging(base: Path) -> int:
    """Delete staged files past their TTL. Returns how many went.

    Called from every ``put_sample*`` entry point rather than on a timer: this
    server has no scheduler, and the moment a sample arrives is exactly when
    the last one is most likely to be stale.
    """
    ttl = _staging_ttl_seconds()
    if ttl <= 0:
        return 0
    cutoff = time.time() - ttl
    removed = 0
    for entry in base.iterdir():
        try:
            info = entry.lstat()
            if stat.S_ISDIR(info.st_mode) or info.st_mtime >= cutoff:
                continue
            entry.unlink()
            removed += 1
        except OSError:  # a file another call already removed
            continue
    return removed


def _evict_stale_uploads() -> None:
    """Drop chunked uploads whose caller never finished them."""
    cutoff = time.monotonic() - _UPLOAD_TTL_SECONDS
    for upload_id in [k for k, v in _UPLOADS.items() if v.get("started_at", 0.0) < cutoff]:
        _UPLOADS.pop(upload_id, None)


def _write_sample(filename: str, blob: bytes, sha256: str) -> dict[str, Any]:
    """Write the bytes under the staging directory, checking the digest first.

    Created with ``O_CREAT|O_EXCL|O_NOFOLLOW`` at 0o600, not written and then
    chmodded: the two-step form leaves the file readable at the process umask
    for as long as the write takes, and would follow a symlink planted at the
    destination.
    """
    if len(blob) > _MAX_SAMPLE_BYTES:
        return {"error": f"sample exceeds {_MAX_SAMPLE_BYTES} bytes"}
    actual = hashlib.sha256(blob).hexdigest()
    if sha256 and actual != sha256.lower():
        return {"error": f"sha256 mismatch: expected {sha256}, received {actual}"}
    base = _staging_dir()
    _prune_staging(base)
    # The caller's filename names the file, never the directory: a name
    # carrying ``..`` or an absolute prefix must not decide where this writes.
    safe = Path(filename or actual).name or actual
    destination = base / f"{actual[:16]}_{safe}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    if not destination.exists():
        flags |= os.O_EXCL
    fd = os.open(destination, flags, 0o600)
    try:
        os.write(fd, blob)
    finally:
        os.close(fd)
    os.chmod(destination, 0o600)
    return {"path": str(destination), "sha256": actual, "size": len(blob)}


@mcp.tool()
def put_sample(filename: str, content_b64: str, sha256: str = "") -> dict[str, Any]:
    """Upload a sample in one call and get back the path to analyse it at."""
    _evict_stale_uploads()
    try:
        blob = base64.b64decode(content_b64, validate=True)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"content_b64 is not valid base64: {exc}", "tool": "put_sample"}
    return _guard("put_sample", _write_sample, filename=filename, blob=blob, sha256=sha256)


@mcp.tool()
def put_sample_begin(filename: str, sha256: str, size: int) -> dict[str, Any]:
    """Start a chunked upload for a sample too large to send in one call."""
    _evict_stale_uploads()
    declared = int(size)
    if declared < 0 or declared > _MAX_SAMPLE_BYTES:
        return {
            "error": f"declared size must be between 0 and {_MAX_SAMPLE_BYTES} bytes",
            "tool": "put_sample_begin",
        }
    upload_id = uuid.uuid4().hex
    _UPLOADS[upload_id] = {
        "filename": filename,
        "sha256": sha256,
        "size": declared,
        "chunks": {},
        "received": 0,
        "started_at": time.monotonic(),
    }
    return {"upload_id": upload_id}


@mcp.tool()
def put_sample_chunk(upload_id: str, seq: int, content_b64: str) -> dict[str, Any]:
    """Send one chunk of a chunked upload, identified by its sequence number."""
    _evict_stale_uploads()
    upload = _UPLOADS.get(upload_id)
    if upload is None:
        return {"error": f"unknown upload_id {upload_id!r}", "tool": "put_sample_chunk"}
    try:
        blob = base64.b64decode(content_b64, validate=True)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"content_b64 is not valid base64: {exc}", "tool": "put_sample_chunk"}
    if len(blob) > _MAX_CHUNK_BYTES:
        return {"error": f"chunk exceeds {_MAX_CHUNK_BYTES} bytes", "tool": "put_sample_chunk"}
    # Keyed by sequence rather than appended: a transport that reorders or
    # retries a chunk must not silently corrupt the file, and the digest check
    # at finish would only tell the caller *that* it did.
    previous = upload["chunks"].get(int(seq))
    running = upload["received"] - (len(previous) if previous else 0) + len(blob)
    # Enforced as the chunks arrive, not at assembly: refusing a 3 GB upload
    # after buffering all of it is not a limit, it is a slower way to run out
    # of memory.
    if running > min(upload["size"] or _MAX_SAMPLE_BYTES, _MAX_SAMPLE_BYTES):
        _UPLOADS.pop(upload_id, None)
        return {"error": "upload exceeds its declared size", "tool": "put_sample_chunk"}
    upload["chunks"][int(seq)] = blob
    upload["received"] = running
    return {"upload_id": upload_id, "seq": int(seq), "received": len(blob)}


@mcp.tool()
def put_sample_finish(upload_id: str) -> dict[str, Any]:
    """Assemble a chunked upload, verify its digest and return the sample's path."""
    _evict_stale_uploads()
    upload = _UPLOADS.pop(upload_id, None)
    if upload is None:
        return {"error": f"unknown upload_id {upload_id!r}", "tool": "put_sample_finish"}
    chunks: dict[int, bytes] = upload["chunks"]
    blob = b"".join(chunks[seq] for seq in sorted(chunks))
    expected = int(upload.get("size") or 0)
    if expected and len(blob) != expected:
        return {
            "error": f"size mismatch: expected {expected} bytes, assembled {len(blob)}",
            "tool": "put_sample_finish",
        }
    return _guard(
        "put_sample_finish",
        _write_sample,
        filename=upload["filename"],
        blob=blob,
        sha256=upload["sha256"],
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
