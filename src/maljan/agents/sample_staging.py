"""Get the sample to a tool server that cannot see the worker's filesystem.

Every path-taking tool in this project assumes the server and the worker share
a filesystem. That is true for a stdio sidecar and false for every other
deployment: a server on the sandbox host, a server in another container, a
server someone runs on their laptop. Until now the answer was a shared volume
and a ``mirror_spec``, which works when you control both ends and not
otherwise.

The convention here is the other answer. A server reached over HTTP that
advertises ``put_sample`` is handed the bytes, and the path it returns is what
that server's tools are called with — ``agents.tool_pinning.pin_paths`` takes
the per-server map and substitutes accordingly. Large samples go through
``put_sample_begin`` / ``put_sample_chunk`` / ``put_sample_finish`` when the
manifest has all three; a server offering only the single-shot call gets the
single-shot call.

**Transport decides, not the manifest.** A stdio sidecar runs on this host and
opens this filesystem, so uploading to it would write a second copy of the
sample for nothing — a full read plus base64 in the worker's memory, a
JSON-RPC transfer, and malware bytes accumulating in a staging directory — to
hand the server a path it could already read. The built-in ``analysis`` sidecar
implements ``put_sample*`` all the same, because an operator may run that very
file behind an HTTP transport on another host, and then it is the case the
convention exists for.

Staging never fails a run. Anything that goes wrong becomes a degradation
reason and ``None``, and the agent then calls that server with the local path
exactly as it did before — which is right when the server does share the
filesystem and merely happens to offer ``put_sample`` as well.
"""

from __future__ import annotations

import base64
import hashlib
import time
from pathlib import Path
from typing import Any

from maljan.core.logger import logger

# The reason string a failed staging contributes, in the same voice as
# ``providers.servers.UNAVAILABLE_REASON`` so the run summary reads as one list.
STAGING_FAILED_REASON = "sample staging failed for '{server}': {reason}"

# Above this, the upload is chunked when the server supports it. 8 MiB of
# base64 is ~11 MiB on the wire, which is already more than a comfortable
# single JSON-RPC message.
CHUNK_THRESHOLD_BYTES = 8 * 1024 * 1024
CHUNK_BYTES = 4 * 1024 * 1024

# How long a staged path is trusted. A sidecar restarts and loses its staging
# directory; re-uploading a sample once every few minutes is cheap next to
# calling every tool with a path that no longer exists.
CACHE_TTL_SECONDS = 30 * 60

SINGLE_SHOT_TOOL = "put_sample"
CHUNKED_TOOLS = ("put_sample_begin", "put_sample_chunk", "put_sample_finish")

# The transports that put a network between the worker and the server. Anything
# else is a local subprocess reading the local filesystem.
REMOTE_TRANSPORTS = frozenset({"http", "streamable-http", "sse"})

# ``(server_key, sha256) -> (path, staged_at)``. Process-wide: one worker
# analyses many samples against the same servers, and a per-job cache would
# re-upload the same sample for every agent bound to the server.
_CACHE: dict[tuple[str, str], tuple[str, float]] = {}


def clear_cache() -> None:
    """Forget every staged path. For tests and for a server that restarted."""
    _CACHE.clear()


def _cached(server_key: str, sha256: str) -> str | None:
    entry = _CACHE.get((server_key, sha256))
    if entry is None:
        return None
    path, staged_at = entry
    if time.monotonic() - staged_at > CACHE_TTL_SECONDS:
        _CACHE.pop((server_key, sha256), None)
        return None
    return path


def supports_staging(tool_names: list[str] | set[str]) -> bool:
    """Whether a manifest advertises the single-shot upload at all."""
    return SINGLE_SHOT_TOOL in set(tool_names)


def _path_from(result: Any) -> str | None:
    """The path out of a tool result, whatever shape the transport gave it."""
    if isinstance(result, str):
        text = result.strip()
        if not text.startswith("{"):
            return text or None
        import json

        try:
            result = json.loads(text)
        except ValueError:
            return None
    if isinstance(result, dict):
        if result.get("error"):
            return None
        path = result.get("path")
        return str(path) if path else None
    return None


def _error_of(result: Any) -> str:
    """The error a tool returned rather than raised, if it returned one."""
    if isinstance(result, dict) and result.get("error"):
        return str(result["error"])
    if isinstance(result, str) and '"error"' in result:
        return result[:200]
    return ""


async def _call(handle: Any, name: str, **kwargs: Any) -> Any:
    """Invoke one tool on an open handle by name."""
    for tool in handle.tools():
        if str(getattr(tool, "name", "")) == name:
            return await tool.ainvoke(kwargs)
    raise LookupError(f"the server does not offer {name!r}")


async def stage_sample(
    registry: Any,
    server_key: str,
    sample_path: str,
    *,
    sha256: str,
    job_id: str,
) -> str | None:
    """Upload the sample to ``server_key`` and return the path it lives at there.

    ``None`` means "call this server with the local path": either it does not
    speak the convention, or the upload failed and the reason has been recorded
    on the registry.
    """
    try:
        handle = registry.get(server_key)
    except Exception as exc:  # noqa: BLE001 — staging never fails a run
        _record(registry, server_key, f"unknown server ({exc})")
        return None
    if not handle.is_open:
        return None
    manifest = set(handle.all_tool_names())
    if not supports_staging(manifest):
        return None

    source = Path(sample_path)
    if not source.is_file():
        _record(registry, server_key, f"no sample at {sample_path}")
        return None

    try:
        blob = source.read_bytes()
        # The digest is computed before the cache is consulted, not after. The
        # store is keyed by the computed value, so a caller that passed no hash
        # would look up under "", miss every time, and re-upload the sample
        # once per agent bound to the server.
        digest = sha256 or hashlib.sha256(blob).hexdigest()
        cached = _cached(server_key, digest)
        if cached is not None:
            return cached
        chunked = len(blob) > CHUNK_THRESHOLD_BYTES and all(t in manifest for t in CHUNKED_TOOLS)
        if chunked:
            path = await _stage_chunked(handle, source.name, blob, digest)
        else:
            path = await _stage_single(handle, source.name, blob, digest)
    except Exception as exc:  # noqa: BLE001 — staging never fails a run
        _record(registry, server_key, f"{type(exc).__name__}: {exc}")
        return None

    if not path:
        _record(registry, server_key, "the server returned no path")
        return None
    logger.info("staged sample %s to '%s' at %s for job %s.", digest[:12], server_key, path, job_id)
    _CACHE[(server_key, digest)] = (path, time.monotonic())
    return path


async def _stage_single(handle: Any, filename: str, blob: bytes, digest: str) -> str | None:
    result = await _call(
        handle,
        SINGLE_SHOT_TOOL,
        filename=filename,
        content_b64=base64.b64encode(blob).decode("ascii"),
        sha256=digest,
    )
    error = _error_of(result)
    if error:
        raise RuntimeError(error)
    return _path_from(result)


async def _stage_chunked(handle: Any, filename: str, blob: bytes, digest: str) -> str | None:
    """Begin, send every chunk in order, finish.

    Sequence numbers rather than a stream: the server keys chunks by ``seq`` so
    a transport that retries one does not corrupt the file, and the digest
    check at ``finish`` is a backstop rather than the only defence.
    """
    begin = await _call(
        handle, "put_sample_begin", filename=filename, sha256=digest, size=len(blob)
    )
    error = _error_of(begin)
    if error:
        raise RuntimeError(error)
    upload_id = begin.get("upload_id") if isinstance(begin, dict) else None
    if not upload_id:
        import json

        parsed = json.loads(begin) if isinstance(begin, str) else {}
        upload_id = parsed.get("upload_id")
    if not upload_id:
        raise RuntimeError("put_sample_begin returned no upload_id")

    for seq, start in enumerate(range(0, len(blob), CHUNK_BYTES)):
        chunk = blob[start : start + CHUNK_BYTES]
        sent = await _call(
            handle,
            "put_sample_chunk",
            upload_id=upload_id,
            seq=seq,
            content_b64=base64.b64encode(chunk).decode("ascii"),
        )
        error = _error_of(sent)
        if error:
            raise RuntimeError(error)

    finished = await _call(handle, "put_sample_finish", upload_id=upload_id)
    error = _error_of(finished)
    if error:
        raise RuntimeError(error)
    return _path_from(finished)


def _record(registry: Any, server_key: str, reason: str) -> None:
    """Put a staging failure on the registry's degradation list, once."""
    message = STAGING_FAILED_REASON.format(server=server_key, reason=reason)
    logger.warning("%s", message)
    reasons = getattr(registry, "degradation_reasons", None)
    if isinstance(reasons, list) and message not in reasons:
        reasons.append(message)


async def stage_for_agent(
    registry: Any,
    tools: list[Any],
    sample_path: str | None,
    *,
    sha256: str,
    job_id: str,
) -> dict[str, str]:
    """Stage the sample to every server among ``tools`` that cannot read it.

    "Cannot read it" is a question about the transport, not the manifest: a
    stdio server is a child process of this worker and opens the same
    filesystem, so it is handed the path and nothing is copied. Only an HTTP
    transport gets the bytes, and only when it advertises the convention.
    """
    if not sample_path:
        return {}
    from maljan.agents.tool_pinning import server_of

    staged: dict[str, str] = {}
    for key in dict.fromkeys(server_of(tool) for tool in tools):
        if not key:
            continue
        try:
            handle = registry.get(key)
        except Exception:  # noqa: BLE001 — a tool from a server that is gone
            continue
        transport = str(getattr(handle.config, "transport", "stdio") or "stdio").lower()
        if transport not in REMOTE_TRANSPORTS:
            continue
        path = await stage_sample(registry, key, sample_path, sha256=sha256, job_id=job_id)
        if path:
            staged[key] = path
    return staged
