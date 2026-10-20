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

import asyncio
import base64
import hashlib
import math
import threading
import time
from pathlib import Path
from typing import Any

from maljan.core.logger import logger
from maljan.pipeline.events import describe_exception

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

# How a reason quotes the error a server answered a staging call with.
STAGING_REFUSED_PREFIX = "the server answered: "


def planned_calls(size: int, manifest: set[str]) -> dict[str, int]:
    """How many times each staging tool is called to upload ``size`` bytes, by name.

    The decision :func:`stage_sample` takes: chunked above
    :data:`CHUNK_THRESHOLD_BYTES` when the server offers all three chunked
    calls, the single-shot call otherwise; nothing for a server that offers
    no upload at all.
    """
    if not supports_staging(manifest):
        return {}
    if size > CHUNK_THRESHOLD_BYTES and all(t in manifest for t in CHUNKED_TOOLS):
        begin, chunk, finish = CHUNKED_TOOLS
        return {begin: 1, chunk: max(1, math.ceil(size / CHUNK_BYTES)), finish: 1}
    return {SINGLE_SHOT_TOOL: 1}


# The transports that put a network between the worker and the server. Anything
# else is a local subprocess reading the local filesystem.
REMOTE_TRANSPORTS = frozenset({"http", "streamable-http", "sse"})

# ``(job_id, server_key, sha256) -> (path, staged_at)``. One entry per job, not
# per process: staging is per job now, so a path cached under an earlier job's
# id names a file inside a directory that job's teardown has removed, and every
# tool call made with it would answer "no such file". Still shared across the
# agents of one job, which is what the cache is for — a sample is uploaded once
# however many agents are bound to the server.
_CACHE: dict[tuple[str, str, str], tuple[str, float]] = {}


def clear_cache() -> None:
    """Forget every staged path. For tests and for a server that restarted."""
    _CACHE.clear()


def forget_job(job_id: str) -> int:
    """Forget what this job staged. Returns how many entries went.

    Called where the job's staging directory is removed, because that is what
    makes the paths in here wrong rather than merely old.
    """
    stale = [key for key in _CACHE if key[0] == str(job_id)]
    for key in stale:
        _CACHE.pop(key, None)
    return len(stale)


def _cached(job_id: str, server_key: str, sha256: str) -> str | None:
    key = (job_id, server_key, sha256)
    entry = _CACHE.get(key)
    if entry is None:
        return None
    path, staged_at = entry
    if time.monotonic() - staged_at > CACHE_TTL_SECONDS:
        _CACHE.pop(key, None)
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


class StagingRefused(RuntimeError):
    """A staging call the server answered with an error; ``quoted`` when the words are its own.

    ``quoted`` is true for words the server wrote as its answer (an ``isError``
    reply, a flat ``error``); a failure the platform reported (a structured
    error, an exception, no session, a resting server) is named by its kind.
    """

    def __init__(self, message: str, *, quoted: bool) -> None:
        super().__init__(message)
        self.quoted = quoted


# The MCP client's marker kind for an answer the server itself marked an error.
_SERVER_S_OWN_ERROR = "tool_returned_error"


def _refusal_of(result: Any) -> StagingRefused | None:
    """The error a tool returned rather than raised, if it returned one.

    Every shape a tool answer may say one in (``tools.errors.error_parts``):
    a flat or structured ``error`` and the MCP client's ``tool_error`` marker,
    as an object or as JSON text. Only a truthy error is one: ``"error":
    null`` beside a path is an answer. The server's words are quoted only
    from its own answer fields (a flat ``error``, the text of an ``isError``
    reply); a structured error, which the platform writes (the guard's
    resting server included), and the client's markers for an exception or
    no session give their kind alone.
    """
    from maljan.tools.errors import error_parts

    parts = error_parts(result)
    if parts is None:
        return None
    code, message, _remedy = parts
    parsed = result
    if isinstance(parsed, str):
        import json

        try:
            parsed = json.loads(parsed.strip())
        except ValueError:
            parsed = None
    error = parsed.get("error") if isinstance(parsed, dict) else None
    if isinstance(error, dict):
        # The structured shape is the platform's (``tools.errors.tool_error``:
        # the guard's resting server, a wrapper's refusal): its kind alone.
        return StagingRefused(str(error.get("code") or code), quoted=False)
    if error:
        # A flat ``error`` is the server's own answer field.
        return StagingRefused(message, quoted=True)
    marker = str(parsed.get("tool_error") or "") if isinstance(parsed, dict) else ""
    if marker == _SERVER_S_OWN_ERROR:
        detail = str(parsed.get("detail") or "").strip() if isinstance(parsed, dict) else ""
        return StagingRefused(detail or marker, quoted=bool(detail))
    kind = marker or code
    raised = str(parsed.get("type") or "") if isinstance(parsed, dict) else ""
    return StagingRefused(f"{kind} ({raised})" if raised else kind, quoted=False)


def _check(result: Any) -> None:
    """Raise the refusal ``result`` carries, if it carries one."""
    refusal = _refusal_of(result)
    if refusal is not None:
        raise refusal


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
    stagings: list[dict[str, Any]] | None = None,
) -> str | None:
    """Upload the sample to ``server_key`` and return the path it lives at there.

    ``None`` means "call this server with the local path": either it does not
    speak the convention, or the upload failed and the reason has been recorded
    on the registry. ``stagings`` is the job's record of what was sent
    (``ServiceContainer.sample_stagings``): an upload is written there before
    its first byte is sent, as attempted, and marked done or failed once it
    ended, so a run's disclosure block names it whatever came of it.
    """
    try:
        handle = registry.get(server_key)
    except Exception as exc:  # noqa: BLE001 — staging never fails a run
        _record(registry, server_key, f"unknown server ({describe_exception(exc)})")
        return None
    if not handle.is_open:
        return None
    manifest = set(handle.all_tool_names())
    if not supports_staging(manifest):
        return None

    source = Path(sample_path)
    if not source.is_file():
        # Never the host path: a reason is published with the run.
        _record(registry, server_key, "no sample at the staged path")
        return None

    sent: dict[str, Any] | None = None
    try:
        blob = source.read_bytes()
        # The digest is computed before the cache is consulted, not after. The
        # store is keyed by the computed value, so a caller that passed no hash
        # would look up under "", miss every time, and re-upload the sample
        # once per agent bound to the server.
        digest = sha256 or hashlib.sha256(blob).hexdigest()
        cached = _cached(job_id, server_key, digest)
        if cached is not None:
            return cached
        sent = _note_staging(stagings, server_key, handle)
        if CHUNKED_TOOLS[0] in planned_calls(len(blob), manifest):
            path = await _stage_chunked(handle, source.name, blob, digest)
        else:
            path = await _stage_single(handle, source.name, blob, digest)
    except asyncio.CancelledError:
        # Stopped from outside (the bound the resolver waits within): the
        # upload did not finish, and the record says so rather than
        # "attempted". The resolver records the reason with its bound.
        _mark_staging(sent, done=False)
        raise
    except Exception as exc:  # noqa: BLE001 — staging never fails a run
        _mark_staging(sent, done=False)
        _record(registry, server_key, _reason_of(exc))
        return None

    _mark_staging(sent, done=bool(path))
    if not path:
        _record(registry, server_key, "the server returned no path")
        return None
    logger.info("staged sample %s to '%s' at %s for job %s.", digest[:12], server_key, path, job_id)
    _CACHE[(job_id, server_key, digest)] = (path, time.monotonic())
    return path


async def _stage_single(handle: Any, filename: str, blob: bytes, digest: str) -> str | None:
    result = await _call(
        handle,
        SINGLE_SHOT_TOOL,
        filename=filename,
        content_b64=base64.b64encode(blob).decode("ascii"),
        sha256=digest,
    )
    _check(result)
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
    _check(begin)
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
        _check(sent)

    finished = await _call(handle, "put_sample_finish", upload_id=upload_id)
    _check(finished)
    return _path_from(finished)


def _note_staging(
    stagings: list[dict[str, Any]] | None, server_key: str, handle: Any
) -> dict[str, Any] | None:
    """Write an upload down as attempted, before its first byte is sent; the record, or ``None``."""
    if stagings is None:
        return None
    from maljan.analysis.disclosure import STAGING_ATTEMPTED, staging_record

    config = getattr(handle, "config", None)
    record = staging_record(
        server_key,
        transport=str(getattr(config, "transport", "") or ""),
        url=str(getattr(config, "url", "") or ""),
        state=STAGING_ATTEMPTED,
    )
    stagings.append(record)
    return record


# Held while a staging record's state is written: the resolver marks an
# unfinished upload failed from its own thread while the upload's coroutine
# may still be ending on the agent loop.
_RECORD_LOCK = threading.Lock()


def _mark_staging(record: dict[str, Any] | None, *, done: bool) -> None:
    """Mark a written-down upload done or failed; one marked failed is never marked done."""
    if record is None:
        return
    from maljan.analysis.disclosure import STAGING_DONE, STAGING_FAILED

    with _RECORD_LOCK:
        if done and record.get("state") == STAGING_FAILED:
            return
        record["state"] = STAGING_DONE if done else STAGING_FAILED


def mark_unfinished_failed(stagings: Any, start: int) -> set[str]:
    """Mark every upload written down from ``start`` on and still attempted failed; their servers."""
    if not isinstance(stagings, list):
        return set()
    from maljan.analysis.disclosure import STAGING_ATTEMPTED, STAGING_FAILED

    marked: set[str] = set()
    with _RECORD_LOCK:
        for record in stagings[start:]:
            if isinstance(record, dict) and record.get("state") == STAGING_ATTEMPTED:
                record["state"] = STAGING_FAILED
                marked.add(str(record.get("server") or ""))
    return marked


def staged_servers(stagings: Any, start: int) -> set[str]:
    """The servers whose upload written down from ``start`` on was marked done."""
    if not isinstance(stagings, list):
        return set()
    from maljan.analysis.disclosure import STAGING_DONE

    with _RECORD_LOCK:
        return {
            str(record.get("server") or "")
            for record in stagings[start:]
            if isinstance(record, dict) and record.get("state") == STAGING_DONE
        }


def cached_path(job_id: str, server_key: str, sha256: str) -> str | None:
    """The path this job's sample was staged to on ``server_key``, while it is trusted."""
    if not sha256:
        return None
    return _cached(str(job_id), server_key, sha256)


def _reason_of(exc: BaseException) -> str:
    """What a failed upload's degradation reason says of ``exc``.

    A reason is published with the run. A server's own error words are said,
    with any credential in a URL masked; any other failure is named by its
    kind and remedy alone (``pipeline.events.describe_exception``), whose
    message can name a host path or a URL with its credential. The log keeps
    the message, masked the same way.
    """
    from maljan.core.settings_masking import masked_text

    if isinstance(exc, StagingRefused):
        if exc.quoted:
            return f"{STAGING_REFUSED_PREFIX}{masked_text(str(exc))}"
        return f"the upload failed: {exc}"
    logger.warning("sample staging failed: %s", masked_text(f"{type(exc).__name__}: {exc}"))
    return describe_exception(exc)


def record_failure(registry: Any, server_key: str, reason: str) -> None:
    """Put a staging failure for ``server_key`` on the registry's degradation list, once."""
    _record(registry, server_key, reason)


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
    stagings: list[dict[str, Any]] | None = None,
) -> dict[str, str]:
    """Stage the sample to every server among ``tools`` that cannot read it.

    "Cannot read it" is a question about the transport, not the manifest: a
    stdio server is a child process of this worker and opens the same
    filesystem, so it is handed the path and nothing is copied. Only an HTTP
    transport gets the bytes, and only when it advertises the convention.
    Each upload is written to ``stagings`` (:func:`stage_sample`).
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
        path = await stage_sample(
            registry, key, sample_path, sha256=sha256, job_id=job_id, stagings=stagings
        )
        if path:
            staged[key] = path
    return staged
